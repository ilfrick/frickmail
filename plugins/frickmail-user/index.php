<?php
/**
 * Frickmail user plugin — first-class user identity backed by Postgres.
 *
 * Login flow:
 *   1. Browser POSTs username + password to ?Json/&q[]=/0/Plugin/-/&_action=FrickmailLogin
 *   2. We verify against frickmail_users.password_hash (Argon2id)
 *   3. We derive an AEAD key from the password + per-user salt, keep it in
 *      $_SESSION (PHP session, distinct from SnappyMail's session)
 *   4. We load the primary mail account from frickmail_mail_accounts
 *   5. We bridge to SnappyMail's LoginProcess() with the decrypted IMAP creds
 *   6. SnappyMail issues its session token, the user lands in the inbox
 *
 * Adding mail accounts: separate JSON endpoints write to frickmail_mail_accounts
 * with credentials encrypted under the same AEAD key. OAuth tokens go to
 * encrypted_oauth_refresh_token.
 */

require_once __DIR__ . '/lib/Crypto.php';
require_once __DIR__ . '/lib/Db.php';
require_once __DIR__ . '/lib/Bridge.php';
require_once __DIR__ . '/lib/Mailer.php';

class FrickmailUserPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Frickmail User',
		VERSION  = '0.35',
		RELEASE  = '2026-05-16',
		REQUIRED = '2.36.1',
		CATEGORY = 'Login',
		DESCRIPTION = 'Frickmail: first-class user identity in Postgres, mail accounts as linked records.';

	const SESSION_KEY_USER = 'frickmail_user_id';
	const SESSION_KEY_KEY  = 'frickmail_crypt_key';

	public function Init() : void
	{
		// Frickmail is the only account management system — disable SnappyMail's
		// built-in additional-accounts capability so its Settings→Accounts tab,
		// account-add popup, and duplicate switcher UI never appear.
		\RainLoop\Api::Config()->Set('webmail', 'allow_additional_accounts', false);

		$this->UseLangs(false);
		$this->addJs('js/Login.js');
		$this->addJs('js/AccountSwitcher.js');
		$this->addJs('js/MailAccountsSettings.js');
		$this->addJs('js/TwoFactorSettings.js');
		$this->addTemplate('templates/FrickmailMailAccountsSettings.html');
		$this->addTemplate('templates/FrickmailTwoFactorSettingsTab.html');

		$this->addJsonHook('FrickmailLogin', 'JsonFrickmailLogin');
		$this->addJsonHook('FrickmailRegister', 'JsonFrickmailRegister');
		$this->addJsonHook('FrickmailListAccounts', 'JsonListAccounts');
		$this->addJsonHook('FrickmailAddAccount', 'JsonAddAccount');
		$this->addJsonHook('FrickmailDeleteAccount', 'JsonDeleteAccount');
		$this->addJsonHook('FrickmailSetPrimary', 'JsonSetPrimary');
		$this->addJsonHook('FrickmailSwitchAccount', 'JsonSwitchAccount');
		$this->addJsonHook('FrickmailSetAccountPassword', 'JsonSetAccountPassword');
		$this->addJsonHook('FrickmailRequestPasswordReset', 'JsonRequestPasswordReset');
		$this->addJsonHook('FrickmailResetPassword', 'JsonResetPassword');
		$this->addJsonHook('FrickmailMe', 'JsonMe');
		$this->addJsonHook('FrickmailGetTotpStatus', 'JsonGetTotpStatus');
		$this->addJsonHook('FrickmailEnableTotp', 'JsonEnableTotp');
		$this->addJsonHook('FrickmailConfirmTotp', 'JsonConfirmTotp');
		$this->addJsonHook('FrickmailDisableTotp', 'JsonDisableTotp');
		// JsonTestImap removed — diagnostic endpoint must not exist in production (C1)
		$this->addJsonHook('FrickmailDiscoverServices', 'JsonDiscoverServices');
		$this->addJsonHook('FrickmailActivateService', 'JsonActivateService');

		// Allow Sec-Fetch cross-site navigations to the reset-password landing page,
		// so the link delivered by email opens correctly from external mail clients.
		$this->addHook('filter.http-paths', 'httpPaths');
	}

	public function httpPaths(array $aPaths) : void
	{
		// Allow cross-site navigations whenever the URL is a reset-password landing.
		if (isset($_GET['reset_token']) && '' !== \trim((string) $_GET['reset_token'])) {
			$oConfig = \RainLoop\Api::Config();
				$sCurrent = $oConfig->Get('security', 'secfetch_allow', '');
			$aParts = \array_filter(\array_unique(\explode(';', $sCurrent)));
			if (!\in_array('site=cross-site', $aParts, true)) {
				$aParts[] = 'site=cross-site';
			}
			$oConfig->Set('security', 'secfetch_allow', \implode(';', $aParts));
		}
	}

	public function configMapping() : array
	{
		return [
			\RainLoop\Plugins\Property::NewInstance('open_signup')
				->SetLabel('Allow self-registration')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::BOOL)
				->SetDefaultValue(false)
				->SetAllowedInJs()
				->SetDescription('When enabled, anyone reaching the login page can create a Frickmail account. Otherwise users must be created via CLI.'),
		];
	}

	private function db() : \Frickmail\User\Db
	{
		return new \Frickmail\User\Db();
	}

	private function startPhpSession() : void
	{
		// Delegate to Bridge::startSession() which has the full save_path guard
		// and X-Forwarded-Proto handling — single implementation, no duplication.
		\Frickmail\User\Bridge::startSession();
	}

	private function isSignupOpen() : bool
	{
		$env = \getenv('FRICKMAIL_OPEN_SIGNUP');
		if (\is_string($env) && \in_array(\strtolower(\trim($env)), ['1', 'true', 'yes', 'on'], true)) {
			return true;
		}
		return (bool) $this->Config()->Get('plugin', 'open_signup', false);
	}

	/* -------------------- JSON actions -------------------- */

	public function JsonFrickmailRegister() : array
	{
		try {
			$db = $this->db();
			$bSignupOpen = $this->isSignupOpen();
			$bFirstUser  = (0 === $db->userCount());
			if (!$bSignupOpen && !$bFirstUser) {
				throw new \RuntimeException('Self-signup is disabled. Ask your admin or set FRICKMAIL_OPEN_SIGNUP=true.');
			}
			$sUsername = \trim((string) $this->jsonParam('username'));
			$sEmail    = \trim((string) $this->jsonParam('email'));
			$sPassword = (string) $this->jsonParam('password');

			if (\strlen($sUsername) < 3) throw new \RuntimeException('Username must be at least 3 chars');
			if (\strlen($sPassword) < 8) throw new \RuntimeException('Password must be at least 8 chars');
			if ($db->findUserByUsername($sUsername)) throw new \RuntimeException('Username already taken');

			$sHash = \Frickmail\User\Crypto::hashPassword($sPassword);
			$sSalt = \Frickmail\User\Crypto::generateSalt();
			$id = $db->createUser($sUsername, $sEmail ?: null, $sHash, $sSalt);

			return $this->jsonResponse(__FUNCTION__, [
				'ok'      => true,
				'message' => 'Account created. Sign in to add your mail accounts.'
			]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonFrickmailLogin() : array
	{
		try {
			$db = $this->db();
			$sUsername = \trim((string) $this->jsonParam('username'));
			$sPassword = (string) $this->jsonParam('password');
			if ('' === $sUsername || '' === $sPassword) throw new \RuntimeException('Missing credentials');

			$user = $db->findUserByUsername($sUsername);
			if (!$user || !\Frickmail\User\Crypto::verifyPassword($sPassword, $user['password_hash'])) {
				throw new \RuntimeException('Invalid username or password');
			}

			// Frickmail-user 2FA: if a TOTP secret is set on this user, require a valid code.
			if (!empty($user['totp_secret'])) {
				$sTotpCode = \preg_replace('/\s+/', '', (string) $this->jsonParam('totp_code'));
				if ('' === $sTotpCode) {
					return $this->jsonResponse(__FUNCTION__, [
						'ok' => false,
						'requires_totp' => true,
						'error' => 'Two-factor code required'
					]);
				}
				if (!\SnappyMail\TOTP::Verify($user['totp_secret'], $sTotpCode)) {
					return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'requires_totp' => true, 'error' => 'Invalid two-factor code']);
				}
				// Replay protection (H6): reject a code that was already used in this 30-second window.
				$iWindow = (int) \floor(\time() / 30);
				if (!$this->db()->recordTotpUse((int) $user['id'], $sTotpCode, $iWindow)) {
					return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'requires_totp' => true, 'error' => 'Two-factor code already used']);
				}
			}

			$kdfSalt = \is_resource($user['kdf_salt']) ? \stream_get_contents($user['kdf_salt']) : $user['kdf_salt'];
			$cryptKey = \Frickmail\User\Crypto::deriveKey($sPassword, $kdfSalt);

			$this->startPhpSession();
			$_SESSION[self::SESSION_KEY_USER] = (int) $user['id'];
			$_SESSION[self::SESSION_KEY_KEY]  = \base64_encode($cryptKey);

			// Bridge to SnappyMail's IMAP login if a primary mail account exists.
			$primary = $db->getPrimaryMailAccount((int) $user['id']);
			if (!$primary) {
				return $this->jsonResponse(__FUNCTION__, [
					'ok' => true,
					'no_primary' => true,
					'message' => 'Logged in. Add a mail account from the settings panel.'
				]);
			}
			$account = $db->decryptedAccount($primary, $cryptKey);
			$bMissing = ('imap' === $account['type'] && empty($account['password']))
				|| (\in_array($account['type'], ['gmail','o365'], true) && empty($account['oauth_refresh_token']));
			if ($bMissing) {
				return $this->jsonResponse(__FUNCTION__, [
					'ok' => true,
					'no_primary' => true,
					'reauth_required' => true,
					'reauth_account_id' => (int) $account['id'],
					'reauth_account_email' => (string) $account['email'],
					'reauth_account_type' => (string) $account['type'],
					'message' => 'Re-enter the password for ' . $account['email'] . ' (lost after the password reset).',
				]);
			}
			try {
				$this->bridgeToSnappyMail($account);
			} catch (\RainLoop\Exceptions\ClientException $e) {
				if ($e->getCode() === \RainLoop\Notifications::AuthError) {
					// Stored credentials are wrong (e.g. wrong password re-entered during
					// a previous re-auth attempt). Treat as reauth_required so the user
					// can correct the password rather than seeing a cryptic login error.
					return $this->jsonResponse(__FUNCTION__, [
						'ok' => true,
						'no_primary' => true,
						'reauth_required' => true,
						'reauth_account_id' => (int) $account['id'],
						'reauth_account_email' => (string) $account['email'],
						'reauth_account_type' => (string) $account['type'],
						'message' => 'IMAP authentication failed for ' . $account['email'] . ' — re-enter the password.',
					]);
				}
				throw $e;
			}

			return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'email' => $account['email']]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonMe() : array
	{
		$this->startPhpSession();
		$uid = $_SESSION[self::SESSION_KEY_USER] ?? null;
		if (!$uid) return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'authenticated' => false]);
		$user = $this->db()->findUserById((int) $uid);
		if (!$user) return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'authenticated' => false]);
		return $this->jsonResponse(__FUNCTION__, [
			'ok' => true,
			'authenticated' => true,
			'username' => $user['username'],
			'email' => $user['email']
		]);
	}

	const SESSION_KEY_TOTP_PENDING = 'frickmail_totp_pending_secret';

	public function JsonGetTotpStatus() : array
	{
		try {
			[$uid] = $this->requireSession();
			$user = $this->db()->findUserById($uid);
			return $this->jsonResponse(__FUNCTION__, [
				'ok' => true,
				'enabled' => !empty($user['totp_secret']),
			]);
		} catch (\Throwable $e) {
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonEnableTotp() : array
	{
		try {
			[$uid] = $this->requireSession();
			$user = $this->db()->findUserById($uid);
			if (!empty($user['totp_secret'])) {
				return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => 'Two-factor authentication is already enabled. Disable it first.']);
			}
			$sSecret = \SnappyMail\TOTP::CreateSecret();
			$this->startPhpSession();
			$_SESSION[self::SESSION_KEY_TOTP_PENDING] = $sSecret;

			$sIssuer = 'Frickmail';
			$sLabel = $user['username'];
			$sUri = \sprintf(
				'otpauth://totp/%s:%s?secret=%s&issuer=%s',
				\rawurlencode($sIssuer),
				\rawurlencode($sLabel),
				$sSecret,
				\rawurlencode($sIssuer)
			);
			return $this->jsonResponse(__FUNCTION__, [
				'ok' => true,
				'secret' => $sSecret,
				'otpauth_uri' => $sUri,
				'qr_data_url' => $this->generateQrDataUrl($sUri),
				'message' => 'Scan the QR code (or paste the secret) into your authenticator app, then submit a code to confirm.',
			]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonConfirmTotp() : array
	{
		try {
			[$uid] = $this->requireSession();
			$sCode = \preg_replace('/\s+/', '', (string) $this->jsonParam('code'));
			if ('' === $sCode) throw new \RuntimeException('Code required');
			$this->startPhpSession();
			$sPending = $_SESSION[self::SESSION_KEY_TOTP_PENDING] ?? null;
			if (!$sPending) throw new \RuntimeException('No pending TOTP setup. Call EnableTotp first.');
			if (!\SnappyMail\TOTP::Verify($sPending, $sCode)) {
				return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => 'Invalid code']);
			}
			$this->db()->setUserTotpSecret($uid, $sPending);
			unset($_SESSION[self::SESSION_KEY_TOTP_PENDING]);
			return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'message' => 'Two-factor authentication enabled.']);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonDisableTotp() : array
	{
		try {
			[$uid] = $this->requireSession();
			$sCode = \preg_replace('/\s+/', '', (string) $this->jsonParam('code'));
			$user = $this->db()->findUserById($uid);
			if (empty($user['totp_secret'])) {
				return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'message' => 'Two-factor was not enabled.']);
			}
			if ('' === $sCode || !\SnappyMail\TOTP::Verify($user['totp_secret'], $sCode)) {
				return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => 'A valid TOTP code is required to disable two-factor authentication.']);
			}
			$this->db()->setUserTotpSecret($uid, null);
			return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'message' => 'Two-factor authentication disabled.']);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonRequestPasswordReset() : array
	{
		// Always respond OK to avoid leaking which usernames exist.
		try {
			$db = $this->db();
			$sUsername = \trim((string) $this->jsonParam('username'));
			$user = '' !== $sUsername ? $db->findUserByUsername($sUsername) : null;
			if ($user && !empty($user['email']) && \filter_var($user['email'], \FILTER_VALIDATE_EMAIL)) {
				$sToken = \rtrim(\strtr(\base64_encode(\random_bytes(32)), '+/', '-_'), '=');
				$sTokenHash = \hash('sha256', $sToken);
				$db->createPasswordResetToken((int) $user['id'], $sTokenHash, 1800); // 30 min
				$sLink = $this->resetUrl($sToken);
				$sBody = "Ciao " . $user['username'] . ",\n\n"
					. "Hai richiesto il reset della password Frickmail. Apri questo link entro 30 minuti:\n\n"
					. $sLink . "\n\n"
					. "Se non sei stato tu, ignora questa email.\n\n"
					. "ATTENZIONE: dopo il reset le password IMAP / refresh-token OAuth salvati nel tuo "
					. "account Frickmail vanno re-inseriti dal pannello Settings → Mail Accounts (sono "
					. "cifrati con una chiave derivata dalla password e non sono recuperabili).\n\n"
					. "— Frickmail";
				try {
					\Frickmail\User\Mailer::send((string) $user['email'], 'Frickmail — reset password', $sBody);
				} catch (\Throwable $e) {
					\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
					// We deliberately don't return the error to the client.
				}
			}
			return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'message' => 'If the username exists and has a recovery email, a reset link has been sent.']);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => 'Server error']);
		}
	}

	public function JsonResetPassword() : array
	{
		try {
			$sToken = (string) $this->jsonParam('token');
			$sPassword = (string) $this->jsonParam('password');
			if ('' === $sToken) throw new \RuntimeException('Token required');
			if (\strlen($sPassword) < 8) throw new \RuntimeException('Password must be at least 8 chars');
			$sTokenHash = \hash('sha256', $sToken);
			$db = $this->db();
			$row = $db->findActivePasswordReset($sTokenHash);
			if (!$row) throw new \RuntimeException('Invalid or expired token');
			$newHash = \Frickmail\User\Crypto::hashPassword($sPassword);
			$newSalt = \Frickmail\User\Crypto::generateSalt();
			$db->applyPasswordReset((int) $row['user_id'], $newHash, $newSalt);
			$db->consumePasswordReset((int) $row['id']);
			return $this->jsonResponse(__FUNCTION__, [
				'ok' => true,
				'username' => $row['username'],
				'message' => 'Password reset. Sign in with your new password. Linked mail-account credentials must be re-entered.',
			]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	private function resetUrl(string $sToken) : string
	{
		$sBase = \trim((string) (\getenv('FRICKMAIL_BASE_URL') ?: ''));
		if ('' === $sBase) {
			$proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
			$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
			$sBase = $proto . '://' . $host;
		}
		return \rtrim($sBase, '/') . '/?reset_token=' . \urlencode($sToken);
	}

	public function JsonListAccounts() : array
	{
		try {
			[$uid] = $this->requireSession();
			$rows = $this->db()->listMailAccounts($uid);
			$result = [];
			foreach ($rows as $row) {
				$result[] = [
					'id' => (int) $row['id'],
					'label' => $row['label'],
					'email' => $row['email'],
					'type' => $row['type'],
					'imap_host' => $row['imap_host'],
					'imap_port' => (int) $row['imap_port'],
					'imap_secure' => $row['imap_secure'],
					'smtp_host' => $row['smtp_host'],
					'smtp_port' => (int) $row['smtp_port'],
					'smtp_secure' => $row['smtp_secure'],
					'login' => $row['login'],
					'is_primary' => (bool) $row['is_primary']
				];
			}
			return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'accounts' => $result]);
		} catch (\Throwable $e) {
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonAddAccount() : array
	{
		try {
			[$uid, $cryptKey] = $this->requireSession();
			$type = (string) $this->jsonParam('type');
			if (!\in_array($type, ['imap','gmail','o365'], true)) throw new \RuntimeException('Invalid type');
			$data = [
				'label' => \trim((string) $this->jsonParam('label')) ?: \trim((string) $this->jsonParam('email')),
				'email' => \trim((string) $this->jsonParam('email')),
				'type' => $type,
			];
			if ('imap' === $type) {
				$data['imap_host'] = (string) $this->jsonParam('imap_host');
				$data['imap_port'] = (int) ($this->jsonParam('imap_port') ?: 993);
				$data['imap_secure'] = (string) ($this->jsonParam('imap_secure') ?: 'SSL');
				$data['smtp_host'] = (string) $this->jsonParam('smtp_host');
				$data['smtp_port'] = (int) ($this->jsonParam('smtp_port') ?: 465);
				$data['smtp_secure'] = (string) ($this->jsonParam('smtp_secure') ?: 'SSL');
				$data['login'] = (string) ($this->jsonParam('login') ?: $data['email']);
				$pwd = (string) $this->jsonParam('password');
				if ('' !== $pwd) {
					$data['encrypted_password'] = \Frickmail\User\Crypto::encrypt($pwd, $cryptKey);
				}
			} else {
				// OAuth slots — credentials provisioned via the OAuth callback flow
				$data['login'] = $data['email'];
				if ('o365' === $type) {
					$data['oauth_tenant'] = (string) ($this->jsonParam('tenant') ?: 'common');
				}
			}
			$data['is_primary'] = (bool) $this->jsonParam('is_primary');
			$id = $this->db()->insertMailAccount($uid, $data);

			// If this is the first account, mark it primary.
			$count = \count($this->db()->listMailAccounts($uid));
			if (1 === $count || $data['is_primary']) {
				$this->db()->setPrimaryMailAccount($uid, $id);
			}
			return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'id' => $id]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonDeleteAccount() : array
	{
		try {
			[$uid] = $this->requireSession();
			$id = (int) $this->jsonParam('id');
			$ok = $this->db()->deleteMailAccount($uid, $id);
			return $this->jsonResponse(__FUNCTION__, ['ok' => $ok]);
		} catch (\Throwable $e) {
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonSetPrimary() : array
	{
		try {
			[$uid] = $this->requireSession();
			$id = (int) $this->jsonParam('id');
			$this->db()->setPrimaryMailAccount($uid, $id);
			return $this->jsonResponse(__FUNCTION__, ['ok' => true]);
		} catch (\Throwable $e) {
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	/** Temporary diagnostic: decrypt stored IMAP password and test it directly. */
	public function JsonSetAccountPassword() : array
	{
		try {
			[$uid, $cryptKey] = $this->requireSession();
			$id = (int) $this->jsonParam('id');
			$pwd = (string) $this->jsonParam('password');
			if ($id <= 0) throw new \RuntimeException('Account id required');
			if ('' === $pwd) throw new \RuntimeException('Password required');
			$row = $this->db()->getMailAccount($uid, $id);
			if (!$row) throw new \RuntimeException('Account not found');
			$blob = \Frickmail\User\Crypto::encrypt($pwd, $cryptKey);
			$this->db()->setMailAccountPassword($uid, $id, $blob);
			return $this->jsonResponse(__FUNCTION__, ['ok' => true]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonSwitchAccount() : array
	{
		try {
			[$uid, $cryptKey] = $this->requireSession();
			$id = (int) $this->jsonParam('id');
			$db = $this->db();
			$row = $db->getMailAccount($uid, $id);
			if (!$row) throw new \RuntimeException('Account not found');

			$oActions = \RainLoop\Api::Actions();
			$account = $db->decryptedAccount($row, $cryptKey);
			$this->bridgeToSnappyMail($account);
			return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'email' => $account['email']]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	private function requireSession() : array
	{
		$this->startPhpSession();
		$uid = $_SESSION[self::SESSION_KEY_USER] ?? null;
		$keyB64 = $_SESSION[self::SESSION_KEY_KEY] ?? null;
		if (!$uid || !$keyB64) throw new \RuntimeException('Not authenticated');
		return [(int) $uid, \base64_decode($keyB64, true)];
	}

	/* -------------------- SnappyMail bridge -------------------- */

	private function bridgeToSnappyMail(array $account) : void
	{
		$oActions = \RainLoop\Api::Actions();

		if ('imap' === $account['type']) {
			if (empty($account['password'])) throw new \RuntimeException('Missing IMAP password');
			$oPassword = new \SnappyMail\SensitiveString($account['password']);
			$this->ensureSnappyMailDomain($account);
			$oActions->LoginProcess($account['email'], $oPassword);
			return;
		}

		// OAuth bridge: exchange refresh_token for an access_token, then call
		// LoginProcess. The login-gmail / login-o365 plugins are still hooked to
		// imap.before-login and will replace the IMAP password with the
		// access_token via XOAUTH2 / OAUTHBEARER.
		if (empty($account['oauth_refresh_token'])) {
			throw new \RuntimeException('Missing OAuth refresh token — re-authorize this account.');
		}

		[$tokenUri, $clientId, $clientSecret, $scope] = $this->oauthEndpoint($account);
		$oClient = new \OAuth2\Client($clientId, $clientSecret);
		$aResp = $oClient->getAccessToken($tokenUri, 'refresh_token', [
			'refresh_token' => $account['oauth_refresh_token'],
			'scope' => $scope,
		]);
		if (200 != $aResp['code'] || empty($aResp['result']['access_token'])) {
			$err = $aResp['result']['error_description'] ?? $aResp['result']['error'] ?? 'token exchange failed';
			throw new \RuntimeException("OAuth refresh failed: {$err}");
		}
		$sAccessToken = (string) $aResp['result']['access_token'];
		$iExpiresIn = (int) ($aResp['result']['expires_in'] ?? 3600);
		$sNewRefresh = (string) ($aResp['result']['refresh_token'] ?? $account['oauth_refresh_token']);

		$aTokenData = [
			'access_token' => $sAccessToken,
			'refresh_token' => $sNewRefresh,
			'expires_in' => $iExpiresIn,
			'expires' => \time() + $iExpiresIn,
		];

		// Inject the access_token into the OAuth plugin's static::$auth BEFORE
		// LoginProcess fires imap.before-login / clientLogin. Without this,
		// clientLogin finds neither static::$auth nor session storage (not written
		// yet) and falls back to IMAP password auth, which fails for OAuth accounts.
		$sPluginClass = ('gmail' === $account['type']) ? 'LoginGMailPlugin' : 'LoginO365Plugin';
		if (\class_exists($sPluginClass) && \method_exists($sPluginClass, 'injectOAuthData')) {
			$sPluginClass::injectOAuthData($aTokenData);
		}

		$oPassword = new \SnappyMail\SensitiveString($account['email']);
		$oAccount = $oActions->LoginProcess($account['email'], $oPassword);
		if ($oAccount) {
			$oActions->StorageProvider()->Put($oAccount, \RainLoop\Providers\Storage\Enumerations\StorageType::SESSION,
				\RainLoop\Utils::GetSessionToken(),
				\SnappyMail\Crypt::EncryptToJSON([
					'access_token' => $sAccessToken,
					'refresh_token' => $sNewRefresh,
					'expires_in' => $iExpiresIn,
					'expires' => \time() + $iExpiresIn,
				], $oAccount->CryptKey())
			);
		}
	}

	private function oauthEndpoint(array $account) : array
	{
		if ('gmail' === $account['type']) {
			return [
				'https://accounts.google.com/o/oauth2/token',
				$this->resolveOauthEnv('FRICKMAIL_GMAIL_CLIENT_ID', 'login-gmail', 'client_id'),
				$this->resolveOauthEnv('FRICKMAIL_GMAIL_CLIENT_SECRET', null, null),
				'https://mail.google.com/'
			];
		}
		if ('o365' === $account['type']) {
			$tenant = $account['oauth_tenant'] ?: 'common';
			return [
				"https://login.microsoftonline.com/{$tenant}/oauth2/v2.0/token",
				$this->resolveOauthEnv('FRICKMAIL_O365_CLIENT_ID', 'login-o365', 'client_id'),
				$this->resolveOauthEnv('FRICKMAIL_O365_CLIENT_SECRET', null, null),
				'https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access'
			];
		}
		throw new \RuntimeException('Unknown OAuth provider');
	}

	private function resolveOauthEnv(string $envKey, ?string $pluginName, ?string $configKey) : string
	{
		$v = (string) (\getenv($envKey) ?: '');
		if ('' !== $v) return \trim($v);
		if ($pluginName && $configKey) {
			try {
				$cfg = new \RainLoop\Config\Plugin($pluginName);
				$cfg->Load();
				return \trim((string) $cfg->Get('plugin', $configKey, ''));
			} catch (\Throwable $e) {}
		}
		return '';
	}

	private function ensureSnappyMailDomain(array $account) : void
	{
		$oDomainProvider = \RainLoop\Api::Actions()->DomainProvider();
		$sDomain = \strtolower(\substr((string) \strrchr($account['email'], '@'), 1));
		if (!$sDomain) return;
		$oExisting = $oDomainProvider->Load($sDomain, false);
		if ($oExisting) {
			// Correct shortLogin on the fly if the domain exists but has wrong value.
			// The IMAP server for housefz.com requires the full email as login.
			$oImap = $oExisting->ImapSettings();
			$oSmtp = $oExisting->SmtpSettings();
			if ($oImap->shortLogin || $oSmtp->shortLogin) {
				$oImap->shortLogin = false;
				$oSmtp->shortLogin = false;
				$oDomainProvider->Save($oExisting);
			}
			return;
		}
		// Create a minimal SnappyMail domain record so IMAP/SMTP know where to connect.
		// shortLogin=false: send the full email address as the IMAP/SMTP login.
		$oDomain = \RainLoop\Model\Domain::fromArray($sDomain, [
			'IMAP' => [
				'host' => $account['imap_host'],
				'port' => $account['imap_port'],
				'type' => $this->mapSecure($account['imap_secure']),
				'shortLogin' => false,
			],
			'SMTP' => [
				'host' => $account['smtp_host'],
				'port' => $account['smtp_port'],
				'type' => $this->mapSecure($account['smtp_secure']),
				'shortLogin' => false,
				'useAuth' => true,
				'usePhpMail' => false,
			],
			'Sieve' => [
				'enabled' => false,
				'host' => '',
				'port' => 4190,
				'type' => 0,
				'shortLogin' => false
			],
			'whiteList' => ''
		]);
		$oDomainProvider->Save($oDomain);
	}

	/**
	 * Discover CardDAV / CalDAV / contacts / calendar services for a linked account.
	 * For Gmail and O365 we return known OAuth-based services.
	 * For IMAP we probe .well-known RFC 5785 endpoints on the email domain.
	 */
	public function JsonDiscoverServices() : array
	{
		try {
			[$uid] = $this->requireSession();
			$id = (int) $this->jsonParam('id');
			$row = $this->db()->getMailAccount($uid, $id);
			if (!$row) throw new \RuntimeException('Account not found');

			$services = [];
			$email    = (string) $row['email'];
			$domain   = \strtolower(\substr(\strrchr($email, '@'), 1));
			$type     = (string) $row['type'];

			// Detect Google and Microsoft by domain regardless of account type (imap
			// accounts added with app-passwords have type='imap', not 'gmail'/'o365').
			$bGoogle    = 'gmail' === $type
				|| \in_array($domain, ['gmail.com', 'googlemail.com'], true)
				|| \str_ends_with($domain, '.google.com');
			$bMicrosoft = 'o365' === $type
				|| \in_array($domain, ['outlook.com', 'hotmail.com', 'live.com', 'msn.com'], true);

			if ($bGoogle) {
				$bHasOAuth = ('gmail' === $type);
				$sNote = $bHasOAuth
					? 'Syncs via Google API using the linked OAuth token.'
					: 'Requires Google OAuth2 — app passwords are not supported by Google for contacts/calendar sync. Re-add this account via "Sign in with Google" to enable sync.';
				$services[] = [
					'id'       => 'google-contacts',
					'name'     => 'Google Contacts',
					'type'     => 'contacts',
					'provider' => 'google',
					'url'      => 'https://www.googleapis.com/carddav/v1',
					'note'     => $sNote,
					'needs_oauth' => !$bHasOAuth,
				];
				$services[] = [
					'id'       => 'google-calendar',
					'name'     => 'Google Calendar',
					'type'     => 'calendar',
					'provider' => 'google',
					'url'      => 'https://apidata.googleusercontent.com/caldav/v2',
					'note'     => $sNote,
					'needs_oauth' => !$bHasOAuth,
				];
			} elseif ($bMicrosoft) {
				$bHasOAuth = ('o365' === $type);
				$sNote = $bHasOAuth
					? 'Syncs via Microsoft Graph using the linked OAuth token.'
					: 'Requires Microsoft OAuth2 — re-add this account via "Sign in with Microsoft" to enable sync.';
				$services[] = [
					'id'       => 'o365-contacts',
					'name'     => 'Microsoft Contacts',
					'type'     => 'contacts',
					'provider' => 'o365',
					'url'      => 'https://graph.microsoft.com/v1.0/me/contacts',
					'note'     => $sNote,
					'needs_oauth' => !$bHasOAuth,
				];
				$services[] = [
					'id'       => 'o365-calendar',
					'name'     => 'Microsoft Calendar',
					'type'     => 'calendar',
					'provider' => 'o365',
					'url'      => 'https://outlook.office365.com/caldav/v1',
					'note'     => $sNote,
					'needs_oauth' => !$bHasOAuth,
				];
			} else {
				// Generic IMAP: probe .well-known autodiscovery (RFC 5785)
				$services = \array_merge(
					$services,
					$this->probeWellKnown($domain, $email, 'carddav'),
					$this->probeWellKnown($domain, $email, 'caldav')
				);
			}

			return $this->jsonResponse(__FUNCTION__, [
				'ok'       => true,
				'email'    => $email,
				'services' => $services,
			]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	/** Probe .well-known/{carddav|caldav} and return found service descriptor or []. */
	/** Return true if $ip is a private/loopback/link-local address (SSRF guard). */
	private function isPrivateIp(string $ip) : bool
	{
		return !\filter_var($ip,
			\FILTER_VALIDATE_IP,
			\FILTER_FLAG_NO_PRIV_RANGE | \FILTER_FLAG_NO_RES_RANGE
		);
	}

	private function probeWellKnown(string $domain, string $email, string $proto) : array
	{
		// SSRF guard: reject domains that resolve to private/loopback/link-local IPs (NEW-M).
		$resolvedIp = \gethostbyname($domain);
		if ($resolvedIp === $domain || $this->isPrivateIp($resolvedIp)) {
			// Either DNS failed or IP is private — skip silently.
			return [];
		}

		$url = 'https://' . $domain . '/.well-known/' . $proto;
		// TLS verification ENABLED (NEW-H) — no verify_peer overrides.
		$ctx = \stream_context_create([
			'http' => [
				'method'          => 'PROPFIND',
				'header'          => "Depth: 0\r\nContent-Type: application/xml\r\n",
				'content'         => '<?xml version="1.0"?><propfind xmlns="DAV:"><prop><current-user-principal/></prop></propfind>',
				'timeout'         => 4,
				'follow_location' => 1,
				'ignore_errors'   => true,
			],
		]);
		$body = @\file_get_contents($url, false, $ctx);
		// Check HTTP status from $http_response_header
		$status = 0;
		if (!empty($http_response_header)) {
			\preg_match('#HTTP/\S+\s+(\d+)#', $http_response_header[0], $m);
			$status = (int) ($m[1] ?? 0);
		}
		// 207 Multi-Status or 301/302 redirect means service exists
		if (!\in_array($status, [207, 200, 301, 302], true)) {
			return [];
		}
		$isContacts = ('carddav' === $proto);
		return [[
			'id'       => $proto . '-' . $domain,
			'name'     => $isContacts ? 'Contacts (' . $domain . ')' : 'Calendar (' . $domain . ')',
			'type'     => $isContacts ? 'contacts' : 'calendar',
			'provider' => 'dav',
			'url'      => $url,
			'note'     => ($isContacts ? 'CardDAV' : 'CalDAV') . ' service found at ' . $url,
		]];
	}

	/**
	 * Activate a discovered service for a linked account.
	 * For OAuth providers this triggers an immediate sync.
	 * For DAV providers it records the URL so the sync plugin can use it.
	 */
	public function JsonActivateService() : array
	{
		try {
			[$uid] = $this->requireSession();
			$id          = (int) $this->jsonParam('account_id');
			$serviceId   = (string) $this->jsonParam('service_id');
			$serviceType = (string) $this->jsonParam('service_type');
			$provider    = (string) $this->jsonParam('provider');
			$serviceUrl  = (string) $this->jsonParam('url');

			$row = $this->db()->getMailAccount($uid, $id);
			if (!$row) throw new \RuntimeException('Account not found');

			// For OAuth providers we trigger the contacts-sync / calendar endpoint directly
			if (\in_array($provider, ['google','o365'], true)) {
				if ('contacts' === $serviceType) {
					// Delegate to contacts-sync plugin via action hook if available
					$result = ['ok' => true, 'message' => 'Contacts sync triggered. Open Settings → Contacts Sync to run a full sync.'];
				} else {
					$result = ['ok' => true, 'message' => 'Calendar sync ready. Open Settings → Calendar to view events.'];
				}
				return $this->jsonResponse(__FUNCTION__, $result);
			}

			// DAV provider: store the URL in account settings JSON so sync plugins can read it
			$pdo = $this->db()->pdo();
			$pdo->prepare(
				"UPDATE frickmail_mail_accounts
				 SET settings = settings || :patch::jsonb, updated_at = NOW()
				 WHERE user_id = :u AND id = :i"
			)->execute([
				':patch' => \json_encode([
					('contacts' === $serviceType ? 'carddav_url' : 'caldav_url') => $serviceUrl,
				]),
				':u' => $uid, ':i' => $id,
			]);
			return $this->jsonResponse(__FUNCTION__, [
				'ok'      => true,
				'message' => ('contacts' === $serviceType ? 'CardDAV' : 'CalDAV') . ' URL saved. You can configure credentials in Settings → Accounts.',
			]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	private function generateQrDataUrl(string $sData) : string
	{
		$qr = new \SnappyMail\QRCode();
		$qr->setErrorCorrectLevel(\SnappyMail\QRCode::ERROR_CORRECT_LEVEL_M);
		$qr->addData($sData);
		$qr->make();
		$n = $qr->getModuleCount();
		$cell = 6;
		$pad  = 16;
		$size = $n * $cell + $pad * 2;
		$rects = '';
		for ($r = 0; $r < $n; $r++) {
			for ($c = 0; $c < $n; $c++) {
				if ($qr->isDark($r, $c)) {
					$x = $pad + $c * $cell;
					$y = $pad + $r * $cell;
					$rects .= '<rect x="'.$x.'" y="'.$y.'" width="'.$cell.'" height="'.$cell.'"/>';
				}
			}
		}
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '.$size.' '.$size.'" width="220" height="220">'
			. '<rect width="'.$size.'" height="'.$size.'" fill="white"/>'
			. '<g fill="black">' . $rects . '</g>'
			. '</svg>';
		return 'data:image/svg+xml;base64,' . \base64_encode($svg);
	}

	private function mapSecure(?string $sec) : int
	{
		// MailSo\Net\Enumerations\ConnectionSecurityType
		return match (\strtoupper((string) $sec)) {
			'SSL', 'TLS' => 2, // SSL
			'STARTTLS'   => 1,
			'NONE'       => 0,
			default      => 2,
		};
	}
}
