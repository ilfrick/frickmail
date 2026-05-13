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
require_once __DIR__ . '/lib/Mailer.php';

class FrickmailUserPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Frickmail User',
		VERSION  = '0.13',
		RELEASE  = '2026-05-13',
		REQUIRED = '2.36.1',
		CATEGORY = 'Login',
		DESCRIPTION = 'Frickmail: first-class user identity in Postgres, mail accounts as linked records.';

	const SESSION_KEY_USER = 'frickmail_user_id';
	const SESSION_KEY_KEY  = 'frickmail_crypt_key';

	public function Init() : void
	{
		$this->UseLangs(false);
		$this->addJs('js/Login.js');
		$this->addJs('js/MailAccountsSettings.js');
		$this->addJs('js/TwoFactorSettings.js');
		$this->addTemplate('templates/MailAccountsSettings.html');
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

		// Allow Sec-Fetch cross-site navigations to the reset-password landing page,
		// so the link delivered by email opens correctly from external mail clients.
		$this->addHook('filter.http-paths', 'httpPaths');
	}

	public function httpPaths(array $aPaths) : void
	{
		// Allow cross-site navigations whenever the URL is a reset-password landing.
		if (isset($_GET['reset_token']) && '' !== \trim((string) $_GET['reset_token'])) {
			$oConfig = \RainLoop\Api::Config();
			$oConfig->Set('security', 'secfetch_allow',
				\trim($oConfig->Get('security', 'secfetch_allow', '') . ';site=cross-site', ';')
			);
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
		if (\PHP_SESSION_ACTIVE !== \session_status()) {
			\session_start([
				'cookie_httponly' => true,
				'cookie_secure'   => !empty($_SERVER['HTTPS']),
				'cookie_samesite' => 'Lax',
				'use_strict_mode' => true,
			]);
		}
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
				'ok' => true,
				'user_id' => $id,
				'first_user' => $bFirstUser,
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
					return $this->jsonResponse(__FUNCTION__, [
						'ok' => false,
						'requires_totp' => true,
						'error' => 'Invalid two-factor code'
					]);
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
			\RainLoop\Api::Actions()->Logger()->Write(
				"[FrickmailReset] token len=" . \strlen($sToken)
				. " head=" . \substr($sToken, 0, 6) . " tail=" . \substr($sToken, -6)
				. " hashHead=" . \substr($sTokenHash, 0, 12),
				\LOG_INFO
			);
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

			// Logout the current SnappyMail session if any, so the bridge starts clean.
			$oActions = \RainLoop\Api::Actions();
			try { $oActions->Logout(true); } catch (\Throwable $e) {}

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

		// Use the email as a SensitiveString password for LoginProcess; the OAuth
		// plugin's clientLogin hook will pull the real access_token from session.
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
		if ($oExisting) return;
		// Create-or-update a minimal SnappyMail domain record so IMAP/SMTP know where to connect
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
