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

class FrickmailUserPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Frickmail User',
		VERSION  = '0.1',
		RELEASE  = '2026-05-04',
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
		$this->addTemplate('templates/MailAccountsSettings.html');

		$this->addJsonHook('FrickmailLogin', 'JsonFrickmailLogin');
		$this->addJsonHook('FrickmailRegister', 'JsonFrickmailRegister');
		$this->addJsonHook('FrickmailListAccounts', 'JsonListAccounts');
		$this->addJsonHook('FrickmailAddAccount', 'JsonAddAccount');
		$this->addJsonHook('FrickmailDeleteAccount', 'JsonDeleteAccount');
		$this->addJsonHook('FrickmailSetPrimary', 'JsonSetPrimary');
		$this->addJsonHook('FrickmailMe', 'JsonMe');
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
			$this->bridgeToSnappyMail($account);

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
			// SnappyMail picks IMAP host from domain config, so ensure it's defined first.
			$this->ensureSnappyMailDomain($account);
			$oActions->LoginProcess($account['email'], $oPassword);
			return;
		}

		// Gmail / O365 — reuse the access_token cached by the OAuth plugins.
		// If not yet cached for this session, exchange the stored refresh_token.
		throw new \RuntimeException('Bridging OAuth accounts is not yet wired — log in via the provider button first.');
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
