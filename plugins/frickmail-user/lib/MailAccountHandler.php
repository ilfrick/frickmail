<?php
namespace Frickmail\User;

/**
 * MailAccountHandler — list/add/delete/setPrimary/setPassword/switchAccount/saveOAuthToken
 * plus the full SnappyMail bridge (bridgeToSnappyMail, oauthEndpoint, resolveOauthEnv,
 * ensureSnappyMailDomain, deleteStaleCryptKey, mapSecure).
 *
 * Pure PHP class; does not extend AbstractPlugin.
 */
class MailAccountHandler
{
	public function __construct(private Db $db) {}

	/* ------------------------------------------------------------------ */
	/*  List accounts                                                        */
	/* ------------------------------------------------------------------ */

	public function listAccounts(int $uid) : array
	{
		$rows   = $this->db->listMailAccounts($uid);
		$result = [];
		foreach ($rows as $row) {
			$result[] = [
				'id'          => (int)  $row['id'],
				'label'       => $row['label'],
				'email'       => $row['email'],
				'type'        => $row['type'],
				'imap_host'   => $row['imap_host'],
				'imap_port'   => (int)  $row['imap_port'],
				'imap_secure' => $row['imap_secure'],
				'smtp_host'   => $row['smtp_host'],
				'smtp_port'   => (int)  $row['smtp_port'],
				'smtp_secure' => $row['smtp_secure'],
				'login'       => $row['login'],
				'is_primary'  => (bool) $row['is_primary'],
			];
		}
		return ['ok' => true, 'accounts' => $result];
	}

	/* ------------------------------------------------------------------ */
	/*  Add account                                                          */
	/* ------------------------------------------------------------------ */

	public function addAccount(int $uid, string $cryptKey, array $params) : array
	{
		$type = $params['type'];
		if (!\in_array($type, ['imap', 'gmail', 'o365'], true)) throw new \RuntimeException('Invalid type');

		$data = [
			'label' => \trim($params['label'] ?? '') ?: \trim($params['email'] ?? ''),
			'email' => \trim($params['email'] ?? ''),
			'type'  => $type,
		];

		if ('imap' === $type) {
			$data['imap_host'] = $params['imap_host'] ?? '';
			$data['smtp_host'] = $params['smtp_host'] ?? '';
			// SSRF guard (M4): reject hostnames that resolve to private/loopback ranges.
			foreach (['imap_host', 'smtp_host'] as $hostField) {
				$h = $data[$hostField] ?? '';
				if ('' === $h) continue;
				$resolved = \gethostbyname($h);
				if ($resolved !== $h && !\filter_var($resolved, \FILTER_VALIDATE_IP, \FILTER_FLAG_NO_PRIV_RANGE | \FILTER_FLAG_NO_RES_RANGE)) {
					throw new \RuntimeException("$hostField resolves to a reserved IP address and cannot be used.");
				}
			}
			$data['imap_port']   = (int)    ($params['imap_port']   ?: 993);
			$data['imap_secure'] = (string) ($params['imap_secure'] ?: 'SSL');
			$data['smtp_port']   = (int)    ($params['smtp_port']   ?: 465);
			$data['smtp_secure'] = (string) ($params['smtp_secure'] ?: 'SSL');
			$data['login']       = (string) ($params['login']       ?: $data['email']);
			$pwd = (string) ($params['password'] ?? '');
			if ('' !== $pwd) {
				$data['encrypted_password'] = Crypto::encrypt($pwd, $cryptKey);
			}
		} else {
			// OAuth slots — credentials provisioned via the OAuth callback flow
			$data['login'] = $data['email'];
			if ('o365' === $type) {
				$data['oauth_tenant'] = (string) ($params['tenant'] ?: 'common');
			}
		}

		// P4 fix: check count BEFORE the insert so we know whether this will be the first account.
		$bIsFirst = 0 === \count($this->db->listMailAccounts($uid));
		$data['is_primary'] = (bool) ($params['is_primary'] ?? false);

		$id = $this->db->insertMailAccount($uid, $data);

		// If this is the first account (or explicitly requested), mark it primary.
		if ($bIsFirst || $data['is_primary']) {
			$this->db->setPrimaryMailAccount($uid, $id);
		}
		return ['ok' => true, 'id' => $id];
	}

	/* ------------------------------------------------------------------ */
	/*  Delete, setPrimary, setPassword, switchAccount                      */
	/* ------------------------------------------------------------------ */

	public function deleteAccount(int $uid, int $id) : array
	{
		$ok = $this->db->deleteMailAccount($uid, $id);
		return ['ok' => $ok];
	}

	public function setPrimary(int $uid, int $id) : array
	{
		$this->db->setPrimaryMailAccount($uid, $id);
		return ['ok' => true];
	}

	public function setAccountPassword(int $uid, string $cryptKey, int $id, string $pwd) : array
	{
		if ($id <= 0) throw new \RuntimeException('Account id required');
		if ('' === $pwd) throw new \RuntimeException('Password required');
		$row = $this->db->getMailAccount($uid, $id);
		if (!$row) throw new \RuntimeException('Account not found');
		$blob = Crypto::encrypt($pwd, $cryptKey);
		$this->db->setMailAccountPassword($uid, $id, $blob);
		return ['ok' => true];
	}

	public function switchAccount(int $uid, string $cryptKey, int $id) : array
	{
		$row = $this->db->getMailAccount($uid, $id);
		if (!$row) throw new \RuntimeException('Account not found');
		$account = $this->db->decryptedAccount($row, $cryptKey);
		$this->bridge($account);
		return ['ok' => true, 'email' => $account['email']];
	}

	/* ------------------------------------------------------------------ */
	/*  Save OAuth token                                                     */
	/* ------------------------------------------------------------------ */

	public function saveOAuthToken(int $uid, string $cryptKey, string $type, string $email, string $token) : array
	{
		if ('' === $email || '' === $token) throw new \RuntimeException('Missing email or token');
		if (!\in_array($type, ['gmail', 'o365'], true)) throw new \RuntimeException('Unknown type');

		$rows  = $this->db->listMailAccounts($uid);
		$found = null;
		foreach ($rows as $r) {
			if (\strtolower($r['email']) === \strtolower($email)) { $found = $r; break; }
		}
		if (!$found) throw new \RuntimeException('Account not found for email ' . $email);

		$cipher = Crypto::encrypt($token, $cryptKey);
		$this->db->saveOAuthRefreshToken($uid, (int) $found['id'], $type, $cipher);
		return ['ok' => true];
	}

	/* ------------------------------------------------------------------ */
	/*  SnappyMail bridge                                                    */
	/* ------------------------------------------------------------------ */

	public function bridge(array $account) : void
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
		$aResp   = $oClient->getAccessToken($tokenUri, 'refresh_token', [
			'refresh_token' => $account['oauth_refresh_token'],
			'scope'         => $scope,
		]);
		if (200 != $aResp['code'] || empty($aResp['result']['access_token'])) {
			$err = $aResp['result']['error_description'] ?? $aResp['result']['error'] ?? 'token exchange failed';
			throw new \RuntimeException("OAuth refresh failed: {$err}");
		}
		$sAccessToken  = (string) $aResp['result']['access_token'];
		$iExpiresIn    = (int)    ($aResp['result']['expires_in'] ?? 3600);
		$sNewRefresh   = (string) ($aResp['result']['refresh_token'] ?? $account['oauth_refresh_token']);

		$aTokenData = [
			'access_token'  => $sAccessToken,
			'refresh_token' => $sNewRefresh,
			'expires_in'    => $iExpiresIn,
			'expires'       => \time() + $iExpiresIn,
		];

		// Inject the access_token into the OAuth plugin's static::$auth BEFORE
		// LoginProcess fires imap.before-login / clientLogin. Without this,
		// clientLogin finds neither static::$auth nor session storage (not written
		// yet) and falls back to IMAP password auth, which fails for OAuth accounts.
		$sPluginClass = ('gmail' === $account['type']) ? 'LoginGMailPlugin' : 'LoginO365Plugin';
		if (\class_exists($sPluginClass) && \method_exists($sPluginClass, 'injectOAuthData')) {
			$sPluginClass::injectOAuthData($aTokenData);
		}

		// The webmail stores a per-account .cryptkey encrypted with the IMAP password.
		// For OAuth accounts we use the email as the pseudo-password. If the stored
		// .cryptkey was encrypted with a different value (e.g. Google user-ID from an
		// old session), LoginProcess throws CryptKeyError. Delete it first — it is
		// recreated automatically with the correct password on the next LoginProcess.
		$this->deleteStaleCryptKey($account['email']);

		$oPassword = new \SnappyMail\SensitiveString($account['email']);
		$oAccount  = $oActions->LoginProcess($account['email'], $oPassword);
		if ($oAccount) {
			$oActions->StorageProvider()->Put(
				$oAccount,
				\RainLoop\Providers\Storage\Enumerations\StorageType::SESSION,
				\RainLoop\Utils::GetSessionToken(),
				\SnappyMail\Crypt::EncryptToJSON([
					'access_token'  => $sAccessToken,
					'refresh_token' => $sNewRefresh,
					'expires_in'    => $iExpiresIn,
					'expires'       => \time() + $iExpiresIn,
				], $oAccount->CryptKey())
			);
		}
	}

	private function deleteStaleCryptKey(string $sEmail) : void
	{
		$sAt = \strpos($sEmail, '@');
		if (false === $sAt) return;
		$sLocal  = \strtolower(\substr($sEmail, 0, $sAt));
		$sDomain = \strtolower(\substr($sEmail, $sAt + 1));
		$sPath   = \rtrim(\APP_DATA_FOLDER_PATH, '/') . '/storage/' . $sDomain . '/' . $sLocal . '/.cryptkey';
		if (\is_file($sPath)) {
			\unlink($sPath);
		}
	}

	private function oauthEndpoint(array $account) : array
	{
		if ('gmail' === $account['type']) {
			return [
				'https://accounts.google.com/o/oauth2/token',
				$this->resolveOauthEnv('FRICKMAIL_GMAIL_CLIENT_ID', 'login-gmail', 'client_id'),
				$this->resolveOauthEnv('FRICKMAIL_GMAIL_CLIENT_SECRET', null, null),
				'https://mail.google.com/',
			];
		}
		if ('o365' === $account['type']) {
			$tenant = $account['oauth_tenant'] ?: 'common';
			return [
				"https://login.microsoftonline.com/{$tenant}/oauth2/v2.0/token",
				$this->resolveOauthEnv('FRICKMAIL_O365_CLIENT_ID', 'login-o365', 'client_id'),
				$this->resolveOauthEnv('FRICKMAIL_O365_CLIENT_SECRET', null, null),
				'https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access',
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
		// Create a minimal domain record so IMAP/SMTP know where to connect.
		// shortLogin=false: send the full email address as the IMAP/SMTP login.
		$oDomain = \RainLoop\Model\Domain::fromArray($sDomain, [
			'IMAP' => [
				'host'       => $account['imap_host'],
				'port'       => $account['imap_port'],
				'type'       => $this->mapSecure($account['imap_secure']),
				'shortLogin' => false,
			],
			'SMTP' => [
				'host'       => $account['smtp_host'],
				'port'       => $account['smtp_port'],
				'type'       => $this->mapSecure($account['smtp_secure']),
				'shortLogin' => false,
				'useAuth'    => true,
				'usePhpMail' => false,
			],
			'Sieve' => [
				'enabled'    => false,
				'host'       => '',
				'port'       => 4190,
				'type'       => 0,
				'shortLogin' => false,
			],
			'whiteList' => '',
		]);
		$oDomainProvider->Save($oDomain);
	}

	/**
	 * Map a security-string to MailSo\Net\Enumerations\ConnectionSecurityType.
	 * NONE=0, SSL=1, STARTTLS=2
	 */
	public function mapSecure(?string $sec) : int
	{
		return match (\strtoupper((string) $sec)) {
			'SSL', 'TLS' => 1,
			'STARTTLS'   => 2,
			'NONE'       => 0,
			default      => 1,
		};
	}
}
