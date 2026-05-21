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
			$accountId    = (int) $row['id'];
			$identityRows = $this->db->listIdentities($uid, $accountId);
			$identities   = [];
			foreach ($identityRows as $ir) {
				$identities[] = [
					'id'         => (int)  $ir['id'],
					'account_id' => $accountId,
					'name'       => $ir['name'],
					'email'      => $ir['email'],
					'reply_to'   => $ir['reply_to'],
					'is_default' => (bool) $ir['is_default'],
				];
			}
			$result[] = [
				'id'          => $accountId,
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
				'identities'  => $identities,
			];
		}
		return ['ok' => true, 'accounts' => $result];
	}

	/* ------------------------------------------------------------------ */
	/*  Sender identities                                                    */
	/* ------------------------------------------------------------------ */

	public function listIdentities(int $uid, int $accountId) : array
	{
		$rows = $this->db->listIdentities($uid, $accountId);
		$result = [];
		foreach ($rows as $ir) {
			$result[] = [
				'id'         => (int)  $ir['id'],
				'account_id' => (int)  $ir['account_id'],
				'name'       => $ir['name'],
				'email'      => $ir['email'],
				'reply_to'   => $ir['reply_to'],
				'is_default' => (bool) $ir['is_default'],
			];
		}
		return ['ok' => true, 'identities' => $result];
	}

	public function addIdentity(int $uid, int $accountId, string $name, string $email, ?string $replyTo, bool $isDefault) : array
	{
		if ('' === \trim($name))  throw new \RuntimeException('Name is required');
		if ('' === \trim($email)) throw new \RuntimeException('Email is required');
		if (!\filter_var($email, \FILTER_VALIDATE_EMAIL)) throw new \RuntimeException('Invalid email address');
		// Verify the account belongs to this user.
		if (!$this->db->getMailAccount($uid, $accountId)) throw new \RuntimeException('Account not found');

		// If marking as default, first clear any existing default for this account.
		if ($isDefault) {
			$existing = $this->db->listIdentities($uid, $accountId);
			foreach ($existing as $ex) {
				if ($ex['is_default']) {
					// We'll let the DB unique index handle it via setDefaultIdentity after insert;
					// for insert we just pass isDefault=false and then set it.
					$isDefault = false;
					$needSetDefault = true;
					break;
				}
			}
		}

		$id = $this->db->addIdentity($uid, $accountId, \trim($name), \trim($email), $replyTo ? \trim($replyTo) : null, $isDefault ?? false);

		if (!empty($needSetDefault)) {
			$this->db->setDefaultIdentity($uid, $id);
		}

		return ['ok' => true, 'id' => $id];
	}

	public function deleteIdentity(int $uid, int $identityId) : array
	{
		$ok = $this->db->deleteIdentity($uid, $identityId);
		return ['ok' => $ok];
	}

	public function setDefaultIdentity(int $uid, int $identityId) : array
	{
		$this->db->setDefaultIdentity($uid, $identityId);
		return ['ok' => true];
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
	/*  Update account settings                                            */
	/* ------------------------------------------------------------------ */

	public function updateAccount(int $uid, string $cryptKey, array $params) : array
	{
		$id = (int) ($params['id'] ?? 0);
		if ($id <= 0) throw new \RuntimeException('Invalid account id');

		// Verify ownership
		$rows = $this->db->listMailAccounts($uid);
		$row  = null;
		foreach ($rows as $r) { if ((int)$r['id'] === $id) { $row = $r; break; } }
		if ($row === null) throw new \RuntimeException('Account not found');

		$data = [];

		// Label is always updatable
		$label = \trim($params['label'] ?? '');
		if ('' !== $label) $data['label'] = $label;

		// IMAP-only fields
		if ('imap' === $row['type']) {
			if (!empty($params['imap_host'])) {
				$imapHost = $params['imap_host'];
				$smtpHost = $params['smtp_host'] ?? '';
				foreach (['imap_host' => $imapHost, 'smtp_host' => $smtpHost] as $field => $h) {
					if ('' === $h) continue;
					$resolved = \gethostbyname($h);
					if ($resolved !== $h && !\filter_var($resolved, \FILTER_VALIDATE_IP, \FILTER_FLAG_NO_PRIV_RANGE | \FILTER_FLAG_NO_RES_RANGE)) {
						throw new \RuntimeException("$field resolves to a reserved IP address");
					}
				}
				$data['imap_host'] = $imapHost;
				if ('' !== $smtpHost) $data['smtp_host'] = $smtpHost;
			}
			if (!empty($params['imap_port']))   $data['imap_port']   = (int) $params['imap_port'];
			if (!empty($params['imap_secure']))  $data['imap_secure'] = (string) $params['imap_secure'];
			if (!empty($params['smtp_port']))    $data['smtp_port']   = (int) $params['smtp_port'];
			if (!empty($params['smtp_secure']))  $data['smtp_secure'] = (string) $params['smtp_secure'];
			if (!empty($params['login']))        $data['login']       = (string) $params['login'];

			$pwd = (string) ($params['password'] ?? '');
			if ('' !== $pwd) {
				$data['encrypted_password'] = Crypto::encrypt($pwd, $cryptKey);
			}
		}

		if (empty($data)) return ['ok' => true]; // nothing to update

		$this->db->updateMailAccount($uid, $id, $data);
		return ['ok' => true];
	}

	/* ------------------------------------------------------------------ */
	/*  Delete, setPrimary, setPassword, switchAccount                      */
	/* ------------------------------------------------------------------ */

	public function deleteAccount(int $uid, int $id) : array
	{
		// Clean the search index before deleting the account row (FK cascade would
		// handle it too, but being explicit avoids any deferred-constraint surprises).
		$this->db->deleteMessageIndex($id);
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

	/* ------------------------------------------------------------------ */
	/*  Full-text search                                                     */
	/* ------------------------------------------------------------------ */

	public function search(int $uid, string $query, int $limit = 50): array
	{
		$query = trim($query);
		if (strlen($query) < 2) throw new \RuntimeException('Query too short');
		$rows = $this->db->searchMessages($uid, $query, $limit);
		return ['ok' => true, 'query' => $query, 'results' => $rows];
	}

	public function indexMessageFromHeader(int $uid, int $accountId, string $folder,
	                                        array $header): void
	{
		// header array: uid, message_id, subject, from_addr, from_name, date_ts, snippet
		$this->db->indexMessage($uid, $accountId, $folder,
			(int)$header['uid'], $header['message_id'] ?? null,
			$header['subject'] ?? null, $header['from_addr'] ?? null,
			$header['from_name'] ?? null, $header['date_ts'] ?? null,
			$header['snippet'] ?? null);
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
				// NOTE: Azure AD app must have Mail.Read, Mail.ReadWrite, Mail.Send, User.Read
				// added as Delegated permissions in the Azure portal for Graph API calls to work.
				'https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access'
				. ' https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite'
				. ' https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read',
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

	/* ---- Unified Inbox --------------------------------------------------- */

	public function unifiedInbox(int $uid, string $cryptKey, int $limit = 40) : array
	{
		$rows   = $this->db->listMailAccounts($uid);
		$all    = [];
		$errors = [];

		foreach ($rows as $row) {
			if ('imap' !== $row['type']) continue;
			$account = $this->db->decryptedAccount($row, $cryptKey);
			if (empty($account['password'])) {
				$errors[] = ($account['email'] ?? '?') . ': no password stored';
				continue;
			}

			try {
				$msgs = $this->fetchInboxHeaders($account, $limit);
				foreach ($msgs as &$m) {
					$m['account_email'] = $account['email'];
					$m['account_id']    = (int) $row['id'];
				}
				unset($m);
				$all = \array_merge($all, $msgs);
			} catch (\Throwable $e) {
				// Collect error but continue — one failing account must not abort the rest.
				$errors[] = ($account['email'] ?? '?') . ': ' . $e->getMessage();
			}
		}

		\usort($all, static fn(array $a, array $b) : int =>
			($b['date_ts'] ?? 0) <=> ($a['date_ts'] ?? 0));

		return [
			'ok'       => true,
			'messages' => \array_slice($all, 0, $limit),
			'errors'   => $errors,
		];
	}

	private function fetchInboxHeaders(array $account, int $limit) : array
	{
		$oSettings = \MailSo\Imap\Settings::fromArray([
			'host'       => $account['imap_host'],
			'port'       => (int) $account['imap_port'],
			'type'       => $this->mapSecure($account['imap_secure']),
			'timeout'    => 10,
			'shortLogin' => false,
		]);
		$oSettings->username   = $account['login'] ?: $account['email'];
		$oSettings->passphrase = $account['password'];

		$oImap = new \MailSo\Imap\ImapClient();
		$oImap->SetTimeOuts(10);
		try {
			$oImap->Connect($oSettings);
			$oImap->Login($oSettings);
			$oInfo = $oImap->FolderExamine('INBOX');
			$total = (int) ($oInfo->MESSAGES ?? 0);
			if (0 === $total) return [];

			$from  = \max(1, $total - $limit + 1);
			$range = ($from === $total) ? (string) $total : "{$from}:{$total}";

			$fetchItems = [
				\MailSo\Imap\Enumerations\FetchType::UID,
				\MailSo\Imap\Enumerations\FetchType::FLAGS,
				\MailSo\Imap\Enumerations\FetchType::INTERNALDATE,
				\MailSo\Imap\Enumerations\FetchType::ENVELOPE,
			];

			$messages = [];
			foreach ($oImap->FetchIterate($fetchItems, $range, false) as $oFetch) {
				$uid     = (int)    $oFetch->GetFetchValue(\MailSo\Imap\Enumerations\FetchType::UID);
				$flags   = (array)  $oFetch->GetFetchValue(\MailSo\Imap\Enumerations\FetchType::FLAGS);
				$dateStr = (string) ($oFetch->GetFetchValue(\MailSo\Imap\Enumerations\FetchType::INTERNALDATE) ?? '');
				$dateTs  = $dateStr ? (int) \strtotime($dateStr) : 0;

				$envelope = $oFetch->GetEnvelope();
				$subject  = '';
				$from     = '';
				if (\is_array($envelope)) {
					$subject = \MailSo\Base\Utils::DecodeHeaderValue((string) ($envelope[1] ?? ''));
					$fromArr = $envelope[2] ?? null;
					if (\is_array($fromArr) && !empty($fromArr[0])) {
						$f       = $fromArr[0];
						$display = isset($f[0]) && '' !== $f[0]
							? \MailSo\Base\Utils::DecodeHeaderValue((string) $f[0]) : '';
						$addr    = ((string)($f[2]??'') && (string)($f[3]??''))
							? $f[2].'@'.$f[3] : '';
						$from    = $display ?: $addr;
					}
				}
				$messages[] = [
					'uid'     => $uid,   'subject' => $subject,
					'from'    => $from,  'date'    => $dateStr,
					'date_ts' => $dateTs,'flags'   => $flags,
					'is_seen' => \in_array('\\Seen', $flags, true),
				];
			}
			return $messages;
		} finally {
			try { $oImap->Logout();     } catch (\Throwable $e) {}
			try { $oImap->Disconnect(); } catch (\Throwable $e) {}
		}
	}

	/* ---- New mail check ------------------------------------------------ */

	public function checkNewMail(int $uid, string $cryptKey, array $lastUids): array
	{
		$rows    = $this->db->listMailAccounts($uid);
		$results = [];

		foreach ($rows as $row) {
			if ('imap' !== $row['type']) continue;
			$account = $this->db->decryptedAccount($row, $cryptKey);
			if (empty($account['password'])) continue;

			$accountId = (int) $row['id'];
			$lastUidnext = (int) ($lastUids[(string) $accountId] ?? 0);

			try {
				[$uidnext, $messages] = $this->fetchInboxStatus($account);
			} catch (\Throwable $e) {
				// Skip failing accounts silently — same pattern as unifiedInbox.
				continue;
			}

			$newCount = 0;
			if ($lastUidnext > 0 && $uidnext > $lastUidnext) {
				// Each increment of UIDNEXT by N means N new messages arrived.
				$newCount = $uidnext - $lastUidnext;
			}

			$results[] = [
				'account_id'    => $accountId,
				'account_email' => $account['email'],
				'uidnext'       => $uidnext,
				'messages'      => $messages,
				'new_count'     => $newCount,
			];
		}

		return ['ok' => true, 'accounts' => $results];
	}

	/**
	 * Fetch the HTML/plain body of a specific message by UID.
	 * Uses MailSo\Mail\MailClient so we get decoded, sanitised body parts.
	 */
	public function getMessageBody(int $uid, string $cryptKey, int $accountId, int $msgUid) : array
	{
		$rows = $this->db->listMailAccounts($uid);
		$row  = null;
		foreach ($rows as $r) { if ((int)$r['id'] === $accountId) { $row = $r; break; } }
		if ($row === null) throw new \RuntimeException('Account not found');
		if ('imap' !== $row['type']) throw new \RuntimeException('Not an IMAP account');

		$account = $this->db->decryptedAccount($row, $cryptKey);
		if (empty($account['password'])) throw new \RuntimeException('No credentials stored');

		$oMailClient = new \MailSo\Mail\MailClient();
		$oImap       = $oMailClient->ImapClient();

		$oSettings = \MailSo\Imap\Settings::fromArray([
			'host'       => $account['imap_host'],
			'port'       => (int) $account['imap_port'],
			'type'       => $this->mapSecure($account['imap_secure']),
			'timeout'    => 15,
			'shortLogin' => false,
		]);
		$oSettings->username   = $account['login'] ?: $account['email'];
		$oSettings->passphrase = $account['password'];

		$oImap->SetTimeOuts(15);
		try {
			$oImap->Connect($oSettings);
			$oImap->Login($oSettings);

			$oMessage = $oMailClient->Message('INBOX', $msgUid, true);
			if (null === $oMessage) return ['ok' => false, 'error' => 'Message not found'];

			return [
				'ok'      => true,
				'html'    => $oMessage->sHtml  ?: '',
				'plain'   => $oMessage->sPlain ?: '',
				'subject' => $oMessage->Subject(),
			];
		} finally {
			try { $oImap->Logout();     } catch (\Throwable $e) {}
			try { $oImap->Disconnect(); } catch (\Throwable $e) {}
		}
	}

	/**
	 * Open IMAP, SELECT/EXAMINE INBOX, return [uidnext, messages].
	 */
	private function fetchInboxStatus(array $account): array
	{
		$oSettings = \MailSo\Imap\Settings::fromArray([
			'host'       => $account['imap_host'],
			'port'       => (int) $account['imap_port'],
			'type'       => $this->mapSecure($account['imap_secure']),
			'timeout'    => 10,
			'shortLogin' => false,
		]);
		$oSettings->username   = $account['login'] ?: $account['email'];
		$oSettings->passphrase = $account['password'];

		$oImap = new \MailSo\Imap\ImapClient();
		$oImap->SetTimeOuts(10);
		try {
			$oImap->Connect($oSettings);
			$oImap->Login($oSettings);
			$oInfo   = $oImap->FolderExamine('INBOX');
			$uidnext = (int) ($oInfo->UIDNEXT   ?? 0);
			$messages = (int) ($oInfo->MESSAGES  ?? 0);
			return [$uidnext, $messages];
		} finally {
			try { $oImap->Logout();     } catch (\Throwable $e) {}
			try { $oImap->Disconnect(); } catch (\Throwable $e) {}
		}
	}

	/* ---- Unified Inbox --------------------------------------------------- */


	/* ---- Import / Export ---------------------------------------------- */

	public function exportMessage(int $uid, string $cryptKey, int $accountId, string $folder, int $imapUid) : string
	{
		$row = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$account = $this->db->decryptedAccount($row, $cryptKey);
		if (empty($account['password'])) throw new \RuntimeException('Missing IMAP password');

		$oImap = $this->openImapConnection($account);
		try {
			$oImap->FolderExamine($folder);
			// BODY.PEEK[] is the full RFC 2822 message (headers + body), does not set \Seen
			$aFetch = $oImap->Fetch([\MailSo\Imap\Enumerations\FetchType::BODY_PEEK . '[]'], (string) $imapUid, true);
			if (empty($aFetch[0])) throw new \RuntimeException('Message not found (UID ' . $imapUid . ')');
			$rawEml = (string) $aFetch[0]->GetFetchValue('BODY[]');
			if ('' === $rawEml) throw new \RuntimeException('Empty message body');
			return $rawEml;
		} finally {
			try { $oImap->Logout();     } catch (\Throwable $e) {}
			try { $oImap->Disconnect(); } catch (\Throwable $e) {}
		}
	}

	/**
	 * Export all messages in a folder, calling $onMessage($rawEml) for each one.
	 *
	 * @param callable $onMessage(string $rawEml): void
	 */
	public function exportFolder(int $uid, string $cryptKey, int $accountId, string $folder, callable $onMessage) : void
	{
		$row = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$account = $this->db->decryptedAccount($row, $cryptKey);
		if (empty($account['password'])) throw new \RuntimeException('Missing IMAP password');

		$oImap = $this->openImapConnection($account);
		try {
			$oInfo = $oImap->FolderExamine($folder);
			$total = (int) ($oInfo->MESSAGES ?? 0);
			if (0 === $total) return;

			$batchSize = 50;
			for ($start = 1; $start <= $total; $start += $batchSize) {
				$end   = \min($start + $batchSize - 1, $total);
				$range = ($start === $end) ? (string) $start : "{$start}:{$end}";
				$aFetch = $oImap->Fetch([\MailSo\Imap\Enumerations\FetchType::BODY_PEEK . '[]'], $range, false);
				foreach ($aFetch as $oFetchResponse) {
					$rawEml = (string) $oFetchResponse->GetFetchValue('BODY[]');
					if ('' !== $rawEml) {
						$onMessage($rawEml);
					}
				}
			}
		} finally {
			try { $oImap->Logout();     } catch (\Throwable $e) {}
			try { $oImap->Disconnect(); } catch (\Throwable $e) {}
		}
	}

	/**
	 * Import a raw EML string by appending it to $targetFolder via IMAP APPEND.
	 */
	public function importEml(int $uid, string $cryptKey, int $accountId, string $rawEml, string $targetFolder = 'INBOX') : void
	{
		if ('' === \trim($rawEml)) throw new \RuntimeException('Empty EML content');
		// Basic EML format check
		if (!\preg_match('/^(From |Received:|Date:|MIME-Version:|Content-Type:|Return-Path:|Message-ID:)/i', \ltrim($rawEml))) {
			throw new \RuntimeException('Invalid EML format: file does not look like an RFC 2822 message');
		}

		$row = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$account = $this->db->decryptedAccount($row, $cryptKey);
		if (empty($account['password'])) throw new \RuntimeException('Missing IMAP password');

		$oImap = $this->openImapConnection($account);
		try {
			$rStream = \fopen('php://memory', 'r+');
			if (false === $rStream) throw new \RuntimeException('Cannot open memory stream');
			\fwrite($rStream, $rawEml);
			\fseek($rStream, 0);

			$iSize   = \strlen($rawEml);
			$iResult = $oImap->MessageAppendStream($targetFolder, $rStream, $iSize, ['\\Seen'], 0);
			\fclose($rStream);

			if (null === $iResult && !\is_int($iResult)) {
				// MessageAppendStream returns null when APPENDUID is not supported — still OK
				// (it throws on real failure). No action needed.
			}
		} finally {
			try { $oImap->Logout();     } catch (\Throwable $e) {}
			try { $oImap->Disconnect(); } catch (\Throwable $e) {}
		}
	}

	/**
	 * Open an authenticated IMAP connection for $account.
	 */
	private function openImapConnection(array $account) : \MailSo\Imap\ImapClient
	{
		$oSettings = \MailSo\Imap\Settings::fromArray([
			'host'       => $account['imap_host'],
			'port'       => (int) $account['imap_port'],
			'type'       => $this->mapSecure($account['imap_secure']),
			'timeout'    => 20,
			'shortLogin' => false,
		]);
		$oSettings->username   = $account['login'] ?: $account['email'];
		$oSettings->passphrase = $account['password'];

		$oImap = new \MailSo\Imap\ImapClient();
		$oImap->SetTimeOuts(20);
		$oImap->Connect($oSettings);
		$oImap->Login($oSettings);
		return $oImap;
	}


	/* ---- Message rules ----------------------------------------------- */

	public function listRules(int $uid, int $accountId) : array
	{
		if (!$this->db->getMailAccount($uid, $accountId)) throw new \RuntimeException('Account not found');
		$rows   = $this->db->listRules($uid, $accountId);
		$result = [];
		foreach ($rows as $row) {
			$conditions = \json_decode((string) $row['conditions'], true) ?: [];
			$actions    = \json_decode((string) $row['actions'],    true) ?: [];
			$result[] = [
				'id'                => (int)  $row['id'],
				'account_id'        => (int)  $row['account_id'],
				'name'              => $row['name'],
				'enabled'           => (bool) $row['enabled'],
				'conditions'        => $conditions['conditions']       ?? [],
				'conditions_logic'  => $conditions['conditions_logic'] ?? 'all',
				'actions'           => $actions,
				'last_run'          => $row['last_run'],
			];
		}
		return ['ok' => true, 'rules' => $result];
	}

	public function addRule(int $uid, int $accountId, string $name, array $conditions, string $conditionsLogic, array $actions) : array
	{
		if ('' === \trim($name)) throw new \RuntimeException('Rule name is required');
		if (!$this->db->getMailAccount($uid, $accountId)) throw new \RuntimeException('Account not found');

		$allowedFields = ['from', 'subject', 'to'];
		$allowedOps    = ['contains', 'not_contains', 'equals'];
		foreach ($conditions as $c) {
			if (!\in_array($c['field'] ?? '', $allowedFields, true)) throw new \RuntimeException('Invalid condition field');
			if (!\in_array($c['op']    ?? '', $allowedOps,    true)) throw new \RuntimeException('Invalid condition operator');
			if (!isset($c['value']) || '' === \trim((string) $c['value'])) throw new \RuntimeException('Condition value is required');
		}
		if (!\in_array($conditionsLogic, ['all', 'any'], true)) $conditionsLogic = 'all';

		$allowedActions = ['move', 'read', 'flag', 'delete'];
		foreach ($actions as $a) {
			if (!\in_array($a['type'] ?? '', $allowedActions, true)) throw new \RuntimeException('Invalid action type');
			if ('move' === ($a['type'] ?? '') && empty($a['params']['folder'])) throw new \RuntimeException('Move action requires a target folder');
		}

		$id = $this->db->addRule($uid, $accountId, \trim($name), $conditions, $conditionsLogic, $actions);
		return ['ok' => true, 'id' => $id];
	}

	public function deleteRule(int $uid, int $ruleId) : array
	{
		$ok = $this->db->deleteRule($uid, $ruleId);
		return ['ok' => $ok];
	}

	public function toggleRule(int $uid, int $ruleId, bool $enabled) : array
	{
		$ok = $this->db->toggleRule($uid, $ruleId, $enabled);
		return ['ok' => $ok];
	}

	/**
	 * Execute all enabled rules for the given account.
	 * Opens a direct IMAP connection and applies SEARCH + STORE/MOVE/EXPUNGE.
	 */
	public function applyRules(int $uid, string $cryptKey, int $accountId) : array
	{
		$row = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		if ('imap' !== $row['type']) throw new \RuntimeException('Rules only supported for IMAP accounts');
		$account = $this->db->decryptedAccount($row, $cryptKey);
		if (empty($account['password'])) throw new \RuntimeException('Missing IMAP password');

		$ruleRows = $this->db->listRules($uid, $accountId);
		$applied  = [];

		if (empty($ruleRows)) {
			return ['ok' => true, 'applied' => []];
		}

		$oImap = $this->openImapConnection($account);
		try {
			$oImap->FolderSelect('INBOX');

			foreach ($ruleRows as $ruleRow) {
				if (!(bool) $ruleRow['enabled']) continue;

				$conditionsPayload = \json_decode((string) $ruleRow['conditions'], true) ?: [];
				$conditions        = $conditionsPayload['conditions']       ?? [];
				$conditionsLogic   = $conditionsPayload['conditions_logic'] ?? 'all';
				$actions           = \json_decode((string) $ruleRow['actions'], true) ?: [];

				if (empty($conditions) || empty($actions)) continue;

				// Build IMAP SEARCH criteria from conditions
				$criteriaList = [];
				foreach ($conditions as $cond) {
					$field = $cond['field'] ?? '';
					$op    = $cond['op']    ?? 'contains';
					$val   = (string) ($cond['value'] ?? '');
					if ('' === $val) continue;

					// Escape double-quotes in the value for IMAP string literals
					$escaped = '"' . \str_replace(['"', '\\'], ['\\"', '\\\\'], $val) . '"';

					switch ($field) {
						case 'from':    $imapField = 'FROM';    break;
						case 'subject': $imapField = 'SUBJECT'; break;
						case 'to':      $imapField = 'TO';      break;
						default:        continue 2;
					}

					if ('not_contains' === $op) {
						$criteriaList[] = 'NOT ' . $imapField . ' ' . $escaped;
					} elseif ('equals' === $op) {
						// IMAP has no exact-match; use HEADER field for closest match
						$headerField = match($field) {
							'from'    => 'From',
							'subject' => 'Subject',
							'to'      => 'To',
							default   => $imapField,
						};
						$criteriaList[] = 'HEADER ' . $headerField . ' ' . $escaped;
					} else {
						// contains
						$criteriaList[] = $imapField . ' ' . $escaped;
					}
				}

				if (empty($criteriaList)) continue;

				if ('any' === $conditionsLogic && \count($criteriaList) > 1) {
					// IMAP OR is binary: OR crit1 crit2. For N>2 nest: OR crit1 (OR crit2 crit3)
					$searchCriteria = $this->buildOrCriteria($criteriaList);
				} else {
					// AND: just concatenate (IMAP default is AND)
					$searchCriteria = \implode(' ', $criteriaList);
				}

				$uids = $oImap->MessageSearch($searchCriteria, true);
				if (empty($uids)) {
					$this->db->updateRuleLastRun((int) $ruleRow['id']);
					continue;
				}

				$oRange = new \MailSo\Imap\SequenceSet($uids, true);
				$matchedCount = \count($uids);

				foreach ($actions as $action) {
					$actionType = $action['type'] ?? '';
					switch ($actionType) {
						case 'move':
							$targetFolder = (string) ($action['params']['folder'] ?? '');
							if ('' === $targetFolder) break;
							$oImap->MessageMove('INBOX', $targetFolder, $oRange);
							break;
						case 'read':
							$oImap->MessageStoreFlag(
								$oRange,
								[\MailSo\Imap\Enumerations\MessageFlag::SEEN],
								\MailSo\Imap\Enumerations\StoreAction::ADD_FLAGS_SILENT
							);
							break;
						case 'flag':
							$oImap->MessageStoreFlag(
								$oRange,
								[\MailSo\Imap\Enumerations\MessageFlag::FLAGGED],
								\MailSo\Imap\Enumerations\StoreAction::ADD_FLAGS_SILENT
							);
							break;
						case 'delete':
							$oImap->MessageDelete('INBOX', $oRange, false);
							break;
					}
				}

				$this->db->updateRuleLastRun((int) $ruleRow['id']);

				$applied[] = [
					'rule_id'      => (int)  $ruleRow['id'],
					'rule_name'    => $ruleRow['name'],
					'matched_count'=> $matchedCount,
					'action_type'  => $actions[0]['type'] ?? '',
				];
			}
		} finally {
			try { $oImap->Logout();     } catch (\Throwable $e) {}
			try { $oImap->Disconnect(); } catch (\Throwable $e) {}
		}

		return ['ok' => true, 'applied' => $applied];
	}

	/**
	 * Build nested IMAP OR expression from a list of criteria strings.
	 * IMAP OR is binary: OR crit1 crit2 or OR crit1 (OR crit2 crit3), etc.
	 */
	private function buildOrCriteria(array $criteria) : string
	{
		if (1 === \count($criteria)) {
			return $criteria[0];
		}
		$right = \array_shift($criteria);
		return 'OR ' . $right . ' (' . $this->buildOrCriteria($criteria) . ')';
	}

	/* ---- Unified Inbox --------------------------------------------------- */


	/* ---- Import / Export ---------------------------------------------- */


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

	/* ---- Microsoft Graph API -------------------------------------------- */

	/**
	 * Return true when the given account row represents an Office 365 / Outlook account.
	 */
	private function isO365Account(array $account) : bool
	{
		return 'o365' === ($account['type'] ?? '');
	}

	/**
	 * Build an authenticated GraphClient for the given account.
	 *
	 * 1. Loads the account row and verifies it is type=o365.
	 * 2. Decrypts the stored OAuth refresh token.
	 * 3. Exchanges the refresh token for a Graph access token (incremental consent).
	 */
	private function graphClientForAccount(array $row, string $cryptKey) : \Frickmail\User\GraphClient
	{
		if (!$this->isO365Account($row)) {
			throw new \RuntimeException('Account is not an Office 365 account (type must be o365)');
		}

		$account = $this->db->decryptedAccount($row, $cryptKey);
		if (empty($account['oauth_refresh_token'])) {
			throw new \RuntimeException('Missing OAuth refresh token — re-authorize this account first.');
		}

		$clientId     = $this->resolveOauthEnv('FRICKMAIL_O365_CLIENT_ID',     'login-o365', 'client_id');
		$clientSecret = $this->resolveOauthEnv('FRICKMAIL_O365_CLIENT_SECRET', null,         null);
		$tenant       = (string) ($row['oauth_tenant'] ?: 'common');

		return \Frickmail\User\GraphClient::fromRefreshToken(
			$account['oauth_refresh_token'],
			$clientId,
			$clientSecret,
			$tenant
		);
	}

	/** List messages in a folder via Graph. */
	public function graphListMessages(
		int $uid, string $cryptKey, int $accountId,
		string $folder = 'inbox', int $top = 50
	) : array {
		$row    = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$client = $this->graphClientForAccount($row, $cryptKey);
		$data   = $client->listMessages($folder, $top);
		return ['ok' => true, 'data' => $data];
	}

	/** Get a single message with full body via Graph. */
	public function graphGetMessage(
		int $uid, string $cryptKey, int $accountId, string $messageId
	) : array {
		$row    = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$client = $this->graphClientForAccount($row, $cryptKey);
		$data   = $client->getMessage($messageId);
		return ['ok' => true, 'message' => $data];
	}

	/** Search messages across all folders via Graph. */
	public function graphSearch(
		int $uid, string $cryptKey, int $accountId, string $query, int $top = 50
	) : array {
		if ('' === \trim($query)) throw new \RuntimeException('Search query is required');
		$row    = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$client = $this->graphClientForAccount($row, $cryptKey);
		$data   = $client->searchMessages($query, $top);
		return ['ok' => true, 'query' => $query, 'data' => $data];
	}

	/** List mail folders via Graph. */
	public function graphListFolders(int $uid, string $cryptKey, int $accountId) : array
	{
		$row    = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$client = $this->graphClientForAccount($row, $cryptKey);
		$data   = $client->listFolders();
		return ['ok' => true, 'data' => $data];
	}

	/** Send a message via Graph /me/sendMail. */
	public function graphSendMail(
		int $uid, string $cryptKey, int $accountId,
		string $to, string $subject, string $bodyHtml
	) : array {
		if ('' === \trim($to))      throw new \RuntimeException('Recipient address is required');
		if ('' === \trim($subject)) throw new \RuntimeException('Subject is required');
		$row    = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$client = $this->graphClientForAccount($row, $cryptKey);
		$client->sendMail([\trim($to)], $subject, $bodyHtml);
		return ['ok' => true];
	}

	/** Mark a message as read or unread via Graph. */
	public function graphMarkRead(
		int $uid, string $cryptKey, int $accountId, string $messageId, bool $isRead
	) : array {
		$row    = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$client = $this->graphClientForAccount($row, $cryptKey);
		$client->markRead($messageId, $isRead);
		return ['ok' => true];
	}

	/** Move a message to another folder via Graph. */
	public function graphMove(
		int $uid, string $cryptKey, int $accountId,
		string $messageId, string $targetFolderId
	) : array {
		$row    = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$client = $this->graphClientForAccount($row, $cryptKey);
		$data   = $client->move($messageId, $targetFolderId);
		return ['ok' => true, 'message' => $data];
	}

	/** Delete a message via Graph (moves to Deleted Items). */
	public function graphDelete(
		int $uid, string $cryptKey, int $accountId, string $messageId
	) : array {
		$row    = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$client = $this->graphClientForAccount($row, $cryptKey);
		$client->deleteMessage($messageId);
		return ['ok' => true];
	}

	/** Get delta (incremental changes) for a folder via Graph. */
	public function graphDelta(
		int $uid, string $cryptKey, int $accountId,
		string $folderId = 'inbox', ?string $deltaToken = null
	) : array {
		$row    = $this->db->getMailAccount($uid, $accountId);
		if (!$row) throw new \RuntimeException('Account not found');
		$client = $this->graphClientForAccount($row, $cryptKey);
		$data   = $client->getDelta($folderId, $deltaToken);
		return ['ok' => true, 'data' => $data];
	}
}
