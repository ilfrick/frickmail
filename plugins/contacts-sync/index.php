<?php
/**
 * Frickmail contacts-sync — pulls contacts from the linked Gmail / Office 365
 * account into the SnappyMail Personal Address Book using the OAuth2 tokens
 * stored by the login-gmail / login-o365 plugins.
 */

use RainLoop\Providers\Storage\Enumerations\StorageType;

class ContactsSyncPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Contacts Sync',
		VERSION  = '0.2',
		RELEASE  = '2026-05-16',
		REQUIRED = '2.36.1',
		CATEGORY = 'Contacts',
		DESCRIPTION = 'Frickmail: import contacts from Gmail (People API) or Office 365 (Microsoft Graph) into the local PAB.';

	const GMAIL_TOKEN_URI = 'https://accounts.google.com/o/oauth2/token';
	const O365_TOKEN_URI  = 'https://login.microsoftonline.com/{{tenant}}/oauth2/v2.0/token';

	public function Init() : void
	{
		$this->UseLangs(false);
		$this->addJs('js/ContactsSyncSettings.js');
		$this->addJs('js/ContactsQuickAdd.js');
		$this->addTemplate('templates/ContactsSyncSettingsTab.html');
		$this->addJsonHook('JsonContactsSync',  'JsonContactsSync');
		$this->addJsonHook('JsonAddContact',    'JsonAddContact');
	}

	public function configMapping() : array
	{
		return [
			\RainLoop\Plugins\Property::NewInstance('auto_sync_on_login')
				->SetLabel('Auto-sync after OAuth2 login')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::BOOL)
				->SetDefaultValue(false)
				->SetAllowedInJs()
				->SetDescription('When enabled, contacts are pulled from the provider every time a user signs in via Gmail/O365 OAuth2.')
		];
	}

	public function JsonAddContact() : array
	{
		$oActions = \RainLoop\Api::Actions();
		$oAccount = $oActions->getMainAccountFromToken(false);
		if (!$oAccount) {
			return $this->jsonResponse(__FUNCTION__, ['error' => 'not authenticated']);
		}
		$sEmail = \trim((string) $this->jsonParam('email'));
		$sName  = \trim((string) ($this->jsonParam('name') ?: $sEmail));
		if ('' === $sEmail || !\filter_var($sEmail, \FILTER_VALIDATE_EMAIL)) {
			return $this->jsonResponse(__FUNCTION__, ['error' => 'invalid email address']);
		}
		$oProvider = $oActions->AddressBookProvider($oAccount);
		if (!$oProvider || !$oProvider->IsActive()) {
			return $this->jsonResponse(__FUNCTION__, ['error' => 'Address book is not active — enable it in admin settings.']);
		}
		try {
			$oVCard = new \Sabre\VObject\Component\VCard(['VERSION' => '4.0']);
			$oVCard->UID = 'manual:' . \md5($sEmail . \microtime(true));
			$oVCard->FN  = $sName;
			$oVCard->add('EMAIL', $sEmail);
			if ($sName !== $sEmail) {
				$parts = \explode(' ', $sName, 2);
				$oVCard->add('N', [$parts[1] ?? '', $parts[0] ?? '', '', '', '']);
			}
			$oContact = new \RainLoop\Providers\AddressBook\Classes\Contact();
			$oContact->setVCard($oVCard);
			$bOk = $oProvider->ContactSave($oContact);
			return $this->jsonResponse(__FUNCTION__, ['ok' => $bOk, 'email' => $sEmail, 'name' => $sName]);
		} catch (\Throwable $e) {
			$oActions->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['error' => $e->getMessage()]);
		}
	}

	public function JsonContactsSync() : array
	{
		$oActions = \RainLoop\Api::Actions();
		$oAccount = $oActions->getMainAccountFromToken(false);
		if (!$oAccount) {
			return $this->jsonResponse(__FUNCTION__, ['error' => 'not authenticated']);
		}
		try {
			$iCount = $this->syncForAccount($oAccount);
			return $this->jsonResponse(__FUNCTION__, ['count' => $iCount, 'email' => $oAccount->Email()]);
		} catch (\Throwable $e) {
			$oActions->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['error' => $e->getMessage()]);
		}
	}

	private function syncForAccount(\RainLoop\Model\Account $oAccount) : int
	{
		$oActions = \RainLoop\Api::Actions();
		$aAuth = null;

		// Primary source: SnappyMail session storage (written by bridgeToSnappyMail).
		try {
			$raw = $oActions->StorageProvider()->Get($oAccount, StorageType::SESSION, \RainLoop\Utils::GetSessionToken());
			if ($raw) {
				$aAuth = \SnappyMail\Crypt::DecryptFromJSON($raw, $oAccount->CryptKey());
			}
		} catch (\Throwable $e) {
			$aAuth = null;
		}

		// Fallback: read refresh_token from Frickmail DB via Bridge.
		if (empty($aAuth['refresh_token'])) {
			$aAuth = $this->loadFrickmailAuth($oAccount->Email()) ?? $aAuth;
		}

		if (empty($aAuth['refresh_token'])) {
			throw new \RuntimeException('No OAuth2 refresh token — sign in with Google/Microsoft via the OAuth2 popup first.');
		}

		$oProvider = $oActions->AddressBookProvider($oAccount);
		if (!$oProvider || !$oProvider->IsActive()) {
			throw new \RuntimeException('Address book provider is not active — enable it in admin settings.');
		}

		$sProvider = $this->detectProvider($oAccount->Email());
		if ('gmail' === $sProvider) {
			return $this->syncGmail($aAuth, $oProvider, $oAccount);
		}
		if ('o365' === $sProvider) {
			return $this->syncO365($aAuth, $oProvider, $oAccount);
		}
		throw new \RuntimeException("Unknown provider for {$oAccount->Email()}");
	}

	private function detectProvider(string $sEmail) : string
	{
		$sEmail = \strtolower($sEmail);
		$aGmail = $this->whitespaceList($this->configFromPlugin('login-gmail', 'domains', 'gmail.com googlemail.com'));
		$aO365  = $this->whitespaceList($this->configFromPlugin('login-o365',  'domains', 'outlook.com hotmail.com live.com msn.com hotmail.it outlook.it live.it'));
		foreach ($aGmail as $d) if (\str_ends_with($sEmail, '@' . $d)) return 'gmail';
		foreach ($aO365  as $d) if (\str_ends_with($sEmail, '@' . $d)) return 'o365';
		return '';
	}

	private function configFromPlugin(string $sPlugin, string $sKey, string $sDefault) : string
	{
		static $aConfigs = [];
		if (!isset($aConfigs[$sPlugin])) {
			try {
				$oCfg = new \RainLoop\Config\Plugin($sPlugin);
				$oCfg->Load();
				$aConfigs[$sPlugin] = $oCfg;
			} catch (\Throwable $e) {
				$aConfigs[$sPlugin] = null;
			}
		}
		$oCfg = $aConfigs[$sPlugin];
		if ($oCfg) {
			$v = (string) $oCfg->Get('plugin', $sKey, $sDefault);
			if ('' !== \trim($v)) return $v;
		}
		return $sDefault;
	}

	private function whitespaceList(string $s) : array
	{
		$a = \preg_split('/\s+/', \strtolower(\trim($s))) ?: [];
		return \array_values(\array_filter(\array_map('trim', $a)));
	}

	private function envOrTrim(string $sValue, string $sEnv) : string
	{
		$sValue = \trim($sValue);
		if ('' === $sValue) {
			$v = \getenv($sEnv);
			if (\is_string($v)) $sValue = \trim($v);
		}
		return $sValue;
	}

	private function refreshToken(string $sTokenUri, string $sClientId, string $sClientSecret, string $sRefreshToken, ?string $sScope = null) : array
	{
		$oClient = new \OAuth2\Client($sClientId, $sClientSecret);
		$aParams = ['refresh_token' => $sRefreshToken];
		if (null !== $sScope) {
			$aParams['scope'] = $sScope;
		}
		$aResp = $oClient->getAccessToken($sTokenUri, 'refresh_token', $aParams);
		if (200 != $aResp['code'] || empty($aResp['result']['access_token'])) {
			$err = $aResp['result']['error_description'] ?? $aResp['result']['error'] ?? 'unknown';
			throw new \RuntimeException("refresh_token exchange failed: {$err}");
		}
		return $aResp['result'];
	}

	private function httpJsonGet(string $sUrl, string $sBearer) : array
	{
		$ch = \curl_init($sUrl);
		\curl_setopt_array($ch, [
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $sBearer, 'Accept: application/json'],
			CURLOPT_TIMEOUT => 30
		]);
		$body = \curl_exec($ch);
		$code = \curl_getinfo($ch, CURLINFO_HTTP_CODE);
		\curl_close($ch);
		if (200 != $code) {
			throw new \RuntimeException("HTTP {$code} GET {$sUrl}: " . \substr((string) $body, 0, 200));
		}
		$j = \json_decode((string) $body, true);
		return \is_array($j) ? $j : [];
	}

	private function syncGmail(array $aAuth, \RainLoop\Providers\AddressBook $oProvider, \RainLoop\Model\Account $oAccount) : int
	{
		$sClientId = $this->envOrTrim($this->configFromPlugin('login-gmail', 'client_id', ''), 'FRICKMAIL_GMAIL_CLIENT_ID');
		// client_secret stored encrypted in admin UI is unreadable from outside the owning plugin —
		// only env-var is supported here, which is fine for PKCE public clients.
		$sClientSecret = $this->envOrTrim('', 'FRICKMAIL_GMAIL_CLIENT_SECRET');
		if (!$sClientId) {
			throw new \RuntimeException('Gmail client_id not configured');
		}

		$aRefresh = $this->refreshToken(self::GMAIL_TOKEN_URI, $sClientId, $sClientSecret, $aAuth['refresh_token']);
		$sToken = $aRefresh['access_token'];

		$iTotal = 0;
		$sPage = '';
		do {
			$sUrl = 'https://people.googleapis.com/v1/people/me/connections?pageSize=200&personFields=names,emailAddresses,phoneNumbers,addresses,organizations,birthdays';
			if ($sPage) $sUrl .= '&pageToken=' . \urlencode($sPage);
			$aData = $this->httpJsonGet($sUrl, $sToken);
			foreach (($aData['connections'] ?? []) as $aPerson) {
				if ($this->savePersonAsContact($oProvider, $aPerson, 'gmail:' . ($aPerson['resourceName'] ?? ''))) {
					$iTotal++;
				}
			}
			$sPage = (string) ($aData['nextPageToken'] ?? '');
		} while ('' !== $sPage);

		return $iTotal;
	}

	private function syncO365(array $aAuth, \RainLoop\Providers\AddressBook $oProvider, \RainLoop\Model\Account $oAccount) : int
	{
		$sClientId = $this->envOrTrim($this->configFromPlugin('login-o365', 'client_id', ''), 'FRICKMAIL_O365_CLIENT_ID');
		$sClientSecret = $this->envOrTrim('', 'FRICKMAIL_O365_CLIENT_SECRET');
		$sTenant = $this->envOrTrim($this->configFromPlugin('login-o365', 'tenant', 'common'), 'FRICKMAIL_O365_TENANT') ?: 'common';
		if (!$sClientId) {
			throw new \RuntimeException('O365 client_id not configured');
		}
		$sTokenUri = \str_replace('{{tenant}}', $sTenant, self::O365_TOKEN_URI);

		// Exchange refresh_token for a Microsoft Graph audience token.
		$aRefresh = $this->refreshToken($sTokenUri, $sClientId, $sClientSecret, $aAuth['refresh_token'],
			'https://graph.microsoft.com/Contacts.Read offline_access');
		$sToken = $aRefresh['access_token'];

		$iTotal = 0;
		$sUrl = 'https://graph.microsoft.com/v1.0/me/contacts?$top=100';
		do {
			$aData = $this->httpJsonGet($sUrl, $sToken);
			foreach (($aData['value'] ?? []) as $aContact) {
				if ($this->saveGraphContact($oProvider, $aContact, 'o365:' . ($aContact['id'] ?? ''))) {
					$iTotal++;
				}
			}
			$sUrl = (string) ($aData['@odata.nextLink'] ?? '');
		} while ('' !== $sUrl);

		return $iTotal;
	}

	private function savePersonAsContact(\RainLoop\Providers\AddressBook $oProvider, array $aPerson, string $sUid) : bool
	{
		$oVCard = new \Sabre\VObject\Component\VCard(['VERSION' => '4.0']);
		$oVCard->UID = $sUid;

		$sFn = '';
		if (!empty($aPerson['names'][0])) {
			$n = $aPerson['names'][0];
			$sFn = (string) ($n['displayName'] ?? \trim(($n['givenName'] ?? '') . ' ' . ($n['familyName'] ?? '')));
			$oVCard->add('N', [
				$n['familyName'] ?? '',
				$n['givenName'] ?? '',
				$n['middleName'] ?? '',
				$n['honorificPrefix'] ?? '',
				$n['honorificSuffix'] ?? ''
			]);
		}
		if ('' === $sFn && !empty($aPerson['emailAddresses'][0]['value'])) {
			$sFn = (string) $aPerson['emailAddresses'][0]['value'];
		}
		if ('' === $sFn) return false;
		$oVCard->FN = $sFn;

		foreach (($aPerson['emailAddresses'] ?? []) as $aEmail) {
			if (!empty($aEmail['value'])) $oVCard->add('EMAIL', $aEmail['value']);
		}
		foreach (($aPerson['phoneNumbers'] ?? []) as $aPhone) {
			if (!empty($aPhone['value'])) $oVCard->add('TEL', $aPhone['value']);
		}
		foreach (($aPerson['organizations'] ?? []) as $aOrg) {
			if (!empty($aOrg['name'])) $oVCard->add('ORG', $aOrg['name']);
			if (!empty($aOrg['title'])) $oVCard->add('TITLE', $aOrg['title']);
		}
		foreach (($aPerson['addresses'] ?? []) as $aAddr) {
			if (!empty($aAddr['formattedValue'])) $oVCard->add('ADR', ['', '', $aAddr['formattedValue'], '', '', '', '']);
		}
		if (!empty($aPerson['birthdays'][0]['date'])) {
			$d = $aPerson['birthdays'][0]['date'];
			if (isset($d['year'], $d['month'], $d['day'])) {
				$oVCard->BDAY = \sprintf('%04d-%02d-%02d', $d['year'], $d['month'], $d['day']);
			}
		}

		$oContact = new \RainLoop\Providers\AddressBook\Classes\Contact();
		$oContact->setVCard($oVCard);
		return $oProvider->ContactSave($oContact);
	}

	private function saveGraphContact(\RainLoop\Providers\AddressBook $oProvider, array $aContact, string $sUid) : bool
	{
		$oVCard = new \Sabre\VObject\Component\VCard(['VERSION' => '4.0']);
		$oVCard->UID = $sUid;

		$sFn = (string) ($aContact['displayName']
			?? \trim(($aContact['givenName'] ?? '') . ' ' . ($aContact['surname'] ?? '')));
		if ('' === $sFn && !empty($aContact['emailAddresses'][0]['address'])) {
			$sFn = (string) $aContact['emailAddresses'][0]['address'];
		}
		if ('' === $sFn) return false;
		$oVCard->FN = $sFn;
		$oVCard->add('N', [
			$aContact['surname'] ?? '',
			$aContact['givenName'] ?? '',
			$aContact['middleName'] ?? '',
			'',
			''
		]);

		foreach (($aContact['emailAddresses'] ?? []) as $aEmail) {
			if (!empty($aEmail['address'])) $oVCard->add('EMAIL', $aEmail['address']);
		}
		foreach (['businessPhones', 'homePhones', 'mobilePhone'] as $sKey) {
			$aPhones = $aContact[$sKey] ?? null;
			if (\is_string($aPhones) && '' !== $aPhones) $oVCard->add('TEL', $aPhones);
			elseif (\is_array($aPhones)) foreach ($aPhones as $sPhone) {
				if ('' !== $sPhone) $oVCard->add('TEL', $sPhone);
			}
		}
		if (!empty($aContact['companyName'])) $oVCard->add('ORG', $aContact['companyName']);
		if (!empty($aContact['jobTitle'])) $oVCard->add('TITLE', $aContact['jobTitle']);
		if (!empty($aContact['birthday'])) {
			$bd = \substr((string) $aContact['birthday'], 0, 10);
			if ('' !== $bd) $oVCard->BDAY = $bd;
		}

		$oContact = new \RainLoop\Providers\AddressBook\Classes\Contact();
		$oContact->setVCard($oVCard);
		return $oProvider->ContactSave($oContact);
	}

	/**
	 * Read the OAuth refresh_token from the Frickmail DB for the given email.
	 * Used as fallback when SnappyMail's session storage doesn't have the token
	 * (e.g. after session token rotation or when the account is not the primary
	 * SnappyMail account at login time).
	 */
	private function loadFrickmailAuth(string $sEmail) : ?array
	{
		$sBase = \APP_PLUGINS_PATH . 'frickmail-user/lib/';
		if (!\is_file($sBase . 'Bridge.php')) return null;
		try {
			require_once $sBase . 'Crypto.php';
			require_once $sBase . 'Db.php';
			require_once $sBase . 'Bridge.php';
			$uid = \Frickmail\User\Bridge::currentUserId();
			$key = \Frickmail\User\Bridge::currentCryptKey();
			if (!$uid || !$key) return null;
			$db = new \Frickmail\User\Db();
			foreach ($db->listMailAccounts($uid) as $row) {
				if (\strtolower((string) $row['email']) !== \strtolower($sEmail)) continue;
				$dec = $db->decryptedAccount($row, $key);
				if (empty($dec['oauth_refresh_token'])) continue;
				return ['refresh_token' => $dec['oauth_refresh_token']];
			}
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
		}
		return null;
	}
}
