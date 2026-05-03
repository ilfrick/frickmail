<?php
/**
 * https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
 * https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps
 * https://learn.microsoft.com/en-us/entra/identity-platform/reply-url#query-parameter-support-in-redirect-uris
 *
 * Frickmail extras:
 *  - PKCE (RFC 7636) so a public client_id with no client_secret is accepted
 *  - env-var fallback (FRICKMAIL_O365_CLIENT_ID / FRICKMAIL_O365_CLIENT_SECRET / FRICKMAIL_O365_TENANT)
 *  - popup-friendly callback that posts a message back to the opener
 *
 * Azure:    redirect_uri=https://{DOMAIN}/?LoginO365
 * Personal: redirect_uri=https://{DOMAIN}/LoginO365
 */

use RainLoop\Model\MainAccount;
use RainLoop\Providers\Storage\Enumerations\StorageType;

class LoginO365Plugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Office365/Outlook OAuth2',
		VERSION  = '0.5',
		RELEASE  = '2026-05-02',
		REQUIRED = '2.36.1',
		CATEGORY = 'Login',
		DESCRIPTION = 'Office365/Outlook IMAP, Sieve & SMTP login via RFC 7628 OAuth2 with PKCE, env-var config and Thunderbird-style popup (Frickmail)';

	// https://login.microsoftonline.com/{{tenant}}/v2.0/.well-known/openid-configuration
	const
		LOGIN_URI = 'https://login.microsoftonline.com/{{tenant}}/oauth2/v2.0/authorize',
		TOKEN_URI = 'https://login.microsoftonline.com/{{tenant}}/oauth2/v2.0/token';

	private static ?array $auth = null;

	public function Init() : void
	{
		$this->UseLangs(true);
		$this->addJs('LoginOAuth2.js');
		$this->addHook('imap.before-login', 'clientLogin');
		$this->addHook('smtp.before-login', 'clientLogin');
		$this->addHook('sieve.before-login', 'clientLogin');

		$this->addPartHook('StartLoginO365', 'ServiceStartLoginO365');
		$this->addPartHook('LoginO365', 'ServiceLoginO365');

		// Prevent Disallowed Sec-Fetch Dest: document Mode: navigate Site: cross-site User: true
		$this->addHook('filter.http-paths', 'httpPaths');
	}

	public function httpPaths(array &$aPaths) : void
	{
		// Personal accounts workaround
		if (!empty($_SERVER['PATH_INFO']) && \str_ends_with($_SERVER['PATH_INFO'], 'LoginO365')) {
			$aPaths = ['LoginO365'];
		}

		if (!empty($aPaths[0]) && \in_array($aPaths[0], ['LoginO365', 'StartLoginO365'], true)) {
			$oConfig = \RainLoop\Api::Config();
			$oConfig->Set('security', 'secfetch_allow',
				\trim($oConfig->Get('security', 'secfetch_allow', '') . ';site=cross-site', ';')
			);
		}
	}

	public function ServiceStartLoginO365() : string
	{
		$oActions = \RainLoop\Api::Actions();
		$oHttp = $oActions->Http();
		$oHttp->ServerNoCache();

		$sClientId = $this->resolveClientId();
		if (!$sClientId) {
			$oActions->Location(\RainLoop\Utils::WebPath());
			exit;
		}

		$sVerifier = $this->generateCodeVerifier();
		$sChallenge = $this->codeChallenge($sVerifier);
		$sNonce = \bin2hex(\random_bytes(8));

		$sState = \SnappyMail\Crypt::EncryptUrlSafe([
			'p' => 'o365',
			'v' => $sVerifier,
			'n' => $sNonce,
			't' => \time()
		]);

		$bPersonal = (bool) $this->Config()->Get('plugin', 'personal', true);
		$sQuery = $bPersonal ? '' : '?';
		$sRedirectUri = $oHttp->GetFullUrl() . '/' . $sQuery . 'LoginO365';
		// GetFullUrl already returns trailing slash; collapse double slashes from concat above.
		$sRedirectUri = \preg_replace('#(?<!:)/{2,}#', '/', $sRedirectUri);

		$sTenant = $this->resolveTenant();
		$sAuthUrl = \str_replace('{{tenant}}', $sTenant, static::LOGIN_URI) . '?' . \http_build_query([
			'response_type' => 'code',
			'client_id' => $sClientId,
			'redirect_uri' => $sRedirectUri,
			'scope' => \implode(' ', [
				'openid',
				'offline_access',
				'email',
				'profile',
				'https://outlook.office.com/IMAP.AccessAsUser.All',
				'https://outlook.office.com/SMTP.Send',
				// Frickmail extras for contacts-sync + calendar plugins (Microsoft Graph audience)
				'https://graph.microsoft.com/Contacts.Read',
				'https://graph.microsoft.com/Calendars.ReadWrite'
			]),
			'state' => $sState,
			'prompt' => 'select_account',
			'code_challenge' => $sChallenge,
			'code_challenge_method' => 'S256'
		]);

		$oActions->Location($sAuthUrl);
		exit;
	}

	public function ServiceLoginO365() : string
	{
		$oActions = \RainLoop\Api::Actions();
		$oHttp = $oActions->Http();
		$oHttp->ServerNoCache();

		$sFallback = \RainLoop\Utils::WebPath() ?: '/';
		$bPopupOk = false;
		$sPopupError = '';
		$sPopupEmail = '';

		try
		{
			if (isset($_GET['error'])) {
				throw new \RuntimeException("{$_GET['error']}: " . ($_GET['error_description'] ?? ''));
			}
			if (empty($_GET['code']) || empty($_GET['state'])) {
				$oActions->Location($sFallback);
				exit;
			}

			$aState = \SnappyMail\Crypt::DecryptUrlSafe((string) $_GET['state']);
			if (!\is_array($aState) || ($aState['p'] ?? '') !== 'o365' || empty($aState['v'])) {
				throw new \RuntimeException('invalid state');
			}
			$sVerifier = (string) $aState['v'];

			$oO365 = $this->o365Connector();
			if (!$oO365) {
				throw new \RuntimeException('OAuth2 client not configured');
			}

			$bPersonal = (bool) $this->Config()->Get('plugin', 'personal', true);
			$sQuery = $bPersonal ? '' : '?';
			$sRedirectUri = $oHttp->GetFullUrl() . '/' . $sQuery . 'LoginO365';
			$sRedirectUri = \preg_replace('#(?<!:)/{2,}#', '/', $sRedirectUri);

			$iExpires = \time();
			$aResponse = $oO365->getAccessToken(
				\str_replace('{{tenant}}', $this->resolveTenant(), static::TOKEN_URI),
				'authorization_code',
				array(
					'code' => $_GET['code'],
					'redirect_uri' => $sRedirectUri,
					'code_verifier' => $sVerifier
				)
			);
			if (200 != $aResponse['code']) {
				if (isset($aResponse['result']['error'])) {
					throw new \RuntimeException(
						$aResponse['code']
						. ': '
						. $aResponse['result']['error']
						. ' / '
						. ($aResponse['result']['error_description'] ?? '')
					);
				}
				throw new \RuntimeException("HTTP: {$aResponse['code']}");
			}
			$aResponse = $aResponse['result'];
			if (empty($aResponse['access_token'])) {
				throw new \RuntimeException('access_token missing');
			}
			if (empty($aResponse['refresh_token'])) {
				throw new \RuntimeException('refresh_token missing');
			}

			$sAccessToken = $aResponse['access_token'];
			$iExpires += (int) ($aResponse['expires_in'] ?? 3600);

			$oO365->setAccessToken($sAccessToken);
			$aUserInfo = $oO365->fetch('https://graph.microsoft.com/oidc/userinfo');
			if (200 != $aUserInfo['code']) {
				throw new \RuntimeException("HTTP: {$aResponse['code']}");
			}
			$aUserInfo = $aUserInfo['result'];
			if (empty($aUserInfo['sub']) && empty($aUserInfo['id'])) {
				throw new \RuntimeException('unknown id');
			}
			$sId = (string) ($aUserInfo['id'] ?? $aUserInfo['sub']);
			$sEmail = (string) ($aUserInfo['email'] ?? $aUserInfo['preferred_username'] ?? '');
			if ('' === $sEmail) {
				throw new \RuntimeException('unknown email address');
			}

			static::$auth = [
				'access_token' => $sAccessToken,
				'refresh_token' => $aResponse['refresh_token'],
				'expires_in' => (int) ($aResponse['expires_in'] ?? 3600),
				'expires' => $iExpires
			];

			$oPassword = new \SnappyMail\SensitiveString($sId);
			$oAccount = $oActions->LoginProcess($sEmail, $oPassword);
			if ($oAccount) {
				$oActions->StorageProvider()->Put($oAccount, StorageType::SESSION, \RainLoop\Utils::GetSessionToken(),
					\SnappyMail\Crypt::EncryptToJSON(static::$auth, $oAccount->CryptKey())
				);
			}
			$bPopupOk = true;
			$sPopupEmail = $sEmail;
		}
		catch (\Exception $oException)
		{
			$oActions->Logger()->WriteException($oException, \LOG_ERR);
			$sPopupError = $oException->getMessage();
		}

		$this->renderPopupCallback($bPopupOk, $sPopupEmail, $sPopupError, $sFallback);
		exit;
	}

	private function renderPopupCallback(bool $bOk, string $sEmail, string $sError, string $sFallbackUri) : void
	{
		\header('Content-Type: text/html; charset=utf-8');
		$sStatus = $bOk ? 'ok' : 'error';
		$sPayload = \json_encode([
			'type' => 'frickmail-oauth2',
			'provider' => 'o365',
			'status' => $sStatus,
			'email' => $sEmail,
			'error' => $sError
		]);
		$sFallback = \htmlspecialchars($sFallbackUri ?: '/', ENT_QUOTES, 'UTF-8');
		echo '<!doctype html><meta charset="utf-8"><title>Frickmail</title><body><script>'
			. '(function(){var msg=' . $sPayload . ';try{if(window.opener && !window.opener.closed){'
			. 'window.opener.postMessage(msg, window.location.origin);window.close();return;}}catch(e){}'
			. 'window.location.replace(' . \json_encode($sFallback) . ');})();'
			. '</script><p>Authentication ' . ($bOk ? 'succeeded' : 'failed') . '. You can close this window.</p></body>';
	}

	public function configMapping() : array
	{
		return [
			\RainLoop\Plugins\Property::NewInstance('personal')
				->SetLabel('Use with personal accounts')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::BOOL)
				->SetDefaultValue(true)
				->SetAllowedInJs()
				->SetDescription('Sign in users with personal Microsoft accounts such as Outlook.com (Hotmail)'),
			\RainLoop\Plugins\Property::NewInstance('client_id')
				->SetLabel('Client ID')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetAllowedInJs()
				->SetDescription('Leave empty to read from FRICKMAIL_O365_CLIENT_ID environment variable. See docs/OAUTH2.md for app registration.'),
			\RainLoop\Plugins\Property::NewInstance('client_secret')
				->SetLabel('Client Secret (optional with PKCE)')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetEncrypted()
				->SetDescription('Leave empty for a public PKCE client. Otherwise reads from FRICKMAIL_O365_CLIENT_SECRET environment variable.'),
			\RainLoop\Plugins\Property::NewInstance('tenant')
				->SetLabel('Tenant')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue('common')
				->SetAllowedInJs()
				->SetDescription('Microsoft tenant: "common", "consumers", "organizations" or a tenant GUID/domain. Reads FRICKMAIL_O365_TENANT if empty.'),
			\RainLoop\Plugins\Property::NewInstance('domains')
				->SetLabel('Domains')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING_TEXT)
				->SetAllowedInJs()
				->SetDefaultValue('outlook.com hotmail.com live.com msn.com hotmail.it outlook.it live.it')
				->SetDescription('Whitespace-separated list of domains routed through Microsoft OAuth2 (add your O365 tenant domains here)')
		];
	}

	private function generateCodeVerifier() : string
	{
		return \rtrim(\strtr(\base64_encode(\random_bytes(96)), '+/', '-_'), '=');
	}

	private function codeChallenge(string $sVerifier) : string
	{
		return \rtrim(\strtr(\base64_encode(\hash('sha256', $sVerifier, true)), '+/', '-_'), '=');
	}

	private function envOrTrim(string $sValue, string $sEnv) : string
	{
		$sValue = \trim($sValue);
		if ('' === $sValue) {
			$sEnvValue = \getenv($sEnv);
			if (\is_string($sEnvValue)) {
				$sValue = \trim($sEnvValue);
			}
		}
		return $sValue;
	}

	private function resolveClientId() : string
	{
		return $this->envOrTrim((string) $this->Config()->Get('plugin', 'client_id', ''), 'FRICKMAIL_O365_CLIENT_ID');
	}

	private function resolveClientSecret() : string
	{
		return $this->envOrTrim((string) $this->Config()->getDecrypted('plugin', 'client_secret', ''), 'FRICKMAIL_O365_CLIENT_SECRET');
	}

	private function resolveTenant() : string
	{
		$sTenant = $this->envOrTrim((string) $this->Config()->Get('plugin', 'tenant', 'common'), 'FRICKMAIL_O365_TENANT');
		return '' !== $sTenant ? $sTenant : 'common';
	}

	private function matchesDomain(string $sEmail) : bool
	{
		$sDomains = \trim((string) $this->Config()->Get('plugin', 'domains', 'outlook.com hotmail.com live.com msn.com hotmail.it outlook.it live.it'));
		if ('' === $sDomains) {
			return false;
		}
		$aDomains = \preg_split('/\s+/', \strtolower($sDomains)) ?: [];
		$sEmail = \strtolower($sEmail);
		foreach ($aDomains as $sDomain) {
			$sDomain = \trim($sDomain);
			if ('' !== $sDomain && \str_ends_with($sEmail, '@' . $sDomain)) {
				return true;
			}
		}
		return false;
	}

	public function clientLogin(\RainLoop\Model\Account $oAccount, \MailSo\Net\NetClient $oClient, \MailSo\Net\ConnectSettings $oSettings) : void
	{
		if ($oAccount instanceof MainAccount && $this->matchesDomain($oAccount->Email())) {
			$oActions = \RainLoop\Api::Actions();
			try {
				$aData = static::$auth ?: \SnappyMail\Crypt::DecryptFromJSON(
					$oActions->StorageProvider()->Get($oAccount, StorageType::SESSION, \RainLoop\Utils::GetSessionToken()),
					$oAccount->CryptKey()
				);
			} catch (\Throwable $oException) {
				return;
			}
			if (!empty($aData['expires']) && !empty($aData['access_token']) && !empty($aData['refresh_token'])) {
				if (\time() >= $aData['expires']) {
					$iExpires = \time();
					$oO365 = $this->o365Connector();
					if ($oO365) {
						$aRefreshTokenResponse = $oO365->getAccessToken(
							\str_replace('{{tenant}}', $this->resolveTenant(), static::TOKEN_URI),
							'refresh_token',
							array('refresh_token' => $aData['refresh_token'])
						);
						if (!empty($aRefreshTokenResponse['result']['access_token'])) {
							$aData['access_token'] = $aRefreshTokenResponse['result']['access_token'];
							$aData['expires_in'] = (int) ($aRefreshTokenResponse['result']['expires_in'] ?? $aData['expires_in'] ?? 3600);
							$aData['expires'] = $iExpires + $aData['expires_in'];
							if (!empty($aRefreshTokenResponse['result']['refresh_token'])) {
								$aData['refresh_token'] = $aRefreshTokenResponse['result']['refresh_token'];
							}
							$oActions->StorageProvider()->Put($oAccount, StorageType::SESSION, \RainLoop\Utils::GetSessionToken(),
								\SnappyMail\Crypt::EncryptToJSON($aData, $oAccount->CryptKey())
							);
						}
					}
				}
				$oSettings->passphrase = $aData['access_token'];
				\array_unshift($oSettings->SASLMechanisms, 'OAUTHBEARER', 'XOAUTH2');
			}
		}
	}

	protected function o365Connector() : ?\OAuth2\Client
	{
		$client_id = $this->resolveClientId();
		$client_secret = $this->resolveClientSecret();
		if (!$client_id) {
			return null;
		}
		try
		{
			$oO365 = new \OAuth2\Client($client_id, $client_secret);
			$oActions = \RainLoop\Api::Actions();
			$sProxy = $oActions->Config()->Get('labs', 'curl_proxy', '');
			if (\strlen($sProxy)) {
				$oO365->setCurlOption(CURLOPT_PROXY, $sProxy);
				$sProxyAuth = $oActions->Config()->Get('labs', 'curl_proxy_auth', '');
				if (\strlen($sProxyAuth)) {
					$oO365->setCurlOption(CURLOPT_PROXYUSERPWD, $sProxyAuth);
				}
			}
			return $oO365;
		}
		catch (\Exception $oException)
		{
			\RainLoop\Api::Actions()->Logger()->WriteException($oException, \LOG_ERR);
		}
		return null;
	}
}
