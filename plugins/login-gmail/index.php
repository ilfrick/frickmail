<?php

/**
 * https://developers.google.com/gmail/imap/imap-smtp
 * https://developers.google.com/gmail/imap/xoauth2-protocol
 * https://console.cloud.google.com/apis/dashboard
 *
 * Frickmail extras:
 *  - PKCE (RFC 7636) so a public client_id with no client_secret is accepted
 *  - env-var fallback (FRICKMAIL_GMAIL_CLIENT_ID / FRICKMAIL_GMAIL_CLIENT_SECRET)
 *  - popup-friendly callback that posts a message back to the opener
 */

use RainLoop\Model\MainAccount;
use RainLoop\Providers\Storage\Enumerations\StorageType;

class LoginGMailPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Login GMail OAuth2',
		VERSION  = '2.39',
		RELEASE  = '2026-05-02',
		REQUIRED = '2.36.1',
		CATEGORY = 'Login',
		DESCRIPTION = 'GMail IMAP, Sieve & SMTP login via RFC 7628 OAuth2 with PKCE, env-var config and Thunderbird-style popup (Frickmail)';

	const
		LOGIN_URI = 'https://accounts.google.com/o/oauth2/auth',
		TOKEN_URI = 'https://accounts.google.com/o/oauth2/token';

	private static ?array $auth = null;

	public function Init() : void
	{
		$this->UseLangs(true);
		$this->addJs('LoginOAuth2.js');
		$this->addHook('imap.before-login', 'clientLogin');
		$this->addHook('smtp.before-login', 'clientLogin');
		$this->addHook('sieve.before-login', 'clientLogin');

		$this->addPartHook('StartLoginGMail', 'ServiceStartLoginGMail');
		$this->addPartHook('LoginGMail', 'ServiceLoginGMail');

		// Prevent Disallowed Sec-Fetch Dest: document Mode: navigate Site: cross-site User: true
		$this->addHook('filter.http-paths', 'httpPaths');
	}

	public function httpPaths(array $aPaths) : void
	{
		if (!empty($aPaths[0]) && \in_array($aPaths[0], ['LoginGMail', 'StartLoginGMail'], true)) {
			$oConfig = \RainLoop\Api::Config();
			$oConfig->Set('security', 'secfetch_allow',
				\trim($oConfig->Get('security', 'secfetch_allow', '') . ';site=cross-site', ';')
			);
		}
	}

	/**
	 * Frontend hits ?StartLoginGMail to launch the OAuth2 flow.
	 * We generate a PKCE verifier, encrypt it inside the state parameter
	 * and 302 to Google's authorization endpoint.
	 */
	public function ServiceStartLoginGMail() : string
	{
		$oActions = \RainLoop\Api::Actions();
		$oHttp = $oActions->Http();
		$oHttp->ServerNoCache();

		$sClientId = $this->resolveClientId();
		if (!$sClientId) {
			$this->renderPopupCallback(false, '', 'Gmail OAuth2 client_id is not configured. Set it in the plugin settings or via FRICKMAIL_GMAIL_CLIENT_ID env-var.', \RainLoop\Utils::WebPath() ?: '/');
			exit;
		}

		$sVerifier = $this->generateCodeVerifier();
		$sChallenge = $this->codeChallenge($sVerifier);
		$sNonce = \bin2hex(\random_bytes(8));

		$sState = \SnappyMail\Crypt::EncryptUrlSafe([
			'p' => 'gmail',
			'v' => $sVerifier,
			'n' => $sNonce,
			't' => \time()
		]);

		$sRedirectUri = $oHttp->GetFullUrl() . '?LoginGMail';
		$sAuthUrl = static::LOGIN_URI . '?' . \http_build_query([
			'response_type' => 'code',
			'client_id' => $sClientId,
			'redirect_uri' => $sRedirectUri,
			'scope' => \implode(' ', [
				'https://www.googleapis.com/auth/userinfo.email',
				'https://www.googleapis.com/auth/userinfo.profile',
				'openid',
				'https://mail.google.com/',
				// Frickmail extras for contacts-sync + calendar plugins
				'https://www.googleapis.com/auth/contacts.readonly',
				'https://www.googleapis.com/auth/calendar'
			]),
			'state' => $sState,
			'access_type' => 'offline',
			'prompt' => 'consent',
			'code_challenge' => $sChallenge,
			'code_challenge_method' => 'S256'
		]);

		$oActions->Location($sAuthUrl);
		exit;
	}

	public function ServiceLoginGMail() : string
	{
		$oActions = \RainLoop\Api::Actions();
		$oHttp = $oActions->Http();
		$oHttp->ServerNoCache();

		$uri = \preg_replace('/.LoginGMail.*$/D', '', $_SERVER['REQUEST_URI']);
		$bPopupOk = false;
		$sPopupError = '';
		$sPopupEmail = '';

		try
		{
			if (isset($_GET['error'])) {
				throw new \RuntimeException($_GET['error']);
			}
			if (empty($_GET['code']) || empty($_GET['state'])) {
				$oActions->Location($uri);
				exit;
			}

			$aState = \SnappyMail\Crypt::DecryptUrlSafe((string) $_GET['state']);
			if (!\is_array($aState) || ($aState['p'] ?? '') !== 'gmail' || empty($aState['v'])) {
				throw new \RuntimeException('invalid state');
			}
			$sVerifier = (string) $aState['v'];

			$oGMail = $this->gmailConnector();
			if (!$oGMail) {
				throw new \RuntimeException('OAuth2 client not configured');
			}

			$iExpires = \time();
			$aResponse = $oGMail->getAccessToken(
				static::TOKEN_URI,
				'authorization_code',
				array(
					'code' => $_GET['code'],
					'redirect_uri' => $oHttp->GetFullUrl() . '?LoginGMail',
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

			$oGMail->setAccessToken($sAccessToken);
			$aUserInfo = $oGMail->fetch('https://www.googleapis.com/oauth2/v2/userinfo');
			if (200 != $aUserInfo['code']) {
				throw new \RuntimeException("HTTP: {$aResponse['code']}");
			}
			$aUserInfo = $aUserInfo['result'];
			if (empty($aUserInfo['id'])) {
				throw new \RuntimeException('unknown id');
			}
			if (empty($aUserInfo['email'])) {
				throw new \RuntimeException('unknown email address');
			}

			static::$auth = [
				'access_token' => $sAccessToken,
				'refresh_token' => $aResponse['refresh_token'],
				'expires_in' => (int) ($aResponse['expires_in'] ?? 3600),
				'expires' => $iExpires
			];

			// Frickmail mode: if a Frickmail user session exists, save the account
			// to the DB and skip the legacy IMAP-as-identity bridge.
			$sFrickmailBridge = \APP_PLUGINS_PATH . 'frickmail-user/lib/Bridge.php';
			if (\is_file($sFrickmailBridge)) {
				require_once $sFrickmailBridge;
				if (\Frickmail\User\Bridge::currentUserId()) {
					\Frickmail\User\Bridge::upsertOAuthAccount('gmail', (string) $aUserInfo['email'], (string) $aResponse['refresh_token']);
					$bPopupOk = true;
					$sPopupEmail = (string) $aUserInfo['email'];
					$this->renderPopupCallback($bPopupOk, $sPopupEmail, '', $uri);
					exit;
				}
			}

			$oPassword = new \SnappyMail\SensitiveString($aUserInfo['id']);
			$oAccount = $oActions->LoginProcess($aUserInfo['email'], $oPassword);
			if ($oAccount) {
				$oActions->StorageProvider()->Put($oAccount, StorageType::SESSION, \RainLoop\Utils::GetSessionToken(),
					\SnappyMail\Crypt::EncryptToJSON(static::$auth, $oAccount->CryptKey())
				);
			}
			$bPopupOk = true;
			$sPopupEmail = (string) $aUserInfo['email'];
		}
		catch (\Exception $oException)
		{
			$oActions->Logger()->WriteException($oException, \LOG_ERR);
			$sPopupError = $oException->getMessage();
		}

		// Render a tiny HTML page that:
		//  - if opened in a popup, posts a message to opener and closes
		//  - otherwise redirects back to the webmail UI (works as a normal full-page flow too)
		$this->renderPopupCallback($bPopupOk, $sPopupEmail, $sPopupError, $uri);
		exit;
	}

	private function renderPopupCallback(bool $bOk, string $sEmail, string $sError, string $sFallbackUri) : void
	{
		\header('Content-Type: text/html; charset=utf-8');
		$sStatus = $bOk ? 'ok' : 'error';
		$sPayload = \json_encode([
			'type' => 'frickmail-oauth2',
			'provider' => 'gmail',
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
			\RainLoop\Plugins\Property::NewInstance('client_id')
				->SetLabel('Client ID')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetAllowedInJs()
				->SetDescription('Leave empty to read from FRICKMAIL_GMAIL_CLIENT_ID environment variable. See docs/OAUTH2.md for app registration.'),
			\RainLoop\Plugins\Property::NewInstance('client_secret')
				->SetLabel('Client Secret (optional with PKCE)')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetEncrypted()
				->SetDescription('Leave empty for a public PKCE client. Otherwise reads from FRICKMAIL_GMAIL_CLIENT_SECRET environment variable.'),
			\RainLoop\Plugins\Property::NewInstance('domains')
				->SetLabel('Domains')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING_TEXT)
				->SetAllowedInJs()
				->SetDefaultValue('gmail.com googlemail.com')
				->SetDescription('Whitespace-separated list of domains routed through Google OAuth2 (add your Workspace domains here)')
		];
	}

	private function generateCodeVerifier() : string
	{
		// 96 bytes -> 128 url-safe base64 chars (well within RFC 7636 [43,128])
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
		return $this->envOrTrim((string) $this->Config()->Get('plugin', 'client_id', ''), 'FRICKMAIL_GMAIL_CLIENT_ID');
	}

	private function resolveClientSecret() : string
	{
		return $this->envOrTrim((string) $this->Config()->getDecrypted('plugin', 'client_secret', ''), 'FRICKMAIL_GMAIL_CLIENT_SECRET');
	}

	private function matchesDomain(string $sEmail) : bool
	{
		$sDomains = \trim((string) $this->Config()->Get('plugin', 'domains', 'gmail.com googlemail.com'));
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
					$oGMail = $this->gmailConnector();
					if ($oGMail) {
						$aRefreshTokenResponse = $oGMail->getAccessToken(
							static::TOKEN_URI,
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

	protected function gmailConnector() : ?\OAuth2\Client
	{
		$client_id = $this->resolveClientId();
		$client_secret = $this->resolveClientSecret();
		if (!$client_id) {
			return null;
		}
		try
		{
			$oGMail = new \OAuth2\Client($client_id, $client_secret);
			$oActions = \RainLoop\Api::Actions();
			$sProxy = $oActions->Config()->Get('labs', 'curl_proxy', '');
			if (\strlen($sProxy)) {
				$oGMail->setCurlOption(CURLOPT_PROXY, $sProxy);
				$sProxyAuth = $oActions->Config()->Get('labs', 'curl_proxy_auth', '');
				if (\strlen($sProxyAuth)) {
					$oGMail->setCurlOption(CURLOPT_PROXYUSERPWD, $sProxyAuth);
				}
			}
			return $oGMail;
		}
		catch (\Exception $oException)
		{
			\RainLoop\Api::Actions()->Logger()->WriteException($oException, \LOG_ERR);
		}
		return null;
	}
}
