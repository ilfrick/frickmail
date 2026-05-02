<?php

/**
 * https://developers.google.com/gmail/imap/imap-smtp
 * https://developers.google.com/gmail/imap/xoauth2-protocol
 * https://console.cloud.google.com/apis/dashboard
 */

use RainLoop\Model\MainAccount;
use RainLoop\Providers\Storage\Enumerations\StorageType;

class LoginGMailPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Login GMail OAuth2',
		VERSION  = '2.38',
		RELEASE  = '2026-05-02',
		REQUIRED = '2.36.1',
		CATEGORY = 'Login',
		DESCRIPTION = 'GMail IMAP, Sieve & SMTP login using RFC 7628 OAuth2 (Frickmail: Workspace domains + refresh fix)';

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

		$this->addPartHook('LoginGMail', 'ServiceLoginGMail');

		// Prevent Disallowed Sec-Fetch Dest: document Mode: navigate Site: cross-site User: true
		$this->addHook('filter.http-paths', 'httpPaths');
	}

	public function httpPaths(array $aPaths) : void
	{
		if (!empty($aPaths[0]) && 'LoginGMail' === $aPaths[0]) {
			$oConfig = \RainLoop\Api::Config();
			$oConfig->Set('security', 'secfetch_allow',
				\trim($oConfig->Get('security', 'secfetch_allow', '') . ';site=cross-site', ';')
			);
		}
	}

	public function ServiceLoginGMail() : string
	{
		$oActions = \RainLoop\Api::Actions();
		$oHttp = $oActions->Http();
		$oHttp->ServerNoCache();

		$uri = \preg_replace('/.LoginGMail.*$/D', '', $_SERVER['REQUEST_URI']);

		try
		{
			if (isset($_GET['error'])) {
				throw new \RuntimeException($_GET['error']);
			}
			if (isset($_GET['code']) && isset($_GET['state']) && 'gmail' === $_GET['state']) {
				$oGMail = $this->gmailConnector();
			}
			if (empty($oGMail)) {
				$oActions->Location($uri);
				exit;
			}

			$iExpires = \time();
			$aResponse = $oGMail->getAccessToken(
				static::TOKEN_URI,
				'authorization_code',
				array(
					'code' => $_GET['code'],
					'redirect_uri' => $oHttp->GetFullUrl().'?LoginGMail'
				)
			);
			if (200 != $aResponse['code']) {
				if (isset($aResponse['result']['error'])) {
					throw new \RuntimeException(
						$aResponse['code']
						. ': '
						. $aResponse['result']['error']
						. ' / '
						. $aResponse['result']['error_description']
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
			$iExpires += $aResponse['expires_in'];

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
				'expires_in' => $aResponse['expires_in'],
				'expires' => $iExpires
			];

			$oPassword = new \SnappyMail\SensitiveString($aUserInfo['id']);
			$oAccount = $oActions->LoginProcess($aUserInfo['email'], $oPassword);
//			$oAccount = MainAccount::NewInstanceFromCredentials($oActions, $aUserInfo['email'], $aUserInfo['email'], $oPassword, true);
			if ($oAccount) {
//				$oActions->SetMainAuthAccount($oAccount);
//				$oActions->SetAuthToken($oAccount);
				$oActions->StorageProvider()->Put($oAccount, StorageType::SESSION, \RainLoop\Utils::GetSessionToken(),
					\SnappyMail\Crypt::EncryptToJSON(static::$auth, $oAccount->CryptKey())
				);
			}
		}
		catch (\Exception $oException)
		{
			$oActions->Logger()->WriteException($oException, \LOG_ERR);
		}
		$oActions->Location($uri);
		exit;
	}

	public function configMapping() : array
	{
		return [
			\RainLoop\Plugins\Property::NewInstance('client_id')
				->SetLabel('Client ID')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetAllowedInJs()
				->SetDescription('https://github.com/the-djmaze/snappymail/wiki/FAQ#gmail'),
			\RainLoop\Plugins\Property::NewInstance('client_secret')
				->SetLabel('Client Secret')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetEncrypted(),
			\RainLoop\Plugins\Property::NewInstance('domains')
				->SetLabel('Domains')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING_TEXT)
				->SetAllowedInJs()
				->SetDefaultValue('gmail.com googlemail.com')
				->SetDescription('Whitespace-separated list of domains that should be authenticated through Google OAuth2 (e.g. add your Google Workspace domains here)')
		];
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
//				$oActions->Logger()->WriteException($oException, \LOG_ERR);
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
		$client_id = \trim($this->Config()->Get('plugin', 'client_id', ''));
		$client_secret = \trim($this->Config()->getDecrypted('plugin', 'client_secret', ''));
		if ($client_id && $client_secret) {
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
				$oActions->Logger()->WriteException($oException, \LOG_ERR);
			}
		}
		return null;
	}
}
