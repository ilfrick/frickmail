<?php

/**
 * Generic OpenID Connect login for Frickmail.
 *
 * Works with any OIDC provider that exposes a Discovery document
 * (Keycloak, Authentik, Auth0, Okta, Dex, …).
 *
 * Flow — login:
 *   1. User clicks "Sign in with <Provider>" on the login page.
 *   2. Plugin generates PKCE verifier + encrypted state, redirects to the
 *      provider's authorization_endpoint (?StartLoginOIDC).
 *   3. Provider redirects back with a code (?LoginOIDC).
 *   4. Plugin exchanges code for tokens, calls userinfo_endpoint.
 *   5. Looks up the OIDC (provider_hash, sub) pair in frickmail_oidc_identities.
 *   6. Decrypts the per-user escrow key, establishes the Frickmail session,
 *      and bridges to SnappyMail / IMAP.
 *
 * Flow — link (called from Settings while already logged in):
 *   Same OAuth redirect, but "mode=link" in the state.
 *   On callback: stores the OIDC identity and writes the escrow key.
 *
 * Escrow key:
 *   The Frickmail cryptKey (32 bytes, normally derived from the user password)
 *   is encrypted with a server-side key derived from APP_SALT and stored in
 *   frickmail_users.oidc_escrow_key. On OIDC login the escrow is decrypted to
 *   recover the cryptKey without requiring the user password.
 *   Implication: the server operator can decrypt stored credentials.
 *   This is an acceptable trade-off for a self-hosted system.
 */

class LoginOIDCPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME        = 'Login OIDC',
		VERSION     = '1.6',
		RELEASE     = '2026-05-23',
		REQUIRED    = '2.36.1',
		CATEGORY    = 'Login',
		DESCRIPTION = 'Generic OpenID Connect (OIDC) login — works with Keycloak, Authentik, Auth0, Okta and any OIDC-compliant provider';

	public function Init() : void
	{
		$this->addJs('LoginOIDC.js');
		$this->addPartHook('StartLoginOIDC', 'ServiceStartLoginOIDC');
		$this->addPartHook('LoginOIDC',      'ServiceLoginOIDC');
		$this->addJsonHook('FrickmailListOidcLinks', 'JsonListOidcLinks');
		$this->addJsonHook('FrickmailUnlinkOidc',    'JsonUnlinkOidc');
		$this->addHook('filter.http-paths', 'httpPaths');
	}

	public function configMapping() : array
	{
		return [
			\RainLoop\Plugins\Property::NewInstance('discovery_url')
				->SetLabel('OIDC Discovery URL')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDescription('Provider base URL — the plugin appends /.well-known/openid-configuration. Example: https://keycloak.example.com/realms/myrealm — env: FRICKMAIL_OIDC_DISCOVERY_URL'),
			\RainLoop\Plugins\Property::NewInstance('client_id')
				->SetLabel('Client ID')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetAllowedInJs()
				->SetDescription('Env: FRICKMAIL_OIDC_CLIENT_ID'),
			\RainLoop\Plugins\Property::NewInstance('client_secret')
				->SetLabel('Client Secret (optional with PKCE)')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetEncrypted()
				->SetDescription('Leave empty for public / PKCE-only clients. Env: FRICKMAIL_OIDC_CLIENT_SECRET'),
			\RainLoop\Plugins\Property::NewInstance('provider_name')
				->SetLabel('Provider Name')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue('SSO')
				->SetAllowedInJs()
				->SetDescription('Display name shown in buttons, e.g. "Keycloak", "Authentik", "Company SSO"'),
			\RainLoop\Plugins\Property::NewInstance('button_label')
				->SetLabel('Login Button Label')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue('Sign in with SSO')
				->SetAllowedInJs(),
		];
	}

	// ── Sec-Fetch whitelist ───────────────────────────────────────────────────

	public function httpPaths(array &$aPaths) : void
	{
		$sPath     = $aPaths[0] ?? '';
		$bOidcPath = \in_array($sPath, ['LoginOIDC', 'StartLoginOIDC'], true);

		// Some OIDC providers strip the first query key from the redirect_uri,
		// redirecting to /?code=xxx&state=yyy instead of /?LoginOIDC&code=xxx&state=yyy.
		// Detect this by decrypting the state and routing to LoginOIDC explicitly.
		if (!$bOidcPath && isset($_GET['code'], $_GET['state'])) {
			$aState = \SnappyMail\Crypt::DecryptUrlSafe((string) $_GET['state'], \APP_SALT);
			if (\is_array($aState) && ($aState['p'] ?? '') === 'oidc') {
				$aPaths[0] = 'LoginOIDC';
				$bOidcPath = true;
			}
		}

		if ($bOidcPath) {
			$oConfig  = \RainLoop\Api::Config();
			$sCurrent = $oConfig->Get('security', 'secfetch_allow', '');
			$aParts   = \array_filter(\array_unique(\explode(';', $sCurrent)));
			// Allow the OIDC provider redirect back (cross-site navigation into the popup).
			if (!\in_array('site=cross-site', $aParts, true)) {
				$aParts[] = 'site=cross-site';
			}
			// Allow the initial popup navigation from within the webmail (same-site,
			// Dest: empty because it is a new auxiliary browsing context, not a document load).
			if (!\in_array('dest=empty,mode=navigate,site=same-site', $aParts, true)) {
				$aParts[] = 'dest=empty,mode=navigate,site=same-site';
			}
			$oConfig->Set('security', 'secfetch_allow', \implode(';', $aParts));
		}
	}

	// ── Part hooks ────────────────────────────────────────────────────────────

	/**
	 * ?StartLoginOIDC           → login mode (default)
	 * ?StartLoginOIDC&mode=link → link mode (requires existing Frickmail session)
	 */
	public function ServiceStartLoginOIDC() : string
	{
		$oActions = \RainLoop\Api::Actions();
		$oHttp    = $oActions->Http();
		$oHttp->ServerNoCache();

		$sDiscovery = $this->resolveDiscoveryUrl();
		$sClientId  = $this->resolveClientId();
		if (!$sDiscovery || !$sClientId) {
			$this->renderCallback(false, '', 'OIDC: discovery_url and client_id must be configured.', \RainLoop\Utils::WebPath() ?: '/');
			exit;
		}

		$aDoc = $this->fetchDiscovery($sDiscovery);
		if (!$aDoc || empty($aDoc['authorization_endpoint'])) {
			$this->renderCallback(false, '', 'OIDC: could not fetch ' . $sDiscovery . '/.well-known/openid-configuration', \RainLoop\Utils::WebPath() ?: '/');
			exit;
		}

		$sMode      = \in_array($_GET['mode'] ?? '', ['link', 'login'], true) ? $_GET['mode'] : 'login';
		$sVerifier  = $this->generateVerifier();
		$sChallenge = $this->challenge($sVerifier);

		$sState = \SnappyMail\Crypt::EncryptUrlSafe([
			'p' => 'oidc',
			'v' => $sVerifier,
			'm' => $sMode,
			't' => \time(),
		], \APP_SALT);

		$sRedirect = $this->baseUrl($oHttp) . '/?LoginOIDC';
		$sAuthUrl  = $aDoc['authorization_endpoint'] . '?' . \http_build_query([
			'response_type'         => 'code',
			'client_id'             => $sClientId,
			'redirect_uri'          => $sRedirect,
			'scope'                 => 'openid email profile',
			'state'                 => $sState,
			'code_challenge'        => $sChallenge,
			'code_challenge_method' => 'S256',
		]);

		$oActions->Location($sAuthUrl);
		exit;
	}

	public function ServiceLoginOIDC() : string
	{
		$oActions = \RainLoop\Api::Actions();
		$oHttp    = $oActions->Http();
		$oHttp->ServerNoCache();

		$sUri   = \preg_replace('/[?](?:LoginOIDC|code).*$/D', '', $_SERVER['REQUEST_URI']) ?: '/';
		$bOk    = false;
		$sError = '';
		$sEmail = '';
		$sMode  = 'login';

		try {
			if (isset($_GET['error'])) {
				throw new \RuntimeException((string) $_GET['error']);
			}
			if (empty($_GET['code']) || empty($_GET['state'])) {
				$oActions->Location($sUri);
				exit;
			}

			$aState = \SnappyMail\Crypt::DecryptUrlSafe((string) $_GET['state'], \APP_SALT);
			if (!\is_array($aState) || ($aState['p'] ?? '') !== 'oidc' || empty($aState['v'])) {
				throw new \RuntimeException('OIDC: invalid state parameter');
			}
			$sMode     = ($aState['m'] ?? '') === 'link' ? 'link' : 'login';
			$sVerifier = (string) $aState['v'];

			$sDiscovery = $this->resolveDiscoveryUrl();
			$aDoc       = $this->fetchDiscovery($sDiscovery);
			if (!$aDoc || empty($aDoc['token_endpoint'])) {
				throw new \RuntimeException('OIDC: discovery document unavailable');
			}

			$sRedirect  = $this->baseUrl($oHttp) . '/?LoginOIDC';
			$aTokenResp = $this->httpPost($aDoc['token_endpoint'], [
				'grant_type'    => 'authorization_code',
				'code'          => (string) $_GET['code'],
				'redirect_uri'  => $sRedirect,
				'client_id'     => $this->resolveClientId(),
				'client_secret' => $this->resolveClientSecret(),
				'code_verifier' => $sVerifier,
			]);

			if (empty($aTokenResp['access_token'])) {
				$sErr = $aTokenResp['error_description'] ?? $aTokenResp['error'] ?? 'no access_token in response';
				throw new \RuntimeException('OIDC token exchange failed: ' . $sErr);
			}

			if (empty($aDoc['userinfo_endpoint'])) {
				throw new \RuntimeException('OIDC provider has no userinfo_endpoint');
			}
			$aUserInfo = $this->httpGet($aDoc['userinfo_endpoint'], $aTokenResp['access_token']);
			if (empty($aUserInfo['sub'])) {
				throw new \RuntimeException('OIDC userinfo missing sub claim');
			}
			if (empty($aUserInfo['email'])) {
				throw new \RuntimeException('OIDC userinfo missing email claim — ensure the "email" scope is authorised');
			}

			$sSub          = (string) $aUserInfo['sub'];
			$sEmail        = (string) $aUserInfo['email'];
			$sProviderHash = $this->providerHash();

			$sBridge = \APP_PLUGINS_PATH . 'frickmail-user/lib/Bridge.php';
			if (!\is_file($sBridge)) {
				throw new \RuntimeException('The frickmail-user plugin is required for OIDC login');
			}
			require_once $sBridge;
			$db = new \Frickmail\User\Db();

			if ('link' === $sMode) {
				// Linking — requires an active Frickmail session.
				$uid      = \Frickmail\User\Bridge::currentUserId();
				$cryptKey = \Frickmail\User\Bridge::currentCryptKey();
				if (!$uid || null === $cryptKey) {
					throw new \RuntimeException('You must be logged in with your Frickmail password before linking an OIDC identity');
				}
				$db->upsertOidcIdentity($uid, $sProviderHash, $sSub);
				$db->setOidcEscrowKey($uid, $this->escrowEncrypt($cryptKey));
				$bOk = true;

			} else {
				// Login — look up identity, establish session, bridge IMAP.
				$aIdentity = $db->findOidcIdentity($sProviderHash, $sSub);
				if (!$aIdentity) {
					throw new \RuntimeException(
						'No Frickmail account is linked to this OIDC identity. '
						. 'Log in with your Frickmail password first, then link your OIDC account from Settings → Preferences.'
					);
				}
				$uid = (int) $aIdentity['user_id'];

				$sEscrow  = $db->getOidcEscrowKey($uid);
				if (null === $sEscrow) {
					throw new \RuntimeException('OIDC escrow key missing — log in with your Frickmail password and re-link OIDC from Settings.');
				}
				$cryptKey = $this->escrowDecrypt($sEscrow);
				if (null === $cryptKey) {
					throw new \RuntimeException('OIDC escrow key could not be decrypted — the server APP_SALT may have changed. Please re-link OIDC from Settings.');
				}

				// Establish the Frickmail PHP session.
				\Frickmail\User\Bridge::startSession();
				\session_regenerate_id(true);
				$_SESSION[\Frickmail\User\Bridge::SESSION_KEY_USER] = $uid;
				$_SESSION[\Frickmail\User\Bridge::SESSION_KEY_KEY]  = \base64_encode($cryptKey);

				// Bridge IMAP here in the popup response. LoginProcess() sets the
				// SnappyMail auth cookie in this HTTP response; the browser stores
				// it domain-wide so the main window picks it up on reload.
				$bReauthRequired = false;
				$oPrimary = $db->getPrimaryMailAccount($uid);
				if ($oPrimary) {
					require_once \APP_PLUGINS_PATH . 'frickmail-user/lib/MailAccountHandler.php';
					$aAccount = $db->decryptedAccount($oPrimary, $cryptKey);
					$oHandler = new \Frickmail\User\MailAccountHandler($db);
					try {
						$oHandler->bridge($aAccount);
					} catch (\RainLoop\Exceptions\ClientException $e) {
						if ($e->getCode() === \RainLoop\Notifications::AuthError) {
							$bReauthRequired = true;
						} else {
							throw $e;
						}
					} catch (\RuntimeException $e) {
						$oActions->Logger()->WriteException($e, \LOG_WARNING);
						$bReauthRequired = true;
					}
				}
				$bOk = true;
			}
		} catch (\Throwable $e) {
			$oActions->Logger()->WriteException($e, \LOG_ERR);
			$sError = $e->getMessage();
		}

		$this->renderCallback($bOk, $sEmail, $sError, $sUri, $sMode, $bReauthRequired ?? false);
		exit;
	}

	// ── JSON hooks ────────────────────────────────────────────────────────────

	public function JsonListOidcLinks() : array
	{
		try {
			$sBridge = \APP_PLUGINS_PATH . 'frickmail-user/lib/Bridge.php';
			if (!\is_file($sBridge)) {
				return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => 'frickmail-user plugin not found']);
			}
			require_once $sBridge;
			$uid = \Frickmail\User\Bridge::currentUserId();
			if (!$uid) {
				return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => 'Not authenticated']);
			}
			$db    = new \Frickmail\User\Db();
			$rows  = $db->listOidcIdentities($uid);
			$pname = \trim((string) $this->Config()->Get('plugin', 'provider_name', 'SSO')) ?: 'SSO';
			return $this->jsonResponse(__FUNCTION__, [
				'ok'    => true,
				'links' => \array_map(fn($r) => [
					'provider_hash' => $r['provider_hash'],
					'provider_name' => $pname,
					'linked_at'     => $r['linked_at'],
				], $rows),
			]);
		} catch (\Throwable $e) {
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonUnlinkOidc() : array
	{
		try {
			$sBridge = \APP_PLUGINS_PATH . 'frickmail-user/lib/Bridge.php';
			if (!\is_file($sBridge)) {
				return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => 'frickmail-user plugin not found']);
			}
			require_once $sBridge;
			$uid = \Frickmail\User\Bridge::currentUserId();
			if (!$uid) {
				return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => 'Not authenticated']);
			}
			$sProviderHash = \trim((string) $this->jsonParam('provider_hash'));
			if (!$sProviderHash) {
				return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => 'provider_hash required']);
			}
			$db = new \Frickmail\User\Db();
			$db->deleteOidcIdentity($uid, $sProviderHash);
			// Clear escrow key if no OIDC identities remain for this user.
			if (empty($db->listOidcIdentities($uid))) {
				$db->setOidcEscrowKey($uid, null);
			}
			return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'message' => 'OIDC identity unlinked.']);
		} catch (\Throwable $e) {
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	// ── Escrow key (cryptKey encrypted with server-side APP_SALT-derived key) ─

	private function serverKey() : string
	{
		return \hash('sha256', \APP_SALT, true);
	}

	private function escrowEncrypt(string $cryptKey) : string
	{
		$nonce  = \random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		$cipher = \sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($cryptKey, '', $nonce, $this->serverKey());
		return $nonce . $cipher;
	}

	private function escrowDecrypt(string $blob) : ?string
	{
		$nl = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
		if (\strlen($blob) < $nl) return null;
		$plain = \sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
			\substr($blob, $nl), '', \substr($blob, 0, $nl), $this->serverKey()
		);
		return false === $plain ? null : $plain;
	}

	// ── OIDC / HTTP helpers ───────────────────────────────────────────────────

	private function resolveDiscoveryUrl() : string
	{
		$v = \trim((string) $this->Config()->Get('plugin', 'discovery_url', ''));
		if ('' === $v) { $e = \getenv('FRICKMAIL_OIDC_DISCOVERY_URL'); if (\is_string($e)) $v = \trim($e); }
		return \rtrim($v, '/');
	}

	private function resolveClientId() : string
	{
		$v = \trim((string) $this->Config()->Get('plugin', 'client_id', ''));
		if ('' === $v) { $e = \getenv('FRICKMAIL_OIDC_CLIENT_ID'); if (\is_string($e)) $v = \trim($e); }
		return $v;
	}

	private function resolveClientSecret() : string
	{
		$v = \trim((string) $this->Config()->getDecrypted('plugin', 'client_secret', ''));
		if ('' === $v) { $e = \getenv('FRICKMAIL_OIDC_CLIENT_SECRET'); if (\is_string($e)) $v = \trim($e); }
		return $v;
	}

	private function providerHash() : string
	{
		return \hash('sha256', $this->resolveDiscoveryUrl());
	}

	private function fetchDiscovery(string $sBase) : ?array
	{
		$ctx  = \stream_context_create(['http' => [
			'method'        => 'GET',
			'timeout'       => 5,
			'ignore_errors' => true,
			'header'        => 'Accept: application/json',
		]]);
		$body = @\file_get_contents(\rtrim($sBase, '/') . '/.well-known/openid-configuration', false, $ctx);
		if (!$body) return null;
		$doc = \json_decode($body, true);
		return \is_array($doc) ? $doc : null;
	}

	private function httpPost(string $url, array $data) : array
	{
		$body = \http_build_query($data);
		$ctx  = \stream_context_create(['http' => [
			'method'        => 'POST',
			'timeout'       => 10,
			'ignore_errors' => true,
			'header'        => "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " . \strlen($body),
			'content'       => $body,
		]]);
		$resp = @\file_get_contents($url, false, $ctx);
		return $resp ? (\json_decode($resp, true) ?: []) : [];
	}

	private function httpGet(string $url, string $token) : array
	{
		$ctx  = \stream_context_create(['http' => [
			'method'        => 'GET',
			'timeout'       => 5,
			'ignore_errors' => true,
			'header'        => "Authorization: Bearer {$token}\r\nAccept: application/json",
		]]);
		$resp = @\file_get_contents($url, false, $ctx);
		return $resp ? (\json_decode($resp, true) ?: []) : [];
	}

	private function baseUrl(\MailSo\Base\Http $oHttp) : string
	{
		$e = \rtrim((string) \getenv('FRICKMAIL_BASE_URL'), '/');
		return '' !== $e ? $e : \rtrim($oHttp->GetFullUrl(), '/');
	}

	private function generateVerifier() : string
	{
		return \rtrim(\strtr(\base64_encode(\random_bytes(96)), '+/', '-_'), '=');
	}

	private function challenge(string $v) : string
	{
		return \rtrim(\strtr(\base64_encode(\hash('sha256', $v, true)), '+/', '-_'), '=');
	}

	private function renderCallback(bool $bOk, string $sEmail, string $sError, string $sFallback, string $sMode = 'login', bool $bReauthRequired = false) : void
	{
		\header('Content-Type: text/html; charset=utf-8');
		$payload = \json_encode([
			'type'            => 'frickmail-oidc',
			'status'          => $bOk ? 'ok' : 'error',
			'mode'            => $sMode,
			'email'           => $sEmail,
			'error'           => $sError,
			'reauth_required' => $bReauthRequired,
		]);
		echo '<!doctype html><meta charset="utf-8"><title>Frickmail</title><body><script>'
			. '(function(){var m=' . $payload . ';'
			. 'try{localStorage.setItem("frickmail-oidc-result",JSON.stringify(m));}catch(e){}'
			. 'try{var bc=new BroadcastChannel("frickmail-oidc");bc.postMessage(m);bc.close();setTimeout(function(){window.close();},100);return;}catch(e){}'
			. 'try{if(window.opener&&!window.opener.closed){window.opener.postMessage(m,window.location.origin);window.close();return;}}catch(e){}'
			. 'window.location.replace(' . \json_encode($sFallback ?: '/') . ');'
			. '})();</script>'
			. '<p>' . ($bOk ? 'Authentication succeeded.' : 'Authentication failed: ' . \htmlspecialchars($sError, \ENT_QUOTES, 'UTF-8')) . ' You can close this window.</p>'
			. '</body>';
	}
}
