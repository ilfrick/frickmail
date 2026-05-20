<?php
/**
 * Frickmail user plugin — first-class user identity backed by Postgres.
 *
 * Login flow:
 *   1. Browser POSTs username + password to ?Json/&q[]=/0/Plugin/-/&_action=FrickmailLogin
 *   2. We verify against frickmail_users.password_hash (Argon2id)
 *   3. We derive an AEAD key from the password + per-user salt, keep it in
 *      $_SESSION (PHP session, distinct from the webmail session)
 *   4. We load the primary mail account from frickmail_mail_accounts
 *   5. We bridge to IMAP login with the decrypted credentials
 *   6. The webmail issues its session token, the user lands in the inbox
 *
 * Adding mail accounts: separate JSON endpoints write to frickmail_mail_accounts
 * with credentials encrypted under the same AEAD key. OAuth tokens go to
 * encrypted_oauth_refresh_token.
 */

require_once __DIR__ . '/lib/Crypto.php';
require_once __DIR__ . '/lib/Db.php';
require_once __DIR__ . '/lib/Bridge.php';
require_once __DIR__ . '/lib/Mailer.php';
require_once __DIR__ . '/lib/AuthHandler.php';
require_once __DIR__ . '/lib/MailAccountHandler.php';
require_once __DIR__ . '/lib/ServiceDiscoveryHandler.php';

class FrickmailUserPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Frickmail User',
		VERSION  = '0.38',
		RELEASE  = '2026-05-16',
		REQUIRED = '2.36.1',
		CATEGORY = 'Login',
		DESCRIPTION = 'Frickmail: first-class user identity in Postgres, mail accounts as linked records.';

	// Expose session-key constants for external code that needs to read the session.
	const SESSION_KEY_USER = \Frickmail\User\AuthHandler::SESSION_KEY_USER;
	const SESSION_KEY_KEY  = \Frickmail\User\AuthHandler::SESSION_KEY_KEY;

	/* ------------------------------------------------------------------ */
	/*  Memoised handler accessors (P6)                                      */
	/* ------------------------------------------------------------------ */

	private ?\Frickmail\User\Db $_db = null;

	private function db() : \Frickmail\User\Db
	{
		return $this->_db ??= new \Frickmail\User\Db();
	}

	private ?\Frickmail\User\AuthHandler $_auth = null;

	private function auth() : \Frickmail\User\AuthHandler
	{
		return $this->_auth ??= new \Frickmail\User\AuthHandler($this->db());
	}

	private ?\Frickmail\User\MailAccountHandler $_mailAccounts = null;

	private function mailAccounts() : \Frickmail\User\MailAccountHandler
	{
		return $this->_mailAccounts ??= new \Frickmail\User\MailAccountHandler($this->db());
	}

	private ?\Frickmail\User\ServiceDiscoveryHandler $_discovery = null;

	private function discovery() : \Frickmail\User\ServiceDiscoveryHandler
	{
		return $this->_discovery ??= new \Frickmail\User\ServiceDiscoveryHandler($this->db());
	}

	/* ------------------------------------------------------------------ */
	/*  Init                                                                 */
	/* ------------------------------------------------------------------ */

	public function Init() : void
	{
		// Frickmail is the only account management system — disable the built-in
		// additional-accounts capability so the Settings→Accounts tab,
		// account-add popup, and duplicate switcher UI never appear.
		\RainLoop\Api::Config()->Set('webmail', 'allow_additional_accounts', false);

		$this->assertNoConflictingPlugins();

		$this->UseLangs(false);
		$this->addJs('js/Login.js');
		$this->addJs('js/AccountSwitcher.js');
		$this->addJs('js/MailAccountsSettings.js');
		$this->addJs('js/TwoFactorSettings.js');
		$this->addJs('js/AdminBranding.js', true);
		$this->addTemplate('templates/FrickmailMailAccountsSettings.html');
		$this->addTemplate('templates/FrickmailTwoFactorSettingsTab.html');

		$this->addJsonHook('FrickmailLogin',               'JsonFrickmailLogin');
		$this->addJsonHook('FrickmailRegister',            'JsonFrickmailRegister');
		$this->addJsonHook('FrickmailListAccounts',        'JsonListAccounts');
		$this->addJsonHook('FrickmailAddAccount',          'JsonAddAccount');
		$this->addJsonHook('FrickmailDeleteAccount',       'JsonDeleteAccount');
		$this->addJsonHook('FrickmailSetPrimary',          'JsonSetPrimary');
		$this->addJsonHook('FrickmailSwitchAccount',       'JsonSwitchAccount');
		$this->addJsonHook('FrickmailSetAccountPassword',  'JsonSetAccountPassword');
		$this->addJsonHook('FrickmailRequestPasswordReset','JsonRequestPasswordReset');
		$this->addJsonHook('FrickmailResetPassword',       'JsonResetPassword');
		$this->addJsonHook('FrickmailMe',                  'JsonMe');
		$this->addJsonHook('FrickmailGetTotpStatus',       'JsonGetTotpStatus');
		$this->addJsonHook('FrickmailEnableTotp',          'JsonEnableTotp');
		$this->addJsonHook('FrickmailConfirmTotp',         'JsonConfirmTotp');
		$this->addJsonHook('FrickmailDisableTotp',         'JsonDisableTotp');
		// JsonTestImap removed — diagnostic endpoint must not exist in production (C1)
		$this->addJsonHook('FrickmailDiscoverServices',    'JsonDiscoverServices');
		$this->addJsonHook('FrickmailActivateService',     'JsonActivateService');
		$this->addJsonHook('FrickmailSaveOAuthToken',      'JsonSaveOAuthToken');

		// Allow Sec-Fetch cross-site navigations to the reset-password landing page,
		// so the link delivered by email opens correctly from external mail clients.
		$this->addHook('filter.http-paths', 'httpPaths');
	}

	public function httpPaths(array $aPaths) : void
	{
		// Allow cross-site navigations whenever the URL is a reset-password landing.
		// Validate token format before relaxing Sec-Fetch-Site (M5): must be base64url, 20-60 chars.
		$token = \trim((string) ($_GET['reset_token'] ?? ''));
		if ('' !== $token && \preg_match('/^[A-Za-z0-9_\-]{20,60}$/', $token)) {
			$oConfig  = \RainLoop\Api::Config();
			$sCurrent = $oConfig->Get('security', 'secfetch_allow', '');
			$aParts   = \array_filter(\array_unique(\explode(';', $sCurrent)));
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

	/* ------------------------------------------------------------------ */
	/*  Dispatcher helper                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * Wrap a handler call: run $action(), wrap success with jsonResponse(), or
	 * log + wrap exceptions as an error response.
	 */
	private function dispatch(string $fn, callable $action) : array
	{
		try {
			$result = $action();
			return $this->jsonResponse($fn, $result);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse($fn, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	/* ------------------------------------------------------------------ */
	/*  Auth actions                                                         */
	/* ------------------------------------------------------------------ */

	public function JsonFrickmailRegister() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			return $this->auth()->register(
				$this->isSignupOpen(),
				\trim((string) $this->jsonParam('username')),
				\trim((string) $this->jsonParam('email')) ?: null,
				(string) $this->jsonParam('password')
			);
		});
	}

	public function JsonFrickmailLogin() : array
	{
		try {
			$totpCode = \preg_replace('/\s+/', '', (string) $this->jsonParam('totp_code'));
			$result   = $this->auth()->login(
				\trim((string) $this->jsonParam('username')),
				(string) $this->jsonParam('password'),
				$totpCode
			);

			if ('bridge_needed' === $result['status']) {
				$account = $result['account'];
				try {
					$this->mailAccounts()->bridge($account);
				} catch (\RainLoop\Exceptions\ClientException $e) {
					if ($e->getCode() === \RainLoop\Notifications::AuthError) {
						// Stored credentials are wrong (e.g. wrong password re-entered during
						// a previous re-auth attempt). Treat as reauth_required so the user
						// can correct the password rather than seeing a cryptic login error.
						return $this->jsonResponse(__FUNCTION__, [
							'ok'                   => true,
							'no_primary'           => true,
							'reauth_required'      => true,
							'reauth_account_id'    => (int)    $account['id'],
							'reauth_account_email' => (string) $account['email'],
							'reauth_account_type'  => (string) $account['type'],
							'message'              => 'IMAP authentication failed for ' . $account['email'] . ' — re-enter the password.',
						]);
					}
					throw $e;
				}
				return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'email' => $account['email']]);
			}

			// All other statuses (totp_required, totp_replay, no_primary, reauth_required)
			// are already well-formed response arrays from AuthHandler::login().
			unset($result['status'], $result['account']);
			return $this->jsonResponse(__FUNCTION__, $result);

		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => $e->getMessage()]);
		}
	}

	public function JsonMe() : array
	{
		return $this->dispatch(__FUNCTION__, fn() => $this->auth()->me());
	}

	public function JsonGetTotpStatus() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid] = $this->auth()->requireSession();
			return $this->auth()->getTotpStatus($uid);
		});
	}

	public function JsonEnableTotp() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid] = $this->auth()->requireSession();
			$result = $this->auth()->enableTotp($uid);
			// Generate QR data URL here (needs plugin context for SnappyMail\QRCode)
			$result['qr_data_url'] = $this->generateQrDataUrl($result['_uri_for_qr']);
			unset($result['_uri_for_qr']);
			return $result;
		});
	}

	public function JsonConfirmTotp() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid] = $this->auth()->requireSession();
			$code = \preg_replace('/\s+/', '', (string) $this->jsonParam('code'));
			return $this->auth()->confirmTotp($uid, $code);
		});
	}

	public function JsonDisableTotp() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid] = $this->auth()->requireSession();
			$code = \preg_replace('/\s+/', '', (string) $this->jsonParam('code'));
			return $this->auth()->disableTotp($uid, $code);
		});
	}

	public function JsonRequestPasswordReset() : array
	{
		// Always respond OK to avoid leaking which usernames exist.
		try {
			$this->auth()->requestPasswordReset(
				\trim((string) $this->jsonParam('username')),
				$this->resetUrl()
			);
			return $this->jsonResponse(__FUNCTION__, [
				'ok'      => true,
				'message' => 'If the username exists and has a recovery email, a reset link has been sent.',
			]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['ok' => false, 'error' => 'Server error']);
		}
	}

	public function JsonResetPassword() : array
	{
		return $this->dispatch(__FUNCTION__, fn() =>
			$this->auth()->resetPassword(
				(string) $this->jsonParam('token'),
				(string) $this->jsonParam('password')
			)
		);
	}

	/* ------------------------------------------------------------------ */
	/*  Mail-account actions                                                 */
	/* ------------------------------------------------------------------ */

	public function JsonListAccounts() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid] = $this->auth()->requireSession();
			return $this->mailAccounts()->listAccounts($uid);
		});
	}

	public function JsonAddAccount() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid, $cryptKey] = $this->auth()->requireSession();
			$params = [
				'type'        => (string) $this->jsonParam('type'),
				'label'       => (string) $this->jsonParam('label'),
				'email'       => (string) $this->jsonParam('email'),
				'imap_host'   => (string) $this->jsonParam('imap_host'),
				'smtp_host'   => (string) $this->jsonParam('smtp_host'),
				'imap_port'   => $this->jsonParam('imap_port'),
				'imap_secure' => $this->jsonParam('imap_secure'),
				'smtp_port'   => $this->jsonParam('smtp_port'),
				'smtp_secure' => $this->jsonParam('smtp_secure'),
				'login'       => $this->jsonParam('login'),
				'password'    => (string) $this->jsonParam('password'),
				'tenant'      => $this->jsonParam('tenant'),
				'is_primary'  => $this->jsonParam('is_primary'),
			];
			return $this->mailAccounts()->addAccount($uid, $cryptKey, $params);
		});
	}

	public function JsonDeleteAccount() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid] = $this->auth()->requireSession();
			return $this->mailAccounts()->deleteAccount($uid, (int) $this->jsonParam('id'));
		});
	}

	public function JsonSetPrimary() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid] = $this->auth()->requireSession();
			return $this->mailAccounts()->setPrimary($uid, (int) $this->jsonParam('id'));
		});
	}

	public function JsonSetAccountPassword() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid, $cryptKey] = $this->auth()->requireSession();
			return $this->mailAccounts()->setAccountPassword(
				$uid, $cryptKey,
				(int)    $this->jsonParam('id'),
				(string) $this->jsonParam('password')
			);
		});
	}

	public function JsonSwitchAccount() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid, $cryptKey] = $this->auth()->requireSession();
			return $this->mailAccounts()->switchAccount($uid, $cryptKey, (int) $this->jsonParam('id'));
		});
	}

	public function JsonSaveOAuthToken() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid, $cryptKey] = $this->auth()->requireSession();
			return $this->mailAccounts()->saveOAuthToken(
				$uid, $cryptKey,
				(string) $this->jsonParam('type'),
				\trim((string) $this->jsonParam('email')),
				(string) $this->jsonParam('refresh_token')
			);
		});
	}

	/* ------------------------------------------------------------------ */
	/*  Service discovery actions                                            */
	/* ------------------------------------------------------------------ */

	public function JsonDiscoverServices() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid] = $this->auth()->requireSession();
			return $this->discovery()->discoverServices($uid, (int) $this->jsonParam('id'));
		});
	}

	public function JsonActivateService() : array
	{
		return $this->dispatch(__FUNCTION__, function () {
			[$uid] = $this->auth()->requireSession();
			return $this->discovery()->activateService(
				$uid,
				(int)    $this->jsonParam('account_id'),
				(string) $this->jsonParam('service_type'),
				(string) $this->jsonParam('provider'),
				(string) $this->jsonParam('url')
			);
		});
	}

	/* ------------------------------------------------------------------ */
	/*  Private helpers                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * Plugins that bypass or corrupt frickmail-user's auth/account model if enabled.
	 * CRITICAL: replace the login flow or change passwords behind frickmail's back.
	 * WARNING:  may cause unexpected behaviour but don't break the system outright.
	 */
	private function assertNoConflictingPlugins() : void
	{
		$critical = [
			// Alternative login systems — bypass frickmail-user entirely
			'login-external', 'login-external-sso', 'login-override', 'login-virtuser',
			'login-cpanel', 'login-remote', 'login-register', 'proxy-auth',
			'ldap-login-mapping', 'ldap-mail-accounts', 'custom-login-mapping',
			// Password changers — modify IMAP passwords without updating the encrypted blob in Postgres
			'change-password', 'change-password-cpanel', 'change-password-froxlor',
			'change-password-hestia', 'change-password-ispconfig', 'change-password-hmailserver',
			'change-password-mailcow', 'change-password-poppassd',
		];
		$warning = [
			// Duplicate 2FA — frickmail-user has its own TOTP; enabling this too causes two
			// separate 2FA flows that are unaware of each other.
			'two-factor-auth',
		];

		$enabled = \array_filter(\array_map('trim',
			\explode(',', \RainLoop\Api::Config()->Get('plugins', 'enabled_list', ''))
		));

		// Use error_log only — calling Actions()->Logger() during Init() is unsafe
		// (Actions may not be fully bootstrapped yet, causing recursive initialisation).
		$found = \array_intersect($critical, $enabled);
		if ($found) {
			\error_log('[frickmail-user] CRITICAL: incompatible plugin(s) enabled — '
				. \implode(', ', $found)
				. '. These bypass or corrupt frickmail-user auth. Disable them immediately.');
		}

		$found = \array_intersect($warning, $enabled);
		if ($found) {
			\error_log('[frickmail-user] WARNING: plugin(s) ' . \implode(', ', $found)
				. ' may conflict with frickmail-user functionality.');
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

	private function resetUrl() : string
	{
		$sBase = \trim((string) (\getenv('FRICKMAIL_BASE_URL') ?: ''));
		if ('' === $sBase) {
			$proto   = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
			// Strip port and validate Host to prevent header injection (M3).
			$rawHost = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
			$host    = \preg_replace('/:\d+$/', '', $rawHost);
			if (!\preg_match('/^[a-zA-Z0-9.\-]+$/', $host)) {
				$host = 'localhost';
			}
			$sBase = $proto . '://' . $host;
		}
		// Return the base URL; AuthHandler::requestPasswordReset will append the token.
		return $sBase;
	}

	private function generateQrDataUrl(string $sData) : string
	{
		$qr = new \SnappyMail\QRCode();
		$qr->setErrorCorrectLevel(\SnappyMail\QRCode::ERROR_CORRECT_LEVEL_M);
		$qr->addData($sData);
		$qr->make();
		$n    = $qr->getModuleCount();
		$cell = 6;
		$pad  = 16;
		$size = $n * $cell + $pad * 2;
		$rects = '';
		for ($r = 0; $r < $n; $r++) {
			for ($c = 0; $c < $n; $c++) {
				if ($qr->isDark($r, $c)) {
					$x     = $pad + $c * $cell;
					$y     = $pad + $r * $cell;
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
}
