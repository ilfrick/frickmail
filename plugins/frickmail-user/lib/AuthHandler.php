<?php
namespace Frickmail\User;

/**
 * AuthHandler — register, login, me, TOTP, password reset.
 *
 * Pure PHP class; does not extend AbstractPlugin.
 * Receives params as plain values from index.php and returns plain arrays.
 */
class AuthHandler
{
	const SESSION_KEY_USER         = 'frickmail_user_id';
	const SESSION_KEY_KEY          = 'frickmail_crypt_key';
	const SESSION_KEY_TOTP_PENDING = 'frickmail_totp_pending_secret';

	public function __construct(private Db $db) {}

	/* ------------------------------------------------------------------ */
	/*  Session helpers                                                      */
	/* ------------------------------------------------------------------ */

	/** Start the PHP session (delegates to Bridge for the single implementation). */
	public function startSession() : void
	{
		Bridge::startSession();
	}

	/**
	 * Assert that a Frickmail session is active.
	 * @return array{int, string}  [uid, cryptKey]
	 * @throws \RuntimeException when not authenticated
	 */
	public function requireSession() : array
	{
		$this->startSession();
		$uid    = $_SESSION[self::SESSION_KEY_USER] ?? null;
		$keyB64 = $_SESSION[self::SESSION_KEY_KEY]  ?? null;
		if (!$uid || !$keyB64) throw new \RuntimeException('Not authenticated');
		return [(int) $uid, \base64_decode($keyB64, true)];
	}

	/* ------------------------------------------------------------------ */
	/*  Register                                                             */
	/* ------------------------------------------------------------------ */

	public function register(bool $signupOpen, string $username, ?string $email, string $password) : array
	{
		$bFirstUser = (0 === $this->db->userCount());
		if (!$signupOpen && !$bFirstUser) {
			throw new \RuntimeException('Self-signup is disabled. Ask your admin or set FRICKMAIL_OPEN_SIGNUP=true.');
		}
		if (\strlen($username) < 3) throw new \RuntimeException('Username must be at least 3 chars');
		if (\strlen($password) < 8) throw new \RuntimeException('Password must be at least 8 chars');
		if ($this->db->findUserByUsername($username)) throw new \RuntimeException('Username already taken');

		$sHash = Crypto::hashPassword($password);
		$sSalt = Crypto::generateSalt();
		$this->db->createUser($username, $email ?: null, $sHash, $sSalt);

		return ['ok' => true, 'message' => 'Account created. Sign in to add your mail accounts.'];
	}

	/* ------------------------------------------------------------------ */
	/*  Login                                                                */
	/* ------------------------------------------------------------------ */

	/**
	 * Verify credentials and establish the Frickmail session.
	 *
	 * Returns an array with key 'status':
	 *   'totp_required'  — caller must re-submit with totp_code
	 *   'totp_replay'    — code already used in this window
	 *   'no_primary'     — login OK but no primary account; nothing to bridge
	 *   'reauth_required'— primary account has no usable credential
	 *   'bridge_needed'  — caller must call MailAccountHandler::bridge($result['account'])
	 *
	 * @throws \RuntimeException on bad credentials
	 */
	public function login(string $username, string $password, string $totpCode) : array
	{
		$user = $this->db->findUserByUsername($username);
		// Always run Argon2id to prevent timing-based username enumeration (M1).
		$hashToVerify = $user ? $user['password_hash'] : Crypto::DUMMY_HASH;
		if (!$user || !Crypto::verifyPassword($password, $hashToVerify)) {
			throw new \RuntimeException('Invalid username or password');
		}

		// Frickmail-user 2FA: if a TOTP secret is set on this user, require a valid code.
		if (!empty($user['totp_secret'])) {
			if ('' === $totpCode) {
				return ['status' => 'totp_required', 'ok' => false, 'requires_totp' => true, 'error' => 'Two-factor code required'];
			}
			if (!\SnappyMail\TOTP::Verify($user['totp_secret'], $totpCode)) {
				return ['status' => 'totp_required', 'ok' => false, 'requires_totp' => true, 'error' => 'Invalid two-factor code'];
			}
			// Replay protection (H6): reject a code that was already used in this 30-second window.
			$iWindow = (int) \floor(\time() / 30);
			if (!$this->db->recordTotpUse((int) $user['id'], $totpCode, $iWindow)) {
				return ['status' => 'totp_replay', 'ok' => false, 'requires_totp' => true, 'error' => 'Two-factor code already used'];
			}
		}

		$kdfSalt  = \is_resource($user['kdf_salt']) ? \stream_get_contents($user['kdf_salt']) : $user['kdf_salt'];
		$cryptKey = Crypto::deriveKey($password, $kdfSalt);

		$this->startSession();
		\session_regenerate_id(true); // prevent session fixation (M2)
		$_SESSION[self::SESSION_KEY_USER] = (int) $user['id'];
		$_SESSION[self::SESSION_KEY_KEY]  = \base64_encode($cryptKey);

		// Bridge to IMAP login if a primary mail account exists.
		$primary = $this->db->getPrimaryMailAccount((int) $user['id']);
		if (!$primary) {
			return [
				'status'     => 'no_primary',
				'ok'         => true,
				'no_primary' => true,
				'message'    => 'Logged in. Add a mail account from the settings panel.',
			];
		}

		$account  = $this->db->decryptedAccount($primary, $cryptKey);
		$bMissing = ('imap' === $account['type'] && empty($account['password']))
			|| (\in_array($account['type'], ['gmail', 'o365'], true) && empty($account['oauth_refresh_token']));
		if ($bMissing) {
			return [
				'status'               => 'reauth_required',
				'ok'                   => true,
				'no_primary'           => true,
				'reauth_required'      => true,
				'reauth_account_id'    => (int)    $account['id'],
				'reauth_account_email' => (string) $account['email'],
				'reauth_account_type'  => (string) $account['type'],
				'message'              => 'Re-enter the password for ' . $account['email'] . ' (lost after the password reset).',
			];
		}

		// Tell index.php to call bridge — pass the account data along.
		return ['status' => 'bridge_needed', 'account' => $account];
	}

	/* ------------------------------------------------------------------ */
	/*  Me                                                                   */
	/* ------------------------------------------------------------------ */

	public function me() : array
	{
		$this->startSession();
		$uid = $_SESSION[self::SESSION_KEY_USER] ?? null;
		if (!$uid) return ['ok' => true, 'authenticated' => false];
		$user = $this->db->findUserById((int) $uid);
		if (!$user) return ['ok' => true, 'authenticated' => false];
		return [
			'ok'            => true,
			'authenticated' => true,
			'username'      => $user['username'],
			'email'         => $user['email'],
		];
	}

	/* ------------------------------------------------------------------ */
	/*  TOTP                                                                 */
	/* ------------------------------------------------------------------ */

	public function getTotpStatus(int $uid) : array
	{
		$user = $this->db->findUserById($uid);
		return ['ok' => true, 'enabled' => !empty($user['totp_secret'])];
	}

	public function enableTotp(int $uid) : array
	{
		$user = $this->db->findUserById($uid);
		if (!empty($user['totp_secret'])) {
			throw new \RuntimeException('Two-factor authentication is already enabled. Disable it first.');
		}
		$sSecret = \SnappyMail\TOTP::CreateSecret();
		$this->startSession();
		$_SESSION[self::SESSION_KEY_TOTP_PENDING] = $sSecret;

		$sIssuer = 'Frickmail';
		$sLabel  = $user['username'];
		$sUri    = \sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s',
			\rawurlencode($sIssuer),
			\rawurlencode($sLabel),
			$sSecret,
			\rawurlencode($sIssuer)
		);
		return [
			'ok'          => true,
			'secret'      => $sSecret,
			'otpauth_uri' => $sUri,
			'message'     => 'Scan the QR code (or paste the secret) into your authenticator app, then submit a code to confirm.',
			// qr_data_url is generated in index.php (needs the plugin's generateQrDataUrl helper)
			'_uri_for_qr' => $sUri,
		];
	}

	public function confirmTotp(int $uid, string $code) : array
	{
		if ('' === $code) throw new \RuntimeException('Code required');
		$this->startSession();
		$sPending = $_SESSION[self::SESSION_KEY_TOTP_PENDING] ?? null;
		if (!$sPending) throw new \RuntimeException('No pending TOTP setup. Call EnableTotp first.');
		if (!\SnappyMail\TOTP::Verify($sPending, $code)) {
			return ['ok' => false, 'error' => 'Invalid code'];
		}
		$this->db->setUserTotpSecret($uid, $sPending);
		unset($_SESSION[self::SESSION_KEY_TOTP_PENDING]);
		return ['ok' => true, 'message' => 'Two-factor authentication enabled.'];
	}

	public function disableTotp(int $uid, string $code) : array
	{
		$user = $this->db->findUserById($uid);
		if (empty($user['totp_secret'])) {
			return ['ok' => true, 'message' => 'Two-factor was not enabled.'];
		}
		if ('' === $code || !\SnappyMail\TOTP::Verify($user['totp_secret'], $code)) {
			return ['ok' => false, 'error' => 'A valid TOTP code is required to disable two-factor authentication.'];
		}
		$this->db->setUserTotpSecret($uid, null);
		return ['ok' => true, 'message' => 'Two-factor authentication disabled.'];
	}

	/* ------------------------------------------------------------------ */
	/*  Password reset                                                       */
	/* ------------------------------------------------------------------ */

	public function requestPasswordReset(string $username, string $resetLink) : void
	{
		// Caller always returns OK regardless; this method either sends or silently skips.
		$user = '' !== $username ? $this->db->findUserByUsername($username) : null;
		if ($user && !empty($user['email']) && \filter_var($user['email'], \FILTER_VALIDATE_EMAIL)) {
			$sToken     = \rtrim(\strtr(\base64_encode(\random_bytes(32)), '+/', '-_'), '=');
			$sTokenHash = \hash('sha256', $sToken);
			$this->db->createPasswordResetToken((int) $user['id'], $sTokenHash, 1800); // 30 min
			$sLink = $this->buildResetUrl($sToken, $resetLink);
			$sBody = "Hello " . $user['username'] . ",\n\n"
				. "You requested a Frickmail password reset. Open this link within 30 minutes:\n\n"
				. $sLink . "\n\n"
				. "If you did not request this, ignore this email.\n\n"
				. "NOTE: after the reset, IMAP passwords and OAuth refresh tokens stored in your "
				. "Frickmail account will need to be re-entered from Settings → Mail Accounts "
				. "(they are encrypted with a key derived from your password and cannot be recovered).\n\n"
				. "— Frickmail";
			try {
				Mailer::send((string) $user['email'], 'Frickmail — password reset', $sBody);
			} catch (\Throwable $e) {
				\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
				// Deliberately not surfaced to the client.
			}
		}
	}

	private function buildResetUrl(string $sToken, string $baseUrl) : string
	{
		return \rtrim($baseUrl, '/') . '/?reset_token=' . \urlencode($sToken);
	}

	public function resetPassword(string $token, string $password) : array
	{
		if ('' === $token)              throw new \RuntimeException('Token required');
		if (\strlen($password) < 8)    throw new \RuntimeException('Password must be at least 8 chars');
		$sTokenHash = \hash('sha256', $token);
		$row = $this->db->findActivePasswordReset($sTokenHash);
		if (!$row) throw new \RuntimeException('Invalid or expired token');
		$newHash = Crypto::hashPassword($password);
		$newSalt = Crypto::generateSalt();
		$this->db->applyPasswordReset((int) $row['user_id'], $newHash, $newSalt);
		$this->db->consumePasswordReset((int) $row['id']);
		return [
			'ok'       => true,
			'username' => $row['username'],
			'message'  => 'Password reset. Sign in with your new password. Linked mail-account credentials must be re-entered.',
		];
	}
}
