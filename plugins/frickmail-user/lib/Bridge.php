<?php
namespace Frickmail\User;

/**
 * Helpers used by external plugins (login-gmail, login-o365) to:
 *   - detect whether the current request is inside a Frickmail-user session
 *   - persist OAuth-account records into frickmail_mail_accounts
 *   - retrieve a user's mail account for the bridge to LoginProcess()
 *
 * Callers should `require_once APP_PLUGINS_PATH . 'frickmail-user/lib/Bridge.php';`
 * which transitively pulls Crypto + Db.
 */

require_once __DIR__ . '/Crypto.php';
require_once __DIR__ . '/Db.php';

class Bridge
{
	const SESSION_KEY_USER = 'frickmail_user_id';
	const SESSION_KEY_KEY  = 'frickmail_crypt_key';

	public static function startSession() : void
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

	public static function currentUserId() : ?int
	{
		self::startSession();
		$uid = $_SESSION[self::SESSION_KEY_USER] ?? null;
		return $uid ? (int) $uid : null;
	}

	public static function currentCryptKey() : ?string
	{
		self::startSession();
		$b64 = $_SESSION[self::SESSION_KEY_KEY] ?? null;
		return $b64 ? \base64_decode($b64, true) : null;
	}

	/** Insert or update an OAuth account for the current Frickmail user. */
	public static function upsertOAuthAccount(string $sType, string $sEmail, string $sRefreshToken, ?string $sTenant = null) : int
	{
		$uid = self::currentUserId();
		$key = self::currentCryptKey();
		if (!$uid || !$key) {
			throw new \RuntimeException('No Frickmail session');
		}
		$db = new Db();
		$existing = self::findByEmail($db, $uid, $sEmail);
		$cipher = Crypto::encrypt($sRefreshToken, $key);
		if ($existing) {
			$st = $db->pdo()->prepare(
				'UPDATE frickmail_mail_accounts SET
					type = :type, encrypted_oauth_refresh_token = :tok,
					oauth_tenant = :tenant, login = :login, updated_at = NOW()
				 WHERE id = :id AND user_id = :uid'
			);
			$st->bindValue(':id', (int) $existing['id'], \PDO::PARAM_INT);
			$st->bindValue(':uid', $uid, \PDO::PARAM_INT);
			$st->bindValue(':type', $sType);
			$st->bindValue(':tok', $cipher, \PDO::PARAM_LOB);
			$st->bindValue(':tenant', $sTenant);
			$st->bindValue(':login', $sEmail);
			$st->execute();
			return (int) $existing['id'];
		}
		$id = $db->insertMailAccount($uid, [
			'label' => $sEmail,
			'email' => $sEmail,
			'type' => $sType,
			'login' => $sEmail,
			'encrypted_oauth_refresh_token' => $cipher,
			'oauth_tenant' => $sTenant,
			'is_primary' => 0 === \count($db->listMailAccounts($uid)),
		]);
		// If this is the first account, mark it primary.
		if ($id && 0 === \count($db->listMailAccounts($uid)) - 1) {
			$db->setPrimaryMailAccount($uid, $id);
		}
		return $id;
	}

	private static function findByEmail(Db $db, int $userId, string $email) : ?array
	{
		$st = $db->pdo()->prepare('SELECT * FROM frickmail_mail_accounts WHERE user_id = :u AND lower(email) = lower(:e) LIMIT 1');
		$st->execute([':u' => $userId, ':e' => $email]);
		$row = $st->fetch();
		return $row ?: null;
	}
}
