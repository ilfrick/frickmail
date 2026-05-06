<?php
namespace Frickmail\User;

class Db
{
	private \PDO $pdo;

	public function __construct()
	{
		$host = \getenv('FRICKMAIL_DB_HOST') ?: 'db';
		$port = \getenv('FRICKMAIL_DB_PORT') ?: '5432';
		$name = \getenv('FRICKMAIL_DB_NAME') ?: 'frickmail';
		$user = \getenv('FRICKMAIL_DB_USER') ?: 'frickmail';
		$pass = \getenv('FRICKMAIL_DB_PASSWORD') ?: 'frickmail';
		$dsn = \sprintf('pgsql:host=%s;port=%s;dbname=%s', $host, $port, $name);
		$this->pdo = new \PDO($dsn, $user, $pass, [
			\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
			\PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
			\PDO::ATTR_TIMEOUT => 5
		]);
	}

	public function pdo() : \PDO { return $this->pdo; }

	/* ---------- Users ---------- */

	public function findUserByUsername(string $username) : ?array
	{
		$st = $this->pdo->prepare('SELECT * FROM frickmail_users WHERE username = :u');
		$st->execute([':u' => \strtolower($username)]);
		$row = $st->fetch();
		return $row ?: null;
	}

	public function findUserById(int $id) : ?array
	{
		$st = $this->pdo->prepare('SELECT * FROM frickmail_users WHERE id = :i');
		$st->execute([':i' => $id]);
		$row = $st->fetch();
		return $row ?: null;
	}

	public function createUser(string $username, ?string $email, string $passwordHash, string $kdfSalt) : int
	{
		// Bind binary bytes as hex string + Postgres decode() because PDO/pgsql
		// treats string params as UTF-8 and rejects raw sodium-salt bytes.
		$st = $this->pdo->prepare(
			"INSERT INTO frickmail_users (username, email, password_hash, kdf_salt)
			 VALUES (:u, :e, :h, decode(:s, 'hex')) RETURNING id"
		);
		$st->execute([
			':u' => \strtolower($username),
			':e' => $email,
			':h' => $passwordHash,
			':s' => \bin2hex($kdfSalt),
		]);
		return (int) $st->fetchColumn();
	}

	public function userCount() : int
	{
		return (int) $this->pdo->query('SELECT COUNT(*) FROM frickmail_users')->fetchColumn();
	}

	public function deleteUser(int $userId) : bool
	{
		$st = $this->pdo->prepare('DELETE FROM frickmail_users WHERE id = :i');
		return $st->execute([':i' => $userId]);
	}

	/* ---------- Mail accounts ---------- */

	public function listMailAccounts(int $userId) : array
	{
		$st = $this->pdo->prepare('SELECT * FROM frickmail_mail_accounts WHERE user_id = :u ORDER BY is_primary DESC, id ASC');
		$st->execute([':u' => $userId]);
		return $st->fetchAll();
	}

	public function getPrimaryMailAccount(int $userId) : ?array
	{
		$st = $this->pdo->prepare('SELECT * FROM frickmail_mail_accounts WHERE user_id = :u AND is_primary LIMIT 1');
		$st->execute([':u' => $userId]);
		$row = $st->fetch();
		if ($row) return $row;
		// fallback: the oldest account
		$st = $this->pdo->prepare('SELECT * FROM frickmail_mail_accounts WHERE user_id = :u ORDER BY id ASC LIMIT 1');
		$st->execute([':u' => $userId]);
		$row = $st->fetch();
		return $row ?: null;
	}

	public function getMailAccount(int $userId, int $accountId) : ?array
	{
		$st = $this->pdo->prepare('SELECT * FROM frickmail_mail_accounts WHERE user_id = :u AND id = :i');
		$st->execute([':u' => $userId, ':i' => $accountId]);
		$row = $st->fetch();
		return $row ?: null;
	}

	public function insertMailAccount(int $userId, array $data) : int
	{
		$encPwd = $data['encrypted_password'] ?? null;
		$encTok = $data['encrypted_oauth_refresh_token'] ?? null;
		$st = $this->pdo->prepare(
			"INSERT INTO frickmail_mail_accounts
				(user_id, label, email, type, imap_host, imap_port, imap_secure,
				 smtp_host, smtp_port, smtp_secure, login,
				 encrypted_password, encrypted_oauth_refresh_token, oauth_tenant, is_primary)
			 VALUES
				(:user_id, :label, :email, :type, :imap_host, :imap_port, :imap_secure,
				 :smtp_host, :smtp_port, :smtp_secure, :login,
				 CASE WHEN :enc_pwd_h = '' THEN NULL ELSE decode(:enc_pwd, 'hex') END,
				 CASE WHEN :enc_tok_h = '' THEN NULL ELSE decode(:enc_tok, 'hex') END,
				 :oauth_tenant, :is_primary)
			 RETURNING id"
		);
		$st->bindValue(':user_id', $userId, \PDO::PARAM_INT);
		$st->bindValue(':label', $data['label']);
		$st->bindValue(':email', $data['email']);
		$st->bindValue(':type', $data['type']);
		$st->bindValue(':imap_host', $data['imap_host'] ?? null);
		$st->bindValue(':imap_port', $data['imap_port'] ?? null, \PDO::PARAM_INT);
		$st->bindValue(':imap_secure', $data['imap_secure'] ?? null);
		$st->bindValue(':smtp_host', $data['smtp_host'] ?? null);
		$st->bindValue(':smtp_port', $data['smtp_port'] ?? null, \PDO::PARAM_INT);
		$st->bindValue(':smtp_secure', $data['smtp_secure'] ?? null);
		$st->bindValue(':login', $data['login'] ?? null);
		$st->bindValue(':enc_pwd', null !== $encPwd ? \bin2hex($encPwd) : '');
		$st->bindValue(':enc_pwd_h', null !== $encPwd ? \bin2hex($encPwd) : '');
		$st->bindValue(':enc_tok', null !== $encTok ? \bin2hex($encTok) : '');
		$st->bindValue(':enc_tok_h', null !== $encTok ? \bin2hex($encTok) : '');
		$st->bindValue(':oauth_tenant', $data['oauth_tenant'] ?? null);
		$st->bindValue(':is_primary', !empty($data['is_primary']), \PDO::PARAM_BOOL);
		$st->execute();
		return (int) $st->fetchColumn();
	}

	public function deleteMailAccount(int $userId, int $accountId) : bool
	{
		$st = $this->pdo->prepare('DELETE FROM frickmail_mail_accounts WHERE user_id = :u AND id = :i');
		return $st->execute([':u' => $userId, ':i' => $accountId]);
	}

	public function setPrimaryMailAccount(int $userId, int $accountId) : void
	{
		$this->pdo->beginTransaction();
		try {
			$st = $this->pdo->prepare('UPDATE frickmail_mail_accounts SET is_primary = FALSE WHERE user_id = :u');
			$st->execute([':u' => $userId]);
			$st = $this->pdo->prepare('UPDATE frickmail_mail_accounts SET is_primary = TRUE WHERE user_id = :u AND id = :i');
			$st->execute([':u' => $userId, ':i' => $accountId]);
			$this->pdo->commit();
		} catch (\Throwable $e) {
			$this->pdo->rollBack();
			throw $e;
		}
	}

	/* ---------- Password reset tokens ---------- */

	public function createPasswordResetToken(int $userId, string $tokenHash, int $ttlSeconds = 1800) : int
	{
		$st = $this->pdo->prepare(
			"INSERT INTO frickmail_password_resets (user_id, token_hash, expires_at)
			 VALUES (:u, :t, NOW() + (:s || ' seconds')::interval) RETURNING id"
		);
		$st->execute([':u' => $userId, ':t' => $tokenHash, ':s' => (string) $ttlSeconds]);
		return (int) $st->fetchColumn();
	}

	public function findActivePasswordReset(string $tokenHash) : ?array
	{
		$st = $this->pdo->prepare(
			'SELECT r.*, u.id AS uid, u.username
			   FROM frickmail_password_resets r
			   JOIN frickmail_users u ON u.id = r.user_id
			  WHERE r.token_hash = :t
			    AND r.used_at IS NULL
			    AND r.expires_at > NOW()
			  LIMIT 1'
		);
		$st->execute([':t' => $tokenHash]);
		$row = $st->fetch();
		return $row ?: null;
	}

	public function consumePasswordReset(int $resetId) : void
	{
		$st = $this->pdo->prepare('UPDATE frickmail_password_resets SET used_at = NOW() WHERE id = :i');
		$st->execute([':i' => $resetId]);
	}

	public function applyPasswordReset(int $userId, string $passwordHash, string $kdfSalt) : void
	{
		$this->pdo->beginTransaction();
		try {
			$st = $this->pdo->prepare(
				"UPDATE frickmail_users
				    SET password_hash = :h, kdf_salt = decode(:s, 'hex'), updated_at = NOW()
				  WHERE id = :i"
			);
			$st->execute([':h' => $passwordHash, ':s' => \bin2hex($kdfSalt), ':i' => $userId]);
			$st = $this->pdo->prepare(
				'UPDATE frickmail_mail_accounts
				    SET encrypted_password = NULL,
				        encrypted_oauth_refresh_token = NULL,
				        updated_at = NOW()
				  WHERE user_id = :u'
			);
			$st->execute([':u' => $userId]);
			$this->pdo->commit();
		} catch (\Throwable $e) {
			$this->pdo->rollBack();
			throw $e;
		}
	}

	public function decryptedAccount(array $row, string $cryptKey) : array
	{
		$copy = $row;
		$copy['password'] = !empty($row['encrypted_password'])
			? Crypto::decrypt(\is_resource($row['encrypted_password']) ? \stream_get_contents($row['encrypted_password']) : $row['encrypted_password'], $cryptKey)
			: null;
		$copy['oauth_refresh_token'] = !empty($row['encrypted_oauth_refresh_token'])
			? Crypto::decrypt(\is_resource($row['encrypted_oauth_refresh_token']) ? \stream_get_contents($row['encrypted_oauth_refresh_token']) : $row['encrypted_oauth_refresh_token'], $cryptKey)
			: null;
		// strip raw blobs from the returned representation
		unset($copy['encrypted_password'], $copy['encrypted_oauth_refresh_token']);
		return $copy;
	}
}
