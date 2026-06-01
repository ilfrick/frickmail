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
		$pass = \getenv('FRICKMAIL_DB_PASSWORD');
		if ('' === $pass || false === $pass) {
			throw new \RuntimeException('FRICKMAIL_DB_PASSWORD environment variable is not set');
		}
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


	public function getUserSettings(int $userId) : array
	{
		$st = $this->pdo->prepare('SELECT settings FROM frickmail_users WHERE id = :i');
		$st->execute([':i' => $userId]);
		$row = $st->fetch();
		if (!$row) return [];
		$decoded = \json_decode((string) $row['settings'], true);
		return \is_array($decoded) ? $decoded : [];
	}

	/**
	 * Merge $patch into the JSONB settings blob for a user (shallow merge via ||).
	 * Keys present in $patch overwrite existing values; other keys are preserved.
	 */
	public function updateUserSettings(int $userId, array $patch) : void
	{
		$st = $this->pdo->prepare(
			"UPDATE frickmail_users
			    SET settings = settings || :patch::jsonb, updated_at = NOW()
			  WHERE id = :i"
		);
		$st->execute([':patch' => \json_encode($patch), ':i' => $userId]);
	}

	/* ---------- Mail accounts ---------- */
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

	public function updateMailAccount(int $userId, int $accountId, array $data) : void
	{
		if (empty($data)) return;
		$allowed = ['label','login','imap_host','imap_port','imap_secure',
		            'smtp_host','smtp_port','smtp_secure','encrypted_password'];
		$sets = [];
		$bind = [':u' => $userId, ':i' => $accountId];
		foreach ($allowed as $col) {
			if (!\array_key_exists($col, $data)) continue;
			if ('encrypted_password' === $col) {
				$sets[] = "encrypted_password = CASE WHEN :enc_pwd_h = '' THEN encrypted_password ELSE decode(:enc_pwd, 'hex') END";
				$hex = \bin2hex($data[$col]);
				$bind[':enc_pwd']  = $hex;
				$bind[':enc_pwd_h'] = $hex;
			} else {
				$sets[] = "$col = :$col";
				$bind[":$col"] = $data[$col];
			}
		}
		if (empty($sets)) return;
		$sql = 'UPDATE frickmail_mail_accounts SET ' . \implode(', ', $sets)
			 . ' WHERE user_id = :u AND id = :i';
		$this->pdo->prepare($sql)->execute($bind);
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

	public function setMailAccountPassword(int $userId, int $accountId, string $encryptedBlob) : bool
	{
		$st = $this->pdo->prepare(
			"UPDATE frickmail_mail_accounts
			    SET encrypted_password = decode(:p, 'hex'), updated_at = NOW()
			  WHERE user_id = :u AND id = :i"
		);
		return $st->execute([':p' => \bin2hex($encryptedBlob), ':u' => $userId, ':i' => $accountId]);
	}

	public function setUserTotpSecret(int $userId, ?string $secret) : void
	{
		$st = $this->pdo->prepare('UPDATE frickmail_users SET totp_secret = :s, updated_at = NOW() WHERE id = :i');
		$st->execute([':s' => $secret, ':i' => $userId]);
	}

	/* ---------- Password reset tokens ---------- */

	public function createPasswordResetToken(int $userId, string $tokenHash, int $ttlSeconds = 1800) : int
	{
		// Invalidate any existing unused tokens for this user before creating a new one (C3).
		$this->pdo->prepare(
			'DELETE FROM frickmail_password_resets WHERE user_id = :u AND used_at IS NULL'
		)->execute([':u' => $userId]);

		// Use a literal interval to avoid parameter-interpolation into SQL expressions (L2).
		$intervalSql = 'NOW() + INTERVAL \'' . \abs($ttlSeconds) . ' seconds\'';
		$st = $this->pdo->prepare(
			"INSERT INTO frickmail_password_resets (user_id, token_hash, expires_at)
			 VALUES (:u, :t, {$intervalSql}) RETURNING id"
		);
		$st->execute([':u' => $userId, ':t' => $tokenHash]);
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

	/**
	 * TOTP replay protection (H6): atomically insert (user_id, code, window) into a
	 * short-lived used-codes table. Returns true if the code had not been used before,
	 * false if this is a replay. Old rows (> 2 windows = 60s) are pruned on each call.
	 *
	 * The frickmail_totp_used table is created by the migration in entrypoint.sh.
	 */
	public function recordTotpUse(int $userId, string $code, int $window) : bool
	{
		// Prune codes older than 2 windows (~60s) to keep the table small.
		$this->pdo->prepare(
			'DELETE FROM frickmail_totp_used WHERE "window" < :w'
		)->execute([':w' => $window - 2]);

		// INSERT ... ON CONFLICT DO NOTHING; rowCount() = 0 means already used.
		$st = $this->pdo->prepare(
			'INSERT INTO frickmail_totp_used (user_id, code, "window") VALUES (:u, :c, :w)
			 ON CONFLICT DO NOTHING'
		);
		$st->execute([':u' => $userId, ':c' => $code, ':w' => $window]);
		return $st->rowCount() === 1;
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

	/* ---------- Convenience writers (P3) ---------- */

	/**
	 * Persist an encrypted OAuth refresh token for an existing mail account.
	 * Updates the account type at the same time so the stored type always
	 * matches the OAuth provider (gmail / o365).
	 */
	public function saveOAuthRefreshToken(int $userId, int $accountId, string $type, string $encryptedCipher) : void
	{
		$this->pdo->prepare(
			"UPDATE frickmail_mail_accounts
			    SET type = :type,
			        encrypted_oauth_refresh_token = decode(:tok, 'hex'),
			        updated_at = NOW()
			  WHERE id = :id AND user_id = :uid"
		)->execute([
			':type' => $type,
			':tok'  => \bin2hex($encryptedCipher),
			':id'   => $accountId,
			':uid'  => $userId,
		]);
	}

	/* ---------- Full-text search index ---------- */

	/**
	 * Upsert a message into the search index.
	 * snippet = first ~200 chars of plain-text body (optional, pass null to omit).
	 */
	public function indexMessage(
		int $userId, int $accountId, string $folder, int $imapUid,
		?string $messageId, ?string $subject, ?string $fromAddr, ?string $fromName,
		?string $dateTsIso, ?string $snippet
	): void {
		// tsvector is computed in SQL — avoids shell quoting issues in the migration script.
		$st = $this->pdo->prepare(
			"INSERT INTO frickmail_message_index
				(user_id, account_id, folder, imap_uid, message_id, subject,
				 from_addr, from_name, date_ts, snippet, tsv, indexed_at)
			 VALUES
				(:uid, :aid, :folder, :imap_uid, :message_id, :subject,
				 :from_addr, :from_name, :date_ts, :snippet,
				 to_tsvector('simple',
				     coalesce(:tsv_subject,'')  || ' ' ||
				     coalesce(:tsv_from_name,'')|| ' ' ||
				     coalesce(:tsv_from_addr,'')|| ' ' ||
				     coalesce(:tsv_snippet,'')),
				 NOW())
			 ON CONFLICT (account_id, folder, imap_uid)
			 DO UPDATE SET
				message_id = EXCLUDED.message_id,
				subject    = EXCLUDED.subject,
				from_addr  = EXCLUDED.from_addr,
				from_name  = EXCLUDED.from_name,
				date_ts    = EXCLUDED.date_ts,
				snippet    = EXCLUDED.snippet,
				tsv        = EXCLUDED.tsv,
				indexed_at = NOW()"
		);
		$st->execute([
			':uid'           => $userId,
			':aid'           => $accountId,
			':folder'        => $folder,
			':imap_uid'      => $imapUid,
			':message_id'    => $messageId,
			':subject'       => $subject,
			':from_addr'     => $fromAddr,
			':from_name'     => $fromName,
			':date_ts'       => $dateTsIso,
			':snippet'       => $snippet,
			':tsv_subject'   => $subject,
			':tsv_from_name' => $fromName,
			':tsv_from_addr' => $fromAddr,
			':tsv_snippet'   => $snippet,
		]);
	}

	/**
	 * Full-text search across all accounts for a user.
	 * Returns rows with: id, account_id, folder, imap_uid, subject, from_addr,
	 * from_name, date_ts, snippet, account_email (joined from mail_accounts).
	 */
	public function searchMessages(int $userId, string $query, int $limit = 50): array
	{
		$st = $this->pdo->prepare(
			'SELECT mi.id, mi.account_id, mi.folder, mi.imap_uid, mi.message_id,
			        mi.subject, mi.from_addr, mi.from_name, mi.date_ts, mi.snippet,
			        ma.email AS account_email
			   FROM frickmail_message_index mi
			   JOIN frickmail_mail_accounts ma ON ma.id = mi.account_id
			  WHERE mi.user_id = :uid
			    AND mi.tsv @@ plainto_tsquery(\'simple\', :q)
			  ORDER BY mi.date_ts DESC NULLS LAST
			  LIMIT :lim'
		);
		$st->bindValue(':uid', $userId, \PDO::PARAM_INT);
		$st->bindValue(':q', $query);
		$st->bindValue(':lim', $limit, \PDO::PARAM_INT);
		$st->execute();
		return $st->fetchAll();
	}

	/**
	 * Delete all indexed messages for an account (call on account delete).
	 */
	public function deleteMessageIndex(int $accountId): void
	{
		$this->pdo->prepare(
			'DELETE FROM frickmail_message_index WHERE account_id = :aid'
		)->execute([':aid' => $accountId]);
	}

	/* ---------- Sender identities ---------- */

	public function listIdentities(int $userId, int $accountId) : array
	{
		$st = $this->pdo->prepare(
			'SELECT * FROM frickmail_identities WHERE user_id = :u AND account_id = :a ORDER BY is_default DESC, id ASC'
		);
		$st->execute([':u' => $userId, ':a' => $accountId]);
		return $st->fetchAll();
	}

	public function addIdentity(int $userId, int $accountId, string $name, string $email, ?string $replyTo, bool $isDefault) : int
	{
		$st = $this->pdo->prepare(
			'INSERT INTO frickmail_identities (account_id, user_id, name, email, reply_to, is_default)
			 VALUES (:a, :u, :n, :e, :r, :d) RETURNING id'
		);
		$st->execute([
			':a' => $accountId,
			':u' => $userId,
			':n' => $name,
			':e' => $email,
			':r' => $replyTo,
			':d' => $isDefault ? 'true' : 'false',
		]);
		return (int) $st->fetchColumn();
	}

	public function deleteIdentity(int $userId, int $identityId) : bool
	{
		$st = $this->pdo->prepare('DELETE FROM frickmail_identities WHERE user_id = :u AND id = :i');
		return $st->execute([':u' => $userId, ':i' => $identityId]);
	}

	public function setDefaultIdentity(int $userId, int $identityId) : void
	{
		// First resolve the account_id for this identity (and verify ownership).
		$st = $this->pdo->prepare(
			'SELECT account_id FROM frickmail_identities WHERE id = :i AND user_id = :u'
		);
		$st->execute([':i' => $identityId, ':u' => $userId]);
		$row = $st->fetch();
		if (!$row) throw new \RuntimeException('Identity not found');
		$accountId = (int) $row['account_id'];

		$this->pdo->beginTransaction();
		try {
			$st = $this->pdo->prepare(
				'UPDATE frickmail_identities SET is_default = FALSE WHERE account_id = :a AND user_id = :u'
			);
			$st->execute([':a' => $accountId, ':u' => $userId]);
			$st = $this->pdo->prepare(
				'UPDATE frickmail_identities SET is_default = TRUE WHERE id = :i AND user_id = :u'
			);
			$st->execute([':i' => $identityId, ':u' => $userId]);
			$this->pdo->commit();
		} catch (\Throwable $e) {
			$this->pdo->rollBack();
			throw $e;
		}
	}

	/**
	 * Persist a single key→url entry in the JSONB settings column of a mail account.
	 * Used for CardDAV / CalDAV URLs discovered via service discovery.
	 */
	public function saveAccountServiceUrl(int $userId, int $accountId, string $key, string $url) : void
	{
		$this->pdo->prepare(
			"UPDATE frickmail_mail_accounts
			 SET settings = settings || :patch::jsonb, updated_at = NOW()
			 WHERE user_id = :u AND id = :i"
		)->execute([
			':patch' => \json_encode([$key => $url]),
			':u'     => $userId,
			':i'     => $accountId,
		]);
	}
	/* ---------- Tasks ---------- */

	public function listTasks(int $userId, ?bool $completed = null, int $limit = 200): array
	{
		if ($completed === null) {
			$st = $this->pdo->prepare(
				'SELECT * FROM frickmail_tasks WHERE user_id = :u
				 ORDER BY completed ASC, due_date ASC NULLS LAST, created_at ASC
				 LIMIT :lim'
			);
			$st->bindValue(':u', $userId, \PDO::PARAM_INT);
			$st->bindValue(':lim', $limit, \PDO::PARAM_INT);
		} else {
			$st = $this->pdo->prepare(
				'SELECT * FROM frickmail_tasks WHERE user_id = :u AND completed = :c
				 ORDER BY due_date ASC NULLS LAST, created_at ASC
				 LIMIT :lim'
			);
			$st->bindValue(':u', $userId, \PDO::PARAM_INT);
			$st->bindValue(':c', $completed, \PDO::PARAM_BOOL);
			$st->bindValue(':lim', $limit, \PDO::PARAM_INT);
		}
		$st->execute();
		return $st->fetchAll();
	}

	public function addTask(int $userId, string $title, ?string $notes, ?string $dueDate): int
	{
		$st = $this->pdo->prepare(
			'INSERT INTO frickmail_tasks (user_id, title, notes, due_date)
			 VALUES (:u, :t, :n, :d) RETURNING id'
		);
		$st->execute([
			':u' => $userId,
			':t' => $title,
			':n' => $notes,
			':d' => $dueDate,
		]);
		return (int) $st->fetchColumn();
	}

	public function completeTask(int $userId, int $taskId, bool $completed): bool
	{
		$st = $this->pdo->prepare(
			'UPDATE frickmail_tasks
			    SET completed = :c,
			        completed_at = CASE WHEN :c2 THEN NOW() ELSE NULL END,
			        updated_at = NOW()
			  WHERE user_id = :u AND id = :i'
		);
		$st->bindValue(':c',  $completed, \PDO::PARAM_BOOL);
		$st->bindValue(':c2', $completed, \PDO::PARAM_BOOL);
		$st->bindValue(':u',  $userId,    \PDO::PARAM_INT);
		$st->bindValue(':i',  $taskId,    \PDO::PARAM_INT);
		$st->execute();
		return $st->rowCount() > 0;
	}

	public function deleteTask(int $userId, int $taskId): bool
	{
		$st = $this->pdo->prepare('DELETE FROM frickmail_tasks WHERE user_id = :u AND id = :i');
		$st->execute([':u' => $userId, ':i' => $taskId]);
		return $st->rowCount() > 0;
	}

	public function updateTask(int $userId, int $taskId, string $title, ?string $notes, ?string $dueDate): bool
	{
		$st = $this->pdo->prepare(
			'UPDATE frickmail_tasks
			    SET title = :t, notes = :n, due_date = :d, updated_at = NOW()
			  WHERE user_id = :u AND id = :i'
		);
		$st->execute([':t' => $title, ':n' => $notes, ':d' => $dueDate, ':u' => $userId, ':i' => $taskId]);
		return $st->rowCount() > 0;
	}

	/* ---------- Message rules ---------- */

	public function listRules(int $userId, int $accountId) : array
	{
		$st = $this->pdo->prepare(
			'SELECT * FROM frickmail_rules WHERE user_id = :u AND account_id = :a ORDER BY id ASC'
		);
		$st->execute([':u' => $userId, ':a' => $accountId]);
		return $st->fetchAll();
	}

	public function addRule(int $userId, int $accountId, string $name, array $conditions, string $conditionsLogic, array $actions) : int
	{
		$st = $this->pdo->prepare(
			'INSERT INTO frickmail_rules (user_id, account_id, name, conditions, actions)
			 VALUES (:u, :a, :n, :c, :act) RETURNING id'
		);
		$conditionsPayload = \json_encode([
			'conditions'        => $conditions,
			'conditions_logic'  => $conditionsLogic,
		]);
		$st->execute([
			':u'   => $userId,
			':a'   => $accountId,
			':n'   => $name,
			':c'   => $conditionsPayload,
			':act' => \json_encode($actions),
		]);
		return (int) $st->fetchColumn();
	}

	public function deleteRule(int $userId, int $ruleId) : bool
	{
		$st = $this->pdo->prepare('DELETE FROM frickmail_rules WHERE user_id = :u AND id = :i');
		return $st->execute([':u' => $userId, ':i' => $ruleId]);
	}

	public function toggleRule(int $userId, int $ruleId, bool $enabled) : bool
	{
		$st = $this->pdo->prepare(
			'UPDATE frickmail_rules SET enabled = :e WHERE user_id = :u AND id = :i'
		);
		return $st->execute([':e' => $enabled ? 'true' : 'false', ':u' => $userId, ':i' => $ruleId]);
	}

	public function updateRuleLastRun(int $ruleId) : void
	{
		$st = $this->pdo->prepare('UPDATE frickmail_rules SET last_run = NOW() WHERE id = :i');
		$st->execute([':i' => $ruleId]);
	}
	public function listSmimeCerts(int $userId) : array
	{
		$st = $this->pdo->prepare(
			'SELECT id, user_id, account_id, email, cert_pem, encrypted_key_pem,
			        fingerprint, subject, not_before, not_after, created_at
			   FROM frickmail_smime_certs
			  WHERE user_id = :u
			  ORDER BY created_at DESC'
		);
		$st->execute([':u' => $userId]);
		return $st->fetchAll();
	}

	/**
	 * Insert a new S/MIME certificate row.
	 *
	 * $encryptedKeyBlob — binary cipher blob (nonce || ciphertext) produced by
	 * Crypto::encrypt(), or null if this is a public-only certificate.
	 *
	 * @return int The new row id.
	 */
	public function addSmimeCert(
		int $userId,
		int $accountId,
		string $email,
		string $certPem,
		?string $encryptedKeyBlob,
		string $fingerprint,
		?string $subject,
		?string $notBefore,
		?string $notAfter
	) : int {
		$st = $this->pdo->prepare(
			"INSERT INTO frickmail_smime_certs
				(user_id, account_id, email, cert_pem, encrypted_key_pem,
				 fingerprint, subject, not_before, not_after)
			 VALUES
				(:user_id, :account_id, :email, :cert_pem,
				 CASE WHEN :enc_key_h = '' THEN NULL ELSE decode(:enc_key, 'hex') END,
				 :fingerprint, :subject, :not_before, :not_after)
			 RETURNING id"
		);
		$st->bindValue(':user_id',    $userId,    \PDO::PARAM_INT);
		$st->bindValue(':account_id', $accountId, \PDO::PARAM_INT);
		$st->bindValue(':email',      $email);
		$st->bindValue(':cert_pem',   $certPem);
		$st->bindValue(':enc_key',    null !== $encryptedKeyBlob ? \bin2hex($encryptedKeyBlob) : '');
		$st->bindValue(':enc_key_h',  null !== $encryptedKeyBlob ? \bin2hex($encryptedKeyBlob) : '');
		$st->bindValue(':fingerprint', $fingerprint);
		$st->bindValue(':subject',    $subject);
		$st->bindValue(':not_before', $notBefore);
		$st->bindValue(':not_after',  $notAfter);
		$st->execute();
		return (int) $st->fetchColumn();
	}

	/**
	 * Retrieve the most-recent certificate row for $email belonging to $userId.
	 * Returns null if not found.
	 */
	public function getSmimeCertByEmail(int $userId, string $email) : ?array
	{
		$st = $this->pdo->prepare(
			'SELECT * FROM frickmail_smime_certs
			  WHERE user_id = :u AND email = :e
			  ORDER BY created_at DESC
			  LIMIT 1'
		);
		$st->execute([':u' => $userId, ':e' => $email]);
		$row = $st->fetch();
		return $row ?: null;
	}

	/**
	 * Delete a certificate by id, enforcing user ownership.
	 * Returns true if a row was deleted, false otherwise.
	 */
	public function deleteSmimeCert(int $userId, int $certId) : bool
	{
		$st = $this->pdo->prepare(
			'DELETE FROM frickmail_smime_certs WHERE user_id = :u AND id = :i'
		);
		$st->execute([':u' => $userId, ':i' => $certId]);
		return $st->rowCount() > 0;
	}

	/* ------------------------------------------------------------------ */
	/*  Web Push subscriptions                                              */
	/* ------------------------------------------------------------------ */

	public function upsertPushSubscription(int $userId, string $endpoint, string $p256dh, string $authKey) : void
	{
		$this->pdo->prepare(
			'INSERT INTO frickmail_push_subscriptions (user_id, endpoint, p256dh, auth_key)
			 VALUES (:u, :ep, :p, :a)
			 ON CONFLICT (user_id, endpoint) DO UPDATE SET p256dh = :p, auth_key = :a'
		)->execute([':u' => $userId, ':ep' => $endpoint, ':p' => $p256dh, ':a' => $authKey]);
	}

	public function deletePushSubscription(int $userId, string $endpoint) : void
	{
		$this->pdo->prepare(
			'DELETE FROM frickmail_push_subscriptions WHERE user_id = :u AND endpoint = :ep'
		)->execute([':u' => $userId, ':ep' => $endpoint]);
	}

	/** Return all push subscriptions for a user as [{endpoint, p256dh, auth_key}] */
	public function listPushSubscriptions(int $userId) : array
	{
		$st = $this->pdo->prepare(
			'SELECT endpoint, p256dh, auth_key FROM frickmail_push_subscriptions WHERE user_id = :u'
		);
		$st->execute([':u' => $userId]);
		return $st->fetchAll(\PDO::FETCH_ASSOC);
	}

	public function getAppSetting(string $key) : ?string
	{
		$st = $this->pdo->prepare(
			'SELECT setting_value FROM frickmail_app_settings WHERE setting_key = :k'
		);
		$st->execute([':k' => $key]);
		$value = $st->fetchColumn();
		return false === $value ? null : (string) $value;
	}

	/* ------------------------------------------------------------------ */
	/*  OIDC identities + escrow key                                        */
	/* ------------------------------------------------------------------ */

	/** Find a linked OIDC identity by (provider_hash, subject). */
	public function findOidcIdentity(string $providerHash, string $subject) : ?array
	{
		$st = $this->pdo->prepare(
			'SELECT * FROM frickmail_oidc_identities WHERE provider_hash = :ph AND subject = :s LIMIT 1'
		);
		$st->execute([':ph' => $providerHash, ':s' => $subject]);
		$row = $st->fetch();
		return $row ?: null;
	}

	/** Insert or update the OIDC identity for a user (one sub per provider per user). */
	public function upsertOidcIdentity(int $userId, string $providerHash, string $subject) : void
	{
		$this->pdo->prepare(
			'INSERT INTO frickmail_oidc_identities (user_id, provider_hash, subject)
			 VALUES (:u, :ph, :s)
			 ON CONFLICT (provider_hash, subject) DO UPDATE SET user_id = :u2, linked_at = NOW()'
		)->execute([':u' => $userId, ':ph' => $providerHash, ':s' => $subject, ':u2' => $userId]);
	}

	/** List all OIDC identities linked to a user. */
	public function listOidcIdentities(int $userId) : array
	{
		$st = $this->pdo->prepare(
			'SELECT * FROM frickmail_oidc_identities WHERE user_id = :u ORDER BY linked_at DESC'
		);
		$st->execute([':u' => $userId]);
		return $st->fetchAll();
	}

	/** Remove a specific OIDC identity (by provider hash) for a user. */
	public function deleteOidcIdentity(int $userId, string $providerHash) : void
	{
		$this->pdo->prepare(
			'DELETE FROM frickmail_oidc_identities WHERE user_id = :u AND provider_hash = :ph'
		)->execute([':u' => $userId, ':ph' => $providerHash]);
	}

	/**
	 * Store the escrow key blob for a user.
	 * Pass null to clear the escrow key (e.g. after all OIDC identities are removed).
	 */
	public function setOidcEscrowKey(int $userId, ?string $blob) : void
	{
		if (null === $blob) {
			$this->pdo->prepare(
				'UPDATE frickmail_users SET oidc_escrow_key = NULL, updated_at = NOW() WHERE id = :i'
			)->execute([':i' => $userId]);
		} else {
			$this->pdo->prepare(
				"UPDATE frickmail_users SET oidc_escrow_key = decode(:b, 'hex'), updated_at = NOW() WHERE id = :i"
			)->execute([':b' => \bin2hex($blob), ':i' => $userId]);
		}
	}

	/** Return the raw escrow key blob for a user, or null if not set. */
	public function getOidcEscrowKey(int $userId) : ?string
	{
		$st = $this->pdo->prepare('SELECT oidc_escrow_key FROM frickmail_users WHERE id = :i');
		$st->execute([':i' => $userId]);
		$row = $st->fetch();
		if (!$row || null === $row['oidc_escrow_key']) return null;
		$raw = $row['oidc_escrow_key'];
		return \is_resource($raw) ? \stream_get_contents($raw) : $raw;
	}
}
