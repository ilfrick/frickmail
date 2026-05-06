<?php
/**
 * Frickmail CLI: reset a user's password.
 *
 * Usage:
 *   docker exec frickmail php /snappymail/plugins-bundled/frickmail-user/cli/reset-password.php \
 *       --username=alice --password='new-password-here'
 *
 * The new password derives a fresh AEAD key, so any IMAP / OAuth credentials
 * encrypted under the previous key become unreadable. The script clears
 * encrypted_password / encrypted_oauth_refresh_token on the user's mail
 * accounts (rows are kept, only the secrets are NULLed) and reports how many
 * accounts need to be re-authenticated.
 */

require_once __DIR__ . '/../lib/Crypto.php';
require_once __DIR__ . '/../lib/Db.php';

$opts = \getopt('', ['username:', 'password:']);
if (empty($opts['username']) || empty($opts['password'])) {
	\fwrite(\STDERR, "Usage: php reset-password.php --username=NAME --password=NEWPASS\n");
	exit(2);
}
if (\strlen((string) $opts['password']) < 8) {
	\fwrite(\STDERR, "[ERR] password must be at least 8 characters\n");
	exit(1);
}

try {
	$db = new \Frickmail\User\Db();
	$user = $db->findUserByUsername($opts['username']);
	if (!$user) {
		\fwrite(\STDERR, "[ERR] No user with username '{$opts['username']}'\n");
		exit(1);
	}
	$newHash = \Frickmail\User\Crypto::hashPassword($opts['password']);
	$newSalt = \Frickmail\User\Crypto::generateSalt();
	$pdo = $db->pdo();
	$pdo->beginTransaction();
	try {
		$st = $pdo->prepare(
			"UPDATE frickmail_users
			 SET password_hash = :h, kdf_salt = decode(:s, 'hex'), updated_at = NOW()
			 WHERE id = :id"
		);
		$st->execute([
			':h' => $newHash,
			':s' => \bin2hex($newSalt),
			':id' => $user['id'],
		]);
		$st = $pdo->prepare(
			'UPDATE frickmail_mail_accounts
			 SET encrypted_password = NULL,
			     encrypted_oauth_refresh_token = NULL,
			     updated_at = NOW()
			 WHERE user_id = :uid AND (encrypted_password IS NOT NULL OR encrypted_oauth_refresh_token IS NOT NULL)'
		);
		$st->execute([':uid' => $user['id']]);
		$cleared = $st->rowCount();
		$pdo->commit();
	} catch (\Throwable $e) {
		$pdo->rollBack();
		throw $e;
	}
	\fprintf(\STDOUT, "[OK] Password reset for '%s' (id=%d)\n", $opts['username'], (int) $user['id']);
	if ($cleared > 0) {
		\fprintf(\STDOUT, "[WARN] %d mail account(s) had encrypted credentials cleared.\n", $cleared);
		\fprintf(\STDOUT, "       After signing in, open Settings -> Mail Accounts and re-enter\n");
		\fprintf(\STDOUT, "       the IMAP password / re-link the OAuth account.\n");
	}
} catch (\Throwable $e) {
	\fwrite(\STDERR, "[ERR] " . $e->getMessage() . "\n");
	exit(1);
}
