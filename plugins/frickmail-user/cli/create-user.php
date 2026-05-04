<?php
/**
 * Frickmail CLI: create a user when self-signup is closed.
 *
 * Usage:
 *   docker exec frickmail php /snappymail/plugins-bundled/frickmail-user/cli/create-user.php \
 *       --username=alice --email=alice@example.com --password='s3cret123'
 */

require_once __DIR__ . '/../lib/Crypto.php';
require_once __DIR__ . '/../lib/Db.php';

$opts = \getopt('', ['username:', 'email::', 'password:']);
if (empty($opts['username']) || empty($opts['password'])) {
	\fwrite(\STDERR, "Usage: php create-user.php --username=NAME --email=EMAIL --password=PASS\n");
	exit(2);
}

try {
	$db = new \Frickmail\User\Db();
	if ($db->findUserByUsername($opts['username'])) {
		\fwrite(\STDERR, "[ERR] Username already exists\n");
		exit(1);
	}
	$hash = \Frickmail\User\Crypto::hashPassword($opts['password']);
	$salt = \Frickmail\User\Crypto::generateSalt();
	$id   = $db->createUser($opts['username'], $opts['email'] ?? null, $hash, $salt);
	\fprintf(\STDOUT, "[OK] Created user '%s' (id=%d)\n", $opts['username'], $id);
} catch (\Throwable $e) {
	\fwrite(\STDERR, "[ERR] " . $e->getMessage() . "\n");
	exit(1);
}
