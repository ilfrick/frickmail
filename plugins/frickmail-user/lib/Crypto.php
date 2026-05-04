<?php
namespace Frickmail\User;

/**
 * Argon2id for the user-password hash (verified at login).
 * libsodium AEAD (xchacha20-poly1305) for at-rest encryption of mail-account
 * credentials. The AEAD key is derived from the user's plain password via
 * Argon2id KDF — kept ONLY in PHP session for the lifetime of the login.
 *
 * Implication: if the user forgets their Frickmail password, the encrypted
 * mail-account credentials are unrecoverable.
 */
class Crypto
{
	const KDF_OPSLIMIT = 3;       // SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE
	const KDF_MEMLIMIT = 67108864; // SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE (64 MB)

	public static function hashPassword(string $password) : string
	{
		return \password_hash($password, \PASSWORD_ARGON2ID);
	}

	public static function verifyPassword(string $password, string $hash) : bool
	{
		return \password_verify($password, $hash);
	}

	public static function generateSalt() : string
	{
		return \random_bytes(\SODIUM_CRYPTO_PWHASH_SALTBYTES);
	}

	/** Derive a 32-byte AEAD key from the user's password + per-user salt. */
	public static function deriveKey(string $password, string $salt) : string
	{
		return \sodium_crypto_pwhash(
			\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
			$password,
			$salt,
			self::KDF_OPSLIMIT,
			self::KDF_MEMLIMIT,
			\SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
		);
	}

	/** Encrypt $plaintext with $key. Returns binary blob (nonce || ciphertext). */
	public static function encrypt(string $plaintext, string $key) : string
	{
		$nonce = \random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		$cipher = \sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
			$plaintext, '', $nonce, $key
		);
		return $nonce . $cipher;
	}

	public static function decrypt(string $blob, string $key) : ?string
	{
		$nlen = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
		if (\strlen($blob) < $nlen) {
			return null;
		}
		$nonce = \substr($blob, 0, $nlen);
		$cipher = \substr($blob, $nlen);
		$plain = \sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
			$cipher, '', $nonce, $key
		);
		return false === $plain ? null : $plain;
	}
}
