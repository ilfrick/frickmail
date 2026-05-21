<?php
namespace Frickmail\User;

/**
 * VAPID Web Push helper — pure PHP, no external libraries.
 *
 * Implements:
 *   - P-256 EC key pair generation (applicationServerKey)
 *   - JWT signing for VAPID Authorization header (ES256 = ECDSA + SHA-256)
 *   - Sending an empty (wake-up) push notification to a PushSubscription endpoint
 *
 * Payload encryption (RFC 8291 / Web Push Encryption) is intentionally omitted:
 * we send an empty-body push that wakes the Service Worker, which then fetches
 * the actual notification data via FrickmailCheckNewMail.  This avoids a
 * dependency on any Composer package while still giving true push behaviour
 * when the browser is backgrounded (tab closed, SW still running).
 */
class VapidPush
{
	/**
	 * Generate a new VAPID key pair for the P-256 (prime256v1) curve.
	 *
	 * @return array{private_pem: string, public_b64u: string}
	 *   private_pem  — PEM-encoded EC private key (store in plugin config, never expose).
	 *   public_b64u  — base64url-encoded uncompressed public key (65 bytes: 0x04||X||Y).
	 *                  This is the `applicationServerKey` passed to pushManager.subscribe().
	 */
	public static function generateKeys(): array
	{
		$key = \openssl_pkey_new([
			'curve_name'       => 'prime256v1',
			'private_key_type' => \OPENSSL_KEYTYPE_EC,
		]);
		if (!$key) {
			throw new \RuntimeException('EC key generation failed: '.\openssl_error_string());
		}

		\openssl_pkey_export($key, $privatePem);
		$d = \openssl_pkey_get_details($key);

		// Uncompressed public key: 0x04 || X(32 bytes) || Y(32 bytes)
		$x      = \str_pad($d['ec']['x'] ?? '', 32, "\0", \STR_PAD_LEFT);
		$y      = \str_pad($d['ec']['y'] ?? '', 32, "\0", \STR_PAD_LEFT);
		$pubRaw = "\x04" . $x . $y;

		return [
			'private_pem' => $privatePem,
			'public_b64u' => self::b64u($pubRaw),
		];
	}

	/**
	 * Build the VAPID Authorization header value for a push POST request.
	 *
	 * @param string $endpoint   Push subscription endpoint URL.
	 * @param string $subject    "mailto:admin@example.com" or "https://example.com".
	 * @param string $privatePem PEM private key (from generateKeys).
	 * @param string $publicB64u base64url public key (from generateKeys).
	 */
	public static function makeAuthHeader(
		string $endpoint,
		string $subject,
		string $privatePem,
		string $publicB64u
	): string {
		$audience = \parse_url($endpoint, \PHP_URL_SCHEME) . '://'
		          . \parse_url($endpoint, \PHP_URL_HOST);

		$jwtHeader  = self::b64u(\json_encode(['typ' => 'JWT', 'alg' => 'ES256']));
		$jwtPayload = self::b64u(\json_encode([
			'aud' => $audience,
			'exp' => \time() + 43200,   // 12-hour token
			'sub' => $subject,
		]));
		$sigInput = $jwtHeader . '.' . $jwtPayload;

		\openssl_sign($sigInput, $derSig, $privatePem, \OPENSSL_ALGO_SHA256);
		$rawSig = self::derToRaw($derSig);

		return 'vapid t=' . $sigInput . '.' . self::b64u($rawSig) . ',k=' . $publicB64u;
	}

	/**
	 * Send an empty (wake-up) Web Push notification.
	 * The SW `push` event fires with no data; the SW then shows a generic
	 * "new mail" notification and calls FrickmailCheckNewMail for details.
	 *
	 * @param array  $sub        PushSubscription with keys 'endpoint', 'p256dh', 'auth'.
	 * @param string $privatePem PEM private key.
	 * @param string $publicB64u base64url public key.
	 * @param string $subject    VAPID contact URI (mailto: or https:).
	 * @param array  $payload    Optional JSON-serialisable notification payload.
	 */
	public static function send(
		array  $sub,
		string $privatePem,
		string $publicB64u,
		string $subject,
		array  $payload = []
	): bool {
		$endpoint = $sub['endpoint'] ?? '';
		if ('' === $endpoint) return false;

		$authHeader = self::makeAuthHeader($endpoint, $subject, $privatePem, $publicB64u);

		$body    = empty($payload) ? '' : \json_encode($payload);
		$headers = [
			'Authorization: ' . $authHeader,
			'TTL: 86400',
		];
		if ('' !== $body) {
			$headers[] = 'Content-Type: application/json';
			$headers[] = 'Content-Length: ' . \strlen($body);
		} else {
			$headers[] = 'Content-Length: 0';
		}

		$ctx  = \stream_context_create([
			'http' => [
				'method'        => 'POST',
				'header'        => \implode("\r\n", $headers),
				'content'       => $body,
				'ignore_errors' => true,
				'timeout'       => 10,
			],
			'ssl' => ['verify_peer' => true],
		]);

		@\file_get_contents($endpoint, false, $ctx);
		$status = (int) \explode(' ', $http_response_header[0] ?? 'HTTP/1.1 0 ')[1];
		return $status >= 200 && $status < 300;
	}

	// ── Private helpers ───────────────────────────────────────────────────────

	private static function b64u(string $data): string
	{
		return \rtrim(\strtr(\base64_encode($data), '+/', '-_'), '=');
	}

	/**
	 * Convert DER-encoded ECDSA signature → raw R||S (64 bytes for P-256).
	 * DER: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
	 */
	private static function derToRaw(string $der): string
	{
		$offset = 2;
		// Long-form length (rare for P-256, but handle it)
		if (\ord($der[1]) > 0x7f) $offset++;

		$offset++;                          // skip 0x02 tag for R
		$rLen   = \ord($der[$offset++]);
		$r      = \substr($der, $offset, $rLen);
		$offset += $rLen;

		$offset++;                          // skip 0x02 tag for S
		$sLen   = \ord($der[$offset++]);
		$s      = \substr($der, $offset, $sLen);

		// Strip DER-mandated leading 0x00 padding, then pad to 32 bytes
		$r = \str_pad(\ltrim($r, "\0"), 32, "\0", \STR_PAD_LEFT);
		$s = \str_pad(\ltrim($s, "\0"), 32, "\0", \STR_PAD_LEFT);

		return $r . $s;
	}
}
