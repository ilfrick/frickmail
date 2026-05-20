<?php
namespace Frickmail\User;

/**
 * S/MIME certificate management: import, store, list, delete, sign, verify.
 *
 * Certificates are stored in frickmail_smime_certs.
 * Private keys (from PKCS#12 bundles) are encrypted at rest using the
 * same Argon2id-derived AEAD key used for mail-account credentials.
 *
 * Signing and verification rely on the PHP openssl extension
 * (openssl_pkcs7_sign / openssl_pkcs7_verify), which require real
 * filesystem paths — we use temporary files and always clean them up.
 */
class SmimeHandler
{
    public function __construct(private Db $db) {}

    /* ------------------------------------------------------------------
     *  Public API
     * ------------------------------------------------------------------ */

    /**
     * Import a PKCS#12 (.p12 / .pfx) bundle that contains a certificate
     * AND its matching private key.
     *
     * @param int    $uid        Frickmail user id
     * @param int    $accountId  Mail account id (for FK)
     * @param string $p12Data    Raw binary PKCS#12 data
     * @param string $p12Password Passphrase protecting the .p12 file
     * @param string $cryptKey   32-byte AEAD key from the user's session
     * @return array {ok, id, email, fingerprint, not_after}
     */
    public function importP12(int $uid, int $accountId, string $p12Data, string $p12Password, string $cryptKey): array
    {
        $this->requireOpenssl();

        $certs = [];
        if (!openssl_pkcs12_read($p12Data, $certs, $p12Password)) {
            throw new \RuntimeException('Failed to read PKCS#12 file — wrong password or corrupt file');
        }

        $certPem  = $certs['cert'] ?? null;
        $keyPem   = $certs['pkey'] ?? null;

        if (!$certPem) {
            throw new \RuntimeException('No certificate found in the PKCS#12 bundle');
        }

        $info = $this->parseCertInfo($certPem);

        // Encrypt private key at rest before persisting
        $encryptedKey = null;
        if ($keyPem) {
            $encryptedKey = Crypto::encrypt($keyPem, $cryptKey);
        }

        $id = $this->db->addSmimeCert(
            $uid,
            $accountId,
            $info['email'],
            $certPem,
            $encryptedKey,
            $info['fingerprint'],
            $info['subject'],
            $info['not_before'],
            $info['not_after']
        );

        return [
            'ok'          => true,
            'id'          => $id,
            'email'       => $info['email'],
            'fingerprint' => $info['fingerprint'],
            'not_after'   => $info['not_after'],
        ];
    }

    /**
     * Import a PEM certificate (no private key) — used to store the public
     * certificate of a recipient so we can encrypt messages to them later.
     *
     * @param int    $uid       Frickmail user id
     * @param int    $accountId Mail account id (for FK)
     * @param string $pemData   PEM-encoded certificate text
     * @return array {ok, id, email, fingerprint, not_after}
     */
    public function importCert(int $uid, int $accountId, string $pemData): array
    {
        $this->requireOpenssl();

        // Validate that this is actually a certificate
        $res = openssl_x509_read($pemData);
        if (false === $res) {
            throw new \RuntimeException('Invalid PEM certificate');
        }

        $info = $this->parseCertInfo($pemData);

        $id = $this->db->addSmimeCert(
            $uid,
            $accountId,
            $info['email'],
            $pemData,
            null,       // no private key
            $info['fingerprint'],
            $info['subject'],
            $info['not_before'],
            $info['not_after']
        );

        return [
            'ok'          => true,
            'id'          => $id,
            'email'       => $info['email'],
            'fingerprint' => $info['fingerprint'],
            'not_after'   => $info['not_after'],
        ];
    }

    /**
     * List all S/MIME certificates for a user.
     *
     * @return array {ok, certs: [...]}  — each cert omits the raw PEM blobs
     */
    public function listCerts(int $uid): array
    {
        $rows = $this->db->listSmimeCerts($uid);
        $certs = array_map(function (array $row): array {
            return [
                'id'          => (int)  $row['id'],
                'account_id'  => (int)  $row['account_id'],
                'email'       => (string) $row['email'],
                'fingerprint' => (string) $row['fingerprint'],
                'subject'     => (string) ($row['subject'] ?? ''),
                'not_before'  => $row['not_before'] ?? null,
                'not_after'   => $row['not_after']  ?? null,
                'has_key'     => !empty($row['encrypted_key_pem']),
                'created_at'  => $row['created_at'] ?? null,
            ];
        }, $rows);
        return ['ok' => true, 'certs' => $certs];
    }

    /**
     * Delete a certificate (and its private key blob) by cert id.
     *
     * @return array {ok}
     */
    public function deleteCert(int $uid, int $certId): array
    {
        $ok = $this->db->deleteSmimeCert($uid, $certId);
        if (!$ok) {
            throw new \RuntimeException('Certificate not found or already deleted');
        }
        return ['ok' => true];
    }

    /**
     * Sign a message body with the user's S/MIME certificate for the given
     * email address.  Returns the signed S/MIME message (PKCS#7 detached).
     *
     * @param int    $uid         Frickmail user id
     * @param string $cryptKey    32-byte AEAD key from the session
     * @param string $email       Email whose cert/key to use for signing
     * @param string $messageBody Plain-text or MIME message body to sign
     * @return string Signed S/MIME message text
     */
    public function signMessage(int $uid, string $cryptKey, string $email, string $messageBody): string
    {
        $this->requireOpenssl();

        $row = $this->db->getSmimeCertByEmail($uid, $email);
        if (!$row) {
            throw new \RuntimeException('No S/MIME certificate found for ' . $email);
        }

        $encryptedKey = $row['encrypted_key_pem'];
        if (is_resource($encryptedKey)) {
            $encryptedKey = stream_get_contents($encryptedKey);
        }
        if (empty($encryptedKey)) {
            throw new \RuntimeException('No private key stored for ' . $email . ' — cannot sign');
        }

        $keyPem = Crypto::decrypt($encryptedKey, $cryptKey);
        if (null === $keyPem) {
            throw new \RuntimeException('Failed to decrypt private key — session key mismatch');
        }

        $certPem = $row['cert_pem'];

        // openssl_pkcs7_sign works with file paths only — use temporary files
        $inFile   = $this->tempFile();
        $outFile  = $this->tempFile();
        try {
            file_put_contents($inFile, $messageBody);
            $ok = openssl_pkcs7_sign(
                $inFile,
                $outFile,
                $certPem,
                $keyPem,
                [],         // extra headers (empty)
                PKCS7_DETACHED
            );
            if (!$ok) {
                throw new \RuntimeException('openssl_pkcs7_sign failed: ' . $this->opensslError());
            }
            $signed = file_get_contents($outFile);
            if (false === $signed) {
                throw new \RuntimeException('Could not read signed message from temp file');
            }
            return $signed;
        } finally {
            $this->unlinkSilent($inFile);
            $this->unlinkSilent($outFile);
        }
    }

    /**
     * Verify a signed S/MIME message.
     *
     * @param string $signedMessage  Raw signed S/MIME message text
     * @return array {ok, verified, signer_email, error?}
     */
    public function verifyMessage(string $signedMessage): array
    {
        $this->requireOpenssl();

        $inFile     = $this->tempFile();
        $signerFile = $this->tempFile();
        $outFile    = $this->tempFile();
        try {
            file_put_contents($inFile, $signedMessage);
            $result = openssl_pkcs7_verify(
                $inFile,
                0,          // flags: 0 = verify and extract signer cert
                $signerFile,
                [],         // CA cert paths (use system trust store)
                null,       // extra certs
                $outFile    // extracted content
            );

            if (false === $result) {
                return [
                    'ok'           => true,
                    'verified'     => false,
                    'signer_email' => null,
                    'error'        => 'Signature verification failed: ' . $this->opensslError(),
                ];
            }

            if (-1 === $result) {
                return [
                    'ok'           => true,
                    'verified'     => false,
                    'signer_email' => null,
                    'error'        => 'Could not parse the signed message',
                ];
            }

            // $result === true — signature is valid; extract signer email from cert
            $signerEmail = null;
            $signerPem   = @file_get_contents($signerFile);
            if ($signerPem) {
                $parsed = openssl_x509_parse($signerPem);
                $signerEmail = $this->emailFromParsed($parsed);
            }

            return [
                'ok'           => true,
                'verified'     => true,
                'signer_email' => $signerEmail,
            ];
        } finally {
            $this->unlinkSilent($inFile);
            $this->unlinkSilent($signerFile);
            $this->unlinkSilent($outFile);
        }
    }

    /* ------------------------------------------------------------------
     *  Private helpers
     * ------------------------------------------------------------------ */

    private function requireOpenssl(): void
    {
        if (!function_exists('openssl_pkcs12_read')) {
            throw new \RuntimeException('openssl extension required but not available');
        }
    }

    /**
     * Parse a PEM certificate and extract the fields we store.
     *
     * @return array {email, fingerprint, subject, not_before, not_after}
     */
    private function parseCertInfo(string $certPem): array
    {
        $parsed = openssl_x509_parse($certPem);
        if (false === $parsed) {
            throw new \RuntimeException('Could not parse certificate: ' . $this->opensslError());
        }

        $email = $this->emailFromParsed($parsed);
        if (!$email) {
            throw new \RuntimeException('Certificate does not contain an email address (subjectAltName or CN)');
        }

        // SHA-1 fingerprint (hex, colon-separated) — standard display format
        $fingerprint = openssl_x509_fingerprint($certPem, 'sha1');
        if (false === $fingerprint) {
            $fingerprint = '';
        }
        // Format as AA:BB:CC:…
        $fingerprint = strtoupper(implode(':', str_split($fingerprint, 2)));

        $subject = '';
        if (!empty($parsed['subject'])) {
            $parts = [];
            foreach ($parsed['subject'] as $k => $v) {
                $parts[] = $k . '=' . (is_array($v) ? implode(',', $v) : $v);
            }
            $subject = implode(', ', $parts);
        }

        $notBefore = isset($parsed['validFrom_time_t'])
            ? date('c', (int) $parsed['validFrom_time_t'])
            : null;
        $notAfter  = isset($parsed['validTo_time_t'])
            ? date('c', (int) $parsed['validTo_time_t'])
            : null;

        return [
            'email'       => $email,
            'fingerprint' => $fingerprint,
            'subject'     => $subject,
            'not_before'  => $notBefore,
            'not_after'   => $notAfter,
        ];
    }

    /**
     * Extract the first email address from a parsed openssl_x509_parse result.
     * Checks subjectAltName first, then falls back to CN.
     */
    private function emailFromParsed(mixed $parsed): ?string
    {
        if (!is_array($parsed)) {
            return null;
        }

        // subjectAltName → 'email:foo@bar.com, ...'
        $san = $parsed['extensions']['subjectAltName'] ?? '';
        if ($san) {
            foreach (explode(',', $san) as $part) {
                $part = trim($part);
                if (str_starts_with(strtolower($part), 'email:')) {
                    $candidate = trim(substr($part, 6));
                    if (filter_var($candidate, FILTER_VALIDATE_EMAIL)) {
                        return $candidate;
                    }
                }
                if (str_starts_with(strtolower($part), 'rfc822name:')) {
                    $candidate = trim(substr($part, 11));
                    if (filter_var($candidate, FILTER_VALIDATE_EMAIL)) {
                        return $candidate;
                    }
                }
            }
        }

        // Fallback: CN that looks like an email
        $cn = $parsed['subject']['CN'] ?? null;
        if ($cn && filter_var($cn, FILTER_VALIDATE_EMAIL)) {
            return $cn;
        }

        // emailAddress field in subject
        $ea = $parsed['subject']['emailAddress'] ?? null;
        if ($ea && filter_var($ea, FILTER_VALIDATE_EMAIL)) {
            return $ea;
        }

        return null;
    }

    /** Create a temporary file and return its path. */
    private function tempFile(): string
    {
        $path = tempnam(sys_get_temp_dir(), 'fm_smime_');
        if (false === $path) {
            throw new \RuntimeException('Could not create temporary file');
        }
        return $path;
    }

    /** Remove a file, ignoring errors. */
    private function unlinkSilent(string $path): void
    {
        if (file_exists($path)) {
            @unlink($path);
        }
    }

    /** Return the last openssl error string (or empty string). */
    private function opensslError(): string
    {
        $msgs = [];
        while ($msg = openssl_error_string()) {
            $msgs[] = $msg;
        }
        return implode('; ', $msgs);
    }
}
