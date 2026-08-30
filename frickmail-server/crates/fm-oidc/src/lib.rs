//! Native OpenID Connect (OIDC) login and identity linking for Frickmail.
//!
//! NOTE: `XNonce::from_slice` is used throughout to match the `chacha20poly1305`
//! crate's idiomatic nonce creation pattern; the `generic-array` deprecation is
//! suppressed at the crate level.

#![allow(deprecated)]
//!
//! This crate implements the OIDC authorization-code flow with PKCE, mirroring
//! the PHP `login-oidc` plugin's behavior so that escrow keys and OIDC state
//! remain cross-compatible between the legacy PHP runtime and the Rust server.
//!
//! Key compatibility points:
//!
//! **State encryption** (`encrypt_state` / `decrypt_state`): matches
//! `SnappyMail\Crypt::EncryptUrlSafe` / `DecryptUrlSafe` using XChaCha20-Poly1305
//! IETF. The passphrase is `sha1(salt . salt, true)` — repeated to fill 32 bytes
//! (matching PHP's `str_pad`), the AAD is the raw `salt` string, and the format
//! is `base64url("sodium") . '.' . base64url(nonce) . '.' . base64url(ciphertext)`.
//!
//! **Escrow key encryption** (`encrypt_escrow_key` / `decrypt_escrow_key`):
//! matches the login-oidc plugin's `escrowEncrypt` / `escrowDecrypt`. The key
//! is `sha256(salt, true)` (32 bytes), AAD is empty, and the format is raw
//! `nonce || ciphertext` (nonce = 24 bytes).

use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use fm_core::{FrickmailConfig, FrickmailError, Result};
use base64::Engine;
use rand_core::{RngCore, OsRng};
use sha1::{Digest, Sha1};
use sha2::Sha256;

/// PKCE code challenge method: S256 (SHA-256 of the verifier).
const PKCE_CHALLENGE_METHOD: &str = "S256";

/// Scopes requested during OIDC authorization.
const OIDC_SCOPES: &str = "openid email profile";

/// XChaCha20-Poly1305 IETF nonce length (24 bytes).
const XCHACHA_NONCE_LEN: usize = 24;

/// XChaCha20-Poly1305 IETF key length (32 bytes).
const XCHACHA_KEY_LEN: usize = 32;

/// SHA-1 produces 20 bytes; the PHP `Passphrase` is padded to 32 bytes.
const SHA1_LEN: usize = 20;

// ── Public types ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Represents a decrypted OIDC state parameter.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct OidcState {
    /// Protocol marker — always `"oidc"`.
    pub p: String,
    /// PKCE code verifier.
    pub v: String,
    /// Login mode: `"login"` or `"link"`.
    pub m: String,
    /// UNIX timestamp when the state was created.
    pub t: u64,
    /// The OIDC discovery URL (issuer) that was used to generate the state.
    /// This is needed during the callback to re-fetch the discovery document.
    pub i: Option<String>,
}

/// Information returned by the OIDC provider after callback processing.
#[derive(Debug, Clone)]
pub struct OidcUserInfo {
    pub subject: String,
    pub email: String,
}

/// Result of an OIDC callback — either a successful login with user info and
/// credential key, or an error message.
#[derive(Debug, Clone)]
pub struct OidcCallbackResult {
    pub ok: bool,
    pub mode: String,
    pub email: Option<String>,
    pub error: Option<String>,
    pub reauth_required: bool,
    pub provider_hash: Option<String>,
    pub subject: Option<String>,
}

/// Payload rendered into the callback HTML page.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct OidcCallbackPayload {
    pub ok: bool,
    pub mode: String,
    pub email: Option<String>,
    pub error: Option<String>,
    pub reauth_required: bool,
}

impl From<OidcCallbackResult> for OidcCallbackPayload {
    fn from(result: OidcCallbackResult) -> Self {
        OidcCallbackPayload {
            ok: result.ok,
            mode: result.mode,
            email: result.email,
            error: result.error,
            reauth_required: result.reauth_required,
        }
    }
}

/// The authorization URL to which the browser should be redirected, along with
/// the encrypted state string that must be passed as the `state` parameter.
#[derive(Debug, Clone)]
pub struct OidcAuthRedirect {
    pub auth_url: String,
    pub encrypted_state: String,
}

// ── Crypto helpers — state encryption (matches SnappyMail\Crypt) ━━━━━━━━━━━

/// Derives the PHP-compatible passphrase from `salt`.
///
/// PHP: `sha1($key . APP_SALT, true)` where `$key = APP_SALT`, giving
/// `sha1(salt . salt, true)`.
fn php_passphrase(salt: &str) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(salt.as_bytes());
    hasher.update(salt.as_bytes());
    hasher.finalize().to_vec()
}

/// Derives the PHP-compatible 32-byte XChaCha20-Poly1305 key from `salt`.
///
/// PHP uses `str_pad('', 32, sha1(salt . salt, true))` which repeats the 20-byte
/// SHA-1 digest to fill 32 bytes (not zero-padding). The first 20 bytes are the
/// SHA-1 output, the next 12 bytes repeat the first 12 bytes of the SHA-1 output.
fn php_passphrase_padded(salt: &str) -> [u8; XCHACHA_KEY_LEN] {
    let passphrase = php_passphrase(salt);
    let mut key = [0u8; XCHACHA_KEY_LEN];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = passphrase[i % SHA1_LEN];
    }
    key
}

/// Encrypts a JSON-serializable value the same way `SnappyMail\Crypt::EncryptUrlSafe`
/// does, using the server `app_salt` as the key. Returns a URL-safe string in
/// the format `base64url("sodium").base64url(nonce).base64url(ciphertext)`.
pub fn encrypt_state<T: serde::Serialize>(value: &T, salt: &str) -> String {
    let json = match serde_json::to_string(value) {
        Ok(json) => json,
        Err(_) => return String::new(),
    };

    let key = php_passphrase_padded(salt);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: json.as_bytes(), aad: salt.as_bytes() },
        )
        .expect("encryption cannot fail with valid key/nonce");

    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.{}",
        enc.encode(b"sodium"),
        enc.encode(nonce),
        enc.encode(ciphertext)
    )
}

/// Decrypts a string produced by `encrypt_state` (or by PHP's
/// `Crypt::DecryptUrlSafe`), returning the deserialized value.
///
/// Accepts both the 3-part format (`sodium.nonce.ciphertext`) and the legacy
/// 2-part format (`nonce.ciphertext`) for backward compatibility.
pub fn decrypt_state<T: serde::de::DeserializeOwned>(data: &str, salt: &str) -> Option<T> {
    let parts: Vec<&str> = data.split('.').collect();

    // The PHP format is: base64url(cipher_name).base64url(nonce).base64url(ciphertext)
    // We also accept the legacy 2-part format: base64url(nonce).base64url(ciphertext)
    let (nonce_b64, ciphertext_b64) = match parts.len() {
        3 => {
            // Verify the cipher name is "sodium" (base64url("sodium") = "c29kaXVt")
            if parts[0] != "c29kaXVt" {
                return None;
            }
            (parts[1], parts[2])
        }
        2 => (parts[0], parts[1]),
        _ => return None,
    };

    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let nonce_bytes = enc.decode(nonce_b64).ok()?;
    let ciphertext = enc.decode(ciphertext_b64).ok()?;

    if nonce_bytes.len() != XCHACHA_NONCE_LEN {
        return None;
    }

    let key = php_passphrase_padded(salt);
    let cipher = XChaCha20Poly1305::new((&key).into());

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload { msg: ciphertext.as_slice(), aad: salt.as_bytes() },
        )
        .ok()?;

    serde_json::from_slice(&plaintext).ok()
}

/// Checks whether a state string decrypts successfully and has the OIDC protocol
/// marker (`p == "oidc"`). Used by the router to detect OIDC callbacks from
/// providers that strip the first query parameter (`?code=…&state=…`).
///
/// This mirrors the PHP plugin's check:
/// `($aState['p'] ?? '') === 'oidc'`
pub fn is_oidc_state(data: &str, salt: &str) -> bool {
    match decrypt_state::<OidcState>(data, salt) {
        Some(state) => state.p == "oidc",
        None => false,
    }
}

// ── Crypto helpers — escrow key encryption (matches login-oidc plugin) ━━━━━

/// Derives the server key for escrow encryption: `sha256(salt, true)`.
fn escrow_server_key(salt: &str) -> [u8; XCHACHA_KEY_LEN] {
    let mut key = [0u8; XCHACHA_KEY_LEN];
    let hash = Sha256::digest(salt.as_bytes());
    key.copy_from_slice(&hash);
    key
}

/// Encrypts a crypt key for escrow storage, matching the login-oidc plugin's
/// `escrowEncrypt`. Returns `nonce || ciphertext` (raw binary).
pub fn encrypt_escrow_key(crypt_key: &[u8], salt: &str) -> Vec<u8> {
    let key = escrow_server_key(salt);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: crypt_key, aad: &b""[..] },
        )
        .expect("escrow encryption cannot fail");

    let mut result = Vec::with_capacity(XCHACHA_NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypts an escrow key blob, matching the login-oidc plugin's
/// `escrowDecrypt`. Returns `None` if decryption fails.
pub fn decrypt_escrow_key(blob: &[u8], salt: &str) -> Option<Vec<u8>> {
    if blob.len() < XCHACHA_NONCE_LEN {
        return None;
    }

    let key = escrow_server_key(salt);
    let cipher = XChaCha20Poly1305::new((&key).into());

    cipher
        .decrypt(
            XNonce::from_slice(&blob[..XCHACHA_NONCE_LEN]),
            Payload { msg: &blob[XCHACHA_NONCE_LEN..], aad: &b""[..] },
        )
        .ok()
}

// ── PKCE helpers ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Generates a high-entropy PKCE code verifier (96 random bytes, base64url, no
/// padding), matching the PHP plugin's `generateVerifier`.
fn generate_pkce_verifier() -> String {
    let mut buf = [0u8; 96];
    OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Computes the PKCE S256 code challenge: `base64url(sha256(verifier))`, matching
/// the PHP plugin's `challenge` method.
fn pkce_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Computes a SHA-256 provider hash, matching the PHP plugin's `providerHash()`.
pub fn provider_hash(discovery_url: &str) -> String {
    let hash = Sha256::digest(discovery_url.trim_end_matches('/').as_bytes());
    hex::encode(hash)
}

// ── OIDC flow ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Builds the authorization redirect URL for the OIDC provider, fetching the
/// discovery document to obtain the `authorization_endpoint`.
///
/// This replaces the PHP plugin's `ServiceStartLoginOIDC` part.
pub async fn start_login(config: &FrickmailConfig) -> Result<OidcAuthRedirect> {
    let oidc = &config.oidc;
    let discovery_url = oidc
        .issuer
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| FrickmailError::BadRequest("OIDC issuer (discovery_url) is not configured".to_string()))?;
    let client_id = oidc
        .client_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| FrickmailError::BadRequest("OIDC client_id is not configured".to_string()))?;

    let salt = config
        .app_salt
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| FrickmailError::BadRequest("OIDC server secret (app_salt) is not configured".to_string()))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let discovery = fetch_discovery_document(discovery_url).await?;
    let auth_endpoint = discovery
        .authorization_endpoint
        .ok_or_else(|| FrickmailError::Upstream(format!("OIDC discovery document missing authorization_endpoint for {discovery_url}")))?;

    let verifier = generate_pkce_verifier();
    let challenge = pkce_challenge(&verifier);

    // The state encrypts the verifier, mode, timestamp, and the discovery URL
    // (needed during callback to re-fetch the discovery document).
    let state_value = OidcState {
        p: "oidc".to_string(),
        v: verifier,
        m: "login".to_string(),
        t: timestamp,
        i: Some(discovery_url.trim_end_matches('/').to_string()),
    };
    let encrypted_state = encrypt_state(&state_value, salt);
    let redirect_uri = format!("{base}/?LoginOIDC", base = config.base_url.trim_end_matches('/'));

    let auth_url = format!(
        "{endpoint}?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}\
         &scope={scope}&state={state}&code_challenge={challenge}&code_challenge_method={method}",
        endpoint = auth_endpoint,
        redirect_uri = url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>(),
        scope = url::form_urlencoded::byte_serialize(OIDC_SCOPES.as_bytes()).collect::<String>(),
        state = url::form_urlencoded::byte_serialize(encrypted_state.as_bytes()).collect::<String>(),
        challenge = url::form_urlencoded::byte_serialize(challenge.as_bytes()).collect::<String>(),
        method = PKCE_CHALLENGE_METHOD,
    );

    Ok(OidcAuthRedirect {
        auth_url,
        encrypted_state,
    })
}

/// OIDC discovery document (only the fields we need).
#[derive(Debug, serde::Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    #[allow(dead_code)]
    issuer: Option<String>,
}

/// Fetches and parses the OIDC discovery document from `{base}/.well-known/openid-configuration`.
async fn fetch_discovery_document(base_url: &str) -> Result<OidcDiscoveryDocument> {
    let url = format!("{}/.well-known/openid-configuration", base_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| FrickmailError::Upstream(format!("Failed to fetch OIDC discovery: {e}")))?;

    if !resp.status().is_success() {
        return Err(FrickmailError::Upstream(format!(
            "OIDC discovery request failed with status {}",
            resp.status()
        )));
    }

    resp.json::<OidcDiscoveryDocument>()
        .await
        .map_err(|e| FrickmailError::Upstream(format!("Invalid OIDC discovery JSON: {e}")))
}

/// Handles the OIDC callback: validates the state, exchanges the code for
/// tokens, fetches user info, and returns the identity information.
///
/// This does NOT establish the session — the caller is responsible for that
/// using `establish_oidc_session`. Returns `OidcCallbackResult` with the
/// outcome and any error details.
pub async fn handle_callback(
    config: &FrickmailConfig,
    encrypted_state: &str,
    code: &str,
) -> Result<OidcCallbackResult> {
    let salt = config
        .app_salt
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| FrickmailError::BadRequest("OIDC server secret (app_salt) is not configured".to_string()))?;

    // Decrypt state
    let state: OidcState = decrypt_state(encrypted_state, salt)
        .ok_or_else(|| FrickmailError::BadRequest("OIDC: invalid state parameter".to_string()))?;

    if state.p != "oidc" || state.v.is_empty() {
        return Ok(OidcCallbackResult {
            ok: false,
            mode: state.m.clone(),
            email: None,
            error: Some("OIDC: invalid state parameter".to_string()),
            reauth_required: false,
            provider_hash: None,
            subject: None,
        });
    }

    // Re-fetch discovery document using the issuer stored in the state.
    // Fall back to the configured issuer if the state was encrypted by PHP
    // (which doesn't store the issuer URL in the state).
    let discovery_url = state
        .i
        .as_deref()
        .or(config.oidc.issuer.as_deref())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| FrickmailError::BadRequest("OIDC state and config missing issuer URL".to_string()))?;

    let discovery = fetch_discovery_document(discovery_url).await?;

    let token_endpoint = discovery
        .token_endpoint
        .ok_or_else(|| FrickmailError::Upstream("OIDC provider missing token_endpoint".to_string()))?;

    let discovery_url_trimmed = discovery_url.trim_end_matches('/');
    let redirect_uri = format!("{base}/?LoginOIDC", base = config.base_url.trim_end_matches('/'));

    // Exchange code for tokens
    let client_id = config.oidc.client_id.as_deref().unwrap_or_default();
    let client_secret = config.oidc.client_secret.as_deref();

    let mut token_params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &redirect_uri),
        ("client_id", client_id),
        ("code_verifier", &state.v),
    ];
    if let Some(secret) = client_secret {
        token_params.push(("client_secret", secret));
    }

    let token_resp = reqwest::Client::new()
        .post(&token_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .form(&token_params)
        .send()
        .await
        .map_err(|e| FrickmailError::Upstream(format!("OIDC token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        let status = token_resp.status();
        let body = token_resp.text().await.unwrap_or_default();
        return Ok(OidcCallbackResult {
            ok: false,
            mode: state.m.clone(),
            email: None,
            error: Some(format!("OIDC token exchange failed (HTTP {status}): {body}")),
            reauth_required: false,
            provider_hash: None,
            subject: None,
        });
    }

    let token_json: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| FrickmailError::Upstream(format!("Invalid OIDC token response JSON: {e}")))?;

    if token_json.get("access_token").is_none() {
        let err = token_json
            .get("error_description")
            .and_then(|v| v.as_str())
            .or_else(|| token_json.get("error").and_then(|v| v.as_str()))
            .unwrap_or("no access_token in OIDC response");
        return Ok(OidcCallbackResult {
            ok: false,
            mode: state.m.clone(),
            email: None,
            error: Some(format!("OIDC token exchange failed: {err}")),
            reauth_required: false,
            provider_hash: None,
            subject: None,
        });
    }

    // Fetch userinfo
    let userinfo_endpoint = discovery
        .userinfo_endpoint
        .ok_or_else(|| FrickmailError::Upstream("OIDC provider missing userinfo_endpoint".to_string()))?;

    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let userinfo = reqwest::Client::new()
        .get(&userinfo_endpoint)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| FrickmailError::Upstream(format!("OIDC userinfo fetch failed: {e}")))?;

    if !userinfo.status().is_success() {
        let status = userinfo.status();
        return Ok(OidcCallbackResult {
            ok: false,
            mode: state.m.clone(),
            email: None,
            error: Some(format!("OIDC userinfo request failed (HTTP {status})")),
            reauth_required: false,
            provider_hash: Some(provider_hash(discovery_url_trimmed)),
            subject: None,
        });
    }

    let userinfo_json: serde_json::Value = userinfo
        .json()
        .await
        .map_err(|e| FrickmailError::Upstream(format!("Invalid OIDC userinfo JSON: {e}")))?;

    let subject = userinfo_json
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FrickmailError::Upstream("OIDC userinfo missing sub claim".to_string()))?;

    let email = userinfo_json
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FrickmailError::Upstream("OIDC userinfo missing email claim".to_string()))?;

    Ok(OidcCallbackResult {
        ok: true,
        mode: state.m.clone(),
        email: Some(email.to_string()),
        error: None,
        reauth_required: false,
        provider_hash: Some(provider_hash(discovery_url_trimmed)),
        subject: Some(subject.to_string()),
    })
}

/// Renders the callback HTML page that communicates the result back to the
/// main window via localStorage, BroadcastChannel, and postMessage.
///
/// The JSON payload sent to the frontend includes `type` and `status` fields
/// to match what the frickmail-oidc plugin JS expects:
/// `{"type":"frickmail-oidc","status":"ok"|"error",...}`.
pub fn render_callback(payload: &OidcCallbackPayload) -> String {
    let status = if payload.ok { "ok" } else { "error" };
    let json = serde_json::json!({
        "type": "frickmail-oidc",
        "status": status,
        "mode": &payload.mode,
        "email": &payload.email,
        "error": &payload.error,
        "reauth_required": payload.reauth_required,
    });
    let json = json.to_string();
    let escaped = escape_for_script_data(&json);
    format!(
        r#"<!doctype html><meta charset="utf-8"><title>Frickmail</title>
<script type="application/json" id="frickmail-oidc-payload">{escaped}</script>
<script>
const payload = document.getElementById('frickmail-oidc-payload').textContent;
try {{ localStorage.setItem('frickmail-oidc-result', payload); }} catch(e) {{}}
const m = JSON.parse(payload);
if (m.status === 'ok') {{
    try {{ if (window.opener && !window.opener.closed) {{ window.opener.location.reload(); }} }} catch(e) {{}}
}}
try {{ var bc = new BroadcastChannel('frickmail-oidc'); bc.postMessage(m); bc.close(); }} catch(e) {{}}
try {{ if (window.opener && !window.opener.closed) {{ window.opener.postMessage(m, window.location.origin); }} }} catch(e) {{}}
setTimeout(function() {{ window.close(); }}, 500);
</script>"#
    )
}

fn escape_for_script_data(input: &str) -> String {
    input
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

// ── Tests ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    fn test_salt() -> &'static str {
        "test-salt-value-for-ci"
    }

    #[test]
    fn escape_json_for_script_context() {
        let html = render_callback(&OidcCallbackPayload {
            ok: false,
            mode: "login".to_string(),
            email: Some("attacker@example.com</script><script>alert(1)</script>".to_string()),
            error: Some("<img src=x onerror=alert(1)>".to_string()),
            reauth_required: false,
        });

        assert!(!html.contains("</script><script>alert(1)</script>"));
        assert!(html.contains("\\u003c/script\\u003e"));
        assert!(html.contains("application/json"));
    }

    #[test]
    fn state_encrypt_decrypt_roundtrip() {
        let state = OidcState {
            p: "oidc".to_string(),
            v: "test-verifier-123".to_string(),
            m: "login".to_string(),
            t: 1700000000,
            i: Some("https://issuer.example.com".to_string()),
        };
        let encrypted = encrypt_state(&state, test_salt());
        let decrypted: Option<OidcState> = decrypt_state(&encrypted, test_salt());
        assert_eq!(decrypted, Some(state));
    }

    #[test]
    fn state_decrypt_rejects_wrong_salt() {
        let state = OidcState {
            p: "oidc".to_string(),
            v: "test-verifier-123".to_string(),
            m: "link".to_string(),
            t: 1700000000,
            i: Some("https://issuer.example.com".to_string()),
        };
        let encrypted = encrypt_state(&state, test_salt());
        let decrypted: Option<OidcState> = decrypt_state(&encrypted, "wrong-salt");
        assert_eq!(decrypted, None);
    }

    #[test]
    fn escrow_encrypt_decrypt_roundtrip() {
        let key = vec![0x42u8; 32];
        let encrypted = encrypt_escrow_key(&key, test_salt());
        let decrypted = decrypt_escrow_key(&encrypted, test_salt());
        assert_eq!(decrypted, Some(key));
    }

    #[test]
    fn escrow_decrypt_rejects_wrong_salt() {
        let key = vec![0x42u8; 32];
        let encrypted = encrypt_escrow_key(&key, test_salt());
        let decrypted = decrypt_escrow_key(&encrypted, "wrong-salt");
        assert_eq!(decrypted, None);
    }

    #[test]
    fn pkce_challenge_matches_php() {
        // The PHP plugin computes: base64url(sha256(verifier)) without padding
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_challenge(verifier);
        // RFC 7636 Appendix B test vector
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn pkce_verifier_is_high_entropy() {
        let v1 = generate_pkce_verifier();
        let v2 = generate_pkce_verifier();
        assert_ne!(v1, v2);
        assert!(v1.len() >= 64);
    }

    #[test]
    fn provider_hash_is_deterministic() {
        let h1 = provider_hash("https://issuer.example.com/");
        let h2 = provider_hash("https://issuer.example.com");
        assert_eq!(h1, h2);
        assert!(!h1.is_empty());
    }

    #[test]
    fn state_format_matches_php_sodium_prefix() {
        // PHP's EncryptUrlSafe produces: base64url("sodium").base64url(nonce).base64url(ciphertext)
        let state = OidcState {
            p: "oidc".to_string(),
            v: "test-verifier".to_string(),
            m: "login".to_string(),
            t: 1700000000,
            i: None,
        };
        let encrypted = encrypt_state(&state, test_salt());
        let parts: Vec<&str> = encrypted.split('.').collect();
        assert_eq!(parts.len(), 3, "encrypted state should have 3 dot-separated parts");
        assert_eq!(parts[0], "c29kaXVt", "first part should be base64url('sodium')");
    }

    #[test]
    fn decrypt_state_accepts_2_part_legacy_format() {
        // Manually construct a 2-part payload (nonce.ciphertext) to verify
        // backward compatibility with the non-PHP format.
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};

        let salt = test_salt();
        let key = php_passphrase_padded(salt);
        let cipher = XChaCha20Poly1305::new(&key.into());
        let nonce = XNonce::from_slice(&[42u8; XCHACHA_NONCE_LEN]);
        let plaintext = b"{\"p\":\"oidc\",\"v\":\"legacy\",\"m\":\"login\",\"t\":1700000000}";
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: salt.as_bytes() })
            .unwrap();

        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let data = format!("{}.{}", enc.encode(nonce), enc.encode(ciphertext));

        let decrypted: Option<OidcState> = decrypt_state(&data, salt);
        assert!(decrypted.is_some());
        let state = decrypted.unwrap();
        assert_eq!(state.p, "oidc");
        assert_eq!(state.v, "legacy");
    }
}
