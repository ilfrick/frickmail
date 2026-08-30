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

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use fm_core::{FrickmailConfig, FrickmailError, Result};
use rand_core::{OsRng, RngCore};
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
            Payload {
                msg: json.as_bytes(),
                aad: salt.as_bytes(),
            },
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
            Payload {
                msg: ciphertext.as_slice(),
                aad: salt.as_bytes(),
            },
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

/// Detects a Gmail/O365 OAuth2 state payload (`p == "gmail"` or `"o365"`),
/// returning the provider when recognized. Used by the router to route
/// callbacks whose redirect URI lost the explicit `Login*` query key.
pub fn oauth2_state_provider(data: &str, salt: &str) -> Option<String> {
    let state = decrypt_state::<Oauth2State>(data, salt)?;
    match state.p.as_str() {
        "gmail" | "o365" => Some(state.p),
        _ => None,
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
            Payload {
                msg: crypt_key,
                aad: &b""[..],
            },
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
            Payload {
                msg: &blob[XCHACHA_NONCE_LEN..],
                aad: &b""[..],
            },
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
        .ok_or_else(|| {
            FrickmailError::BadRequest("OIDC issuer (discovery_url) is not configured".to_string())
        })?;
    let client_id = oidc
        .client_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            FrickmailError::BadRequest("OIDC client_id is not configured".to_string())
        })?;

    let salt = config
        .app_salt
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            FrickmailError::BadRequest(
                "OIDC server secret (app_salt) is not configured".to_string(),
            )
        })?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let discovery = fetch_discovery_document(discovery_url).await?;
    let auth_endpoint = discovery.authorization_endpoint.ok_or_else(|| {
        FrickmailError::Upstream(format!(
            "OIDC discovery document missing authorization_endpoint for {discovery_url}"
        ))
    })?;

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
    let redirect_uri = format!(
        "{base}/?LoginOIDC",
        base = config.base_url.trim_end_matches('/')
    );

    let auth_url = format!(
        "{endpoint}?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}\
         &scope={scope}&state={state}&code_challenge={challenge}&code_challenge_method={method}",
        endpoint = auth_endpoint,
        redirect_uri =
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>(),
        scope = url::form_urlencoded::byte_serialize(OIDC_SCOPES.as_bytes()).collect::<String>(),
        state =
            url::form_urlencoded::byte_serialize(encrypted_state.as_bytes()).collect::<String>(),
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
    let url = format!(
        "{}/.well-known/openid-configuration",
        base_url.trim_end_matches('/')
    );
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
        .ok_or_else(|| {
            FrickmailError::BadRequest(
                "OIDC server secret (app_salt) is not configured".to_string(),
            )
        })?;

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
        .ok_or_else(|| {
            FrickmailError::BadRequest("OIDC state and config missing issuer URL".to_string())
        })?;

    let discovery = fetch_discovery_document(discovery_url).await?;

    let token_endpoint = discovery.token_endpoint.ok_or_else(|| {
        FrickmailError::Upstream("OIDC provider missing token_endpoint".to_string())
    })?;

    let discovery_url_trimmed = discovery_url.trim_end_matches('/');
    let redirect_uri = format!(
        "{base}/?LoginOIDC",
        base = config.base_url.trim_end_matches('/')
    );

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
            error: Some(format!(
                "OIDC token exchange failed (HTTP {status}): {body}"
            )),
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
    let userinfo_endpoint = discovery.userinfo_endpoint.ok_or_else(|| {
        FrickmailError::Upstream("OIDC provider missing userinfo_endpoint".to_string())
    })?;

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

// ── OAuth2 provider helpers (Gmail / O365) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Google OAuth2 authorization and token endpoints (hardcoded — no discovery).
const GMAIL_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/auth";
const GMAIL_TOKEN_URL: &str = "https://accounts.google.com/o/oauth2/token";
const GMAIL_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
const GMAIL_SCOPES: &str = "openid email profile \
    https://mail.google.com/ \
    https://www.googleapis.com/auth/contacts.readonly \
    https://www.googleapis.com/auth/calendar";

/// Microsoft (O365/Outlook) OAuth2 endpoints (hardcoded with tenant template).
const O365_AUTH_URL: &str = "https://login.microsoftonline.com/{{tenant}}/oauth2/v2.0/authorize";
const O365_TOKEN_URL: &str = "https://login.microsoftonline.com/{{tenant}}/oauth2/v2.0/token";
const O365_USERINFO_URL: &str = "https://graph.microsoft.com/oidc/userinfo";
const O365_SCOPES: &str = "openid offline_access email profile \
    https://outlook.office.com/IMAP.AccessAsUser.All \
    https://outlook.office.com/SMTP.Send \
    https://graph.microsoft.com/Contacts.Read \
    https://graph.microsoft.com/Calendars.ReadWrite";

/// State encrypted by Gmail/O365 `StartLogin*` part hooks.
///
/// Mirrors the PHP plugins' `EncryptUrlSafe` payload:
/// `{p, v, n, t}` where `p` is the provider (`"gmail"` or `"o365"`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Oauth2State {
    pub p: String,
    pub v: String,
    pub n: String,
    pub t: u64,
}

/// Result of a Gmail/O365 OAuth2 callback.
#[derive(Debug, Clone)]
pub struct Oauth2CallbackResult {
    pub ok: bool,
    pub email: Option<String>,
    pub error: Option<String>,
    /// In Frickmail mode, when no session is present the refresh token is
    /// passed back to the opener via postMessage so the main window can
    /// call `FrickmailSaveOAuthToken` + `FrickmailSwitchAccount`.
    pub pending_refresh_token: Option<String>,
}

fn oauth2_client_id(config: &FrickmailConfig, provider: &str) -> Result<String> {
    let id = match provider {
        "gmail" => config.oauth2.gmail.client_id.as_deref(),
        "o365" => config.oauth2.o365.client_id.as_deref(),
        _ => None,
    };
    id.and_then(|s| {
        let s = s.trim();
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    })
    .ok_or_else(|| {
        FrickmailError::BadRequest(format!("{provider} OAuth2 client_id is not configured"))
    })
}

fn salt_from_config(config: &FrickmailConfig) -> Result<&str> {
    config
        .app_salt
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            FrickmailError::BadRequest(
                "OAuth2 server secret (app_salt) is not configured".to_string(),
            )
        })
}

/// Builds an encrypted OAuth2 state payload and returns both the encrypted
/// form and the decrypted `Oauth2State` (so the caller can read `v` for PKCE).
fn build_pkce_state(provider: &str, salt: &str) -> (String, Oauth2State) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut nonce_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_bytes);

    let state = Oauth2State {
        p: provider.to_string(),
        v: generate_pkce_verifier(),
        n: hex_encode(&nonce_bytes),
        t: now,
    };
    let encrypted = encrypt_state(&state, salt);
    (encrypted, state)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Resolves the O365 redirect URI from the configuration.
///
/// Work/tenant registrations use the query-style `https://host/?LoginO365`
/// reply URL documented in the README. Personal Microsoft accounts
/// (`oauth2.o365.personal = true`, matching the legacy plugin's "personal"
/// mode) require the path-style `https://host/LoginO365` reply URL; the
/// router serves both shapes.
fn o365_redirect_uri(config: &FrickmailConfig) -> String {
    let base = config.base_url.trim_end_matches('/');
    if config.oauth2.o365.personal {
        format!("{base}/LoginO365")
    } else {
        format!("{base}/?LoginO365")
    }
}

/// Builds the authorization redirect URL for Gmail OAuth2 with PKCE.
///
/// Replaces the PHP plugin's `ServiceStartLoginGMail` part hook.
pub async fn gmail_start_login(config: &FrickmailConfig) -> Result<OidcAuthRedirect> {
    let client_id = oauth2_client_id(config, "gmail")?;
    let salt = salt_from_config(config)?;

    let (encrypted_state, state) = build_pkce_state("gmail", salt);
    let challenge = pkce_challenge(&state.v);

    let redirect_uri = format!(
        "{base}/?LoginGMail",
        base = config.base_url.trim_end_matches('/')
    );

    let auth_url = format!(
        "{endpoint}?response_type=code\
         &client_id={client_id}\
         &redirect_uri={redirect_uri}\
         &scope={scope}\
         &state={state}\
         &access_type=offline\
         &prompt=consent\
         &code_challenge={challenge}\
         &code_challenge_method={method}",
        endpoint = GMAIL_AUTH_URL,
        redirect_uri =
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>(),
        scope = url::form_urlencoded::byte_serialize(GMAIL_SCOPES.as_bytes()).collect::<String>(),
        state =
            url::form_urlencoded::byte_serialize(encrypted_state.as_bytes()).collect::<String>(),
        challenge = url::form_urlencoded::byte_serialize(challenge.as_bytes()).collect::<String>(),
        method = PKCE_CHALLENGE_METHOD,
    );

    Ok(OidcAuthRedirect {
        auth_url,
        encrypted_state,
    })
}

/// Handles the Gmail OAuth2 callback: decrypts state, exchanges the code for
/// tokens, fetches userinfo, and returns the identity information.
///
/// Does NOT save the token to the database — the caller must do that in
/// Frickmail mode. Returns `Oauth2CallbackResult`.
pub async fn gmail_handle_callback(
    config: &FrickmailConfig,
    encrypted_state: &str,
    code: &str,
) -> Result<Oauth2CallbackResult> {
    let salt = salt_from_config(config)?;
    let state: Oauth2State = decrypt_state(encrypted_state, salt)
        .ok_or_else(|| FrickmailError::BadRequest("Gmail: invalid state parameter".to_string()))?;

    if state.p != "gmail" || state.v.is_empty() {
        return Ok(Oauth2CallbackResult {
            ok: false,
            email: None,
            error: Some("Gmail: invalid state parameter".to_string()),
            pending_refresh_token: None,
        });
    }

    let client_id = oauth2_client_id(config, "gmail")?;
    let client_secret = config.oauth2.gmail.client_secret.as_deref();

    let redirect_uri = format!(
        "{base}/?LoginGMail",
        base = config.base_url.trim_end_matches('/')
    );

    let token_json = exchange_oauth2_code(
        GMAIL_TOKEN_URL,
        &client_id,
        client_secret,
        code,
        &redirect_uri,
        &state.v,
    )
    .await?;

    let refresh_token = token_json
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FrickmailError::Upstream("Gmail OAuth2: refresh_token missing".to_string())
        })?;

    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FrickmailError::Upstream("Gmail OAuth2: access_token missing".to_string())
        })?;

    let email = fetch_oauth2_userinfo(GMAIL_USERINFO_URL, access_token).await?;

    Ok(Oauth2CallbackResult {
        ok: true,
        email: Some(email),
        error: None,
        pending_refresh_token: Some(refresh_token.to_string()),
    })
}

/// Builds the authorization redirect URL for O365/Microsoft OAuth2 with PKCE.
///
/// Replaces the PHP plugin's `ServiceStartLoginO365` part hook. Handles tenant
/// selection and personal-vs-work account redirect URI differences.
pub async fn o365_start_login(config: &FrickmailConfig) -> Result<OidcAuthRedirect> {
    let client_id = oauth2_client_id(config, "o365")?;
    let salt = salt_from_config(config)?;

    let tenant = if config.oauth2.o365.tenant.trim().is_empty() {
        "common".to_string()
    } else {
        config.oauth2.o365.tenant.trim().to_string()
    };

    let (encrypted_state, state) = build_pkce_state("o365", salt);
    let challenge = pkce_challenge(&state.v);

    let redirect_uri = o365_redirect_uri(config);

    let auth_url = format!(
        "{endpoint}?response_type=code\
         &client_id={client_id}\
         &redirect_uri={redirect_uri}\
         &scope={scope}\
         &state={state}\
         &prompt=select_account\
         &code_challenge={challenge}\
         &code_challenge_method={method}",
        endpoint = O365_AUTH_URL.replace("{{tenant}}", &tenant),
        redirect_uri =
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>(),
        scope = url::form_urlencoded::byte_serialize(O365_SCOPES.as_bytes()).collect::<String>(),
        state =
            url::form_urlencoded::byte_serialize(encrypted_state.as_bytes()).collect::<String>(),
        challenge = url::form_urlencoded::byte_serialize(challenge.as_bytes()).collect::<String>(),
        method = PKCE_CHALLENGE_METHOD,
    );

    Ok(OidcAuthRedirect {
        auth_url,
        encrypted_state,
    })
}

/// Handles the O365/Microsoft OAuth2 callback.
///
/// Replaces the PHP plugin's `ServiceLoginO365` part hook. Exchanges the code
/// for tokens, fetches userinfo from Microsoft Graph, and returns the identity.
pub async fn o365_handle_callback(
    config: &FrickmailConfig,
    encrypted_state: &str,
    code: &str,
) -> Result<Oauth2CallbackResult> {
    let salt = salt_from_config(config)?;
    let state: Oauth2State = decrypt_state(encrypted_state, salt)
        .ok_or_else(|| FrickmailError::BadRequest("O365: invalid state parameter".to_string()))?;

    if state.p != "o365" || state.v.is_empty() {
        return Ok(Oauth2CallbackResult {
            ok: false,
            email: None,
            error: Some("O365: invalid state parameter".to_string()),
            pending_refresh_token: None,
        });
    }

    let client_id = oauth2_client_id(config, "o365")?;
    let client_secret = config.oauth2.o365.client_secret.as_deref();
    let tenant = if config.oauth2.o365.tenant.trim().is_empty() {
        "common".to_string()
    } else {
        config.oauth2.o365.tenant.trim().to_string()
    };

    let token_url = O365_TOKEN_URL.replace("{{tenant}}", &tenant);
    let redirect_uri = o365_redirect_uri(config);

    let token_json = exchange_oauth2_code(
        &token_url,
        &client_id,
        client_secret,
        code,
        &redirect_uri,
        &state.v,
    )
    .await?;

    let refresh_token = token_json
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FrickmailError::Upstream("O365 OAuth2: refresh_token missing".to_string())
        })?;

    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FrickmailError::Upstream("O365 OAuth2: access_token missing".to_string()))?;

    let email = fetch_oauth2_userinfo(O365_USERINFO_URL, access_token).await?;

    Ok(Oauth2CallbackResult {
        ok: true,
        email: Some(email),
        error: None,
        pending_refresh_token: Some(refresh_token.to_string()),
    })
}

/// Exchanges an authorization code for tokens at the provider's token endpoint.
async fn exchange_oauth2_code(
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<serde_json::Value> {
    let mut params: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];
    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }

    let resp = reqwest::Client::new()
        .post(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .form(&params)
        .send()
        .await
        .map_err(|e| FrickmailError::Upstream(format!("OAuth2 token exchange failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(FrickmailError::Upstream(format!(
            "OAuth2 token exchange failed (HTTP {status}): {body}"
        )));
    }

    let json: serde_json::Value = resp.json().await.map_err(|e| {
        FrickmailError::Upstream(format!("Invalid OAuth2 token response JSON: {e}"))
    })?;

    Ok(json)
}

/// Fetches the user's email from a provider's userinfo endpoint.
/// Accepts `email`, `email_address`, or `preferred_username` fields.
async fn fetch_oauth2_userinfo(userinfo_url: &str, access_token: &str) -> Result<String> {
    let resp = reqwest::Client::new()
        .get(userinfo_url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| FrickmailError::Upstream(format!("OAuth2 userinfo fetch failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(FrickmailError::Upstream(format!(
            "OAuth2 userinfo request failed (HTTP {status})"
        )));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FrickmailError::Upstream(format!("Invalid OAuth2 userinfo JSON: {e}")))?;

    let email = json
        .get("email")
        .or_else(|| json.get("email_address"))
        .or_else(|| json.get("preferred_username"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            FrickmailError::Upstream("OAuth2 userinfo missing email claim".to_string())
        })?;

    Ok(email.to_string())
}

/// Renders the popup callback HTML for Gmail/O365 OAuth2, matching the PHP
/// plugin's `renderPopupCallback`. The JSON payload uses
/// `type: "frickmail-oauth2"` with a `provider` field.
///
/// If opened as a popup, the script posts the payload (success or error, like
/// the PHP plugin) to the opener via `window.opener.postMessage` and then
/// closes itself. If opened as a full-page navigation (no opener), it
/// redirects back to the webmail root. The payload is deliberately NOT
/// written to localStorage: for the no-session flow it carries the
/// long-lived refresh token, which must not be persisted in the browser.
pub fn render_oauth2_callback(provider: &str, result: &Oauth2CallbackResult) -> String {
    let status = if result.ok { "ok" } else { "error" };
    let mut payload = serde_json::json!({
        "type": "frickmail-oauth2",
        "provider": provider,
        "status": status,
        "email": &result.email,
        "error": &result.error,
    });
    if let Some(token) = &result.pending_refresh_token {
        payload["pending_refresh_token"] = serde_json::Value::String(token.clone());
    }

    let json = payload.to_string();
    let escaped = escape_for_script_data(&json);
    let summary = if result.ok { "succeeded" } else { "failed" };
    format!(
        r#"<!doctype html><meta charset="utf-8"><title>Frickmail</title>
<script type="application/json" id="frickmail-oauth2-payload">{escaped}</script>
<script>
const payload = document.getElementById('frickmail-oauth2-payload').textContent;
const m = JSON.parse(payload);
(function() {{
    try {{ if (window.opener && !window.opener.closed) {{
        window.opener.postMessage(m, window.location.origin);
        window.close();
        return;
    }} }} catch(e) {{}}
    window.location.replace('/');
}})();
</script><p>Authentication {summary}. You can close this window.</p>"#
    )
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
        assert_eq!(
            parts.len(),
            3,
            "encrypted state should have 3 dot-separated parts"
        );
        assert_eq!(
            parts[0], "c29kaXVt",
            "first part should be base64url('sodium')"
        );
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
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: salt.as_bytes(),
                },
            )
            .unwrap();

        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let data = format!("{}.{}", enc.encode(nonce), enc.encode(ciphertext));

        let decrypted: Option<OidcState> = decrypt_state(&data, salt);
        assert!(decrypted.is_some());
        let state = decrypted.unwrap();
        assert_eq!(state.p, "oidc");
        assert_eq!(state.v, "legacy");
    }

    // ── OAuth2 provider (Gmail / O365) tests ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    fn oauth2_test_config() -> FrickmailConfig {
        let mut config: FrickmailConfig = serde_json::from_str("{}").expect("default config");
        config.base_url = "https://mail.example.com".to_string();
        config.app_salt = Some(test_salt().to_string());
        config
    }

    #[test]
    fn oauth2_state_roundtrip_and_provider_detection() {
        let state = Oauth2State {
            p: "gmail".to_string(),
            v: "oauth2-verifier".to_string(),
            n: "0123456789abcdef".to_string(),
            t: 1700000000,
        };
        let encrypted = encrypt_state(&state, test_salt());
        let decrypted: Option<Oauth2State> = decrypt_state(&encrypted, test_salt());
        assert_eq!(decrypted, Some(state));

        assert_eq!(
            oauth2_state_provider(&encrypted, test_salt()),
            Some("gmail".to_string())
        );
        assert_eq!(oauth2_state_provider("garbage", test_salt()), None);
    }

    #[test]
    fn oauth2_state_is_not_oidc_state() {
        let state = Oauth2State {
            p: "o365".to_string(),
            v: "oauth2-verifier".to_string(),
            n: "0123456789abcdef".to_string(),
            t: 1700000000,
        };
        let encrypted = encrypt_state(&state, test_salt());
        assert_eq!(
            oauth2_state_provider(&encrypted, test_salt()),
            Some("o365".to_string())
        );
        assert!(!is_oidc_state(&encrypted, test_salt()));

        let oidc_state = OidcState {
            p: "oidc".to_string(),
            v: "verifier".to_string(),
            m: "login".to_string(),
            t: 1700000000,
            i: None,
        };
        let oidc_encrypted = encrypt_state(&oidc_state, test_salt());
        assert_eq!(oauth2_state_provider(&oidc_encrypted, test_salt()), None);
        assert!(is_oidc_state(&oidc_encrypted, test_salt()));
    }

    #[test]
    fn render_oauth2_callback_includes_pending_token_and_escapes() {
        let ok_result = Oauth2CallbackResult {
            ok: true,
            email: Some("user@example.com".to_string()),
            error: None,
            pending_refresh_token: Some("token-123".to_string()),
        };
        let html = render_oauth2_callback("gmail", &ok_result);
        assert!(html.contains("frickmail-oauth2"));
        assert!(html.contains("\"provider\":\"gmail\""));
        assert!(html.contains("pending_refresh_token"));
        assert!(html.contains("token-123"));

        let bad_result = Oauth2CallbackResult {
            ok: false,
            email: Some("attacker@example.com</script>".to_string()),
            error: Some("<img src=x onerror=alert(1)>".to_string()),
            pending_refresh_token: None,
        };
        let html = render_oauth2_callback("o365", &bad_result);
        assert!(!html.contains("</script><script>"));
        assert!(html.contains("\\u003c/script\\u003e"));
    }

    #[tokio::test]
    async fn gmail_start_login_builds_pkce_auth_url() {
        let mut config = oauth2_test_config();
        config.oauth2.gmail.client_id = Some("gmail-client-id".to_string());

        let redirect = gmail_start_login(&config).await.expect("redirect");
        assert!(redirect.auth_url.starts_with(GMAIL_AUTH_URL));
        assert!(redirect.auth_url.contains("client_id=gmail-client-id"));
        assert!(redirect
            .auth_url
            .contains("redirect_uri=https%3A%2F%2Fmail.example.com%2F%3FLoginGMail"));
        assert!(redirect.auth_url.contains("code_challenge_method=S256"));
        assert!(redirect.auth_url.contains("access_type=offline"));
        assert!(redirect.auth_url.contains("prompt=consent"));
        assert!(redirect
            .auth_url
            .contains("https%3A%2F%2Fmail.google.com%2F"));
        // The state must decrypt back to a gmail state with a usable verifier.
        let state_param = redirect
            .auth_url
            .split("state=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .map(|value| {
                url::form_urlencoded::parse(format!("s={value}").as_bytes())
                    .next()
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let state: Oauth2State = decrypt_state(&state_param, test_salt()).expect("state decrypts");
        assert_eq!(state.p, "gmail");
        assert!(!state.v.is_empty());
        assert!(!state.n.is_empty());
    }

    #[tokio::test]
    async fn gmail_start_login_requires_client_id() {
        let config = oauth2_test_config();
        let err = gmail_start_login(&config).await.expect_err("must fail");
        assert!(err.to_string().contains("client_id"));
    }

    #[tokio::test]
    async fn o365_start_login_uses_configured_tenant_and_endpoints() {
        let mut config = oauth2_test_config();
        config.oauth2.o365.client_id = Some("o365-client-id".to_string());
        config.oauth2.o365.tenant = "contoso.onmicrosoft.com".to_string();

        let redirect = o365_start_login(&config).await.expect("redirect");
        assert!(redirect.auth_url.starts_with(
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize"
        ));
        assert!(redirect.auth_url.contains("client_id=o365-client-id"));
        assert!(redirect.auth_url.contains("prompt=select_account"));
        assert!(redirect
            .auth_url
            .contains("redirect_uri=https%3A%2F%2Fmail.example.com%2F%3FLoginO365"));
        assert!(redirect.auth_url.contains("IMAP.AccessAsUser.All"));

        // State must decrypt to an o365 state.
        let state_param = redirect
            .auth_url
            .split("state=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .map(|value| {
                url::form_urlencoded::parse(format!("s={value}").as_bytes())
                    .next()
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let state: Oauth2State = decrypt_state(&state_param, test_salt()).expect("state decrypts");
        assert_eq!(state.p, "o365");
    }

    #[test]
    fn o365_token_endpoint_uses_microsoftonline_host() {
        assert!(O365_TOKEN_URL.starts_with("https://login.microsoftonline.com/"));
        assert!(!O365_TOKEN_URL.contains("microsoftazure.com"));
    }

    #[tokio::test]
    async fn o365_start_login_personal_uses_path_style_redirect_uri() {
        let mut config = oauth2_test_config();
        config.oauth2.o365.client_id = Some("o365-client-id".to_string());
        config.oauth2.o365.personal = true;

        let redirect = o365_start_login(&config).await.expect("redirect");
        assert!(redirect
            .auth_url
            .contains("redirect_uri=https%3A%2F%2Fmail.example.com%2FLoginO365"));
        assert!(!redirect.auth_url.contains("%3FLoginO365"));
    }

    #[tokio::test]
    async fn oauth2_start_login_requires_app_salt() {
        let mut config = oauth2_test_config();
        config.app_salt = None;
        config.oauth2.gmail.client_id = Some("gmail-client-id".to_string());
        let err = gmail_start_login(&config).await.expect_err("must fail");
        assert!(err.to_string().contains("app_salt"));
    }
}
