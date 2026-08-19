use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use data_encoding::BASE32_NOPAD;
use fm_core::{FrickmailError, Result, UserSession};
use hmac::{Hmac, Mac};
use openssl::{
    asn1::Asn1TimeRef,
    hash::MessageDigest,
    nid::Nid,
    pkcs12::Pkcs12,
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::PKey,
    stack::Stack,
    x509::store::X509StoreBuilder,
    x509::{X509NameRef, X509Ref, X509},
};
use p256::{
    ecdsa::SigningKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use qrcode::{render::svg, QrCode};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Number, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sqlx::{AnyPool, Connection, Row};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

pub const KDF_SALT_BYTES: usize = 16;
pub const CREDENTIAL_KEY_BYTES: usize = 32;
pub const KDF_OPSLIMIT: u32 = 3;
pub const KDF_MEMLIMIT_KIB: u32 = 65_536;
pub const ACCOUNT_SECRET_NONCE_BYTES: usize = 24;
pub const PASSWORD_HASH_OPSLIMIT: u32 = 4;
pub const PASSWORD_HASH_MEMLIMIT_KIB: u32 = 65_536;
pub const DUMMY_PASSWORD_HASH: &str =
    "$argon2id$v=19$m=65536,t=4,p=1$TTJYNUVsNlE5Q1RwTzZacQ$AnMUliGcTz3HHGhxmAib/d0fPagGYhpUa1uQxLPgyeg";
/// Largest PEM certificate accepted at import and when resolving stored
/// certificate material.  A DER X.509 certificate is far smaller in normal
/// use; this leaves room for sizeable chains without making crypto requests
/// an unbounded database-to-OpenSSL allocation path.
pub const SMIME_CERT_PEM_MAX_BYTES: usize = 64 * 1024;
/// PKCS#12 bundles contain both a certificate and an optional private key.
pub const SMIME_P12_MAX_BYTES: usize = 512 * 1024;
pub const SMIME_PRIVATE_KEY_PEM_MAX_BYTES: usize = 64 * 1024;
const SMIME_PRIVATE_KEY_ENCRYPTED_MAX_BYTES: usize =
    SMIME_PRIVATE_KEY_PEM_MAX_BYTES + ACCOUNT_SECRET_NONCE_BYTES + 16;
const VAPID_SETTING_KEY: &str = "vapid_keys";
const SMIME_CRYPTO_CONCURRENCY: usize = 2;

fn smime_crypto_semaphore() -> &'static Arc<tokio::sync::Semaphore> {
    static SEMAPHORE: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    SEMAPHORE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(SMIME_CRYPTO_CONCURRENCY)))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FrickmailUser {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub kdf_salt: Vec<u8>,
    pub settings: Value,
    pub totp_secret: Option<String>,
    pub oidc_escrow_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrickmailMe {
    pub ok: bool,
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailIdentity {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub email: String,
    pub reply_to: Option<String>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailAccount {
    pub id: i64,
    pub label: String,
    pub email: String,
    #[serde(rename = "type")]
    pub account_type: String,
    pub imap_host: Option<String>,
    pub imap_port: Option<i64>,
    pub imap_secure: Option<String>,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<i64>,
    pub smtp_secure: Option<String>,
    pub login: Option<String>,
    pub is_primary: bool,
    pub identities: Vec<MailIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailAccountConnectionSecret {
    pub id: i64,
    pub email: String,
    pub account_type: String,
    pub imap_host: Option<String>,
    pub imap_port: Option<i64>,
    pub imap_secure: Option<String>,
    pub login: Option<String>,
    pub encrypted_password: Option<Vec<u8>>,
    pub encrypted_oauth_refresh_token: Option<Vec<u8>>,
    pub oauth_tenant: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct NewMailAccount {
    pub label: Option<String>,
    pub email: String,
    pub account_type: String,
    pub imap_host: Option<String>,
    pub imap_port: Option<i64>,
    pub imap_secure: Option<String>,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<i64>,
    pub smtp_secure: Option<String>,
    pub login: Option<String>,
    pub password: Option<String>,
    pub oauth_tenant: Option<String>,
    pub is_primary: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct UpdateMailAccount {
    pub id: i64,
    pub label: Option<String>,
    pub imap_host: Option<String>,
    pub imap_port: Option<i64>,
    pub imap_secure: Option<String>,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<i64>,
    pub smtp_secure: Option<String>,
    pub login: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMailIdentity {
    pub account_id: i64,
    pub name: String,
    pub email: String,
    pub reply_to: Option<String>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MailRule {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub enabled: bool,
    pub conditions: Value,
    pub conditions_logic: String,
    pub actions: Value,
    pub last_run: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewMailRule {
    pub account_id: i64,
    pub name: String,
    pub conditions: Vec<Value>,
    pub conditions_logic: String,
    pub actions: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailTask {
    pub id: i64,
    pub user_id: i64,
    pub title: String,
    pub notes: Option<String>,
    pub due_date: Option<String>,
    pub completed: bool,
    pub completed_at: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMailTask {
    pub title: String,
    pub notes: Option<String>,
    pub due_date: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMailTask {
    pub id: i64,
    pub title: String,
    pub notes: Option<String>,
    pub due_date: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskFilter {
    All,
    Pending,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushSubscription {
    pub endpoint: String,
    pub p256dh: String,
    pub auth_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VapidKeyBundle {
    pub public_b64u: String,
    pub private_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcLink {
    pub provider_hash: String,
    pub provider_name: String,
    pub linked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmimeCertificate {
    pub id: i64,
    pub account_id: i64,
    pub email: String,
    pub fingerprint: String,
    pub subject: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub has_key: bool,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSmimeCert {
    pub account_id: i64,
    pub pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSmimeP12 {
    pub account_id: i64,
    pub p12_der: Vec<u8>,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmimeImportResult {
    pub ok: bool,
    pub id: i64,
    pub email: String,
    pub fingerprint: String,
    pub not_after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmimeVerifyResult {
    pub ok: bool,
    pub verified: bool,
    pub signer_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSmimeCert {
    cert_pem: String,
    email: String,
    fingerprint: String,
    subject: String,
    not_before: Option<String>,
    not_after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmimeSigningMaterial {
    cert_pem: String,
    encrypted_key_pem: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageSearchResult {
    pub id: i64,
    pub account_id: i64,
    pub folder: String,
    pub imap_uid: i64,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub from_addr: Option<String>,
    pub from_name: Option<String>,
    pub date_ts: Option<String>,
    pub snippet: Option<String>,
    pub account_email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnifiedInboxMessage {
    pub account_id: i64,
    pub account_email: String,
    pub folder: String,
    #[serde(rename = "uid")]
    pub imap_uid: i64,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    #[serde(rename = "from")]
    pub from_display: String,
    pub from_addr: Option<String>,
    pub from_name: Option<String>,
    pub date_ts: i64,
    pub snippet: Option<String>,
    pub flags: Vec<String>,
    pub is_seen: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexedMessageBody {
    pub account_id: i64,
    pub folder: String,
    pub imap_uid: i64,
    pub subject: Option<String>,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetResult {
    pub ok: bool,
    pub username: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetRequestResult {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing)]
    pub delivery: Option<PasswordResetDelivery>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetDelivery {
    pub to: String,
    pub username: String,
    pub reset_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterUserResult {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivateServiceResult {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpSetupResult {
    pub ok: bool,
    pub secret: String,
    pub otpauth_uri: String,
    pub qr_data_url: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpActionResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl FrickmailMe {
    pub fn anonymous() -> Self {
        Self {
            ok: true,
            authenticated: false,
            username: None,
            email: None,
        }
    }

    pub fn from_session(session: &UserSession) -> Self {
        Self {
            ok: true,
            authenticated: true,
            username: Some(session.username.clone()),
            email: session.email.clone(),
        }
    }

    pub fn from_user(user: &FrickmailUser) -> Self {
        Self {
            ok: true,
            authenticated: true,
            username: Some(user.username.clone()),
            email: user.email.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SqlxUserRepository;

impl SqlxUserRepository {
    pub async fn find_by_id(pool: &AnyPool, id: i64) -> Result<Option<FrickmailUser>> {
        fetch_optional_user_by(pool, "id", id).await
    }

    pub async fn find_by_username(pool: &AnyPool, username: &str) -> Result<Option<FrickmailUser>> {
        fetch_optional_user_by(pool, "username", normalize_username(username)).await
    }

    pub async fn user_count(pool: &AnyPool) -> Result<i64> {
        sqlx::query("SELECT COUNT(*) AS count FROM frickmail_users")
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get::<i64, _>("count"))
            .map_err(db_error)
    }

    pub async fn preferences(pool: &AnyPool, user_id: i64) -> Result<Option<Value>> {
        let Some(user) = Self::find_by_id(pool, user_id).await? else {
            return Ok(None);
        };

        Ok(Some(preferences_from_settings(&user.settings)))
    }

    pub async fn totp_enabled(pool: &AnyPool, user_id: i64) -> Result<bool> {
        Ok(Self::find_by_id(pool, user_id)
            .await?
            .and_then(|user| user.totp_secret)
            .is_some_and(|secret| !secret.is_empty() && secret != "0"))
    }

    pub async fn begin_totp_setup(pool: &AnyPool, user_id: i64) -> Result<TotpSetupResult> {
        begin_totp_setup(pool, user_id).await
    }

    pub async fn confirm_totp(
        pool: &AnyPool,
        user_id: i64,
        pending_secret: String,
        code: String,
    ) -> Result<TotpActionResult> {
        confirm_totp(pool, user_id, pending_secret, code).await
    }

    pub async fn disable_totp(
        pool: &AnyPool,
        user_id: i64,
        code: String,
    ) -> Result<TotpActionResult> {
        disable_totp(pool, user_id, code).await
    }

    pub async fn verify_totp_login_code(
        pool: &AnyPool,
        user_id: i64,
        secret: &str,
        code: String,
    ) -> Result<TotpActionResult> {
        verify_totp_login_code(pool, user_id, secret, code).await
    }

    pub async fn update_preferences(
        pool: &AnyPool,
        user_id: i64,
        patch: &Value,
    ) -> Result<Option<Value>> {
        let Some(user) = Self::find_by_id(pool, user_id).await? else {
            return Ok(None);
        };

        let clean = clean_preferences_patch(patch);
        if clean.is_empty() {
            return Ok(Some(preferences_from_settings(&user.settings)));
        }

        update_settings_patch(pool, user_id, &Value::Object(clean)).await?;
        Self::preferences(pool, user_id).await
    }

    pub async fn list_mail_accounts(pool: &AnyPool, user_id: i64) -> Result<Vec<MailAccount>> {
        let mut accounts = fetch_mail_accounts(pool, user_id).await?;
        let identities = fetch_mail_identities(pool, user_id).await?;
        let mut identities_by_account = HashMap::<i64, Vec<MailIdentity>>::new();
        for identity in identities {
            identities_by_account
                .entry(identity.account_id)
                .or_default()
                .push(identity);
        }

        for account in &mut accounts {
            account.identities = identities_by_account
                .remove(&account.id)
                .unwrap_or_default();
        }

        Ok(accounts)
    }

    pub async fn get_mail_account(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
    ) -> Result<Option<MailAccount>> {
        fetch_mail_account(pool, user_id, account_id).await
    }

    pub async fn get_mail_account_settings(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
    ) -> Result<Option<Value>> {
        fetch_mail_account_settings(pool, user_id, account_id).await
    }

    pub async fn update_mail_account_settings(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
        patch: &Value,
    ) -> Result<bool> {
        update_mail_account_settings_patch(pool, user_id, account_id, patch)
            .await
            .map(|rows| rows > 0)
    }

    pub async fn set_mail_account_checkable_folder(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
        folder: &str,
        checkable: bool,
    ) -> Result<bool> {
        mutate_mail_account_checkable_folders(pool, user_id, account_id, |checkable_folders| {
            if checkable {
                checkable_folders.push(folder.to_string());
            } else if let Some(index) = checkable_folders.iter().position(|item| item == folder) {
                checkable_folders.remove(index);
            }
            deduplicate_strings(checkable_folders);
        })
        .await
    }

    pub async fn rename_mail_account_checkable_folders(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
        old_name: &str,
        new_name: &str,
        delimiter: &str,
        checkable: bool,
    ) -> Result<bool> {
        mutate_mail_account_checkable_folders(pool, user_id, account_id, |checkable_folders| {
            rename_checkable_folder_subtree(
                checkable_folders,
                old_name,
                new_name,
                delimiter,
                checkable,
            );
        })
        .await
    }

    pub async fn get_mail_account_connection_secret(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
    ) -> Result<Option<MailAccountConnectionSecret>> {
        fetch_mail_account_connection_secret(pool, user_id, account_id).await
    }

    pub async fn add_mail_account(
        pool: &AnyPool,
        user_id: i64,
        input: NewMailAccount,
        credential_key: &[u8],
    ) -> Result<i64> {
        add_mail_account(pool, user_id, input, credential_key).await
    }

    pub async fn update_mail_account(
        pool: &AnyPool,
        user_id: i64,
        input: UpdateMailAccount,
        credential_key: &[u8],
    ) -> Result<()> {
        update_mail_account(pool, user_id, input, credential_key).await
    }

    pub async fn list_mail_identities(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
    ) -> Result<Vec<MailIdentity>> {
        fetch_mail_identities_for_account(pool, user_id, account_id).await
    }

    pub async fn add_mail_identity(
        pool: &AnyPool,
        user_id: i64,
        input: NewMailIdentity,
    ) -> Result<i64> {
        add_mail_identity(pool, user_id, input).await
    }

    pub async fn delete_mail_identity(
        pool: &AnyPool,
        user_id: i64,
        identity_id: i64,
    ) -> Result<()> {
        delete_mail_identity(pool, user_id, identity_id).await
    }

    pub async fn set_default_mail_identity(
        pool: &AnyPool,
        user_id: i64,
        identity_id: i64,
    ) -> Result<()> {
        set_default_mail_identity(pool, user_id, identity_id).await
    }

    pub async fn list_mail_rules(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
    ) -> Result<Vec<MailRule>> {
        list_mail_rules(pool, user_id, account_id).await
    }

    pub async fn add_mail_rule(pool: &AnyPool, user_id: i64, input: NewMailRule) -> Result<i64> {
        add_mail_rule(pool, user_id, input).await
    }

    pub async fn delete_mail_rule(pool: &AnyPool, user_id: i64, rule_id: i64) -> Result<()> {
        delete_mail_rule(pool, user_id, rule_id).await
    }

    pub async fn toggle_mail_rule(
        pool: &AnyPool,
        user_id: i64,
        rule_id: i64,
        enabled: bool,
    ) -> Result<()> {
        toggle_mail_rule(pool, user_id, rule_id, enabled).await
    }

    pub async fn update_mail_rule_last_run(
        pool: &AnyPool,
        user_id: i64,
        rule_id: i64,
    ) -> Result<()> {
        update_mail_rule_last_run(pool, user_id, rule_id).await
    }

    pub async fn list_tasks(
        pool: &AnyPool,
        user_id: i64,
        filter: TaskFilter,
    ) -> Result<Vec<MailTask>> {
        list_tasks(pool, user_id, filter).await
    }

    pub async fn add_task(pool: &AnyPool, user_id: i64, input: NewMailTask) -> Result<i64> {
        add_task(pool, user_id, input).await
    }

    pub async fn complete_task(
        pool: &AnyPool,
        user_id: i64,
        task_id: i64,
        completed: bool,
    ) -> Result<bool> {
        complete_task(pool, user_id, task_id, completed).await
    }

    pub async fn delete_task(pool: &AnyPool, user_id: i64, task_id: i64) -> Result<bool> {
        delete_task(pool, user_id, task_id).await
    }

    pub async fn update_task(pool: &AnyPool, user_id: i64, input: UpdateMailTask) -> Result<bool> {
        update_task(pool, user_id, input).await
    }

    pub async fn upsert_push_subscription(
        pool: &AnyPool,
        user_id: i64,
        input: PushSubscription,
    ) -> Result<()> {
        upsert_push_subscription(pool, user_id, input).await
    }

    pub async fn delete_push_subscription(
        pool: &AnyPool,
        user_id: i64,
        endpoint: String,
    ) -> Result<()> {
        delete_push_subscription(pool, user_id, endpoint).await
    }

    pub async fn list_push_subscriptions(
        pool: &AnyPool,
        user_id: i64,
    ) -> Result<Vec<PushSubscription>> {
        list_push_subscriptions(pool, user_id).await
    }

    pub async fn get_or_create_vapid_public_key(pool: &AnyPool) -> Result<String> {
        get_or_create_vapid_public_key(pool).await
    }

    pub async fn get_or_create_vapid_key_bundle(pool: &AnyPool) -> Result<VapidKeyBundle> {
        get_or_create_vapid_key_bundle(pool).await
    }

    pub async fn list_oidc_links(
        pool: &AnyPool,
        user_id: i64,
        provider_name: &str,
    ) -> Result<Vec<OidcLink>> {
        list_oidc_links(pool, user_id, provider_name).await
    }

    pub async fn unlink_oidc_identity(
        pool: &AnyPool,
        user_id: i64,
        provider_hash: String,
    ) -> Result<()> {
        unlink_oidc_identity(pool, user_id, provider_hash).await
    }

    pub async fn list_smime_certs(pool: &AnyPool, user_id: i64) -> Result<Vec<SmimeCertificate>> {
        list_smime_certs(pool, user_id).await
    }

    pub async fn import_smime_cert(
        pool: &AnyPool,
        user_id: i64,
        input: NewSmimeCert,
    ) -> Result<SmimeImportResult> {
        import_smime_cert(pool, user_id, input).await
    }

    pub async fn import_smime_p12(
        pool: &AnyPool,
        user_id: i64,
        input: NewSmimeP12,
        credential_key: &[u8],
    ) -> Result<SmimeImportResult> {
        import_smime_p12(pool, user_id, input, credential_key).await
    }

    pub async fn delete_smime_cert(pool: &AnyPool, user_id: i64, cert_id: i64) -> Result<bool> {
        delete_smime_cert(pool, user_id, cert_id).await
    }

    pub async fn sign_smime_message(
        pool: &AnyPool,
        user_id: i64,
        email: &str,
        message_body: &[u8],
        credential_key: &[u8],
    ) -> Result<Vec<u8>> {
        sign_smime_message(pool, user_id, None, email, message_body, credential_key).await
    }

    /// Signs using certificate material owned by one selected mail account.
    /// Compose must not select a same-email identity/certificate from another
    /// account belonging to the same user.
    pub async fn sign_smime_message_for_account(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
        email: &str,
        message_body: &[u8],
        credential_key: &[u8],
    ) -> Result<Vec<u8>> {
        sign_smime_message(
            pool,
            user_id,
            Some(account_id),
            email,
            message_body,
            credential_key,
        )
        .await
    }

    /// Signs a bounded compose MIME entity with explicitly supplied S/MIME
    /// material. The caller is responsible for authenticating the request and
    /// applying its own request-level limits.
    pub async fn sign_smime_message_with_material(
        certificate_pem: &str,
        private_key_pem: &str,
        passphrase: &str,
        message_body: &[u8],
    ) -> Result<Vec<u8>> {
        sign_smime_message_with_material(certificate_pem, private_key_pem, passphrase, message_body)
            .await
    }

    /// Reports whether a selected-account identity has bounded stored signing
    /// material. Compose uses this to match MailSo's identity fallback before
    /// asking OpenSSL to sign.
    pub async fn has_smime_signing_material_for_account(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
        email: &str,
    ) -> Result<bool> {
        Ok(
            fetch_smime_signing_material(pool, user_id, Some(account_id), email)
                .await?
                .is_some_and(|material| {
                    material
                        .encrypted_key_pem
                        .as_deref()
                        .is_some_and(|key| !key.is_empty())
                }),
        )
    }

    pub fn verify_smime_message(message: &[u8]) -> SmimeVerifyResult {
        verify_smime_message(message)
    }

    /// Encrypts a message body for S/MIME delivery using the recipient
    /// certificates identified by `cert_tokens` (database IDs or PEM strings).
    pub async fn encrypt_smime_message(
        pool: &AnyPool,
        user_id: i64,
        cert_tokens: &[String],
        message_body: &[u8],
    ) -> Result<Vec<u8>> {
        encrypt_smime_message(pool, user_id, cert_tokens, message_body).await
    }

    pub async fn delete_mail_account(pool: &AnyPool, user_id: i64, account_id: i64) -> Result<()> {
        delete_mail_account(pool, user_id, account_id).await
    }

    pub async fn set_primary_mail_account(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
    ) -> Result<()> {
        set_primary_mail_account(pool, user_id, account_id).await
    }

    pub async fn set_mail_account_password(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
        password: String,
        credential_key: &[u8],
    ) -> Result<bool> {
        set_mail_account_password(pool, user_id, account_id, password, credential_key).await
    }

    pub async fn save_oauth_refresh_token(
        pool: &AnyPool,
        user_id: i64,
        account_type: String,
        email: String,
        token: String,
        credential_key: &[u8],
    ) -> Result<bool> {
        save_oauth_refresh_token(pool, user_id, account_type, email, token, credential_key).await
    }

    pub async fn search_messages(
        pool: &AnyPool,
        user_id: i64,
        query: String,
        limit: i64,
    ) -> Result<Vec<MessageSearchResult>> {
        search_messages(pool, user_id, query, limit).await
    }

    pub async fn unified_inbox_messages(
        pool: &AnyPool,
        user_id: i64,
        limit: i64,
    ) -> Result<Vec<UnifiedInboxMessage>> {
        unified_inbox_messages(pool, user_id, limit).await
    }

    pub async fn indexed_message_body(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
        folder: String,
        imap_uid: i64,
    ) -> Result<Option<IndexedMessageBody>> {
        indexed_message_body(pool, user_id, account_id, folder, imap_uid).await
    }

    pub async fn request_password_reset(
        pool: &AnyPool,
        username: String,
        base_url: String,
    ) -> Result<PasswordResetRequestResult> {
        request_password_reset(pool, username, base_url).await
    }

    pub async fn reset_password(
        pool: &AnyPool,
        token: String,
        password: String,
    ) -> Result<PasswordResetResult> {
        reset_password(pool, token, password).await
    }

    pub async fn register_user(
        pool: &AnyPool,
        signup_open: bool,
        username: String,
        email: Option<String>,
        password: String,
    ) -> Result<RegisterUserResult> {
        register_user(pool, signup_open, username, email, password).await
    }

    pub async fn activate_service(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
        service_type: String,
        provider: String,
        service_url: String,
    ) -> Result<ActivateServiceResult> {
        activate_service(
            pool,
            user_id,
            account_id,
            service_type,
            provider,
            service_url,
        )
        .await
    }
}

pub fn normalize_username(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(password_hash).map_err(|err| {
        FrickmailError::Upstream(format!("frickmail password hash is invalid: {err}"))
    })?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn verify_login_password(password: &str, user: Option<&FrickmailUser>) -> Result<bool> {
    let hash = user
        .map(|user| user.password_hash.as_str())
        .unwrap_or(DUMMY_PASSWORD_HASH);

    let verified = verify_password(password, hash).unwrap_or(false);
    Ok(user.is_some() && verified)
}

pub fn hash_login_password(password: &str) -> Result<String> {
    let params = Params::new(PASSWORD_HASH_MEMLIMIT_KIB, PASSWORD_HASH_OPSLIMIT, 1, None)
        .map_err(|err| FrickmailError::Upstream(format!("invalid Argon2id hash params: {err}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| FrickmailError::Upstream(format!("Frickmail password hash failed: {err}")))
}

pub fn generate_kdf_salt() -> Vec<u8> {
    let mut salt = vec![0_u8; KDF_SALT_BYTES];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn password_reset_token_hash(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

fn generic_password_reset_request_result() -> PasswordResetRequestResult {
    PasswordResetRequestResult {
        ok: true,
        message: "If the username exists and has a recovery email, a reset link has been sent."
            .to_string(),
        delivery: None,
    }
}

fn generate_password_reset_token() -> String {
    let mut token = [0_u8; 32];
    OsRng.fill_bytes(&mut token);
    URL_SAFE_NO_PAD.encode(token)
}

fn valid_recovery_email(email: &str) -> bool {
    let email = email.trim();
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.chars().any(char::is_whitespace)
}

fn build_password_reset_url(base_url: &str, token: &str) -> String {
    format!(
        "{}/?reset_token={}",
        base_url.trim_end_matches('/'),
        url_encode(token)
    )
}

fn generate_totp_secret() -> String {
    let mut secret = [0_u8; 20];
    OsRng.fill_bytes(&mut secret);
    BASE32_NOPAD.encode(&secret)
}

fn normalize_totp_code(code: &str) -> String {
    code.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn verify_totp_code_at_current_time(secret: &str, code: &str) -> Result<bool> {
    Ok(matched_totp_counter_at_current_time(secret, code)?.is_some())
}

fn matched_totp_counter_at_current_time(secret: &str, code: &str) -> Result<Option<i64>> {
    let counter = current_totp_counter();
    for offset in -1..=1 {
        let candidate = counter + offset;
        if candidate < 0 {
            continue;
        }
        if constant_time_eq(
            totp_code(secret, candidate as u64)?.as_bytes(),
            code.as_bytes(),
        ) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for i in 0..max_len {
        diff |= usize::from(*left.get(i).unwrap_or(&0) ^ *right.get(i).unwrap_or(&0));
    }
    diff == 0
}

fn current_totp_counter() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| (duration.as_secs() / 30) as i64)
        .unwrap_or_default()
}

fn totp_code(secret: &str, counter: u64) -> Result<String> {
    let secret = secret.trim().to_ascii_uppercase();
    let key = BASE32_NOPAD
        .decode(secret.as_bytes())
        .map_err(|err| FrickmailError::BadRequest(format!("invalid TOTP secret: {err}")))?;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&key)
        .map_err(|err| FrickmailError::Upstream(format!("TOTP HMAC failed: {err}")))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let value = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    Ok(format!("{:06}", value % 1_000_000))
}

fn url_encode(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn qr_data_url(input: &str) -> Result<String> {
    let code = QrCode::new(input.as_bytes())
        .map_err(|err| FrickmailError::Upstream(format!("TOTP QR generation failed: {err}")))?;
    let svg = code.render::<svg::Color>().min_dimensions(256, 256).build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(svg.as_bytes())
    ))
}

pub fn derive_credential_key(password: &str, salt: &[u8]) -> Result<[u8; CREDENTIAL_KEY_BYTES]> {
    if salt.len() != KDF_SALT_BYTES {
        return Err(FrickmailError::BadRequest(format!(
            "invalid Frickmail KDF salt length: expected {KDF_SALT_BYTES}, got {}",
            salt.len()
        )));
    }

    let params = Params::new(
        KDF_MEMLIMIT_KIB,
        KDF_OPSLIMIT,
        1,
        Some(CREDENTIAL_KEY_BYTES),
    )
    .map_err(|err| FrickmailError::Upstream(format!("invalid Argon2id KDF params: {err}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; CREDENTIAL_KEY_BYTES];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|err| FrickmailError::Upstream(format!("Frickmail KDF failed: {err}")))?;
    Ok(key)
}

#[allow(deprecated)]
pub fn encrypt_account_secret(plaintext: &str, key: &[u8]) -> Result<Vec<u8>> {
    let cipher = account_secret_cipher(key)?;
    let mut nonce = [0_u8; ACCOUNT_SECRET_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&XNonce::clone_from_slice(&nonce), plaintext.as_bytes())
        .map_err(|err| {
            FrickmailError::Upstream(format!("Frickmail credential encryption failed: {err}"))
        })?;
    let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

#[allow(deprecated)]
pub fn decrypt_account_secret(blob: &[u8], key: &[u8]) -> Result<Option<String>> {
    if blob.len() < ACCOUNT_SECRET_NONCE_BYTES {
        return Ok(None);
    }

    let cipher = account_secret_cipher(key)?;
    let (nonce, ciphertext) = blob.split_at(ACCOUNT_SECRET_NONCE_BYTES);
    let plaintext = match cipher.decrypt(&XNonce::clone_from_slice(nonce), ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => return Ok(None),
    };
    Ok(String::from_utf8(plaintext).ok())
}

fn account_secret_cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    if key.len() != CREDENTIAL_KEY_BYTES {
        return Err(FrickmailError::BadRequest(format!(
            "invalid Frickmail credential key length: expected {CREDENTIAL_KEY_BYTES}, got {}",
            key.len()
        )));
    }
    XChaCha20Poly1305::new_from_slice(key).map_err(|err| {
        FrickmailError::Upstream(format!("Frickmail credential cipher setup failed: {err}"))
    })
}

pub fn preferences_from_settings(settings: &Value) -> Value {
    let stored = settings.as_object();
    let prefs = preference_schema()
        .iter()
        .map(|spec| {
            (
                spec.key.to_string(),
                stored
                    .and_then(|settings| settings.get(spec.key))
                    .cloned()
                    .unwrap_or_else(|| spec.default.clone()),
            )
        })
        .collect();

    Value::Object(prefs)
}

pub fn clean_preferences_patch(patch: &Value) -> Map<String, Value> {
    let Some(patch) = patch.as_object() else {
        return Map::new();
    };

    let mut clean = Map::new();
    for spec in preference_schema() {
        let Some(value) = patch.get(spec.key) else {
            continue;
        };

        if value.is_null() && spec.default.is_null() {
            clean.insert(spec.key.to_string(), Value::Null);
            continue;
        }

        let value = match spec.kind {
            PreferenceKind::Int { min, max } => {
                let value = value_to_i64(value).clamp(min, max);
                Value::Number(Number::from(value))
            }
            PreferenceKind::Bool => Value::Bool(value_to_php_bool(value)),
            PreferenceKind::String { allowed } => {
                let value = value_to_php_string(value);
                if !allowed.contains(&value.as_str()) {
                    continue;
                }
                Value::String(value)
            }
            PreferenceKind::ArrayInt => {
                let Some(values) = value.as_array() else {
                    continue;
                };
                Value::Array(
                    values
                        .iter()
                        .map(|value| Value::Number(Number::from(value_to_i64(value))))
                        .collect(),
                )
            }
        };

        clean.insert(spec.key.to_string(), value);
    }

    clean
}

async fn update_settings_patch(pool: &AnyPool, user_id: i64, patch: &Value) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let query = update_settings_patch_query(&backend);

    sqlx::query(query)
        .bind(patch.to_string())
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn update_mail_account_settings_patch(
    pool: &AnyPool,
    user_id: i64,
    account_id: i64,
    patch: &Value,
) -> Result<u64> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let query = update_mail_account_settings_patch_query(&backend);

    sqlx::query(query)
        .bind(patch.to_string())
        .bind(user_id)
        .bind(account_id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
        .map_err(db_error)
}

async fn mutate_mail_account_checkable_folders<F>(
    pool: &AnyPool,
    user_id: i64,
    account_id: i64,
    mutate: F,
) -> Result<bool>
where
    F: FnOnce(&mut Vec<String>),
{
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let mut transaction = conn
        .begin_with(begin_account_primary_transaction_query(&backend))
        .await
        .map_err(db_error)?;

    sqlx::query(lock_user_account_mutations_query(&backend))
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
    let row = sqlx::query(mail_account_settings_for_update_query(&backend))
        .bind(user_id)
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db_error)?;
    let Some(row) = row else {
        transaction.commit().await.map_err(db_error)?;
        return Ok(false);
    };

    let settings_json: String = row.try_get("settings_json").map_err(db_error)?;
    let mut settings: Value = serde_json::from_str(&settings_json).map_err(json_error)?;
    let settings_object = settings.as_object_mut().ok_or_else(|| {
        FrickmailError::Upstream(
            "frickmail mail account settings JSON is not an object".to_string(),
        )
    })?;
    let mut checkable_folders =
        checkable_folders_from_setting(settings_object.get("CheckableFolder"));
    mutate(&mut checkable_folders);
    settings_object.insert(
        "CheckableFolder".to_string(),
        Value::String(serde_json::to_string(&checkable_folders).map_err(json_error)?),
    );

    sqlx::query(replace_mail_account_settings_query(&backend))
        .bind(serde_json::to_string(&settings).map_err(json_error)?)
        .bind(user_id)
        .bind(account_id)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
    transaction.commit().await.map_err(db_error)?;
    Ok(true)
}

fn checkable_folders_from_setting(setting: Option<&Value>) -> Vec<String> {
    match setting {
        Some(Value::String(encoded)) => {
            serde_json::from_str::<Vec<String>>(encoded).unwrap_or_default()
        }
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn deduplicate_strings(values: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn rename_checkable_folder_subtree(
    checkable_folders: &mut Vec<String>,
    old_name: &str,
    new_name: &str,
    delimiter: &str,
    checkable: bool,
) {
    let old_prefix = (!delimiter.is_empty()).then(|| format!("{old_name}{delimiter}"));
    let mut renamed = Vec::with_capacity(checkable_folders.len() + usize::from(checkable));
    for folder in checkable_folders.drain(..) {
        if folder == old_name {
            continue;
        }
        if let Some(suffix) = old_prefix
            .as_deref()
            .and_then(|prefix| folder.strip_prefix(prefix))
        {
            renamed.push(format!("{new_name}{delimiter}{suffix}"));
        } else {
            renamed.push(folder);
        }
    }
    if checkable {
        renamed.push(new_name.to_string());
    }
    deduplicate_strings(&mut renamed);
    *checkable_folders = renamed;
}

async fn fetch_optional_user_by<T>(
    pool: &AnyPool,
    column: &str,
    value: T,
) -> Result<Option<FrickmailUser>>
where
    T: Send + Sync + 'static,
    for<'q> T: sqlx::Encode<'q, sqlx::Any> + sqlx::Type<sqlx::Any>,
{
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let query = user_select_query(&backend, column);
    let row = sqlx::query(&query)
        .bind(value)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_error)?;

    row.map(row_to_user).transpose()
}

async fn fetch_mail_accounts(pool: &AnyPool, user_id: i64) -> Result<Vec<MailAccount>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let query = mail_accounts_query(&backend);

    sqlx::query(query)
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(row_to_mail_account)
        .collect()
}

async fn fetch_mail_account(
    pool: &AnyPool,
    user_id: i64,
    account_id: i64,
) -> Result<Option<MailAccount>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    fetch_mail_account_on_conn(&mut conn, &backend, user_id, account_id).await
}

async fn fetch_mail_account_settings(
    pool: &AnyPool,
    user_id: i64,
    account_id: i64,
) -> Result<Option<Value>> {
    if account_id <= 0 {
        return Err(FrickmailError::BadRequest(
            "Account id required".to_string(),
        ));
    }

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let row = sqlx::query(mail_account_settings_query(&backend))
        .bind(user_id)
        .bind(account_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_error)?;
    row.map(|row| {
        let settings_json: String = row.try_get("settings_json").map_err(db_error)?;
        serde_json::from_str(&settings_json).map_err(json_error)
    })
    .transpose()
}

async fn fetch_mail_account_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
    account_id: i64,
) -> Result<Option<MailAccount>> {
    sqlx::query(mail_account_query(backend))
        .bind(user_id)
        .bind(account_id)
        .fetch_optional(&mut **conn)
        .await
        .map_err(db_error)?
        .map(row_to_mail_account)
        .transpose()
}

async fn fetch_mail_account_connection_secret(
    pool: &AnyPool,
    user_id: i64,
    account_id: i64,
) -> Result<Option<MailAccountConnectionSecret>> {
    if account_id <= 0 {
        return Err(FrickmailError::BadRequest(
            "Account id required".to_string(),
        ));
    }

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query(mail_account_connection_secret_query(&backend))
        .bind(user_id)
        .bind(account_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_error)?
        .map(row_to_mail_account_connection_secret)
        .transpose()
}

async fn add_mail_account(
    pool: &AnyPool,
    user_id: i64,
    input: NewMailAccount,
    credential_key: &[u8],
) -> Result<i64> {
    let prepared = prepare_new_mail_account(input, credential_key)?;
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query(begin_account_primary_transaction_query(&backend))
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;

    let result = async {
        lock_user_account_mutations_on_conn(&mut conn, &backend, user_id).await?;
        let account_count = mail_account_count_on_conn(&mut conn, &backend, user_id).await?;
        let make_primary = account_count == 0 || prepared.request_primary;
        let account_id =
            insert_mail_account_on_conn(&mut conn, &backend, user_id, &prepared).await?;

        if make_primary {
            sqlx::query(clear_primary_mail_accounts_query(&backend))
                .bind(user_id)
                .execute(&mut *conn)
                .await
                .map_err(db_error)?;
            sqlx::query(set_primary_mail_account_query(&backend))
                .bind(user_id)
                .bind(account_id)
                .execute(&mut *conn)
                .await
                .map_err(db_error)?;
        }

        Ok(account_id)
    }
    .await;

    match result {
        Ok(account_id) => sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .map(|_| account_id)
            .map_err(db_error),
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(err)
        }
    }
}

async fn update_mail_account(
    pool: &AnyPool,
    user_id: i64,
    input: UpdateMailAccount,
    credential_key: &[u8],
) -> Result<()> {
    if input.id <= 0 {
        return Err(FrickmailError::BadRequest("Invalid account id".to_string()));
    }

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let existing = fetch_mail_account_on_conn(&mut conn, &backend, user_id, input.id)
        .await?
        .ok_or_else(|| FrickmailError::BadRequest("Account not found".to_string()))?;

    let original_label = existing.label.clone();
    let label = trim_non_empty(input.label).unwrap_or_else(|| original_label.clone());
    if existing.account_type != "imap" {
        if label != original_label {
            sqlx::query(update_mail_account_label_query(&backend))
                .bind(&label)
                .bind(user_id)
                .bind(input.id)
                .execute(&mut *conn)
                .await
                .map_err(db_error)?;
        }
        return Ok(());
    }

    let new_imap_host = trim_non_empty(input.imap_host);
    let new_smtp_host = trim_non_empty(input.smtp_host);
    validate_optional_mail_host(new_imap_host.as_deref(), "imap_host")?;
    validate_optional_mail_host(new_smtp_host.as_deref(), "smtp_host")?;
    let encrypted_password = encrypt_optional_secret(input.password, credential_key)?;
    sqlx::query(update_imap_mail_account_query(&backend))
        .bind(&label)
        .bind(new_imap_host.or(existing.imap_host))
        .bind(input.imap_port.or(existing.imap_port))
        .bind(trim_non_empty(input.imap_secure).or(existing.imap_secure))
        .bind(new_smtp_host.or(existing.smtp_host))
        .bind(input.smtp_port.or(existing.smtp_port))
        .bind(trim_non_empty(input.smtp_secure).or(existing.smtp_secure))
        .bind(trim_non_empty(input.login).or(existing.login))
        .bind(encrypted_password)
        .bind(user_id)
        .bind(input.id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn register_user(
    pool: &AnyPool,
    signup_open: bool,
    username: String,
    email: Option<String>,
    password: String,
) -> Result<RegisterUserResult> {
    let username = normalize_username(&username);
    if username.len() < 3 {
        return Err(FrickmailError::BadRequest(
            "Username must be at least 3 chars".to_string(),
        ));
    }
    if password.len() < 8 {
        return Err(FrickmailError::BadRequest(
            "Password must be at least 8 chars".to_string(),
        ));
    }
    let email = email.and_then(|value| {
        let value = value.trim().to_string();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    });

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let mysql_signup_lock = !signup_open && backend == "MySQL";
    if mysql_signup_lock {
        acquire_mysql_signup_lock(&mut conn).await?;
    }

    let begin = if !signup_open && backend == "SQLite" {
        "BEGIN IMMEDIATE"
    } else {
        "BEGIN"
    };
    if let Err(err) = sqlx::query(begin).execute(&mut *conn).await {
        if mysql_signup_lock {
            let _ = release_mysql_signup_lock(&mut conn).await;
        }
        return Err(db_error(err));
    }

    let result = async {
        if !signup_open {
            acquire_closed_signup_lock_on_conn(&mut conn, &backend).await?;
            if user_count_on_conn(&mut conn).await? > 0 {
                return Err(FrickmailError::BadRequest(
                    "Self-signup is disabled. Ask your admin or set FRICKMAIL_OPEN_SIGNUP=true."
                        .to_string(),
                ));
            }
        }
        if user_exists_by_username_on_conn(&mut conn, &backend, &username).await? {
            return Err(FrickmailError::BadRequest(
                "Username already taken".to_string(),
            ));
        }

        let password_hash = hash_login_password(&password)?;
        let kdf_salt = generate_kdf_salt();
        insert_user_on_conn(
            &mut conn,
            &backend,
            &username,
            email.as_deref(),
            &password_hash,
            &kdf_salt,
        )
        .await?;

        Ok(RegisterUserResult {
            ok: true,
            message: "Account created. Sign in to add your mail accounts.".to_string(),
        })
    }
    .await;

    match result {
        Ok(result) => {
            let commit = sqlx::query("COMMIT").execute(&mut *conn).await;
            if mysql_signup_lock {
                let _ = release_mysql_signup_lock(&mut conn).await;
            }
            commit.map_err(db_error)?;
            Ok(result)
        }
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            if mysql_signup_lock {
                let _ = release_mysql_signup_lock(&mut conn).await;
            }
            Err(err)
        }
    }
}

async fn acquire_mysql_signup_lock(conn: &mut sqlx::pool::PoolConnection<sqlx::Any>) -> Result<()> {
    let locked = sqlx::query("SELECT GET_LOCK('frickmail_register_first_user', 10) AS locked")
        .fetch_one(&mut **conn)
        .await
        .and_then(|row| row.try_get::<i64, _>("locked"))
        .map_err(db_error)?;
    if locked == 1 {
        Ok(())
    } else {
        Err(FrickmailError::Upstream(
            "frickmail user database error: could not acquire signup lock".to_string(),
        ))
    }
}

async fn release_mysql_signup_lock(conn: &mut sqlx::pool::PoolConnection<sqlx::Any>) -> Result<()> {
    sqlx::query("SELECT RELEASE_LOCK('frickmail_register_first_user')")
        .execute(&mut **conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn begin_totp_setup(pool: &AnyPool, user_id: i64) -> Result<TotpSetupResult> {
    let user = SqlxUserRepository::find_by_id(pool, user_id)
        .await?
        .ok_or(FrickmailError::Unauthorized)?;
    if user
        .totp_secret
        .as_deref()
        .is_some_and(|secret| !secret.is_empty() && secret != "0")
    {
        return Err(FrickmailError::BadRequest(
            "Two-factor authentication is already enabled. Disable it first.".to_string(),
        ));
    }

    let secret = generate_totp_secret();
    let issuer = "Frickmail";
    let otpauth_uri = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        url_encode(issuer),
        url_encode(&user.username),
        secret,
        url_encode(issuer)
    );

    Ok(TotpSetupResult {
        ok: true,
        secret,
        qr_data_url: qr_data_url(&otpauth_uri)?,
        otpauth_uri,
        message:
            "Scan the QR code (or paste the secret) into your authenticator app, then submit a code to confirm."
                .to_string(),
    })
}

async fn confirm_totp(
    pool: &AnyPool,
    user_id: i64,
    pending_secret: String,
    code: String,
) -> Result<TotpActionResult> {
    let code = normalize_totp_code(&code);
    if code.is_empty() {
        return Err(FrickmailError::BadRequest("Code required".to_string()));
    }
    if pending_secret.is_empty() {
        return Err(FrickmailError::BadRequest(
            "No pending TOTP setup. Call EnableTotp first.".to_string(),
        ));
    }
    if !verify_totp_code_at_current_time(&pending_secret, &code)? {
        return Ok(TotpActionResult {
            ok: false,
            message: None,
            error: Some("Invalid code".to_string()),
        });
    }

    update_totp_secret(pool, user_id, Some(&pending_secret)).await?;
    Ok(TotpActionResult {
        ok: true,
        message: Some("Two-factor authentication enabled.".to_string()),
        error: None,
    })
}

async fn verify_totp_login_code(
    pool: &AnyPool,
    user_id: i64,
    secret: &str,
    code: String,
) -> Result<TotpActionResult> {
    let code = normalize_totp_code(&code);
    if code.is_empty() {
        return Ok(TotpActionResult {
            ok: false,
            message: None,
            error: Some("Two-factor code required".to_string()),
        });
    }
    let Some(matched_window) = matched_totp_counter_at_current_time(secret, &code)? else {
        return Ok(TotpActionResult {
            ok: false,
            message: None,
            error: Some("Invalid two-factor code".to_string()),
        });
    };
    if !record_totp_use(pool, user_id, &code, matched_window).await? {
        return Ok(TotpActionResult {
            ok: false,
            message: None,
            error: Some("Two-factor code already used".to_string()),
        });
    }

    Ok(TotpActionResult {
        ok: true,
        message: None,
        error: None,
    })
}

async fn disable_totp(pool: &AnyPool, user_id: i64, code: String) -> Result<TotpActionResult> {
    let Some(user) = SqlxUserRepository::find_by_id(pool, user_id).await? else {
        return Err(FrickmailError::Unauthorized);
    };
    let Some(secret) = user
        .totp_secret
        .filter(|secret| !secret.is_empty() && secret != "0")
    else {
        return Ok(TotpActionResult {
            ok: true,
            message: Some("Two-factor was not enabled.".to_string()),
            error: None,
        });
    };

    let code = normalize_totp_code(&code);
    if code.is_empty() || !verify_totp_code_at_current_time(&secret, &code)? {
        return Ok(TotpActionResult {
            ok: false,
            message: None,
            error: Some(
                "A valid TOTP code is required to disable two-factor authentication.".to_string(),
            ),
        });
    }

    update_totp_secret(pool, user_id, None).await?;
    Ok(TotpActionResult {
        ok: true,
        message: Some("Two-factor authentication disabled.".to_string()),
        error: None,
    })
}

async fn update_totp_secret(pool: &AnyPool, user_id: i64, secret: Option<&str>) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let affected = sqlx::query(update_totp_secret_query(&backend))
        .bind(secret)
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map_err(db_error)?
        .rows_affected();
    if affected == 0 {
        return Err(FrickmailError::Unauthorized);
    }
    Ok(())
}

async fn record_totp_use(pool: &AnyPool, user_id: i64, code: &str, window: i64) -> Result<bool> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query(prune_totp_used_query(&backend))
        .bind(window - 2)
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;

    sqlx::query(insert_totp_used_query(&backend))
        .bind(user_id)
        .bind(code)
        .bind(window)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(db_error)
}

async fn acquire_closed_signup_lock_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
) -> Result<()> {
    if backend == "PostgreSQL" {
        sqlx::query("LOCK TABLE frickmail_users IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut **conn)
            .await
            .map_err(db_error)?;
    }
    Ok(())
}

async fn user_count_on_conn(conn: &mut sqlx::pool::PoolConnection<sqlx::Any>) -> Result<i64> {
    sqlx::query("SELECT COUNT(*) AS count FROM frickmail_users")
        .fetch_one(&mut **conn)
        .await
        .and_then(|row| row.try_get::<i64, _>("count"))
        .map_err(db_error)
}

async fn user_exists_by_username_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    username: &str,
) -> Result<bool> {
    let query = match backend {
        "PostgreSQL" => "SELECT 1 FROM frickmail_users WHERE username = $1",
        _ => "SELECT 1 FROM frickmail_users WHERE username = ?",
    };
    sqlx::query(query)
        .bind(username)
        .fetch_optional(&mut **conn)
        .await
        .map(|row| row.is_some())
        .map_err(db_error)
}

async fn insert_user_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    username: &str,
    email: Option<&str>,
    password_hash: &str,
    kdf_salt: &[u8],
) -> Result<i64> {
    let settings = json!({}).to_string();

    if matches!(backend, "PostgreSQL" | "SQLite") {
        return sqlx::query(insert_user_returning_query(backend))
            .bind(username)
            .bind(email)
            .bind(password_hash)
            .bind(kdf_salt)
            .bind(&settings)
            .fetch_one(&mut **conn)
            .await
            .and_then(|row| row.try_get("id"))
            .map_err(db_error);
    }

    sqlx::query(insert_user_query())
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(kdf_salt)
        .bind(&settings)
        .execute(&mut **conn)
        .await
        .map_err(db_error)?
        .last_insert_id()
        .ok_or_else(|| {
            FrickmailError::Upstream(
                "frickmail user database error: inserted user id is unavailable".to_string(),
            )
        })
}

async fn activate_service(
    pool: &AnyPool,
    user_id: i64,
    account_id: i64,
    service_type: String,
    provider: String,
    service_url: String,
) -> Result<ActivateServiceResult> {
    if fetch_mail_account(pool, user_id, account_id)
        .await?
        .is_none()
    {
        return Err(FrickmailError::BadRequest("Account not found".to_string()));
    }

    let service_type = service_type.trim();
    let provider = provider.trim();
    if matches!(provider, "google" | "o365") {
        let message = if service_type == "contacts" {
            "Contacts sync triggered. Open Settings -> Contacts Sync to run a full sync."
        } else {
            "Calendar sync ready. Open Settings -> Calendar to view events."
        };
        return Ok(ActivateServiceResult {
            ok: true,
            message: message.to_string(),
        });
    }

    let key = if service_type == "contacts" {
        "carddav_url"
    } else {
        "caldav_url"
    };
    update_mail_account_settings_patch(pool, user_id, account_id, &json!({ key: service_url }))
        .await?;

    Ok(ActivateServiceResult {
        ok: true,
        message: format!(
            "{} URL saved. You can configure credentials in Settings -> Accounts.",
            if service_type == "contacts" {
                "CardDAV"
            } else {
                "CalDAV"
            }
        ),
    })
}

async fn fetch_mail_identities(pool: &AnyPool, user_id: i64) -> Result<Vec<MailIdentity>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let query = mail_identities_query(&backend);

    sqlx::query(query)
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(row_to_mail_identity)
        .collect()
}

async fn fetch_mail_identities_for_account(
    pool: &AnyPool,
    user_id: i64,
    account_id: i64,
) -> Result<Vec<MailIdentity>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let query = mail_identities_for_account_query(&backend);

    sqlx::query(query)
        .bind(user_id)
        .bind(account_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(row_to_mail_identity)
        .collect()
}

async fn add_mail_identity(pool: &AnyPool, user_id: i64, input: NewMailIdentity) -> Result<i64> {
    let name = input.name.trim().to_string();
    let email = input.email.trim().to_string();
    let reply_to = input.reply_to.and_then(|value| {
        let value = value.trim().to_string();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    });

    if name.is_empty() {
        return Err(FrickmailError::BadRequest("Name is required".to_string()));
    }
    if email.is_empty() {
        return Err(FrickmailError::BadRequest("Email is required".to_string()));
    }
    if !looks_like_email_address(&email) {
        return Err(FrickmailError::BadRequest(
            "Invalid email address".to_string(),
        ));
    }

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query("BEGIN")
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;

    let result = async {
        if !mail_account_exists_on_conn(&mut conn, &backend, user_id, input.account_id).await? {
            return Err(FrickmailError::BadRequest("Account not found".to_string()));
        }

        let mut is_default = input.is_default;
        let mut set_default_after_insert = false;
        if is_default
            && mail_identity_default_exists_on_conn(&mut conn, &backend, user_id, input.account_id)
                .await?
        {
            is_default = false;
            set_default_after_insert = true;
        }

        let id = insert_mail_identity_on_conn(
            &mut conn,
            &backend,
            user_id,
            input.account_id,
            &name,
            &email,
            reply_to.as_deref(),
            is_default,
        )
        .await?;

        if set_default_after_insert {
            set_default_mail_identity_values_on_conn(&mut conn, &backend, user_id, id).await?;
        }

        Ok(id)
    }
    .await;

    match result {
        Ok(id) => sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .map(|_| id)
            .map_err(db_error),
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(err)
        }
    }
}

async fn delete_mail_identity(pool: &AnyPool, user_id: i64, identity_id: i64) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let query = delete_mail_identity_query(&backend);

    sqlx::query(query)
        .bind(user_id)
        .bind(identity_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn set_default_mail_identity(pool: &AnyPool, user_id: i64, identity_id: i64) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    set_default_mail_identity_on_conn(&mut conn, &backend, user_id, identity_id).await
}

async fn mail_account_exists_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
    account_id: i64,
) -> Result<bool> {
    let count: i64 = sqlx::query(mail_account_exists_query(backend))
        .bind(user_id)
        .bind(account_id)
        .fetch_one(&mut **conn)
        .await
        .and_then(|row| row.try_get("count"))
        .map_err(db_error)?;

    Ok(count > 0)
}

struct ActivePasswordReset {
    reset_id: i64,
    user_id: i64,
    username: String,
}

async fn active_password_reset_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    token_hash: &str,
) -> Result<Option<ActivePasswordReset>> {
    sqlx::query(active_password_reset_query(backend))
        .bind(token_hash)
        .fetch_optional(&mut **conn)
        .await
        .map_err(db_error)?
        .map(|row| {
            Ok(ActivePasswordReset {
                reset_id: row.try_get("reset_id").map_err(db_error)?,
                user_id: row.try_get("user_id").map_err(db_error)?,
                username: row.try_get("username").map_err(db_error)?,
            })
        })
        .transpose()
}

async fn mail_identity_default_exists_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
    account_id: i64,
) -> Result<bool> {
    let count: i64 = sqlx::query(mail_identity_default_exists_query(backend))
        .bind(user_id)
        .bind(account_id)
        .fetch_one(&mut **conn)
        .await
        .and_then(|row| row.try_get("count"))
        .map_err(db_error)?;

    Ok(count > 0)
}

#[allow(clippy::too_many_arguments)]
async fn insert_mail_identity_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
    account_id: i64,
    name: &str,
    email: &str,
    reply_to: Option<&str>,
    is_default: bool,
) -> Result<i64> {
    if matches!(backend, "PostgreSQL" | "SQLite") {
        return sqlx::query(insert_mail_identity_returning_query(backend))
            .bind(account_id)
            .bind(user_id)
            .bind(name)
            .bind(email)
            .bind(reply_to)
            .bind(is_default)
            .fetch_one(&mut **conn)
            .await
            .and_then(|row| row.try_get("id"))
            .map_err(db_error);
    }

    sqlx::query(insert_mail_identity_query(backend))
        .bind(account_id)
        .bind(user_id)
        .bind(name)
        .bind(email)
        .bind(reply_to)
        .bind(is_default)
        .execute(&mut **conn)
        .await
        .map_err(db_error)?
        .last_insert_id()
        .ok_or_else(|| {
            FrickmailError::Upstream(
                "frickmail user database error: inserted identity id is unavailable".to_string(),
            )
        })
}

async fn set_default_mail_identity_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
    identity_id: i64,
) -> Result<()> {
    sqlx::query("BEGIN")
        .execute(&mut **conn)
        .await
        .map_err(db_error)?;

    let result =
        set_default_mail_identity_values_on_conn(conn, backend, user_id, identity_id).await;

    match result {
        Ok(()) => sqlx::query("COMMIT")
            .execute(&mut **conn)
            .await
            .map(|_| ())
            .map_err(db_error),
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut **conn).await;
            Err(err)
        }
    }
}

async fn set_default_mail_identity_values_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
    identity_id: i64,
) -> Result<()> {
    let account_id: Option<i64> = sqlx::query(mail_identity_account_query(backend))
        .bind(identity_id)
        .bind(user_id)
        .fetch_optional(&mut **conn)
        .await
        .map_err(db_error)?
        .map(|row| row.try_get("account_id").map_err(db_error))
        .transpose()?;
    let Some(account_id) = account_id else {
        return Err(FrickmailError::BadRequest("Identity not found".to_string()));
    };

    sqlx::query(clear_default_identities_query(backend))
        .bind(account_id)
        .bind(user_id)
        .execute(&mut **conn)
        .await
        .map_err(db_error)?;

    sqlx::query(set_default_identity_query(backend))
        .bind(identity_id)
        .bind(user_id)
        .execute(&mut **conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn list_mail_rules(pool: &AnyPool, user_id: i64, account_id: i64) -> Result<Vec<MailRule>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    if !mail_account_exists_on_conn(&mut conn, &backend, user_id, account_id).await? {
        return Err(FrickmailError::BadRequest("Account not found".to_string()));
    }

    sqlx::query(mail_rules_query(&backend))
        .bind(user_id)
        .bind(account_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(row_to_mail_rule)
        .collect()
}

async fn add_mail_rule(pool: &AnyPool, user_id: i64, input: NewMailRule) -> Result<i64> {
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err(FrickmailError::BadRequest(
            "Rule name is required".to_string(),
        ));
    }

    let conditions_logic = match input.conditions_logic.as_str() {
        "all" | "any" => input.conditions_logic,
        _ => "all".to_string(),
    };
    validate_rule_conditions(&input.conditions)?;
    validate_rule_actions(&input.actions)?;

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    if !mail_account_exists_on_conn(&mut conn, &backend, user_id, input.account_id).await? {
        return Err(FrickmailError::BadRequest("Account not found".to_string()));
    }

    insert_mail_rule_on_conn(
        &mut conn,
        &backend,
        user_id,
        input.account_id,
        &name,
        &input.conditions,
        &conditions_logic,
        &input.actions,
    )
    .await
}

async fn delete_mail_rule(pool: &AnyPool, user_id: i64, rule_id: i64) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(delete_mail_rule_query(&backend))
        .bind(user_id)
        .bind(rule_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn toggle_mail_rule(pool: &AnyPool, user_id: i64, rule_id: i64, enabled: bool) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(toggle_mail_rule_query(&backend))
        .bind(if enabled { 1_i64 } else { 0_i64 })
        .bind(user_id)
        .bind(rule_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn update_mail_rule_last_run(pool: &AnyPool, user_id: i64, rule_id: i64) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(update_mail_rule_last_run_query(&backend))
        .bind(user_id)
        .bind(rule_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn list_tasks(pool: &AnyPool, user_id: i64, filter: TaskFilter) -> Result<Vec<MailTask>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let query = tasks_query(&backend, filter);
    let mut sql = sqlx::query(query).bind(user_id);
    if !matches!(filter, TaskFilter::All) {
        sql = sql.bind(matches!(filter, TaskFilter::Completed) as i64);
    }
    sql.bind(200_i64)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(row_to_mail_task)
        .collect()
}

async fn add_task(pool: &AnyPool, user_id: i64, input: NewMailTask) -> Result<i64> {
    let title = input.title.trim().to_string();
    if title.is_empty() {
        return Err(FrickmailError::BadRequest("title is required".to_string()));
    }
    let notes = optional_non_empty_string(input.notes);
    let due_date = optional_non_empty_string(input.due_date);

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    if matches!(backend.as_str(), "PostgreSQL" | "SQLite") {
        return sqlx::query(insert_task_returning_query(&backend))
            .bind(user_id)
            .bind(&title)
            .bind(notes.as_deref())
            .bind(due_date.as_deref())
            .fetch_one(&mut *conn)
            .await
            .and_then(|row| row.try_get("id"))
            .map_err(db_error);
    }

    sqlx::query(insert_task_query(&backend))
        .bind(user_id)
        .bind(&title)
        .bind(notes.as_deref())
        .bind(due_date.as_deref())
        .execute(&mut *conn)
        .await
        .map_err(db_error)?
        .last_insert_id()
        .ok_or_else(|| {
            FrickmailError::Upstream(
                "frickmail user database error: inserted task id is unavailable".to_string(),
            )
        })
}

async fn complete_task(
    pool: &AnyPool,
    user_id: i64,
    task_id: i64,
    completed: bool,
) -> Result<bool> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(complete_task_query(&backend))
        .bind(if completed { 1_i64 } else { 0_i64 })
        .bind(if completed { 1_i64 } else { 0_i64 })
        .bind(user_id)
        .bind(task_id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(db_error)
}

async fn delete_task(pool: &AnyPool, user_id: i64, task_id: i64) -> Result<bool> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(delete_task_query(&backend))
        .bind(user_id)
        .bind(task_id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(db_error)
}

async fn update_task(pool: &AnyPool, user_id: i64, input: UpdateMailTask) -> Result<bool> {
    let title = input.title.trim().to_string();
    if title.is_empty() {
        return Err(FrickmailError::BadRequest("title is required".to_string()));
    }
    let notes = optional_non_empty_string(input.notes);
    let due_date = optional_non_empty_string(input.due_date);

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(update_task_query(&backend))
        .bind(&title)
        .bind(notes.as_deref())
        .bind(due_date.as_deref())
        .bind(user_id)
        .bind(input.id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(db_error)
}

async fn upsert_push_subscription(
    pool: &AnyPool,
    user_id: i64,
    input: PushSubscription,
) -> Result<()> {
    if input.endpoint.is_empty() || input.p256dh.is_empty() || input.auth_key.is_empty() {
        return Err(FrickmailError::BadRequest(
            "Missing subscription fields".to_string(),
        ));
    }

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query(upsert_push_subscription_query(&backend))
        .bind(user_id)
        .bind(input.endpoint)
        .bind(input.p256dh)
        .bind(input.auth_key)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn delete_push_subscription(pool: &AnyPool, user_id: i64, endpoint: String) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query(delete_push_subscription_query(&backend))
        .bind(user_id)
        .bind(endpoint)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn list_push_subscriptions(pool: &AnyPool, user_id: i64) -> Result<Vec<PushSubscription>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(push_subscriptions_query(&backend))
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(row_to_push_subscription)
        .collect()
}

async fn get_or_create_vapid_public_key(pool: &AnyPool) -> Result<String> {
    get_or_create_vapid_key_bundle(pool)
        .await
        .map(|bundle| bundle.public_b64u)
}

async fn get_or_create_vapid_key_bundle(pool: &AnyPool) -> Result<VapidKeyBundle> {
    ensure_app_settings_table(pool).await?;

    if let Some(bundle) = read_vapid_key_bundle(pool).await? {
        return Ok(bundle);
    }

    let bundle = generate_vapid_key_bundle()?;
    insert_app_setting_if_absent(
        pool,
        VAPID_SETTING_KEY,
        serde_json::to_string(&bundle).map_err(json_error)?,
    )
    .await?;

    read_vapid_key_bundle(pool).await?.ok_or_else(|| {
        FrickmailError::Upstream("VAPID key creation did not persist a usable key".to_string())
    })
}

async fn read_vapid_key_bundle(pool: &AnyPool) -> Result<Option<VapidKeyBundle>> {
    let Some(value) = get_app_setting(pool, VAPID_SETTING_KEY).await? else {
        return Ok(None);
    };

    let bundle = serde_json::from_str::<VapidKeyBundle>(&value).map_err(|err| {
        FrickmailError::Upstream(format!("stored VAPID key bundle is invalid: {err}"))
    })?;
    if bundle.public_b64u.is_empty() || bundle.private_pem.is_empty() {
        return Err(FrickmailError::Upstream(
            "stored VAPID key bundle is incomplete".to_string(),
        ));
    }

    Ok(Some(bundle))
}

fn generate_vapid_key_bundle() -> Result<VapidKeyBundle> {
    let signing_key = SigningKey::random(&mut OsRng);
    let public_b64u = URL_SAFE_NO_PAD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|err| FrickmailError::Upstream(format!("VAPID key generation failed: {err}")))?
        .to_string();

    Ok(VapidKeyBundle {
        public_b64u,
        private_pem,
    })
}

async fn get_app_setting(pool: &AnyPool, key: &str) -> Result<Option<String>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query(app_setting_select_query(&backend))
        .bind(key)
        .fetch_optional(&mut *conn)
        .await
        .map(|row| row.map(|row| row.get::<String, _>("setting_value")))
        .map_err(db_error)
}

async fn ensure_app_settings_table(pool: &AnyPool) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query(app_setting_create_table_query(&backend))
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn insert_app_setting_if_absent(pool: &AnyPool, key: &str, value: String) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query(app_setting_insert_if_absent_query(&backend))
        .bind(key)
        .bind(value)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn list_oidc_links(
    pool: &AnyPool,
    user_id: i64,
    provider_name: &str,
) -> Result<Vec<OidcLink>> {
    let provider_name = oidc_provider_name(provider_name);
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(oidc_links_query(&backend))
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(|row| row_to_oidc_link(row, &provider_name))
        .collect()
}

async fn unlink_oidc_identity(pool: &AnyPool, user_id: i64, provider_hash: String) -> Result<()> {
    let provider_hash = provider_hash.trim().to_string();
    if provider_hash.is_empty() {
        return Err(FrickmailError::BadRequest(
            "provider_hash required".to_string(),
        ));
    }

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query("BEGIN")
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;

    let result = async {
        sqlx::query(delete_oidc_identity_query(&backend))
            .bind(user_id)
            .bind(provider_hash)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;

        let remaining: i64 = sqlx::query(oidc_identity_count_query(&backend))
            .bind(user_id)
            .fetch_one(&mut *conn)
            .await
            .and_then(|row| row.try_get("count"))
            .map_err(db_error)?;
        if remaining == 0 {
            sqlx::query(clear_oidc_escrow_key_query(&backend))
                .bind(user_id)
                .execute(&mut *conn)
                .await
                .map_err(db_error)?;
        }

        Ok(())
    }
    .await;

    match result {
        Ok(()) => sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(db_error),
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(err)
        }
    }
}

async fn list_smime_certs(pool: &AnyPool, user_id: i64) -> Result<Vec<SmimeCertificate>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(smime_certs_query(&backend))
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(row_to_smime_certificate)
        .collect()
}

async fn import_smime_cert(
    pool: &AnyPool,
    user_id: i64,
    input: NewSmimeCert,
) -> Result<SmimeImportResult> {
    if input.account_id <= 0 {
        return Err(FrickmailError::BadRequest(
            "account_id required".to_string(),
        ));
    }
    let pem = input.pem.trim().to_string();
    validate_smime_cert_pem_size(&pem)?;
    if fetch_mail_account(pool, user_id, input.account_id)
        .await?
        .is_none()
    {
        return Err(FrickmailError::BadRequest("Account not found".to_string()));
    }
    let parsed = run_smime_blocking("certificate import", move || parse_smime_cert(&pem)).await?;

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let id = insert_smime_cert_on_conn(
        &mut conn,
        &backend,
        user_id,
        input.account_id,
        &parsed.cert_pem,
        &parsed,
        None,
    )
    .await?;

    Ok(SmimeImportResult {
        ok: true,
        id,
        email: parsed.email,
        fingerprint: parsed.fingerprint,
        not_after: parsed.not_after,
    })
}

async fn import_smime_p12(
    pool: &AnyPool,
    user_id: i64,
    input: NewSmimeP12,
    credential_key: &[u8],
) -> Result<SmimeImportResult> {
    if input.account_id <= 0 {
        return Err(FrickmailError::BadRequest(
            "account_id required".to_string(),
        ));
    }
    if input.p12_der.is_empty() {
        return Err(FrickmailError::BadRequest("p12_b64 required".to_string()));
    }
    if input.p12_der.len() > SMIME_P12_MAX_BYTES {
        return Err(FrickmailError::BadRequest(
            "PKCS#12 bundle exceeds the safety limit".to_string(),
        ));
    }
    if fetch_mail_account(pool, user_id, input.account_id)
        .await?
        .is_none()
    {
        return Err(FrickmailError::BadRequest("Account not found".to_string()));
    }

    let p12_der = input.p12_der;
    let password = input.password;
    let (parsed, key_pem) = run_smime_blocking("PKCS#12 import", move || {
        let parsed_archive = Pkcs12::from_der(&p12_der)
            .and_then(|archive| archive.parse2(&password))
            .map_err(|_| {
                FrickmailError::BadRequest(
                    "Failed to read PKCS#12 file - wrong password or corrupt file".to_string(),
                )
            })?;
        let cert = parsed_archive.cert.ok_or_else(|| {
            FrickmailError::BadRequest("No certificate found in the PKCS#12 bundle".to_string())
        })?;
        let cert_pem = String::from_utf8(cert.to_pem().map_err(|err| {
            FrickmailError::Upstream(format!("S/MIME certificate export failed: {err}"))
        })?)
        .map_err(|err| {
            FrickmailError::Upstream(format!("S/MIME certificate PEM encoding failed: {err}"))
        })?;
        validate_smime_cert_pem_size(&cert_pem)?;
        let parsed = parse_smime_cert(&cert_pem)?;
        let key_pem = parsed_archive
            .pkey
            .map(|key| -> Result<String> {
                let key_pem = String::from_utf8(key.private_key_to_pem_pkcs8().map_err(|err| {
                    FrickmailError::Upstream(format!("S/MIME private key export failed: {err}"))
                })?)
                .map_err(|err| {
                    FrickmailError::Upstream(format!(
                        "S/MIME private key PEM encoding failed: {err}"
                    ))
                })?;
                if key_pem.len() > SMIME_PRIVATE_KEY_PEM_MAX_BYTES {
                    return Err(FrickmailError::BadRequest(
                        "S/MIME private key exceeds the safety limit".to_string(),
                    ));
                }
                Ok(key_pem)
            })
            .transpose()?;
        Ok((parsed, key_pem))
    })
    .await?;
    let encrypted_key_pem = key_pem
        .as_deref()
        .map(|key_pem| encrypt_account_secret(key_pem, credential_key))
        .transpose()?;

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let id = insert_smime_cert_on_conn(
        &mut conn,
        &backend,
        user_id,
        input.account_id,
        &parsed.cert_pem,
        &parsed,
        encrypted_key_pem,
    )
    .await?;

    Ok(SmimeImportResult {
        ok: true,
        id,
        email: parsed.email,
        fingerprint: parsed.fingerprint,
        not_after: parsed.not_after,
    })
}

fn parse_smime_cert(pem: &str) -> Result<ParsedSmimeCert> {
    let cert = X509::from_pem(pem.as_bytes())
        .map_err(|_| FrickmailError::BadRequest("Invalid PEM certificate".to_string()))?;
    let email = smime_cert_email(&cert).ok_or_else(|| {
        FrickmailError::BadRequest("Certificate does not contain an email address".to_string())
    })?;
    let fingerprint = cert
        .digest(MessageDigest::sha1())
        .map_err(|err| {
            FrickmailError::Upstream(format!("S/MIME certificate fingerprint failed: {err}"))
        })?
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let cert_pem = String::from_utf8(cert.to_pem().map_err(|err| {
        FrickmailError::Upstream(format!("S/MIME certificate export failed: {err}"))
    })?)
    .map_err(|err| {
        FrickmailError::Upstream(format!("S/MIME certificate PEM encoding failed: {err}"))
    })?;

    Ok(ParsedSmimeCert {
        cert_pem,
        email,
        fingerprint,
        subject: x509_subject_string(cert.subject_name()),
        not_before: asn1_time_to_rfc3339(cert.not_before()),
        not_after: asn1_time_to_rfc3339(cert.not_after()),
    })
}

fn smime_cert_email(cert: &X509Ref) -> Option<String> {
    cert.subject_alt_names()
        .and_then(|names| {
            names
                .iter()
                .filter_map(|name| name.email())
                .map(str::trim)
                .find(|email| looks_like_email(email))
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            x509_name_entry_text(cert.subject_name(), Nid::COMMONNAME)
                .filter(|value| looks_like_email(value))
        })
        .or_else(|| {
            x509_name_entry_text(cert.subject_name(), Nid::PKCS9_EMAILADDRESS)
                .filter(|value| looks_like_email(value))
        })
}

fn looks_like_email(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && !domain.contains('@') && domain.contains('.')
}

fn x509_name_entry_text(name: &X509NameRef, nid: Nid) -> Option<String> {
    name.entries_by_nid(nid).find_map(|entry| {
        entry
            .data()
            .as_utf8()
            .ok()
            .map(|value| value.to_string())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn x509_subject_string(name: &X509NameRef) -> String {
    name.entries()
        .filter_map(|entry| {
            let value = entry.data().as_utf8().ok()?.to_string();
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            let label = entry.object().nid().short_name().unwrap_or("UNKNOWN");
            Some(format!("{label}={value}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn asn1_time_to_rfc3339(value: &Asn1TimeRef) -> Option<String> {
    NaiveDateTime::parse_from_str(&value.to_string(), "%b %e %H:%M:%S %Y GMT")
        .ok()
        .map(|datetime| DateTime::<Utc>::from_naive_utc_and_offset(datetime, Utc).to_rfc3339())
}

async fn delete_smime_cert(pool: &AnyPool, user_id: i64, cert_id: i64) -> Result<bool> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(delete_smime_cert_query(&backend))
        .bind(user_id)
        .bind(cert_id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(db_error)
}

/// Runs bounded OpenSSL work off Tokio's async workers.  The owned permit lives
/// inside the blocking task, so a caller timeout cannot admit more crypto while
/// an already-started operation is still consuming CPU or memory.
async fn run_smime_blocking<T, F>(operation: &'static str, work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let permit = smime_crypto_semaphore()
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| FrickmailError::Upstream("S/MIME crypto admission unavailable".to_string()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| FrickmailError::Upstream(format!("S/MIME {operation} task failed")))?
}

async fn sign_smime_message(
    pool: &AnyPool,
    user_id: i64,
    account_id: Option<i64>,
    email: &str,
    message_body: &[u8],
    credential_key: &[u8],
) -> Result<Vec<u8>> {
    let email = email.trim();
    if email.is_empty() {
        return Err(FrickmailError::BadRequest("email required".to_string()));
    }
    let material = fetch_smime_signing_material(pool, user_id, account_id, email)
        .await?
        .ok_or_else(|| {
            FrickmailError::BadRequest(format!("No S/MIME certificate found for {email}"))
        })?;
    let encrypted_key = material
        .encrypted_key_pem
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            FrickmailError::BadRequest(format!("No private key stored for {email} - cannot sign"))
        })?;
    let key_pem = decrypt_account_secret(encrypted_key, credential_key)?.ok_or_else(|| {
        FrickmailError::BadRequest(
            "Failed to decrypt private key - session key mismatch".to_string(),
        )
    })?;
    validate_smime_cert_pem_size(&material.cert_pem)?;
    if key_pem.len() > SMIME_PRIVATE_KEY_PEM_MAX_BYTES {
        return Err(FrickmailError::BadRequest(
            "S/MIME private key exceeds the safety limit".to_string(),
        ));
    }
    let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::STREAM;
    let message_body = message_body.to_vec();
    let cert_pem = material.cert_pem;
    let permit = smime_crypto_semaphore()
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| FrickmailError::Upstream("S/MIME crypto admission unavailable".to_string()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let cert = X509::from_pem(cert_pem.as_bytes()).map_err(|err| {
            FrickmailError::Upstream(format!("S/MIME certificate load failed: {err}"))
        })?;
        let key = PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|err| {
            FrickmailError::BadRequest(format!("S/MIME private key load failed: {err}"))
        })?;
        let certs = Stack::new().map_err(|err| {
            FrickmailError::Upstream(format!("S/MIME certificate stack init failed: {err}"))
        })?;
        let pkcs7 = Pkcs7::sign(&cert, &key, &certs, &message_body, flags)
            .map_err(|err| FrickmailError::Upstream(format!("openssl_pkcs7_sign failed: {err}")))?;
        pkcs7
            .to_smime(&message_body, flags)
            .map_err(|err| FrickmailError::Upstream(format!("openssl_pkcs7_sign failed: {err}")))
    })
    .await
    .map_err(|_| FrickmailError::Upstream("S/MIME signing task failed".to_string()))?
}

async fn sign_smime_message_with_material(
    certificate_pem: &str,
    private_key_pem: &str,
    passphrase: &str,
    message_body: &[u8],
) -> Result<Vec<u8>> {
    validate_smime_cert_pem_size(certificate_pem)?;
    if private_key_pem.len() > SMIME_PRIVATE_KEY_PEM_MAX_BYTES {
        return Err(FrickmailError::BadRequest(
            "S/MIME private key exceeds the safety limit".to_string(),
        ));
    }
    if passphrase.len() > 4096 {
        return Err(FrickmailError::BadRequest(
            "S/MIME private-key passphrase exceeds the safety limit".to_string(),
        ));
    }
    let certificate_pem = certificate_pem.to_string();
    let private_key_pem = private_key_pem.to_string();
    let passphrase = passphrase.to_string();
    let message_body = message_body.to_vec();
    run_smime_blocking("direct signing", move || {
        let cert = X509::from_pem(certificate_pem.as_bytes()).map_err(|err| {
            FrickmailError::BadRequest(format!("S/MIME certificate load failed: {err}"))
        })?;
        let key = if passphrase.is_empty() {
            PKey::private_key_from_pem(private_key_pem.as_bytes())
        } else {
            PKey::private_key_from_pem_passphrase(private_key_pem.as_bytes(), passphrase.as_bytes())
        }
        .map_err(|err| {
            FrickmailError::BadRequest(format!("S/MIME private key load failed: {err}"))
        })?;
        let certs = Stack::new().map_err(|err| {
            FrickmailError::Upstream(format!("S/MIME certificate stack init failed: {err}"))
        })?;
        let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::STREAM;
        let pkcs7 = Pkcs7::sign(&cert, &key, &certs, &message_body, flags)
            .map_err(|err| FrickmailError::Upstream(format!("openssl_pkcs7_sign failed: {err}")))?;
        pkcs7
            .to_smime(&message_body, flags)
            .map_err(|err| FrickmailError::Upstream(format!("openssl_pkcs7_sign failed: {err}")))
    })
    .await
}

fn verify_smime_message(message: &[u8]) -> SmimeVerifyResult {
    let (pkcs7, content) = match Pkcs7::from_smime(message) {
        Ok(value) => value,
        Err(_) => {
            return SmimeVerifyResult {
                ok: true,
                verified: false,
                signer_email: None,
                error: Some("Could not parse the signed message".to_string()),
            }
        }
    };
    let certs = match Stack::new() {
        Ok(certs) => certs,
        Err(err) => {
            return SmimeVerifyResult {
                ok: true,
                verified: false,
                signer_email: None,
                error: Some(format!("Signature verification failed: {err}")),
            }
        }
    };
    let store = match X509StoreBuilder::new().and_then(|mut builder| {
        builder.set_default_paths()?;
        Ok(builder.build())
    }) {
        Ok(store) => store,
        Err(err) => {
            return SmimeVerifyResult {
                ok: true,
                verified: false,
                signer_email: None,
                error: Some(format!("Signature verification failed: {err}")),
            }
        }
    };
    let mut output = Vec::new();
    if let Err(err) = pkcs7.verify(
        &certs,
        &store,
        content.as_deref(),
        Some(&mut output),
        Pkcs7Flags::empty(),
    ) {
        return SmimeVerifyResult {
            ok: true,
            verified: false,
            signer_email: None,
            error: Some(format!("Signature verification failed: {err}")),
        };
    }
    let signer_email = pkcs7
        .signers(&certs, Pkcs7Flags::empty())
        .ok()
        .and_then(|signers| {
            if signers.is_empty() {
                None
            } else {
                smime_cert_email(&signers[0])
            }
        });

    SmimeVerifyResult {
        ok: true,
        verified: true,
        signer_email,
        error: None,
    }
}

/// Resolves bounded certificate tokens (database IDs or PEM strings) into PEM
/// material.  Parsing remains in the retained blocking crypto admission below,
/// so no caller can make an async worker run OpenSSL parsing.
async fn resolve_smime_certificate_pems(
    pool: &AnyPool,
    user_id: i64,
    cert_tokens: &[String],
) -> Result<Vec<String>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let mut cert_pems = Vec::with_capacity(cert_tokens.len());

    for token in cert_tokens {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let cert_pem = if let Ok(id) = token.parse::<i64>() {
            // Resolve by database ID
            let row = if backend == "PostgreSQL" {
                sqlx::query(
                    "SELECT cert_pem FROM frickmail_smime_certs \
                     WHERE id = $1 AND user_id = $2 AND LENGTH(cert_pem) <= $3",
                )
                .bind(id)
                .bind(user_id)
                .bind(SMIME_CERT_PEM_MAX_BYTES as i64)
                .fetch_optional(&mut *conn)
                .await
                .map_err(db_error)?
            } else {
                sqlx::query(
                    "SELECT cert_pem FROM frickmail_smime_certs \
                     WHERE id = ? AND user_id = ? AND LENGTH(cert_pem) <= ?",
                )
                .bind(id)
                .bind(user_id)
                .bind(SMIME_CERT_PEM_MAX_BYTES as i64)
                .fetch_optional(&mut *conn)
                .await
                .map_err(db_error)?
            };
            let row = row.ok_or_else(|| {
                FrickmailError::BadRequest(format!("S/MIME certificate ID {id} not found"))
            })?;
            let pem: String = row.try_get("cert_pem").map_err(db_error)?;
            pem
        } else if token.starts_with("-----BEGIN CERTIFICATE-----") {
            token.to_string()
        } else {
            // Try as a fingerprint - look up by fingerprint
            let row = if backend == "PostgreSQL" {
                sqlx::query(
                    "SELECT cert_pem FROM frickmail_smime_certs \
                             WHERE fingerprint = $1 AND user_id = $2 AND LENGTH(cert_pem) <= $3",
                )
                .bind(token)
                .bind(user_id)
                .bind(SMIME_CERT_PEM_MAX_BYTES as i64)
                .fetch_optional(&mut *conn)
                .await
                .map_err(db_error)?
            } else {
                sqlx::query(
                    "SELECT cert_pem FROM frickmail_smime_certs \
                             WHERE fingerprint = ? AND user_id = ? AND LENGTH(cert_pem) <= ?",
                )
                .bind(token)
                .bind(user_id)
                .bind(SMIME_CERT_PEM_MAX_BYTES as i64)
                .fetch_optional(&mut *conn)
                .await
                .map_err(db_error)?
            };
            match row {
                Some(row) => {
                    let pem: String = row.try_get("cert_pem").map_err(db_error)?;
                    pem
                }
                None => token.to_string(), // Assume it's a PEM string
            }
        };

        validate_smime_cert_pem_size(&cert_pem)?;
        cert_pems.push(cert_pem);
    }

    Ok(cert_pems)
}

async fn encrypt_smime_message(
    pool: &AnyPool,
    user_id: i64,
    cert_tokens: &[String],
    message_body: &[u8],
) -> Result<Vec<u8>> {
    if cert_tokens.is_empty() {
        return Err(FrickmailError::BadRequest(
            "No S/MIME certificates provided for encryption".to_string(),
        ));
    }

    let cert_pems = resolve_smime_certificate_pems(pool, user_id, cert_tokens).await?;

    if cert_pems.is_empty() {
        return Err(FrickmailError::BadRequest(
            "No valid S/MIME certificates found for encryption".to_string(),
        ));
    }

    let message_body = message_body.to_vec();
    let permit = smime_crypto_semaphore()
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| FrickmailError::Upstream("S/MIME crypto admission unavailable".to_string()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut certs = Stack::new().map_err(|err| {
            FrickmailError::Upstream(format!("S/MIME cert stack init failed: {err}"))
        })?;
        for cert_pem in cert_pems {
            let cert = X509::from_pem(cert_pem.as_bytes()).map_err(|err| {
                FrickmailError::Upstream(format!(
                    "S/MIME recipient certificate parse failed: {err}"
                ))
            })?;
            certs.push(cert).map_err(|err| {
                FrickmailError::Upstream(format!("S/MIME recipient cert stack push failed: {err}"))
            })?;
        }
        let cipher = openssl::symm::Cipher::aes_128_cbc();
        let flags = Pkcs7Flags::NOOLDMIMETYPE;
        let pkcs7 = Pkcs7::encrypt(&certs, &message_body, cipher, flags).map_err(|err| {
            FrickmailError::Upstream(format!("openssl_pkcs7_encrypt failed: {err}"))
        })?;
        pkcs7.to_smime(&message_body, flags).map_err(|err| {
            FrickmailError::Upstream(format!("openssl_pkcs7_encrypt to_smime failed: {err}"))
        })
    })
    .await
    .map_err(|_| FrickmailError::Upstream("S/MIME encryption task failed".to_string()))?
}

fn validate_smime_cert_pem_size(pem: &str) -> Result<()> {
    if pem.len() > SMIME_CERT_PEM_MAX_BYTES {
        return Err(FrickmailError::BadRequest(
            "S/MIME certificate exceeds the safety limit".to_string(),
        ));
    }
    Ok(())
}

async fn fetch_smime_signing_material(
    pool: &AnyPool,
    user_id: i64,
    account_id: Option<i64>,
    email: &str,
) -> Result<Option<SmimeSigningMaterial>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let row = if let Some(account_id) = account_id {
        sqlx::query(smime_signing_material_for_account_query(&backend))
            .bind(user_id)
            .bind(account_id)
            .bind(email)
            .bind(SMIME_CERT_PEM_MAX_BYTES as i64)
            .bind(SMIME_PRIVATE_KEY_ENCRYPTED_MAX_BYTES as i64)
            .fetch_optional(&mut *conn)
            .await
            .map_err(db_error)?
    } else {
        sqlx::query(smime_signing_material_query(&backend))
            .bind(user_id)
            .bind(email)
            .bind(SMIME_CERT_PEM_MAX_BYTES as i64)
            .bind(SMIME_PRIVATE_KEY_ENCRYPTED_MAX_BYTES as i64)
            .fetch_optional(&mut *conn)
            .await
            .map_err(db_error)?
    };
    row.map(row_to_smime_signing_material).transpose()
}

async fn delete_mail_account(pool: &AnyPool, user_id: i64, account_id: i64) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query("BEGIN")
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;

    let result = async {
        sqlx::query(delete_message_index_for_account_query(&backend))
            .bind(user_id)
            .bind(account_id)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;

        sqlx::query(delete_mail_account_query(&backend))
            .bind(user_id)
            .bind(account_id)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;

        Ok(())
    }
    .await;

    match result {
        Ok(()) => sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(db_error),
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(err)
        }
    }
}

async fn set_primary_mail_account(pool: &AnyPool, user_id: i64, account_id: i64) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query(begin_account_primary_transaction_query(&backend))
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;

    let result = async {
        lock_user_account_mutations_on_conn(&mut conn, &backend, user_id).await?;
        sqlx::query(clear_primary_mail_accounts_query(&backend))
            .bind(user_id)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;

        sqlx::query(set_primary_mail_account_query(&backend))
            .bind(user_id)
            .bind(account_id)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;

        Ok(())
    }
    .await;

    match result {
        Ok(()) => sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(db_error),
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(err)
        }
    }
}

async fn set_mail_account_password(
    pool: &AnyPool,
    user_id: i64,
    account_id: i64,
    password: String,
    credential_key: &[u8],
) -> Result<bool> {
    if account_id <= 0 {
        return Err(FrickmailError::BadRequest(
            "Account id required".to_string(),
        ));
    }
    let password = trim_required(password, "Password required")?;
    let encrypted_password = encrypt_account_secret(&password, credential_key)?;
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    if !mail_account_exists_on_conn(&mut conn, &backend, user_id, account_id).await? {
        return Err(FrickmailError::BadRequest("Account not found".to_string()));
    }

    sqlx::query(set_mail_account_password_query(&backend))
        .bind(encrypted_password)
        .bind(user_id)
        .bind(account_id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(db_error)
}

async fn save_oauth_refresh_token(
    pool: &AnyPool,
    user_id: i64,
    account_type: String,
    email: String,
    token: String,
    credential_key: &[u8],
) -> Result<bool> {
    let account_type = normalize_oauth_account_type(&account_type)?;
    let email = trim_required(email, "Missing email or token")?;
    let token = trim_required(token, "Missing email or token")?;
    let encrypted_token = encrypt_account_secret(&token, credential_key)?;
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let account_id = mail_account_id_by_email_on_conn(&mut conn, &backend, user_id, &email)
        .await?
        .ok_or_else(|| {
            FrickmailError::BadRequest(format!("Account not found for email {email}"))
        })?;

    sqlx::query(save_oauth_refresh_token_query(&backend))
        .bind(&account_type)
        .bind(encrypted_token)
        .bind(user_id)
        .bind(account_id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(db_error)
}

async fn search_messages(
    pool: &AnyPool,
    user_id: i64,
    query: String,
    limit: i64,
) -> Result<Vec<MessageSearchResult>> {
    let query = query.trim().to_string();
    if query.len() < 2 {
        return Err(FrickmailError::BadRequest("Query too short".to_string()));
    }
    let limit = limit.clamp(1, 100);

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let mut sql = sqlx::query(search_messages_query(&backend)).bind(user_id);
    sql = sql.bind(&query).bind(limit);

    sql.fetch_all(&mut *conn)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(row_to_message_search_result)
        .collect()
}

async fn unified_inbox_messages(
    pool: &AnyPool,
    user_id: i64,
    limit: i64,
) -> Result<Vec<UnifiedInboxMessage>> {
    let limit = limit.clamp(1, 100);
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    sqlx::query(unified_inbox_messages_query(&backend))
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(row_to_unified_inbox_message)
        .collect()
}

async fn indexed_message_body(
    pool: &AnyPool,
    user_id: i64,
    account_id: i64,
    folder: String,
    imap_uid: i64,
) -> Result<Option<IndexedMessageBody>> {
    if account_id <= 0 {
        return Err(FrickmailError::BadRequest(
            "account_id required".to_string(),
        ));
    }
    if imap_uid <= 0 {
        return Err(FrickmailError::BadRequest("uid required".to_string()));
    }
    let folder = folder.trim();
    if folder.is_empty() {
        return Err(FrickmailError::BadRequest("folder required".to_string()));
    }

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query(indexed_message_body_query(&backend))
        .bind(user_id)
        .bind(account_id)
        .bind(folder)
        .bind(imap_uid)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_error)?
        .map(|row| {
            Ok(IndexedMessageBody {
                account_id: row.try_get("account_id").map_err(db_error)?,
                folder: row.try_get("folder").map_err(db_error)?,
                imap_uid: row.try_get("imap_uid").map_err(db_error)?,
                subject: row.try_get("subject").map_err(db_error)?,
                snippet: row.try_get("snippet").map_err(db_error)?,
            })
        })
        .transpose()
}

async fn request_password_reset(
    pool: &AnyPool,
    username: String,
    base_url: String,
) -> Result<PasswordResetRequestResult> {
    let username = username.trim();
    if username.is_empty() {
        return Ok(generic_password_reset_request_result());
    }

    let Some(user) = SqlxUserRepository::find_by_username(pool, username).await? else {
        return Ok(generic_password_reset_request_result());
    };
    let Some(email) = user
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| valid_recovery_email(email))
    else {
        return Ok(generic_password_reset_request_result());
    };

    let token = generate_password_reset_token();
    let token_hash = password_reset_token_hash(&token);
    create_password_reset_token(pool, user.id, &token_hash).await?;

    Ok(PasswordResetRequestResult {
        delivery: Some(PasswordResetDelivery {
            to: email.to_string(),
            username: user.username,
            reset_url: build_password_reset_url(&base_url, &token),
        }),
        ..generic_password_reset_request_result()
    })
}

async fn create_password_reset_token(pool: &AnyPool, user_id: i64, token_hash: &str) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query("BEGIN")
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;

    let result = async {
        sqlx::query(delete_unused_password_resets_query(&backend))
            .bind(user_id)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;

        sqlx::query(insert_password_reset_query(&backend))
            .bind(user_id)
            .bind(token_hash)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;

        Ok(())
    }
    .await;

    match result {
        Ok(()) => sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(db_error),
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(err)
        }
    }
}

async fn reset_password(
    pool: &AnyPool,
    token: String,
    password: String,
) -> Result<PasswordResetResult> {
    if token.is_empty() {
        return Err(FrickmailError::BadRequest("Token required".to_string()));
    }
    if password.len() < 8 {
        return Err(FrickmailError::BadRequest(
            "Password must be at least 8 chars".to_string(),
        ));
    }

    let token_hash = password_reset_token_hash(&token);
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    sqlx::query("BEGIN")
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;

    let result = async {
        let reset = active_password_reset_on_conn(&mut conn, &backend, &token_hash)
            .await?
            .ok_or_else(|| FrickmailError::BadRequest("Invalid or expired token".to_string()))?;

        let consumed = sqlx::query(consume_password_reset_query(&backend))
            .bind(reset.reset_id)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?
            .rows_affected();
        if consumed != 1 {
            return Err(FrickmailError::BadRequest(
                "Invalid or expired token".to_string(),
            ));
        }

        let password_hash = hash_login_password(&password)?;
        let mut kdf_salt = vec![0_u8; KDF_SALT_BYTES];
        OsRng.fill_bytes(&mut kdf_salt);

        sqlx::query(apply_password_reset_user_query(&backend))
            .bind(&password_hash)
            .bind(&kdf_salt)
            .bind(reset.user_id)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;

        sqlx::query(clear_mail_account_credentials_query(&backend))
            .bind(reset.user_id)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;

        Ok(PasswordResetResult {
            ok: true,
            username: reset.username,
            message: "Password reset. Sign in with your new password. Linked mail-account credentials must be re-entered.".to_string(),
        })
    }
    .await;

    match result {
        Ok(result) => sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .map(|_| result)
            .map_err(db_error),
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(err)
        }
    }
}

fn validate_rule_conditions(conditions: &[Value]) -> Result<()> {
    for condition in conditions {
        let field = condition.get("field").and_then(Value::as_str).unwrap_or("");
        if !matches!(field, "from" | "subject" | "to") {
            return Err(FrickmailError::BadRequest(
                "Invalid condition field".to_string(),
            ));
        }

        let op = condition.get("op").and_then(Value::as_str).unwrap_or("");
        if !matches!(op, "contains" | "not_contains" | "equals") {
            return Err(FrickmailError::BadRequest(
                "Invalid condition operator".to_string(),
            ));
        }

        let value = condition
            .get("value")
            .map(value_to_php_string)
            .unwrap_or_default();
        if value.trim().is_empty() {
            return Err(FrickmailError::BadRequest(
                "Condition value is required".to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_rule_actions(actions: &[Value]) -> Result<()> {
    for action in actions {
        let action_type = action.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(action_type, "move" | "read" | "flag" | "delete") {
            return Err(FrickmailError::BadRequest(
                "Invalid action type".to_string(),
            ));
        }

        let folder = action
            .get("params")
            .and_then(|params| params.get("folder"))
            .map(value_to_php_string)
            .unwrap_or_default();
        if action_type == "move" && (folder.is_empty() || folder == "0") {
            return Err(FrickmailError::BadRequest(
                "Move action requires a target folder".to_string(),
            ));
        }
    }

    Ok(())
}

fn optional_non_empty_string(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn trim_non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_string();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

fn trim_required(value: String, message: &str) -> Result<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(FrickmailError::BadRequest(message.to_string()));
    }
    Ok(value)
}

struct PreparedMailAccount {
    label: String,
    email: String,
    account_type: String,
    imap_host: Option<String>,
    imap_port: Option<i64>,
    imap_secure: Option<String>,
    smtp_host: Option<String>,
    smtp_port: Option<i64>,
    smtp_secure: Option<String>,
    login: Option<String>,
    encrypted_password: Option<Vec<u8>>,
    oauth_tenant: Option<String>,
    request_primary: bool,
}

fn prepare_new_mail_account(
    input: NewMailAccount,
    credential_key: &[u8],
) -> Result<PreparedMailAccount> {
    let account_type = normalize_account_type(&input.account_type)?;
    let email = trim_required(input.email, "Email is required")?;
    let label = trim_non_empty(input.label).unwrap_or_else(|| email.clone());

    if account_type == "imap" {
        let imap_host = trim_non_empty(input.imap_host).unwrap_or_default();
        let smtp_host = trim_non_empty(input.smtp_host).unwrap_or_default();
        validate_optional_mail_host(Some(&imap_host), "imap_host")?;
        validate_optional_mail_host(Some(&smtp_host), "smtp_host")?;
        return Ok(PreparedMailAccount {
            label,
            email: email.clone(),
            account_type,
            imap_host: Some(imap_host),
            imap_port: Some(input.imap_port.unwrap_or(993)),
            imap_secure: Some(
                trim_non_empty(input.imap_secure).unwrap_or_else(|| "SSL".to_string()),
            ),
            smtp_host: Some(smtp_host),
            smtp_port: Some(input.smtp_port.unwrap_or(465)),
            smtp_secure: Some(
                trim_non_empty(input.smtp_secure).unwrap_or_else(|| "SSL".to_string()),
            ),
            login: Some(trim_non_empty(input.login).unwrap_or(email)),
            encrypted_password: encrypt_optional_secret(input.password, credential_key)?,
            oauth_tenant: None,
            request_primary: input.is_primary,
        });
    }

    let oauth_tenant = if account_type == "o365" {
        Some(trim_non_empty(input.oauth_tenant).unwrap_or_else(|| "common".to_string()))
    } else {
        None
    };
    Ok(PreparedMailAccount {
        label,
        email: email.clone(),
        account_type,
        imap_host: None,
        imap_port: None,
        imap_secure: None,
        smtp_host: None,
        smtp_port: None,
        smtp_secure: None,
        login: Some(email),
        encrypted_password: None,
        oauth_tenant,
        request_primary: input.is_primary,
    })
}

fn normalize_account_type(account_type: &str) -> Result<String> {
    let account_type = account_type.trim().to_ascii_lowercase();
    match account_type.as_str() {
        "imap" | "gmail" | "o365" => Ok(account_type),
        _ => Err(FrickmailError::BadRequest("Unknown type".to_string())),
    }
}

fn normalize_oauth_account_type(account_type: &str) -> Result<String> {
    let account_type = account_type.trim().to_ascii_lowercase();
    match account_type.as_str() {
        "gmail" | "o365" => Ok(account_type),
        _ => Err(FrickmailError::BadRequest("Unknown type".to_string())),
    }
}

fn encrypt_optional_secret(
    secret: Option<String>,
    credential_key: &[u8],
) -> Result<Option<Vec<u8>>> {
    trim_non_empty(secret)
        .map(|secret| encrypt_account_secret(&secret, credential_key))
        .transpose()
}

fn validate_optional_mail_host(host: Option<&str>, field: &str) -> Result<()> {
    let Some(host) = host else {
        return Ok(());
    };
    let host = host.trim();
    if host.is_empty() {
        return Ok(());
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return validate_public_mail_ip(ip, field);
    }
    if host.contains(':') {
        return Err(FrickmailError::BadRequest(format!(
            "{field} must be a hostname or IP address without a port"
        )));
    }

    let resolved = match (host, 0_u16).to_socket_addrs() {
        Ok(resolved) => resolved,
        // PHP's gethostbyname() also stores unresolved hostnames. The bridge
        // will fail later if the hostname never resolves.
        Err(_) => return Ok(()),
    };

    for address in resolved {
        validate_public_mail_ip(address.ip(), field)?;
    }
    Ok(())
}

fn validate_public_mail_ip(ip: IpAddr, field: &str) -> Result<()> {
    if mail_ip_is_reserved(ip) {
        return Err(FrickmailError::BadRequest(format!(
            "{field} resolves to a reserved IP address and cannot be used."
        )));
    }
    Ok(())
}

fn mail_ip_is_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ipv4_is_reserved(ip),
        IpAddr::V6(ip) => ipv6_is_reserved(ip),
    }
}

fn ipv4_is_reserved(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || ip.is_unspecified()
        || octets[0] == 0
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
}

fn ipv6_is_reserved(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return ipv4_is_reserved(mapped);
    }

    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

async fn lock_user_account_mutations_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
) -> Result<()> {
    sqlx::query(lock_user_account_mutations_query(backend))
        .bind(user_id)
        .execute(&mut **conn)
        .await
        .map(|_| ())
        .map_err(db_error)
}

async fn mail_account_count_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
) -> Result<i64> {
    sqlx::query(mail_account_count_query(backend))
        .bind(user_id)
        .fetch_one(&mut **conn)
        .await
        .and_then(|row| row.try_get("count"))
        .map_err(db_error)
}

async fn mail_account_id_by_email_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
    email: &str,
) -> Result<Option<i64>> {
    sqlx::query(mail_account_id_by_email_query(backend))
        .bind(user_id)
        .bind(email)
        .fetch_optional(&mut **conn)
        .await
        .map_err(db_error)?
        .map(|row| row.try_get("id").map_err(db_error))
        .transpose()
}

async fn insert_mail_account_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
    account: &PreparedMailAccount,
) -> Result<i64> {
    if matches!(backend, "PostgreSQL" | "SQLite") {
        return bind_insert_mail_account(
            sqlx::query(insert_mail_account_returning_query(backend)),
            user_id,
            account,
        )
        .fetch_one(&mut **conn)
        .await
        .and_then(|row| row.try_get("id"))
        .map_err(db_error);
    }

    bind_insert_mail_account(
        sqlx::query(insert_mail_account_query(backend)),
        user_id,
        account,
    )
    .execute(&mut **conn)
    .await
    .map_err(db_error)?
    .last_insert_id()
    .ok_or_else(|| {
        FrickmailError::Upstream(
            "frickmail user database error: inserted mail account id is unavailable".to_string(),
        )
    })
}

fn bind_insert_mail_account<'q>(
    query: sqlx::query::Query<'q, sqlx::Any, sqlx::any::AnyArguments<'q>>,
    user_id: i64,
    account: &'q PreparedMailAccount,
) -> sqlx::query::Query<'q, sqlx::Any, sqlx::any::AnyArguments<'q>> {
    query
        .bind(user_id)
        .bind(&account.label)
        .bind(&account.email)
        .bind(&account.account_type)
        .bind(&account.imap_host)
        .bind(account.imap_port)
        .bind(&account.imap_secure)
        .bind(&account.smtp_host)
        .bind(account.smtp_port)
        .bind(&account.smtp_secure)
        .bind(&account.login)
        .bind(&account.encrypted_password)
        .bind(None::<Vec<u8>>)
        .bind(&account.oauth_tenant)
        .bind(0_i64)
}

async fn insert_smime_cert_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
    account_id: i64,
    pem: &str,
    parsed: &ParsedSmimeCert,
    encrypted_key_pem: Option<Vec<u8>>,
) -> Result<i64> {
    if matches!(backend, "PostgreSQL" | "SQLite") {
        return bind_insert_smime_cert(
            sqlx::query(insert_smime_cert_returning_query(backend)),
            user_id,
            account_id,
            pem,
            parsed,
            encrypted_key_pem,
        )
        .fetch_one(&mut **conn)
        .await
        .and_then(|row| row.try_get("id"))
        .map_err(db_error);
    }

    bind_insert_smime_cert(
        sqlx::query(insert_smime_cert_query(backend)),
        user_id,
        account_id,
        pem,
        parsed,
        encrypted_key_pem,
    )
    .execute(&mut **conn)
    .await
    .map_err(db_error)?
    .last_insert_id()
    .ok_or_else(|| {
        FrickmailError::Upstream(
            "frickmail user database error: inserted S/MIME certificate id is unavailable"
                .to_string(),
        )
    })
}

fn bind_insert_smime_cert<'q>(
    query: sqlx::query::Query<'q, sqlx::Any, sqlx::any::AnyArguments<'q>>,
    user_id: i64,
    account_id: i64,
    pem: &'q str,
    parsed: &'q ParsedSmimeCert,
    encrypted_key_pem: Option<Vec<u8>>,
) -> sqlx::query::Query<'q, sqlx::Any, sqlx::any::AnyArguments<'q>> {
    query
        .bind(user_id)
        .bind(account_id)
        .bind(&parsed.email)
        .bind(pem)
        .bind(encrypted_key_pem)
        .bind(&parsed.fingerprint)
        .bind(&parsed.subject)
        .bind(&parsed.not_before)
        .bind(&parsed.not_after)
}

#[allow(clippy::too_many_arguments)]
async fn insert_mail_rule_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    backend: &str,
    user_id: i64,
    account_id: i64,
    name: &str,
    conditions: &[Value],
    conditions_logic: &str,
    actions: &[Value],
) -> Result<i64> {
    let conditions_payload = json!({
        "conditions": conditions,
        "conditions_logic": conditions_logic,
    })
    .to_string();
    let actions_payload = Value::Array(actions.to_vec()).to_string();

    if matches!(backend, "PostgreSQL" | "SQLite") {
        return sqlx::query(insert_mail_rule_returning_query(backend))
            .bind(user_id)
            .bind(account_id)
            .bind(name)
            .bind(&conditions_payload)
            .bind(&actions_payload)
            .fetch_one(&mut **conn)
            .await
            .and_then(|row| row.try_get("id"))
            .map_err(db_error);
    }

    sqlx::query(insert_mail_rule_query(backend))
        .bind(user_id)
        .bind(account_id)
        .bind(name)
        .bind(&conditions_payload)
        .bind(&actions_payload)
        .execute(&mut **conn)
        .await
        .map_err(db_error)?
        .last_insert_id()
        .ok_or_else(|| {
            FrickmailError::Upstream(
                "frickmail user database error: inserted rule id is unavailable".to_string(),
            )
        })
}

fn user_select_query(backend: &str, column: &str) -> String {
    let placeholder = match backend {
        "PostgreSQL" => "$1",
        _ => "?",
    };
    let settings = match backend {
        "MySQL" => "CAST(settings AS CHAR)",
        _ => "CAST(settings AS TEXT)",
    };

    format!(
        "SELECT id, username, email, password_hash, kdf_salt, {settings} AS settings_json, \
         totp_secret, oidc_escrow_key FROM frickmail_users WHERE {column} = {placeholder}"
    )
}

fn insert_user_returning_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_users (username, email, password_hash, kdf_salt, settings) \
             VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING id"
        }
        _ => {
            "INSERT INTO frickmail_users (username, email, password_hash, kdf_salt, settings) \
             VALUES (?, ?, ?, ?, ?) RETURNING id"
        }
    }
}

fn insert_user_query() -> &'static str {
    "INSERT INTO frickmail_users (username, email, password_hash, kdf_salt, settings) \
     VALUES (?, ?, ?, ?, ?)"
}

fn mail_accounts_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT id, label, email, type, imap_host, imap_port, imap_secure, smtp_host, smtp_port, smtp_secure, login, \
                CASE WHEN is_primary THEN 1 ELSE 0 END AS is_primary \
             FROM frickmail_mail_accounts WHERE user_id = $1 ORDER BY is_primary DESC, id ASC"
        }
        _ => {
            "SELECT id, label, email, type, imap_host, imap_port, imap_secure, smtp_host, smtp_port, smtp_secure, login, \
                CASE WHEN is_primary THEN 1 ELSE 0 END AS is_primary \
             FROM frickmail_mail_accounts WHERE user_id = ? ORDER BY is_primary DESC, id ASC"
        }
    }
}

fn mail_account_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT id, label, email, type, imap_host, imap_port, imap_secure, smtp_host, smtp_port, smtp_secure, login, \
                CASE WHEN is_primary THEN 1 ELSE 0 END AS is_primary \
             FROM frickmail_mail_accounts WHERE user_id = $1 AND id = $2"
        }
        _ => {
            "SELECT id, label, email, type, imap_host, imap_port, imap_secure, smtp_host, smtp_port, smtp_secure, login, \
                CASE WHEN is_primary THEN 1 ELSE 0 END AS is_primary \
             FROM frickmail_mail_accounts WHERE user_id = ? AND id = ?"
        }
    }
}

fn mail_account_settings_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT CAST(settings AS TEXT) AS settings_json FROM frickmail_mail_accounts WHERE user_id = $1 AND id = $2"
        }
        "MySQL" => {
            "SELECT CAST(settings AS CHAR) AS settings_json FROM frickmail_mail_accounts WHERE user_id = ? AND id = ?"
        }
        _ => {
            "SELECT CAST(settings AS TEXT) AS settings_json FROM frickmail_mail_accounts WHERE user_id = ? AND id = ?"
        }
    }
}

fn mail_account_connection_secret_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT id, email, type, imap_host, imap_port, imap_secure, login, encrypted_password, encrypted_oauth_refresh_token, oauth_tenant \
             FROM frickmail_mail_accounts WHERE user_id = $1 AND id = $2"
        }
        _ => {
            "SELECT id, email, type, imap_host, imap_port, imap_secure, login, encrypted_password, encrypted_oauth_refresh_token, oauth_tenant \
             FROM frickmail_mail_accounts WHERE user_id = ? AND id = ?"
        }
    }
}

fn mail_account_count_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => "SELECT COUNT(*) AS count FROM frickmail_mail_accounts WHERE user_id = $1",
        _ => "SELECT COUNT(*) AS count FROM frickmail_mail_accounts WHERE user_id = ?",
    }
}

fn begin_account_primary_transaction_query(backend: &str) -> &'static str {
    match backend {
        "SQLite" => "BEGIN IMMEDIATE",
        _ => "BEGIN",
    }
}

fn lock_user_account_mutations_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => "SELECT id FROM frickmail_users WHERE id = $1 FOR UPDATE",
        "MySQL" => "SELECT id FROM frickmail_users WHERE id = ? FOR UPDATE",
        _ => "SELECT id FROM frickmail_users WHERE id = ?",
    }
}

fn mail_account_id_by_email_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT id FROM frickmail_mail_accounts WHERE user_id = $1 AND lower(email) = lower($2) LIMIT 1"
        }
        _ => {
            "SELECT id FROM frickmail_mail_accounts WHERE user_id = ? AND lower(email) = lower(?) LIMIT 1"
        }
    }
}

fn insert_mail_account_returning_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_mail_accounts \
                (user_id, label, email, type, imap_host, imap_port, imap_secure, smtp_host, smtp_port, smtp_secure, login, \
                 encrypted_password, encrypted_oauth_refresh_token, oauth_tenant, is_primary) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, ($15 <> 0)) RETURNING id"
        }
        _ => {
            "INSERT INTO frickmail_mail_accounts \
                (user_id, label, email, type, imap_host, imap_port, imap_secure, smtp_host, smtp_port, smtp_secure, login, \
                 encrypted_password, encrypted_oauth_refresh_token, oauth_tenant, is_primary) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id"
        }
    }
}

fn insert_mail_account_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_mail_accounts \
                (user_id, label, email, type, imap_host, imap_port, imap_secure, smtp_host, smtp_port, smtp_secure, login, \
                 encrypted_password, encrypted_oauth_refresh_token, oauth_tenant, is_primary) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, ($15 <> 0))"
        }
        _ => {
            "INSERT INTO frickmail_mail_accounts \
                (user_id, label, email, type, imap_host, imap_port, imap_secure, smtp_host, smtp_port, smtp_secure, login, \
                 encrypted_password, encrypted_oauth_refresh_token, oauth_tenant, is_primary) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        }
    }
}

fn update_mail_account_label_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_mail_accounts SET label = $1, updated_at = NOW() WHERE user_id = $2 AND id = $3"
        }
        _ => {
            "UPDATE frickmail_mail_accounts SET label = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND id = ?"
        }
    }
}

fn update_imap_mail_account_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_mail_accounts \
                SET label = $1, imap_host = $2, imap_port = $3, imap_secure = $4, \
                    smtp_host = $5, smtp_port = $6, smtp_secure = $7, login = $8, \
                    encrypted_password = COALESCE($9, encrypted_password), updated_at = NOW() \
              WHERE user_id = $10 AND id = $11"
        }
        _ => {
            "UPDATE frickmail_mail_accounts \
                SET label = ?, imap_host = ?, imap_port = ?, imap_secure = ?, \
                    smtp_host = ?, smtp_port = ?, smtp_secure = ?, login = ?, \
                    encrypted_password = COALESCE(?, encrypted_password), updated_at = CURRENT_TIMESTAMP \
              WHERE user_id = ? AND id = ?"
        }
    }
}

fn mail_identities_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT id, account_id, name, email, reply_to, \
                CASE WHEN is_default THEN 1 ELSE 0 END AS is_default \
             FROM frickmail_identities WHERE user_id = $1 ORDER BY account_id ASC, is_default DESC, id ASC"
        }
        _ => {
            "SELECT id, account_id, name, email, reply_to, \
                CASE WHEN is_default THEN 1 ELSE 0 END AS is_default \
             FROM frickmail_identities WHERE user_id = ? ORDER BY account_id ASC, is_default DESC, id ASC"
        }
    }
}

fn mail_identities_for_account_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT id, account_id, name, email, reply_to, \
                CASE WHEN is_default THEN 1 ELSE 0 END AS is_default \
             FROM frickmail_identities WHERE user_id = $1 AND account_id = $2 ORDER BY is_default DESC, id ASC"
        }
        _ => {
            "SELECT id, account_id, name, email, reply_to, \
                CASE WHEN is_default THEN 1 ELSE 0 END AS is_default \
             FROM frickmail_identities WHERE user_id = ? AND account_id = ? ORDER BY is_default DESC, id ASC"
        }
    }
}

fn mail_account_exists_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT COUNT(*) AS count FROM frickmail_mail_accounts WHERE user_id = $1 AND id = $2"
        }
        _ => "SELECT COUNT(*) AS count FROM frickmail_mail_accounts WHERE user_id = ? AND id = ?",
    }
}

fn mail_identity_default_exists_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT COUNT(*) AS count FROM frickmail_identities WHERE user_id = $1 AND account_id = $2 AND is_default = TRUE"
        }
        _ => {
            "SELECT COUNT(*) AS count FROM frickmail_identities WHERE user_id = ? AND account_id = ? AND is_default = 1"
        }
    }
}

fn insert_mail_identity_returning_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_identities (account_id, user_id, name, email, reply_to, is_default) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id"
        }
        _ => {
            "INSERT INTO frickmail_identities (account_id, user_id, name, email, reply_to, is_default) \
             VALUES (?, ?, ?, ?, ?, ?) RETURNING id"
        }
    }
}

fn insert_mail_identity_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_identities (account_id, user_id, name, email, reply_to, is_default) \
             VALUES ($1, $2, $3, $4, $5, $6)"
        }
        _ => {
            "INSERT INTO frickmail_identities (account_id, user_id, name, email, reply_to, is_default) \
             VALUES (?, ?, ?, ?, ?, ?)"
        }
    }
}

fn delete_mail_identity_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => "DELETE FROM frickmail_identities WHERE user_id = $1 AND id = $2",
        _ => "DELETE FROM frickmail_identities WHERE user_id = ? AND id = ?",
    }
}

fn mail_identity_account_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT account_id FROM frickmail_identities WHERE id = $1 AND user_id = $2"
        }
        _ => "SELECT account_id FROM frickmail_identities WHERE id = ? AND user_id = ?",
    }
}

fn clear_default_identities_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_identities SET is_default = FALSE WHERE account_id = $1 AND user_id = $2"
        }
        _ => "UPDATE frickmail_identities SET is_default = 0 WHERE account_id = ? AND user_id = ?",
    }
}

fn set_default_identity_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_identities SET is_default = TRUE WHERE id = $1 AND user_id = $2"
        }
        _ => "UPDATE frickmail_identities SET is_default = 1 WHERE id = ? AND user_id = ?",
    }
}

fn mail_rules_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT id, account_id, name, conditions::text AS conditions_json, actions::text AS actions_json, \
                CASE WHEN enabled THEN 1 ELSE 0 END AS enabled, last_run::text AS last_run \
             FROM frickmail_rules WHERE user_id = $1 AND account_id = $2 ORDER BY id ASC"
        }
        "MySQL" => {
            "SELECT id, account_id, name, CAST(conditions AS CHAR) AS conditions_json, CAST(actions AS CHAR) AS actions_json, \
                CASE WHEN enabled THEN 1 ELSE 0 END AS enabled, CAST(last_run AS CHAR) AS last_run \
             FROM frickmail_rules WHERE user_id = ? AND account_id = ? ORDER BY id ASC"
        }
        _ => {
            "SELECT id, account_id, name, CAST(conditions AS TEXT) AS conditions_json, CAST(actions AS TEXT) AS actions_json, \
                CASE WHEN enabled THEN 1 ELSE 0 END AS enabled, CAST(last_run AS TEXT) AS last_run \
             FROM frickmail_rules WHERE user_id = ? AND account_id = ? ORDER BY id ASC"
        }
    }
}

fn tasks_query(backend: &str, filter: TaskFilter) -> &'static str {
    match (backend, filter) {
        ("PostgreSQL", TaskFilter::All) => {
            "SELECT id, user_id, title, notes, due_date::text AS due_date, \
                CASE WHEN completed THEN 1 ELSE 0 END AS completed, completed_at::text AS completed_at, \
                created_at::text AS created_at, updated_at::text AS updated_at \
             FROM frickmail_tasks WHERE user_id = $1 \
             ORDER BY completed ASC, due_date ASC NULLS LAST, created_at ASC LIMIT $2"
        }
        ("PostgreSQL", _) => {
            "SELECT id, user_id, title, notes, due_date::text AS due_date, \
                CASE WHEN completed THEN 1 ELSE 0 END AS completed, completed_at::text AS completed_at, \
                created_at::text AS created_at, updated_at::text AS updated_at \
             FROM frickmail_tasks WHERE user_id = $1 AND completed = ($2 <> 0) \
             ORDER BY due_date ASC NULLS LAST, created_at ASC LIMIT $3"
        }
        ("MySQL", TaskFilter::All) => {
            "SELECT id, user_id, title, notes, CAST(due_date AS CHAR) AS due_date, \
                CASE WHEN completed THEN 1 ELSE 0 END AS completed, CAST(completed_at AS CHAR) AS completed_at, \
                CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at \
             FROM frickmail_tasks WHERE user_id = ? \
             ORDER BY completed ASC, due_date IS NULL ASC, due_date ASC, created_at ASC LIMIT ?"
        }
        ("MySQL", _) => {
            "SELECT id, user_id, title, notes, CAST(due_date AS CHAR) AS due_date, \
                CASE WHEN completed THEN 1 ELSE 0 END AS completed, CAST(completed_at AS CHAR) AS completed_at, \
                CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at \
             FROM frickmail_tasks WHERE user_id = ? AND completed = ? \
             ORDER BY due_date IS NULL ASC, due_date ASC, created_at ASC LIMIT ?"
        }
        (_, TaskFilter::All) => {
            "SELECT id, user_id, title, notes, CAST(due_date AS TEXT) AS due_date, \
                CASE WHEN completed THEN 1 ELSE 0 END AS completed, CAST(completed_at AS TEXT) AS completed_at, \
                CAST(created_at AS TEXT) AS created_at, CAST(updated_at AS TEXT) AS updated_at \
             FROM frickmail_tasks WHERE user_id = ? \
             ORDER BY completed ASC, due_date IS NULL ASC, due_date ASC, created_at ASC LIMIT ?"
        }
        (_, _) => {
            "SELECT id, user_id, title, notes, CAST(due_date AS TEXT) AS due_date, \
                CASE WHEN completed THEN 1 ELSE 0 END AS completed, CAST(completed_at AS TEXT) AS completed_at, \
                CAST(created_at AS TEXT) AS created_at, CAST(updated_at AS TEXT) AS updated_at \
             FROM frickmail_tasks WHERE user_id = ? AND completed = ? \
             ORDER BY due_date IS NULL ASC, due_date ASC, created_at ASC LIMIT ?"
        }
    }
}

fn insert_task_returning_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_tasks (user_id, title, notes, due_date) \
             VALUES ($1, $2, $3, $4::date) RETURNING id"
        }
        _ => {
            "INSERT INTO frickmail_tasks (user_id, title, notes, due_date) \
             VALUES (?, ?, ?, ?) RETURNING id"
        }
    }
}

fn insert_task_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_tasks (user_id, title, notes, due_date) \
             VALUES ($1, $2, $3, $4::date)"
        }
        _ => {
            "INSERT INTO frickmail_tasks (user_id, title, notes, due_date) \
             VALUES (?, ?, ?, ?)"
        }
    }
}

fn complete_task_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_tasks \
                SET completed = ($1 <> 0), completed_at = CASE WHEN $2 <> 0 THEN NOW() ELSE NULL END, updated_at = NOW() \
              WHERE user_id = $3 AND id = $4"
        }
        _ => {
            "UPDATE frickmail_tasks \
                SET completed = ?, completed_at = CASE WHEN ? <> 0 THEN CURRENT_TIMESTAMP ELSE NULL END, updated_at = CURRENT_TIMESTAMP \
              WHERE user_id = ? AND id = ?"
        }
    }
}

fn delete_task_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => "DELETE FROM frickmail_tasks WHERE user_id = $1 AND id = $2",
        _ => "DELETE FROM frickmail_tasks WHERE user_id = ? AND id = ?",
    }
}

fn update_task_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_tasks SET title = $1, notes = $2, due_date = $3::date, updated_at = NOW() \
              WHERE user_id = $4 AND id = $5"
        }
        _ => {
            "UPDATE frickmail_tasks SET title = ?, notes = ?, due_date = ?, updated_at = CURRENT_TIMESTAMP \
              WHERE user_id = ? AND id = ?"
        }
    }
}

fn upsert_push_subscription_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_push_subscriptions (user_id, endpoint, p256dh, auth_key) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (user_id, endpoint) DO UPDATE SET p256dh = EXCLUDED.p256dh, auth_key = EXCLUDED.auth_key"
        }
        "MySQL" => {
            "INSERT INTO frickmail_push_subscriptions (user_id, endpoint, p256dh, auth_key) \
             VALUES (?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE p256dh = VALUES(p256dh), auth_key = VALUES(auth_key)"
        }
        _ => {
            "INSERT INTO frickmail_push_subscriptions (user_id, endpoint, p256dh, auth_key) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (user_id, endpoint) DO UPDATE SET p256dh = excluded.p256dh, auth_key = excluded.auth_key"
        }
    }
}

fn delete_push_subscription_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "DELETE FROM frickmail_push_subscriptions WHERE user_id = $1 AND endpoint = $2"
        }
        _ => "DELETE FROM frickmail_push_subscriptions WHERE user_id = ? AND endpoint = ?",
    }
}

fn push_subscriptions_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT endpoint, p256dh, auth_key FROM frickmail_push_subscriptions WHERE user_id = $1 ORDER BY id ASC"
        }
        _ => {
            "SELECT endpoint, p256dh, auth_key FROM frickmail_push_subscriptions WHERE user_id = ? ORDER BY id ASC"
        }
    }
}

fn app_setting_select_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => "SELECT setting_value FROM frickmail_app_settings WHERE setting_key = $1",
        _ => "SELECT setting_value FROM frickmail_app_settings WHERE setting_key = ?",
    }
}

fn app_setting_create_table_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "CREATE TABLE IF NOT EXISTS frickmail_app_settings (
                setting_key   VARCHAR(191) PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"
        }
        "MySQL" => {
            "CREATE TABLE IF NOT EXISTS frickmail_app_settings (
                setting_key   VARCHAR(191) PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )"
        }
        _ => {
            "CREATE TABLE IF NOT EXISTS frickmail_app_settings (
                setting_key   VARCHAR(191) PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"
        }
    }
}

fn app_setting_insert_if_absent_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_app_settings (setting_key, setting_value) \
             VALUES ($1, $2) \
             ON CONFLICT (setting_key) DO NOTHING"
        }
        "MySQL" => {
            "INSERT IGNORE INTO frickmail_app_settings (setting_key, setting_value) \
             VALUES (?, ?)"
        }
        _ => {
            "INSERT OR IGNORE INTO frickmail_app_settings (setting_key, setting_value) \
             VALUES (?, ?)"
        }
    }
}

fn oidc_links_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT provider_hash, linked_at::text AS linked_at \
             FROM frickmail_oidc_identities WHERE user_id = $1 ORDER BY linked_at DESC"
        }
        "MySQL" => {
            "SELECT provider_hash, CAST(linked_at AS CHAR) AS linked_at \
             FROM frickmail_oidc_identities WHERE user_id = ? ORDER BY linked_at DESC"
        }
        _ => {
            "SELECT provider_hash, CAST(linked_at AS TEXT) AS linked_at \
             FROM frickmail_oidc_identities WHERE user_id = ? ORDER BY linked_at DESC"
        }
    }
}

fn delete_oidc_identity_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "DELETE FROM frickmail_oidc_identities WHERE user_id = $1 AND provider_hash = $2"
        }
        _ => "DELETE FROM frickmail_oidc_identities WHERE user_id = ? AND provider_hash = ?",
    }
}

fn oidc_identity_count_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT COUNT(*) AS count FROM frickmail_oidc_identities WHERE user_id = $1"
        }
        _ => "SELECT COUNT(*) AS count FROM frickmail_oidc_identities WHERE user_id = ?",
    }
}

fn clear_oidc_escrow_key_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_users SET oidc_escrow_key = NULL, updated_at = NOW() WHERE id = $1"
        }
        _ => {
            "UPDATE frickmail_users SET oidc_escrow_key = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        }
    }
}

fn smime_certs_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT id, account_id, email, fingerprint, COALESCE(subject, '') AS subject, \
                not_before::text AS not_before, not_after::text AS not_after, \
                CASE WHEN encrypted_key_pem IS NULL OR octet_length(encrypted_key_pem) = 0 THEN 0 ELSE 1 END AS has_key, \
                created_at::text AS created_at \
             FROM frickmail_smime_certs WHERE user_id = $1 ORDER BY created_at DESC"
        }
        "MySQL" => {
            "SELECT id, account_id, email, fingerprint, COALESCE(subject, '') AS subject, \
                CAST(not_before AS CHAR) AS not_before, CAST(not_after AS CHAR) AS not_after, \
                CASE WHEN encrypted_key_pem IS NULL OR LENGTH(encrypted_key_pem) = 0 THEN 0 ELSE 1 END AS has_key, \
                CAST(created_at AS CHAR) AS created_at \
             FROM frickmail_smime_certs WHERE user_id = ? ORDER BY created_at DESC"
        }
        _ => {
            "SELECT id, account_id, email, fingerprint, COALESCE(subject, '') AS subject, \
                CAST(not_before AS TEXT) AS not_before, CAST(not_after AS TEXT) AS not_after, \
                CASE WHEN encrypted_key_pem IS NULL OR length(encrypted_key_pem) = 0 THEN 0 ELSE 1 END AS has_key, \
                CAST(created_at AS TEXT) AS created_at \
             FROM frickmail_smime_certs WHERE user_id = ? ORDER BY created_at DESC"
        }
    }
}

fn insert_smime_cert_returning_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_smime_certs \
                (user_id, account_id, email, cert_pem, encrypted_key_pem, fingerprint, subject, not_before, not_after) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id"
        }
        _ => {
            "INSERT INTO frickmail_smime_certs \
                (user_id, account_id, email, cert_pem, encrypted_key_pem, fingerprint, subject, not_before, not_after) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id"
        }
    }
}

fn insert_smime_cert_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_smime_certs \
                (user_id, account_id, email, cert_pem, encrypted_key_pem, fingerprint, subject, not_before, not_after) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        }
        _ => {
            "INSERT INTO frickmail_smime_certs \
                (user_id, account_id, email, cert_pem, encrypted_key_pem, fingerprint, subject, not_before, not_after) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        }
    }
}

fn delete_smime_cert_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => "DELETE FROM frickmail_smime_certs WHERE user_id = $1 AND id = $2",
        _ => "DELETE FROM frickmail_smime_certs WHERE user_id = ? AND id = ?",
    }
}

fn smime_signing_material_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT cert_pem, encrypted_key_pem FROM frickmail_smime_certs \
             WHERE user_id = $1 AND email = $2 \
               AND LENGTH(cert_pem) <= $3 \
               AND (encrypted_key_pem IS NULL OR octet_length(encrypted_key_pem) <= $4) \
             ORDER BY created_at DESC, id DESC LIMIT 1"
        }
        _ => {
            "SELECT cert_pem, encrypted_key_pem FROM frickmail_smime_certs \
             WHERE user_id = ? AND email = ? \
               AND LENGTH(cert_pem) <= ? \
               AND (encrypted_key_pem IS NULL OR LENGTH(encrypted_key_pem) <= ?) \
             ORDER BY created_at DESC, id DESC LIMIT 1"
        }
    }
}

fn smime_signing_material_for_account_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT cert_pem, encrypted_key_pem FROM frickmail_smime_certs \
             WHERE user_id = $1 AND account_id = $2 AND email = $3 \
               AND LENGTH(cert_pem) <= $4 \
               AND (encrypted_key_pem IS NULL OR octet_length(encrypted_key_pem) <= $5) \
             ORDER BY created_at DESC, id DESC LIMIT 1"
        }
        _ => {
            "SELECT cert_pem, encrypted_key_pem FROM frickmail_smime_certs \
             WHERE user_id = ? AND account_id = ? AND email = ? \
               AND LENGTH(cert_pem) <= ? \
               AND (encrypted_key_pem IS NULL OR LENGTH(encrypted_key_pem) <= ?) \
             ORDER BY created_at DESC, id DESC LIMIT 1"
        }
    }
}

fn delete_message_index_for_account_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "DELETE FROM frickmail_message_index WHERE user_id = $1 AND account_id = $2"
        }
        _ => "DELETE FROM frickmail_message_index WHERE user_id = ? AND account_id = ?",
    }
}

fn delete_mail_account_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => "DELETE FROM frickmail_mail_accounts WHERE user_id = $1 AND id = $2",
        _ => "DELETE FROM frickmail_mail_accounts WHERE user_id = ? AND id = ?",
    }
}

fn clear_primary_mail_accounts_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => "UPDATE frickmail_mail_accounts SET is_primary = FALSE WHERE user_id = $1",
        _ => "UPDATE frickmail_mail_accounts SET is_primary = 0 WHERE user_id = ?",
    }
}

fn set_primary_mail_account_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_mail_accounts SET is_primary = TRUE WHERE user_id = $1 AND id = $2"
        }
        _ => "UPDATE frickmail_mail_accounts SET is_primary = 1 WHERE user_id = ? AND id = ?",
    }
}

fn set_mail_account_password_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_mail_accounts \
                SET encrypted_password = $1, updated_at = NOW() \
              WHERE user_id = $2 AND id = $3"
        }
        _ => {
            "UPDATE frickmail_mail_accounts \
                SET encrypted_password = ?, updated_at = CURRENT_TIMESTAMP \
              WHERE user_id = ? AND id = ?"
        }
    }
}

fn save_oauth_refresh_token_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_mail_accounts \
                SET type = $1, encrypted_oauth_refresh_token = $2, updated_at = NOW() \
              WHERE user_id = $3 AND id = $4"
        }
        _ => {
            "UPDATE frickmail_mail_accounts \
                SET type = ?, encrypted_oauth_refresh_token = ?, updated_at = CURRENT_TIMESTAMP \
              WHERE user_id = ? AND id = ?"
        }
    }
}

fn search_messages_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT mi.id, mi.account_id, mi.folder, mi.imap_uid, mi.message_id, \
                mi.subject, mi.from_addr, mi.from_name, mi.date_ts::text AS date_ts, \
                mi.snippet, ma.email AS account_email \
             FROM frickmail_message_index mi \
             JOIN frickmail_mail_accounts ma ON ma.id = mi.account_id AND ma.user_id = mi.user_id \
             WHERE mi.user_id = $1 AND mi.tsv @@ plainto_tsquery('simple', $2) \
             ORDER BY mi.date_ts DESC NULLS LAST LIMIT $3"
        }
        "MySQL" => {
            "SELECT mi.id, mi.account_id, mi.folder, mi.imap_uid, mi.message_id, \
                mi.subject, mi.from_addr, mi.from_name, CAST(mi.date_ts AS CHAR) AS date_ts, \
                mi.snippet, ma.email AS account_email \
             FROM frickmail_message_index mi \
             JOIN frickmail_mail_accounts ma ON ma.id = mi.account_id AND ma.user_id = mi.user_id \
             WHERE mi.user_id = ? \
               AND LOCATE(LOWER(?), LOWER(CONCAT_WS(' ', COALESCE(mi.subject, ''), COALESCE(mi.from_name, ''), COALESCE(mi.from_addr, ''), COALESCE(mi.snippet, '')))) > 0 \
             ORDER BY mi.date_ts IS NULL ASC, mi.date_ts DESC LIMIT ?"
        }
        _ => {
            "SELECT mi.id, mi.account_id, mi.folder, mi.imap_uid, mi.message_id, \
                mi.subject, mi.from_addr, mi.from_name, CAST(mi.date_ts AS TEXT) AS date_ts, \
                mi.snippet, ma.email AS account_email \
             FROM frickmail_message_index mi \
             JOIN frickmail_mail_accounts ma ON ma.id = mi.account_id AND ma.user_id = mi.user_id \
             WHERE mi.user_id = ? \
               AND instr(lower(COALESCE(mi.subject, '') || ' ' || COALESCE(mi.from_name, '') || ' ' || COALESCE(mi.from_addr, '') || ' ' || COALESCE(mi.snippet, '')), lower(?)) > 0 \
             ORDER BY mi.date_ts IS NULL ASC, mi.date_ts DESC LIMIT ?"
        }
    }
}

fn unified_inbox_messages_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT mi.account_id, ma.email AS account_email, mi.folder, mi.imap_uid, \
                mi.message_id, mi.subject, mi.from_addr, mi.from_name, \
                mi.date_ts::text AS date_ts, mi.snippet \
             FROM frickmail_message_index mi \
             JOIN frickmail_mail_accounts ma ON ma.id = mi.account_id AND ma.user_id = mi.user_id \
             WHERE mi.user_id = $1 AND mi.folder = 'INBOX' \
               AND ma.type = 'imap' \
               AND ma.encrypted_password IS NOT NULL \
               AND octet_length(ma.encrypted_password) > 0 \
             ORDER BY mi.date_ts DESC NULLS LAST, mi.imap_uid DESC LIMIT $2"
        }
        "MySQL" => {
            "SELECT mi.account_id, ma.email AS account_email, mi.folder, mi.imap_uid, \
                mi.message_id, mi.subject, mi.from_addr, mi.from_name, \
                CAST(mi.date_ts AS CHAR) AS date_ts, mi.snippet \
             FROM frickmail_message_index mi \
             JOIN frickmail_mail_accounts ma ON ma.id = mi.account_id AND ma.user_id = mi.user_id \
             WHERE mi.user_id = ? AND mi.folder = 'INBOX' \
               AND ma.type = 'imap' \
               AND ma.encrypted_password IS NOT NULL \
               AND LENGTH(ma.encrypted_password) > 0 \
             ORDER BY mi.date_ts IS NULL ASC, mi.date_ts DESC, mi.imap_uid DESC LIMIT ?"
        }
        _ => {
            "SELECT mi.account_id, ma.email AS account_email, mi.folder, mi.imap_uid, \
                mi.message_id, mi.subject, mi.from_addr, mi.from_name, \
                CAST(mi.date_ts AS TEXT) AS date_ts, mi.snippet \
             FROM frickmail_message_index mi \
             JOIN frickmail_mail_accounts ma ON ma.id = mi.account_id AND ma.user_id = mi.user_id \
             WHERE mi.user_id = ? AND mi.folder = 'INBOX' \
               AND ma.type = 'imap' \
               AND ma.encrypted_password IS NOT NULL \
               AND length(ma.encrypted_password) > 0 \
             ORDER BY mi.date_ts IS NULL ASC, mi.date_ts DESC, mi.imap_uid DESC LIMIT ?"
        }
    }
}

fn indexed_message_body_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT mi.account_id, mi.folder, mi.imap_uid, mi.subject, mi.snippet \
             FROM frickmail_message_index mi \
             JOIN frickmail_mail_accounts ma ON ma.id = mi.account_id AND ma.user_id = mi.user_id \
             WHERE mi.user_id = $1 AND mi.account_id = $2 AND mi.folder = $3 AND mi.imap_uid = $4"
        }
        _ => {
            "SELECT mi.account_id, mi.folder, mi.imap_uid, mi.subject, mi.snippet \
             FROM frickmail_message_index mi \
             JOIN frickmail_mail_accounts ma ON ma.id = mi.account_id AND ma.user_id = mi.user_id \
             WHERE mi.user_id = ? AND mi.account_id = ? AND mi.folder = ? AND mi.imap_uid = ?"
        }
    }
}

fn active_password_reset_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT r.id AS reset_id, r.user_id, u.username \
             FROM frickmail_password_resets r \
             JOIN frickmail_users u ON u.id = r.user_id \
             WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.expires_at > NOW() \
             LIMIT 1"
        }
        _ => {
            "SELECT r.id AS reset_id, r.user_id, u.username \
             FROM frickmail_password_resets r \
             JOIN frickmail_users u ON u.id = r.user_id \
             WHERE r.token_hash = ? AND r.used_at IS NULL AND r.expires_at > CURRENT_TIMESTAMP \
             LIMIT 1"
        }
    }
}

fn delete_unused_password_resets_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "DELETE FROM frickmail_password_resets WHERE user_id = $1 AND used_at IS NULL"
        }
        _ => "DELETE FROM frickmail_password_resets WHERE user_id = ? AND used_at IS NULL",
    }
}

fn insert_password_reset_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_password_resets (user_id, token_hash, expires_at) \
             VALUES ($1, $2, NOW() + INTERVAL '1800 seconds')"
        }
        "MySQL" => {
            "INSERT INTO frickmail_password_resets (user_id, token_hash, expires_at) \
             VALUES (?, ?, DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 1800 SECOND))"
        }
        _ => {
            "INSERT INTO frickmail_password_resets (user_id, token_hash, expires_at) \
             VALUES (?, ?, datetime(CURRENT_TIMESTAMP, '+1800 seconds'))"
        }
    }
}

fn apply_password_reset_user_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_users \
             SET password_hash = $1, kdf_salt = $2, updated_at = NOW() \
             WHERE id = $3"
        }
        "MySQL" => {
            "UPDATE frickmail_users \
             SET password_hash = ?, kdf_salt = ?, updated_at = CURRENT_TIMESTAMP \
             WHERE id = ?"
        }
        _ => {
            "UPDATE frickmail_users \
             SET password_hash = ?, kdf_salt = ?, updated_at = CURRENT_TIMESTAMP \
             WHERE id = ?"
        }
    }
}

fn clear_mail_account_credentials_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_mail_accounts \
             SET encrypted_password = NULL, encrypted_oauth_refresh_token = NULL, updated_at = NOW() \
             WHERE user_id = $1"
        }
        _ => {
            "UPDATE frickmail_mail_accounts \
             SET encrypted_password = NULL, encrypted_oauth_refresh_token = NULL, updated_at = CURRENT_TIMESTAMP \
             WHERE user_id = ?"
        }
    }
}

fn update_totp_secret_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_users SET totp_secret = $1, updated_at = NOW() WHERE id = $2"
        }
        _ => {
            "UPDATE frickmail_users SET totp_secret = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        }
    }
}

fn prune_totp_used_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => "DELETE FROM frickmail_totp_used WHERE \"window\" < $1",
        "MySQL" => "DELETE FROM frickmail_totp_used WHERE `window` < ?",
        _ => "DELETE FROM frickmail_totp_used WHERE \"window\" < ?",
    }
}

fn insert_totp_used_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_totp_used (user_id, code, \"window\") \
             VALUES ($1, $2, $3) \
             ON CONFLICT DO NOTHING"
        }
        "MySQL" => {
            "INSERT IGNORE INTO frickmail_totp_used (user_id, code, `window`) \
             VALUES (?, ?, ?)"
        }
        _ => {
            "INSERT OR IGNORE INTO frickmail_totp_used (user_id, code, \"window\") \
             VALUES (?, ?, ?)"
        }
    }
}

fn consume_password_reset_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_password_resets SET used_at = NOW() WHERE id = $1 AND used_at IS NULL"
        }
        _ => {
            "UPDATE frickmail_password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_at IS NULL"
        }
    }
}

fn insert_mail_rule_returning_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_rules (user_id, account_id, name, conditions, actions) \
             VALUES ($1, $2, $3, $4::jsonb, $5::jsonb) RETURNING id"
        }
        _ => {
            "INSERT INTO frickmail_rules (user_id, account_id, name, conditions, actions) \
             VALUES (?, ?, ?, ?, ?) RETURNING id"
        }
    }
}

fn insert_mail_rule_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "INSERT INTO frickmail_rules (user_id, account_id, name, conditions, actions) \
             VALUES ($1, $2, $3, $4::jsonb, $5::jsonb)"
        }
        _ => {
            "INSERT INTO frickmail_rules (user_id, account_id, name, conditions, actions) \
             VALUES (?, ?, ?, ?, ?)"
        }
    }
}

fn delete_mail_rule_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => "DELETE FROM frickmail_rules WHERE user_id = $1 AND id = $2",
        _ => "DELETE FROM frickmail_rules WHERE user_id = ? AND id = ?",
    }
}

fn toggle_mail_rule_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_rules SET enabled = ($1 <> 0) WHERE user_id = $2 AND id = $3"
        }
        _ => "UPDATE frickmail_rules SET enabled = ? WHERE user_id = ? AND id = ?",
    }
}

fn update_mail_rule_last_run_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_rules SET last_run = CURRENT_TIMESTAMP WHERE user_id = $1 AND id = $2"
        }
        _ => "UPDATE frickmail_rules SET last_run = CURRENT_TIMESTAMP WHERE user_id = ? AND id = ?",
    }
}

fn update_settings_patch_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_users SET settings = settings || $1::jsonb, updated_at = NOW() WHERE id = $2"
        }
        "MySQL" => {
            "UPDATE frickmail_users SET settings = JSON_MERGE_PATCH(COALESCE(settings, JSON_OBJECT()), CAST(? AS JSON)), updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        }
        _ => {
            "UPDATE frickmail_users SET settings = json_patch(COALESCE(settings, '{}'), ?), updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        }
    }
}

fn update_mail_account_settings_patch_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_mail_accounts SET settings = COALESCE(settings, '{}'::jsonb) || $1::jsonb, updated_at = NOW() WHERE user_id = $2 AND id = $3"
        }
        "MySQL" => {
            "UPDATE frickmail_mail_accounts SET settings = JSON_MERGE_PATCH(COALESCE(settings, JSON_OBJECT()), CAST(? AS JSON)), updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND id = ?"
        }
        _ => {
            "UPDATE frickmail_mail_accounts SET settings = json_patch(COALESCE(settings, '{}'), ?), updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND id = ?"
        }
    }
}

fn mail_account_settings_for_update_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "SELECT CAST(settings AS TEXT) AS settings_json FROM frickmail_mail_accounts WHERE user_id = $1 AND id = $2 FOR UPDATE"
        }
        "MySQL" => {
            "SELECT CAST(settings AS CHAR) AS settings_json FROM frickmail_mail_accounts WHERE user_id = ? AND id = ? FOR UPDATE"
        }
        _ => {
            "SELECT CAST(settings AS TEXT) AS settings_json FROM frickmail_mail_accounts WHERE user_id = ? AND id = ?"
        }
    }
}

fn replace_mail_account_settings_query(backend: &str) -> &'static str {
    match backend {
        "PostgreSQL" => {
            "UPDATE frickmail_mail_accounts SET settings = $1::jsonb, updated_at = NOW() WHERE user_id = $2 AND id = $3"
        }
        "MySQL" => {
            "UPDATE frickmail_mail_accounts SET settings = CAST(? AS JSON), updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND id = ?"
        }
        _ => {
            "UPDATE frickmail_mail_accounts SET settings = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND id = ?"
        }
    }
}

fn row_to_mail_account(row: sqlx::any::AnyRow) -> Result<MailAccount> {
    Ok(MailAccount {
        id: row.try_get("id").map_err(db_error)?,
        label: row.try_get("label").map_err(db_error)?,
        email: row.try_get("email").map_err(db_error)?,
        account_type: row.try_get("type").map_err(db_error)?,
        imap_host: row.try_get("imap_host").map_err(db_error)?,
        imap_port: row.try_get("imap_port").map_err(db_error)?,
        imap_secure: row.try_get("imap_secure").map_err(db_error)?,
        smtp_host: row.try_get("smtp_host").map_err(db_error)?,
        smtp_port: row.try_get("smtp_port").map_err(db_error)?,
        smtp_secure: row.try_get("smtp_secure").map_err(db_error)?,
        login: row.try_get("login").map_err(db_error)?,
        is_primary: int_flag(&row, "is_primary")?,
        identities: Vec::new(),
    })
}

fn row_to_mail_account_connection_secret(
    row: sqlx::any::AnyRow,
) -> Result<MailAccountConnectionSecret> {
    Ok(MailAccountConnectionSecret {
        id: row.try_get("id").map_err(db_error)?,
        email: row.try_get("email").map_err(db_error)?,
        account_type: row.try_get("type").map_err(db_error)?,
        imap_host: row.try_get("imap_host").map_err(db_error)?,
        imap_port: row.try_get("imap_port").map_err(db_error)?,
        imap_secure: row.try_get("imap_secure").map_err(db_error)?,
        login: row.try_get("login").map_err(db_error)?,
        encrypted_password: row.try_get("encrypted_password").map_err(db_error)?,
        encrypted_oauth_refresh_token: row
            .try_get("encrypted_oauth_refresh_token")
            .map_err(db_error)?,
        oauth_tenant: row.try_get("oauth_tenant").map_err(db_error)?,
    })
}

fn row_to_mail_identity(row: sqlx::any::AnyRow) -> Result<MailIdentity> {
    Ok(MailIdentity {
        id: row.try_get("id").map_err(db_error)?,
        account_id: row.try_get("account_id").map_err(db_error)?,
        name: row.try_get("name").map_err(db_error)?,
        email: row.try_get("email").map_err(db_error)?,
        reply_to: row.try_get("reply_to").map_err(db_error)?,
        is_default: int_flag(&row, "is_default")?,
    })
}

fn row_to_mail_rule(row: sqlx::any::AnyRow) -> Result<MailRule> {
    let conditions_json: Option<String> = row.try_get("conditions_json").map_err(db_error)?;
    let actions_json: Option<String> = row.try_get("actions_json").map_err(db_error)?;
    let conditions_payload = json_or_empty_object(conditions_json.as_deref());

    Ok(MailRule {
        id: row.try_get("id").map_err(db_error)?,
        account_id: row.try_get("account_id").map_err(db_error)?,
        name: row.try_get("name").map_err(db_error)?,
        enabled: int_flag(&row, "enabled")?,
        conditions: conditions_payload
            .get("conditions")
            .cloned()
            .unwrap_or_else(|| json!([])),
        conditions_logic: conditions_payload
            .get("conditions_logic")
            .and_then(Value::as_str)
            .unwrap_or("all")
            .to_string(),
        actions: json_or_empty_array(actions_json.as_deref()),
        last_run: row.try_get("last_run").map_err(db_error)?,
    })
}

fn row_to_mail_task(row: sqlx::any::AnyRow) -> Result<MailTask> {
    Ok(MailTask {
        id: row.try_get("id").map_err(db_error)?,
        user_id: row.try_get("user_id").map_err(db_error)?,
        title: row.try_get("title").map_err(db_error)?,
        notes: row.try_get("notes").map_err(db_error)?,
        due_date: row.try_get("due_date").map_err(db_error)?,
        completed: int_flag(&row, "completed")?,
        completed_at: row.try_get("completed_at").map_err(db_error)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        updated_at: row.try_get("updated_at").map_err(db_error)?,
    })
}

fn row_to_oidc_link(row: sqlx::any::AnyRow, provider_name: &str) -> Result<OidcLink> {
    Ok(OidcLink {
        provider_hash: row.try_get("provider_hash").map_err(db_error)?,
        provider_name: provider_name.to_string(),
        linked_at: row.try_get("linked_at").map_err(db_error)?,
    })
}

fn row_to_push_subscription(row: sqlx::any::AnyRow) -> Result<PushSubscription> {
    Ok(PushSubscription {
        endpoint: row.try_get("endpoint").map_err(db_error)?,
        p256dh: row.try_get("p256dh").map_err(db_error)?,
        auth_key: row.try_get("auth_key").map_err(db_error)?,
    })
}

fn row_to_smime_certificate(row: sqlx::any::AnyRow) -> Result<SmimeCertificate> {
    Ok(SmimeCertificate {
        id: row.try_get("id").map_err(db_error)?,
        account_id: row.try_get("account_id").map_err(db_error)?,
        email: row.try_get("email").map_err(db_error)?,
        fingerprint: row.try_get("fingerprint").map_err(db_error)?,
        subject: row.try_get("subject").map_err(db_error)?,
        not_before: row.try_get("not_before").map_err(db_error)?,
        not_after: row.try_get("not_after").map_err(db_error)?,
        has_key: int_flag(&row, "has_key")?,
        created_at: row.try_get("created_at").map_err(db_error)?,
    })
}

fn row_to_smime_signing_material(row: sqlx::any::AnyRow) -> Result<SmimeSigningMaterial> {
    Ok(SmimeSigningMaterial {
        cert_pem: row.try_get("cert_pem").map_err(db_error)?,
        encrypted_key_pem: row.try_get("encrypted_key_pem").map_err(db_error)?,
    })
}

fn row_to_message_search_result(row: sqlx::any::AnyRow) -> Result<MessageSearchResult> {
    Ok(MessageSearchResult {
        id: row.try_get("id").map_err(db_error)?,
        account_id: row.try_get("account_id").map_err(db_error)?,
        folder: row.try_get("folder").map_err(db_error)?,
        imap_uid: row.try_get("imap_uid").map_err(db_error)?,
        message_id: row.try_get("message_id").map_err(db_error)?,
        subject: row.try_get("subject").map_err(db_error)?,
        from_addr: row.try_get("from_addr").map_err(db_error)?,
        from_name: row.try_get("from_name").map_err(db_error)?,
        date_ts: row.try_get("date_ts").map_err(db_error)?,
        snippet: row.try_get("snippet").map_err(db_error)?,
        account_email: row.try_get("account_email").map_err(db_error)?,
    })
}

fn row_to_unified_inbox_message(row: sqlx::any::AnyRow) -> Result<UnifiedInboxMessage> {
    let from_name: Option<String> = row.try_get("from_name").map_err(db_error)?;
    let from_addr: Option<String> = row.try_get("from_addr").map_err(db_error)?;
    let from_display = from_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or(from_addr.as_deref())
        .unwrap_or_default()
        .to_string();
    let date_value: Option<String> = row.try_get("date_ts").map_err(db_error)?;

    Ok(UnifiedInboxMessage {
        account_id: row.try_get("account_id").map_err(db_error)?,
        account_email: row.try_get("account_email").map_err(db_error)?,
        folder: row.try_get("folder").map_err(db_error)?,
        imap_uid: row.try_get("imap_uid").map_err(db_error)?,
        message_id: row.try_get("message_id").map_err(db_error)?,
        subject: row.try_get("subject").map_err(db_error)?,
        from_display,
        from_addr,
        from_name,
        date_ts: normalize_message_epoch(date_value.as_deref()),
        snippet: row.try_get("snippet").map_err(db_error)?,
        flags: Vec::new(),
        is_seen: true,
    })
}

fn normalize_message_epoch(value: Option<&str>) -> i64 {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return 0;
    };
    if let Ok(epoch) = value.parse::<i64>() {
        return epoch;
    }
    if let Ok(datetime) = DateTime::parse_from_rfc3339(value) {
        return datetime.timestamp();
    }
    if let Some(normalized) = normalize_db_timestamp_for_rfc3339(value) {
        if let Ok(datetime) = DateTime::parse_from_rfc3339(&normalized) {
            return datetime.timestamp();
        }
    }
    for format in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(datetime) = NaiveDateTime::parse_from_str(value, format) {
            return DateTime::<Utc>::from_naive_utc_and_offset(datetime, Utc).timestamp();
        }
    }
    0
}

fn normalize_db_timestamp_for_rfc3339(value: &str) -> Option<String> {
    let mut value = value.replacen(' ', "T", 1);
    let bytes = value.as_bytes();
    if bytes.len() >= 3 {
        let offset = &bytes[bytes.len() - 3..];
        if matches!(offset[0], b'+' | b'-')
            && offset[1].is_ascii_digit()
            && offset[2].is_ascii_digit()
        {
            value.push_str(":00");
            return Some(value);
        }
    }
    if bytes.len() >= 5 {
        let offset = &bytes[bytes.len() - 5..];
        if matches!(offset[0], b'+' | b'-') && offset[1..].iter().all(u8::is_ascii_digit) {
            value.insert(value.len() - 2, ':');
            return Some(value);
        }
    }
    None
}

fn sha256_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(input);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn int_flag(row: &sqlx::any::AnyRow, column: &str) -> Result<bool> {
    let value: i64 = row.try_get(column).map_err(db_error)?;
    Ok(value != 0)
}

fn json_or_empty_array(raw: Option<&str>) -> Value {
    raw.and_then(|raw| serde_json::from_str(raw).ok())
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]))
}

fn json_or_empty_object(raw: Option<&str>) -> Value {
    raw.and_then(|raw| serde_json::from_str(raw).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn looks_like_email_address(email: &str) -> bool {
    if email.is_empty()
        || email
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace())
    {
        return false;
    }

    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };

    !local.is_empty() && !domain.is_empty() && !domain.contains('@')
}

fn oidc_provider_name(provider_name: &str) -> String {
    let provider_name = provider_name.trim();
    if provider_name.is_empty() {
        "SSO".to_string()
    } else {
        provider_name.to_string()
    }
}

fn row_to_user(row: sqlx::any::AnyRow) -> Result<FrickmailUser> {
    let settings_json: String = row.try_get("settings_json").map_err(db_error)?;
    let settings = serde_json::from_str(&settings_json).map_err(|err| {
        FrickmailError::Upstream(format!("frickmail user settings JSON is invalid: {err}"))
    })?;

    Ok(FrickmailUser {
        id: row.try_get("id").map_err(db_error)?,
        username: row.try_get("username").map_err(db_error)?,
        email: row.try_get("email").map_err(db_error)?,
        password_hash: row.try_get("password_hash").map_err(db_error)?,
        kdf_salt: row.try_get("kdf_salt").map_err(db_error)?,
        settings,
        totp_secret: row.try_get("totp_secret").map_err(db_error)?,
        oidc_escrow_key: row.try_get("oidc_escrow_key").map_err(db_error)?,
    })
}

fn db_error(err: sqlx::Error) -> FrickmailError {
    FrickmailError::Upstream(format!("frickmail user database error: {err}"))
}

fn json_error(err: serde_json::Error) -> FrickmailError {
    FrickmailError::Upstream(format!("frickmail JSON error: {err}"))
}

#[derive(Debug, Clone)]
struct PreferenceSpec {
    key: &'static str,
    default: Value,
    kind: PreferenceKind,
}

#[derive(Debug, Clone, Copy)]
enum PreferenceKind {
    Int { min: i64, max: i64 },
    Bool,
    String { allowed: &'static [&'static str] },
    ArrayInt,
}

fn preference_schema() -> Vec<PreferenceSpec> {
    vec![
        PreferenceSpec {
            key: "notifications_poll_interval",
            default: json!(60),
            kind: PreferenceKind::Int { min: 30, max: 300 },
        },
        PreferenceSpec {
            key: "notifications_accounts",
            default: Value::Null,
            kind: PreferenceKind::ArrayInt,
        },
        PreferenceSpec {
            key: "smime_auto_sign",
            default: json!(false),
            kind: PreferenceKind::Bool,
        },
        PreferenceSpec {
            key: "unified_inbox_limit",
            default: json!(40),
            kind: PreferenceKind::Int { min: 10, max: 100 },
        },
        PreferenceSpec {
            key: "tasks_default_tab",
            default: json!("all"),
            kind: PreferenceKind::String {
                allowed: &["all", "pending", "completed"],
            },
        },
    ]
}

fn value_to_i64(value: &Value) -> i64 {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| {
                number
                    .as_u64()
                    .map(|value| value.min(i64::MAX as u64) as i64)
            })
            .or_else(|| number.as_f64().map(|value| value as i64))
            .unwrap_or_default(),
        Value::Bool(value) => i64::from(*value),
        Value::String(value) => value.trim().parse::<i64>().unwrap_or_default(),
        _ => 0,
    }
}

fn value_to_php_bool(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Null => false,
        Value::Number(number) => number
            .as_i64()
            .map(|value| value != 0)
            .or_else(|| number.as_u64().map(|value| value != 0))
            .or_else(|| number.as_f64().map(|value| value != 0.0))
            .unwrap_or(false),
        Value::String(value) => !value.is_empty() && value != "0",
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
    }
}

fn value_to_php_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Bool(true) => "1".to_string(),
        Value::Bool(false) | Value::Null => String::new(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) => "Array".to_string(),
        Value::Object(_) => "Object".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use argon2::{
        password_hash::{PasswordHasher, SaltString},
        Argon2,
    };
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        x509::{extension::SubjectAlternativeName, X509NameBuilder, X509},
    };
    use serde_json::{json, Value};
    use sqlx::{any::AnyPoolOptions, AnyPool, Row};

    use super::{
        clean_preferences_patch, current_totp_counter, decrypt_account_secret,
        derive_credential_key, encrypt_account_secret, normalize_username,
        preferences_from_settings, totp_code, url_encode, verify_login_password, verify_password,
        FrickmailMe, NewMailAccount, NewMailRule, NewMailTask, NewSmimeCert, PushSubscription,
        SqlxUserRepository, TaskFilter, UpdateMailAccount, UpdateMailTask, VapidKeyBundle,
        ACCOUNT_SECRET_NONCE_BYTES, CREDENTIAL_KEY_BYTES, DUMMY_PASSWORD_HASH, KDF_SALT_BYTES,
        VAPID_SETTING_KEY,
    };
    use fm_core::UserSession;

    #[test]
    fn username_normalization_matches_php_login_flow() {
        assert_eq!(normalize_username("  Nicola.EXAMPLE  "), "nicola.example");
    }

    #[test]
    fn password_verifier_accepts_argon2id_phc_hashes() {
        let salt = SaltString::encode_b64(b"frickmail-test-salt").unwrap();
        let hash = Argon2::default()
            .hash_password(b"correct horse battery staple", &salt)
            .unwrap()
            .to_string();

        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn login_password_verification_uses_dummy_hash_for_missing_users() {
        assert!(!verify_login_password("anything", None).unwrap());
        assert!(!verify_password("anything", DUMMY_PASSWORD_HASH).unwrap());
    }

    #[test]
    fn login_password_verification_treats_malformed_hashes_as_invalid() {
        let mut user = test_user(42, json!({}));
        user.password_hash = "not-a-phc-hash".to_string();

        assert!(!verify_login_password("anything", Some(&user)).unwrap());
    }

    #[test]
    fn credential_key_derivation_matches_frickmail_sodium_shape() {
        let salt = [7_u8; KDF_SALT_BYTES];
        let key = derive_credential_key("secret", &salt).unwrap();
        let same = derive_credential_key("secret", &salt).unwrap();
        let other = derive_credential_key("secret", &[8_u8; KDF_SALT_BYTES]).unwrap();

        assert_eq!(key.len(), CREDENTIAL_KEY_BYTES);
        assert_eq!(key, same);
        assert_ne!(key, other);
    }

    #[test]
    fn credential_key_derivation_rejects_invalid_salt_lengths() {
        assert!(derive_credential_key("secret", b"short").is_err());
    }

    #[test]
    fn account_secret_crypto_matches_php_blob_shape() {
        let key = [9_u8; CREDENTIAL_KEY_BYTES];
        let other_key = [10_u8; CREDENTIAL_KEY_BYTES];
        let blob = encrypt_account_secret("imap-password", &key).unwrap();

        assert!(blob.len() > ACCOUNT_SECRET_NONCE_BYTES);
        assert_ne!(blob, b"imap-password");
        assert_eq!(
            decrypt_account_secret(&blob, &key).unwrap().as_deref(),
            Some("imap-password")
        );
        assert_eq!(decrypt_account_secret(&blob, &other_key).unwrap(), None);
        assert!(encrypt_account_secret("secret", b"short").is_err());
        assert_eq!(decrypt_account_secret(b"short", &key).unwrap(), None);
    }

    #[test]
    fn me_response_matches_legacy_unauthenticated_shape() {
        assert_eq!(
            FrickmailMe::anonymous(),
            FrickmailMe {
                ok: true,
                authenticated: false,
                username: None,
                email: None,
            }
        );
    }

    #[test]
    fn me_response_projects_rust_session() {
        let session = UserSession {
            user_id: 42,
            username: "nicola".to_string(),
            email: Some("nicola@example.com".to_string()),
        };

        assert_eq!(
            FrickmailMe::from_session(&session),
            FrickmailMe {
                ok: true,
                authenticated: true,
                username: Some("nicola".to_string()),
                email: Some("nicola@example.com".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn repository_reads_existing_user_schema() {
        let pool = sqlite_pool().await;
        sqlx::query(
            "CREATE TABLE frickmail_users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT,
                password_hash TEXT NOT NULL,
                kdf_salt BLOB NOT NULL,
                settings JSON NOT NULL,
                totp_secret TEXT,
                oidc_escrow_key BLOB
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO frickmail_users
                (id, username, email, password_hash, kdf_salt, settings, totp_secret, oidc_escrow_key)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(7_i64)
        .bind("alice")
        .bind("alice@example.com")
        .bind("$argon2id$v=19$m=65536,t=3,p=1$placeholder")
        .bind(vec![1_u8, 2, 3, 4])
        .bind(json!({"theme":"frickmail"}).to_string())
        .bind("123456")
        .bind(vec![9_u8, 8, 7])
        .execute(&pool)
        .await
        .unwrap();

        let by_id = SqlxUserRepository::find_by_id(&pool, 7)
            .await
            .unwrap()
            .unwrap();
        let by_name = SqlxUserRepository::find_by_username(&pool, " ALICE ")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(by_id, by_name);
        assert_eq!(by_id.username, "alice");
        assert_eq!(by_id.email.as_deref(), Some("alice@example.com"));
        assert_eq!(by_id.kdf_salt, vec![1, 2, 3, 4]);
        assert_eq!(by_id.settings, json!({"theme":"frickmail"}));
        assert_eq!(by_id.totp_secret.as_deref(), Some("123456"));
        assert_eq!(by_id.oidc_escrow_key, Some(vec![9, 8, 7]));
        assert_eq!(SqlxUserRepository::user_count(&pool).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn repository_registers_users_with_php_signup_rules() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;

        let first = SqlxUserRepository::register_user(
            &pool,
            false,
            "  Alice  ".to_string(),
            Some("alice@example.com".to_string()),
            "correct horse battery staple".to_string(),
        )
        .await
        .unwrap();
        assert_eq!(
            first.message,
            "Account created. Sign in to add your mail accounts."
        );

        let alice = SqlxUserRepository::find_by_username(&pool, "ALICE")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alice.username, "alice");
        assert_eq!(alice.email.as_deref(), Some("alice@example.com"));
        assert_eq!(alice.kdf_salt.len(), KDF_SALT_BYTES);
        assert!(verify_password("correct horse battery staple", &alice.password_hash).unwrap());
        assert_eq!(alice.settings, json!({}));

        let blocked = SqlxUserRepository::register_user(
            &pool,
            false,
            "bob".to_string(),
            None,
            "another good password".to_string(),
        )
        .await
        .unwrap_err()
        .public_message();
        assert_eq!(
            blocked,
            "Self-signup is disabled. Ask your admin or set FRICKMAIL_OPEN_SIGNUP=true."
        );

        SqlxUserRepository::register_user(
            &pool,
            true,
            "bob".to_string(),
            Some("".to_string()),
            "another good password".to_string(),
        )
        .await
        .unwrap();
        assert!(SqlxUserRepository::find_by_username(&pool, "bob")
            .await
            .unwrap()
            .unwrap()
            .email
            .is_none());

        let duplicate = SqlxUserRepository::register_user(
            &pool,
            true,
            "ALICE".to_string(),
            None,
            "another good password".to_string(),
        )
        .await
        .unwrap_err()
        .public_message();
        assert_eq!(duplicate, "Username already taken");
    }

    #[test]
    fn preferences_merge_defaults_and_stored_settings() {
        let prefs = preferences_from_settings(&json!({
            "notifications_poll_interval": 120,
            "tasks_default_tab": "pending",
            "unrelated": true
        }));

        assert_eq!(prefs["notifications_poll_interval"], 120);
        assert_eq!(prefs["tasks_default_tab"], "pending");
        assert_eq!(prefs["smime_auto_sign"], false);
        assert_eq!(prefs["unified_inbox_limit"], 40);
        assert_eq!(prefs["notifications_accounts"], Value::Null);
        assert!(prefs.get("unrelated").is_none());
    }

    #[test]
    fn preferences_patch_matches_legacy_validation_rules() {
        let clean = clean_preferences_patch(&json!({
            "notifications_poll_interval": 5,
            "unified_inbox_limit": 500,
            "smime_auto_sign": "0",
            "tasks_default_tab": "completed",
            "notifications_accounts": ["1", "bad", 3],
            "ignored": true
        }));

        assert_eq!(clean["notifications_poll_interval"], 30);
        assert_eq!(clean["unified_inbox_limit"], 100);
        assert_eq!(clean["smime_auto_sign"], false);
        assert_eq!(clean["tasks_default_tab"], "completed");
        assert_eq!(clean["notifications_accounts"], json!([1, 0, 3]));
        assert!(clean.get("ignored").is_none());
    }

    #[tokio::test]
    async fn repository_updates_preferences_in_existing_settings_column() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        insert_user(
            &pool,
            9,
            json!({"tasks_default_tab":"pending","custom":"preserve"}),
        )
        .await;

        let prefs = SqlxUserRepository::update_preferences(
            &pool,
            9,
            &json!({
                "notifications_poll_interval": 5,
                "smime_auto_sign": true,
                "tasks_default_tab": "invalid",
                "notifications_accounts": null
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let user = SqlxUserRepository::find_by_id(&pool, 9)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(prefs["notifications_poll_interval"], 30);
        assert_eq!(prefs["smime_auto_sign"], true);
        assert_eq!(prefs["tasks_default_tab"], "pending");
        assert_eq!(prefs["notifications_accounts"], Value::Null);
        assert_eq!(user.settings["custom"], "preserve");
    }

    #[tokio::test]
    async fn repository_lists_mail_accounts_without_secret_columns() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 11, json!({})).await;
        insert_mail_account(&pool, 100, 11, "Work", true).await;
        insert_mail_account(&pool, 101, 11, "Personal", false).await;
        insert_identity(&pool, 200, 11, 100, "Default", true).await;
        insert_identity(&pool, 201, 11, 100, "Alias", false).await;

        let accounts = SqlxUserRepository::list_mail_accounts(&pool, 11)
            .await
            .unwrap();

        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].id, 100);
        assert_eq!(accounts[0].label, "Work");
        assert_eq!(accounts[0].email, "work@example.com");
        assert_eq!(accounts[0].account_type, "imap");
        assert_eq!(accounts[0].imap_host.as_deref(), Some("imap.example.com"));
        assert_eq!(accounts[0].imap_port, Some(993));
        assert!(accounts[0].is_primary);
        assert_eq!(accounts[0].identities.len(), 2);
        assert_eq!(accounts[0].identities[0].id, 200);
        assert!(accounts[0].identities[0].is_default);
        assert_eq!(accounts[1].id, 101);
        assert!(accounts[1].identities.is_empty());
    }

    #[tokio::test]
    async fn repository_gets_one_mail_account_with_user_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 13, json!({})).await;
        insert_user(&pool, 14, json!({})).await;
        insert_mail_account(&pool, 120, 13, "Work", true).await;
        insert_mail_account(&pool, 121, 14, "OtherUser", true).await;

        let account = SqlxUserRepository::get_mail_account(&pool, 13, 120)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(account.email, "work@example.com");
        assert_eq!(account.account_type, "imap");
        assert!(account.identities.is_empty());

        let account = SqlxUserRepository::get_mail_account(&pool, 13, 121)
            .await
            .unwrap();
        assert!(account.is_none());
    }

    #[tokio::test]
    async fn repository_gets_connection_secret_with_user_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 141, json!({})).await;
        insert_user(&pool, 142, json!({})).await;
        let key = [14_u8; CREDENTIAL_KEY_BYTES];

        let owner_account_id = SqlxUserRepository::add_mail_account(
            &pool,
            141,
            NewMailAccount {
                label: Some("Owner".to_string()),
                email: "owner@example.com".to_string(),
                account_type: "imap".to_string(),
                imap_host: Some("imap.example.com".to_string()),
                imap_port: Some(993),
                imap_secure: Some("SSL".to_string()),
                smtp_host: None,
                smtp_port: None,
                smtp_secure: None,
                login: Some("owner-login".to_string()),
                password: Some("imap-secret".to_string()),
                oauth_tenant: None,
                is_primary: true,
            },
            &key,
        )
        .await
        .unwrap();
        let other_account_id = SqlxUserRepository::add_mail_account(
            &pool,
            142,
            NewMailAccount {
                label: Some("Other".to_string()),
                email: "other@example.com".to_string(),
                account_type: "imap".to_string(),
                imap_host: Some("imap.other.example".to_string()),
                imap_port: Some(993),
                imap_secure: Some("SSL".to_string()),
                smtp_host: None,
                smtp_port: None,
                smtp_secure: None,
                login: None,
                password: Some("other-secret".to_string()),
                oauth_tenant: None,
                is_primary: true,
            },
            &key,
        )
        .await
        .unwrap();

        let secret =
            SqlxUserRepository::get_mail_account_connection_secret(&pool, 141, owner_account_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(secret.id, owner_account_id);
        assert_eq!(secret.email, "owner@example.com");
        assert_eq!(secret.account_type, "imap");
        assert_eq!(secret.imap_host.as_deref(), Some("imap.example.com"));
        assert_eq!(secret.imap_port, Some(993));
        assert_eq!(secret.imap_secure.as_deref(), Some("SSL"));
        assert_eq!(secret.login.as_deref(), Some("owner-login"));
        assert_eq!(
            decrypt_account_secret(&secret.encrypted_password.unwrap(), &key)
                .unwrap()
                .as_deref(),
            Some("imap-secret")
        );

        let leaked =
            SqlxUserRepository::get_mail_account_connection_secret(&pool, 141, other_account_id)
                .await
                .unwrap();
        assert!(leaked.is_none());
        assert!(
            SqlxUserRepository::get_mail_account_connection_secret(&pool, 141, 0)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn repository_adds_mail_account_with_encrypted_password_and_primary_rules() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 15, json!({})).await;
        let key = [3_u8; CREDENTIAL_KEY_BYTES];

        let first_id = SqlxUserRepository::add_mail_account(
            &pool,
            15,
            NewMailAccount {
                label: None,
                email: "owner@example.com".to_string(),
                account_type: "imap".to_string(),
                imap_host: Some("8.8.8.8".to_string()),
                imap_port: None,
                imap_secure: None,
                smtp_host: Some("8.8.4.4".to_string()),
                smtp_port: None,
                smtp_secure: None,
                login: None,
                password: Some("secret-pass".to_string()),
                oauth_tenant: None,
                is_primary: false,
            },
            &key,
        )
        .await
        .unwrap();

        let accounts = SqlxUserRepository::list_mail_accounts(&pool, 15)
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, first_id);
        assert_eq!(accounts[0].label, "owner@example.com");
        assert_eq!(accounts[0].imap_port, Some(993));
        assert_eq!(accounts[0].smtp_port, Some(465));
        assert!(accounts[0].is_primary);
        let password_blob = account_encrypted_password(&pool, first_id).await.unwrap();
        assert_ne!(password_blob, b"secret-pass");
        assert_eq!(
            decrypt_account_secret(&password_blob, &key)
                .unwrap()
                .as_deref(),
            Some("secret-pass")
        );

        let second_id = SqlxUserRepository::add_mail_account(
            &pool,
            15,
            NewMailAccount {
                label: Some("Gmail".to_string()),
                email: "owner@gmail.com".to_string(),
                account_type: "gmail".to_string(),
                imap_host: None,
                imap_port: None,
                imap_secure: None,
                smtp_host: None,
                smtp_port: None,
                smtp_secure: None,
                login: None,
                password: None,
                oauth_tenant: None,
                is_primary: true,
            },
            &key,
        )
        .await
        .unwrap();

        let accounts = SqlxUserRepository::list_mail_accounts(&pool, 15)
            .await
            .unwrap();
        assert_eq!(accounts[0].id, second_id);
        assert!(accounts[0].is_primary);
        assert_eq!(accounts[0].account_type, "gmail");
        assert_eq!(accounts[0].login.as_deref(), Some("owner@gmail.com"));
        assert!(
            !accounts
                .iter()
                .find(|account| account.id == first_id)
                .unwrap()
                .is_primary
        );
    }

    #[tokio::test]
    async fn repository_updates_imap_account_and_preserves_password_when_empty() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 16, json!({})).await;
        insert_mail_account(&pool, 122, 16, "Work", true).await;
        let key = [4_u8; CREDENTIAL_KEY_BYTES];
        SqlxUserRepository::set_mail_account_password(
            &pool,
            16,
            122,
            "old-secret".to_string(),
            &key,
        )
        .await
        .unwrap();
        let old_blob = account_encrypted_password(&pool, 122).await.unwrap();

        SqlxUserRepository::update_mail_account(
            &pool,
            16,
            UpdateMailAccount {
                id: 122,
                label: Some(" Work Updated ".to_string()),
                imap_host: Some("1.1.1.1".to_string()),
                imap_port: Some(143),
                imap_secure: Some("STARTTLS".to_string()),
                smtp_host: Some("8.8.8.8".to_string()),
                smtp_port: Some(587),
                smtp_secure: Some("STARTTLS".to_string()),
                login: Some("owner".to_string()),
                password: Some("".to_string()),
            },
            &key,
        )
        .await
        .unwrap();

        let account = SqlxUserRepository::get_mail_account(&pool, 16, 122)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(account.label, "Work Updated");
        assert_eq!(account.imap_host.as_deref(), Some("1.1.1.1"));
        assert_eq!(account.imap_port, Some(143));
        assert_eq!(account.smtp_port, Some(587));
        assert_eq!(account.login.as_deref(), Some("owner"));
        assert_eq!(
            account_encrypted_password(&pool, 122).await.unwrap(),
            old_blob
        );

        SqlxUserRepository::set_mail_account_password(
            &pool,
            16,
            122,
            "new-secret".to_string(),
            &key,
        )
        .await
        .unwrap();
        let new_blob = account_encrypted_password(&pool, 122).await.unwrap();
        assert_ne!(new_blob, old_blob);
        assert_eq!(
            decrypt_account_secret(&new_blob, &key).unwrap().as_deref(),
            Some("new-secret")
        );
    }

    #[tokio::test]
    async fn repository_rejects_reserved_mail_hosts() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 19, json!({})).await;
        insert_mail_account(&pool, 125, 19, "Work", true).await;
        let key = [6_u8; CREDENTIAL_KEY_BYTES];

        let err = SqlxUserRepository::add_mail_account(
            &pool,
            19,
            NewMailAccount {
                label: None,
                email: "blocked@example.com".to_string(),
                account_type: "imap".to_string(),
                imap_host: Some("127.0.0.1".to_string()),
                imap_port: None,
                imap_secure: None,
                smtp_host: Some("8.8.8.8".to_string()),
                smtp_port: None,
                smtp_secure: None,
                login: None,
                password: None,
                oauth_tenant: None,
                is_primary: false,
            },
            &key,
        )
        .await
        .unwrap_err();
        assert!(err.public_message().contains("reserved IP"));

        let err = SqlxUserRepository::update_mail_account(
            &pool,
            19,
            UpdateMailAccount {
                id: 125,
                label: None,
                imap_host: None,
                imap_port: None,
                imap_secure: None,
                smtp_host: Some("10.0.0.2".to_string()),
                smtp_port: None,
                smtp_secure: None,
                login: None,
                password: None,
            },
            &key,
        )
        .await
        .unwrap_err();
        assert!(err.public_message().contains("reserved IP"));

        let err = SqlxUserRepository::add_mail_account(
            &pool,
            19,
            NewMailAccount {
                label: None,
                email: "mapped@example.com".to_string(),
                account_type: "imap".to_string(),
                imap_host: Some("::ffff:127.0.0.1".to_string()),
                imap_port: None,
                imap_secure: None,
                smtp_host: Some("8.8.8.8".to_string()),
                smtp_port: None,
                smtp_secure: None,
                login: None,
                password: None,
                oauth_tenant: None,
                is_primary: false,
            },
            &key,
        )
        .await
        .unwrap_err();
        assert!(err.public_message().contains("reserved IP"));
    }

    #[tokio::test]
    async fn repository_saves_oauth_token_by_case_insensitive_email_and_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 17, json!({})).await;
        insert_user(&pool, 18, json!({})).await;
        insert_mail_account(&pool, 123, 17, "Oauth", true).await;
        insert_mail_account(&pool, 124, 18, "Other", true).await;
        let key = [5_u8; CREDENTIAL_KEY_BYTES];

        let ok = SqlxUserRepository::save_oauth_refresh_token(
            &pool,
            17,
            "o365".to_string(),
            "OAUTH@example.com".to_string(),
            "refresh-token".to_string(),
            &key,
        )
        .await
        .unwrap();
        assert!(ok);
        assert_eq!(account_type(&pool, 123).await, "o365");
        let token_blob = account_oauth_refresh_token(&pool, 123).await.unwrap();
        assert_eq!(
            decrypt_account_secret(&token_blob, &key)
                .unwrap()
                .as_deref(),
            Some("refresh-token")
        );
        assert!(account_oauth_refresh_token(&pool, 124).await.is_none());

        let err = SqlxUserRepository::save_oauth_refresh_token(
            &pool,
            17,
            "imap".to_string(),
            "oauth@example.com".to_string(),
            "refresh-token".to_string(),
            &key,
        )
        .await
        .unwrap_err();
        assert!(err.public_message().contains("Unknown type"));
    }

    #[tokio::test]
    async fn repository_activates_services_with_account_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 33, json!({})).await;
        insert_user(&pool, 34, json!({})).await;
        insert_mail_account(&pool, 170, 33, "Work", true).await;
        insert_mail_account(&pool, 171, 34, "OtherUser", true).await;

        let result = SqlxUserRepository::activate_service(
            &pool,
            33,
            170,
            "contacts".to_string(),
            "google".to_string(),
            "https://ignored.example/contacts".to_string(),
        )
        .await
        .unwrap();
        assert_eq!(
            result.message,
            "Contacts sync triggered. Open Settings -> Contacts Sync to run a full sync."
        );
        assert_eq!(mail_account_settings(&pool, 170).await, json!({}));

        let result = SqlxUserRepository::activate_service(
            &pool,
            33,
            170,
            "calendar".to_string(),
            "dav".to_string(),
            "https://dav.example/.well-known/caldav".to_string(),
        )
        .await
        .unwrap();
        assert_eq!(
            result.message,
            "CalDAV URL saved. You can configure credentials in Settings -> Accounts."
        );
        assert_eq!(
            mail_account_settings(&pool, 170).await,
            json!({"caldav_url": "https://dav.example/.well-known/caldav"})
        );

        let err = SqlxUserRepository::activate_service(
            &pool,
            33,
            171,
            "contacts".to_string(),
            "dav".to_string(),
            "https://dav.example/.well-known/carddav".to_string(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.public_message(), "Account not found");
    }

    #[tokio::test]
    async fn repository_deletes_mail_account_and_user_scoped_message_index() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        create_message_index_table(&pool).await;
        insert_user(&pool, 15, json!({})).await;
        insert_user(&pool, 16, json!({})).await;
        insert_mail_account(&pool, 130, 15, "Work", true).await;
        insert_mail_account(&pool, 131, 16, "OtherUser", true).await;
        insert_message_index(&pool, 15, 130, "INBOX", 1).await;
        insert_message_index(&pool, 16, 131, "INBOX", 2).await;

        SqlxUserRepository::delete_mail_account(&pool, 16, 130)
            .await
            .unwrap();
        assert_eq!(mail_account_count(&pool, 15).await, 1);
        assert_eq!(message_index_count(&pool, 15, 130).await, 1);

        SqlxUserRepository::delete_mail_account(&pool, 15, 130)
            .await
            .unwrap();
        assert_eq!(mail_account_count(&pool, 15).await, 0);
        assert_eq!(message_index_count(&pool, 15, 130).await, 0);
        assert_eq!(mail_account_count(&pool, 16).await, 1);
        assert_eq!(message_index_count(&pool, 16, 131).await, 1);
    }

    #[tokio::test]
    async fn repository_searches_message_index_with_user_scope_and_limit() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        create_message_index_table(&pool).await;
        insert_user(&pool, 27, json!({})).await;
        insert_user(&pool, 28, json!({})).await;
        insert_mail_account(&pool, 150, 27, "Work", true).await;
        insert_mail_account(&pool, 151, 28, "OtherUser", true).await;
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 1,
                user_id: 27,
                account_id: 150,
                folder: "INBOX",
                imap_uid: 10,
                message_id: Some("msg-1"),
                subject: Some("Quarterly Invoice"),
                from_addr: Some("billing@example.com"),
                from_name: Some("Billing"),
                date_ts: Some("2026-06-02 10:00:00"),
                snippet: Some("Please pay this invoice"),
            },
        )
        .await;
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 2,
                user_id: 27,
                account_id: 150,
                folder: "Archive",
                imap_uid: 11,
                message_id: Some("msg-2"),
                subject: Some("Invoice reminder"),
                from_addr: Some("boss@example.com"),
                from_name: Some("Boss"),
                date_ts: Some("2026-06-03 10:00:00"),
                snippet: Some("Second invoice"),
            },
        )
        .await;
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 3,
                user_id: 28,
                account_id: 151,
                folder: "INBOX",
                imap_uid: 12,
                message_id: Some("msg-3"),
                subject: Some("Invoice other"),
                from_addr: Some("other@example.com"),
                from_name: Some("Other"),
                date_ts: Some("2026-06-04 10:00:00"),
                snippet: Some("Should not leak"),
            },
        )
        .await;

        let results = SqlxUserRepository::search_messages(&pool, 27, " invoice ".to_string(), 1)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, 2);
        assert_eq!(results[0].account_id, 150);
        assert_eq!(results[0].folder, "Archive");
        assert_eq!(results[0].imap_uid, 11);
        assert_eq!(results[0].message_id.as_deref(), Some("msg-2"));
        assert_eq!(results[0].subject.as_deref(), Some("Invoice reminder"));
        assert_eq!(results[0].from_addr.as_deref(), Some("boss@example.com"));
        assert_eq!(results[0].from_name.as_deref(), Some("Boss"));
        assert_eq!(results[0].date_ts.as_deref(), Some("2026-06-03 10:00:00"));
        assert_eq!(results[0].snippet.as_deref(), Some("Second invoice"));
        assert_eq!(results[0].account_email, "work@example.com");

        let err = SqlxUserRepository::search_messages(&pool, 27, "i".to_string(), 50)
            .await
            .unwrap_err();
        assert_eq!(err.public_message(), "Query too short");
    }

    #[tokio::test]
    async fn repository_lists_unified_inbox_from_index_with_user_scope_and_epoch_dates() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        create_message_index_table(&pool).await;
        insert_user(&pool, 31, json!({})).await;
        insert_user(&pool, 32, json!({})).await;
        insert_mail_account(&pool, 160, 31, "Work", true).await;
        insert_mail_account(&pool, 161, 31, "Personal", false).await;
        insert_mail_account(&pool, 162, 32, "OtherUser", true).await;
        insert_mail_account(&pool, 163, 31, "OAuthOnly", false).await;
        insert_mail_account(&pool, 164, 31, "NoPassword", false).await;
        sqlx::query("UPDATE frickmail_mail_accounts SET type = 'gmail' WHERE id = ?")
            .bind(163_i64)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE frickmail_mail_accounts SET encrypted_password = NULL WHERE id = ?")
            .bind(164_i64)
            .execute(&pool)
            .await
            .unwrap();
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 11,
                user_id: 31,
                account_id: 160,
                folder: "INBOX",
                imap_uid: 20,
                message_id: Some("msg-20"),
                subject: Some("Older inbox"),
                from_addr: Some("billing@example.com"),
                from_name: Some("Billing"),
                date_ts: Some("2026-06-02 10:00:00"),
                snippet: Some("Old indexed body"),
            },
        )
        .await;
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 12,
                user_id: 31,
                account_id: 161,
                folder: "INBOX",
                imap_uid: 21,
                message_id: Some("msg-21"),
                subject: Some("Newest inbox"),
                from_addr: Some("friend@example.com"),
                from_name: None,
                date_ts: Some("2026-06-03T10:00:00Z"),
                snippet: Some("New indexed body"),
            },
        )
        .await;
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 13,
                user_id: 31,
                account_id: 160,
                folder: "Archive",
                imap_uid: 22,
                message_id: Some("msg-22"),
                subject: Some("Archived"),
                from_addr: Some("archive@example.com"),
                from_name: Some("Archive"),
                date_ts: Some("2026-06-04 10:00:00"),
                snippet: Some("Should not appear"),
            },
        )
        .await;
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 14,
                user_id: 32,
                account_id: 162,
                folder: "INBOX",
                imap_uid: 23,
                message_id: Some("msg-23"),
                subject: Some("Other user"),
                from_addr: Some("other@example.com"),
                from_name: Some("Other"),
                date_ts: Some("2026-06-05 10:00:00"),
                snippet: Some("Should not leak"),
            },
        )
        .await;
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 15,
                user_id: 31,
                account_id: 163,
                folder: "INBOX",
                imap_uid: 24,
                message_id: Some("msg-24"),
                subject: Some("OAuth-only account"),
                from_addr: Some("oauth@example.com"),
                from_name: Some("OAuth"),
                date_ts: Some("2026-06-06 10:00:00"),
                snippet: Some("Non-IMAP accounts should not appear"),
            },
        )
        .await;
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 16,
                user_id: 31,
                account_id: 164,
                folder: "INBOX",
                imap_uid: 25,
                message_id: Some("msg-25"),
                subject: Some("Passwordless account"),
                from_addr: Some("nopass@example.com"),
                from_name: Some("NoPassword"),
                date_ts: Some("2026-06-07 10:00:00"),
                snippet: Some("Credential-cleared accounts should not appear"),
            },
        )
        .await;

        let messages = SqlxUserRepository::unified_inbox_messages(&pool, 31, 10)
            .await
            .unwrap();

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].account_id, 161);
        assert_eq!(messages[0].account_email, "personal@example.com");
        assert_eq!(messages[0].imap_uid, 21);
        assert_eq!(messages[0].from_display, "friend@example.com");
        assert_eq!(messages[0].date_ts, 1_780_480_800);
        assert_eq!(messages[0].flags, Vec::<String>::new());
        assert!(messages[0].is_seen);
        assert_eq!(messages[1].account_id, 160);
        assert_eq!(messages[1].from_display, "Billing");
        assert_eq!(messages[1].date_ts, 1_780_394_400);

        let limited = SqlxUserRepository::unified_inbox_messages(&pool, 31, 1)
            .await
            .unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].imap_uid, 21);
    }

    #[test]
    fn unified_inbox_epoch_parser_accepts_common_db_timestamp_formats() {
        assert_eq!(
            super::normalize_message_epoch(Some("2026-06-03T10:00:00Z")),
            1_780_480_800
        );
        assert_eq!(
            super::normalize_message_epoch(Some("2026-06-03 10:00:00.123456")),
            1_780_480_800
        );
        assert_eq!(
            super::normalize_message_epoch(Some("2026-06-03 10:00:00+00")),
            1_780_480_800
        );
        assert_eq!(
            super::normalize_message_epoch(Some("2026-06-03 12:00:00+0200")),
            1_780_480_800
        );
    }

    #[tokio::test]
    async fn repository_gets_indexed_message_body_with_user_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        create_message_index_table(&pool).await;
        insert_user(&pool, 35, json!({})).await;
        insert_user(&pool, 36, json!({})).await;
        insert_mail_account(&pool, 180, 35, "Work", true).await;
        insert_mail_account(&pool, 181, 36, "OtherUser", true).await;
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 4,
                user_id: 35,
                account_id: 180,
                folder: "INBOX",
                imap_uid: 20,
                message_id: Some("body-1"),
                subject: Some("Body subject"),
                from_addr: Some("sender@example.com"),
                from_name: Some("Sender"),
                date_ts: Some("2026-06-02 11:00:00"),
                snippet: Some("Indexed plain body preview"),
            },
        )
        .await;
        insert_search_message(
            &pool,
            SearchMessageSeed {
                id: 5,
                user_id: 36,
                account_id: 181,
                folder: "INBOX",
                imap_uid: 20,
                message_id: Some("body-2"),
                subject: Some("Leaked subject"),
                from_addr: Some("other@example.com"),
                from_name: Some("Other"),
                date_ts: Some("2026-06-02 12:00:00"),
                snippet: Some("Must not leak"),
            },
        )
        .await;

        let body =
            SqlxUserRepository::indexed_message_body(&pool, 35, 180, "INBOX".to_string(), 20)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(body.account_id, 180);
        assert_eq!(body.folder, "INBOX");
        assert_eq!(body.imap_uid, 20);
        assert_eq!(body.subject.as_deref(), Some("Body subject"));
        assert_eq!(body.snippet.as_deref(), Some("Indexed plain body preview"));

        let missing =
            SqlxUserRepository::indexed_message_body(&pool, 35, 181, "INBOX".to_string(), 20)
                .await
                .unwrap();
        assert!(missing.is_none());

        let err = SqlxUserRepository::indexed_message_body(&pool, 35, 0, "INBOX".to_string(), 20)
            .await
            .unwrap_err();
        assert_eq!(err.public_message(), "account_id required");

        let err = SqlxUserRepository::indexed_message_body(&pool, 35, 180, "INBOX".to_string(), 0)
            .await
            .unwrap_err();
        assert_eq!(err.public_message(), "uid required");
    }

    #[tokio::test]
    async fn repository_requests_password_reset_without_account_leakage() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_password_reset_table(&pool).await;
        insert_user(&pool, 28, json!({})).await;

        let result = SqlxUserRepository::request_password_reset(
            &pool,
            " USER28 ".to_string(),
            "https://mail.example/webmail/".to_string(),
        )
        .await
        .unwrap();

        assert!(result.ok);
        assert_eq!(
            result.message,
            "If the username exists and has a recovery email, a reset link has been sent."
        );
        let delivery = result.delivery.as_ref().unwrap();
        assert_eq!(delivery.to, "user28@example.com");
        assert_eq!(delivery.username, "user28");
        assert!(delivery
            .reset_url
            .starts_with("https://mail.example/webmail/?reset_token="));
        assert!(delivery.reset_url.len() > "https://mail.example/webmail/?reset_token=".len());
        assert_eq!(active_password_reset_count(&pool, 28).await, 1);
        assert!(serde_json::to_value(&result)
            .unwrap()
            .get("delivery")
            .is_none());

        let second = SqlxUserRepository::request_password_reset(
            &pool,
            "user28".to_string(),
            "https://mail.example".to_string(),
        )
        .await
        .unwrap();
        assert!(second.delivery.is_some());
        assert_eq!(active_password_reset_count(&pool, 28).await, 1);

        let unknown = SqlxUserRepository::request_password_reset(
            &pool,
            "missing".to_string(),
            "https://mail.example".to_string(),
        )
        .await
        .unwrap();
        assert!(unknown.delivery.is_none());
    }

    #[tokio::test]
    async fn repository_resets_password_and_invalidates_credentials() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        create_password_reset_table(&pool).await;
        insert_user(&pool, 29, json!({})).await;
        insert_mail_account(&pool, 160, 29, "Work", true).await;
        set_oauth_refresh_token(&pool, 160, vec![8_u8, 9, 10]).await;
        insert_password_reset(
            &pool,
            500,
            29,
            &super::sha256_hex(b"reset-token"),
            "2999-01-01 00:00:00",
            None,
        )
        .await;

        let result = SqlxUserRepository::reset_password(
            &pool,
            "reset-token".to_string(),
            "new-secret".to_string(),
        )
        .await
        .unwrap();

        assert!(result.ok);
        assert_eq!(result.username, "user29");
        assert_eq!(
            result.message,
            "Password reset. Sign in with your new password. Linked mail-account credentials must be re-entered."
        );
        let user = SqlxUserRepository::find_by_id(&pool, 29)
            .await
            .unwrap()
            .unwrap();
        assert!(verify_login_password("new-secret", Some(&user)).unwrap());
        assert_eq!(user.kdf_salt.len(), KDF_SALT_BYTES);
        assert_ne!(user.kdf_salt, vec![1_u8, 2, 3, 4]);
        assert!(account_credentials_are_null(&pool, 160).await);
        assert!(password_reset_used_at(&pool, 500).await.is_some());

        let err = SqlxUserRepository::reset_password(
            &pool,
            "reset-token".to_string(),
            "another-secret".to_string(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.public_message(), "Invalid or expired token");

        let err = SqlxUserRepository::reset_password(
            &pool,
            "missing-token".to_string(),
            "short".to_string(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.public_message(), "Password must be at least 8 chars");
    }

    #[tokio::test]
    async fn repository_sets_primary_mail_account_with_user_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 17, json!({})).await;
        insert_user(&pool, 18, json!({})).await;
        insert_mail_account(&pool, 140, 17, "Work", true).await;
        insert_mail_account(&pool, 141, 17, "Personal", false).await;
        insert_mail_account(&pool, 142, 18, "OtherUser", true).await;

        SqlxUserRepository::set_primary_mail_account(&pool, 17, 141)
            .await
            .unwrap();
        let accounts = SqlxUserRepository::list_mail_accounts(&pool, 17)
            .await
            .unwrap();
        assert_eq!(accounts[0].id, 141);
        assert!(accounts[0].is_primary);
        assert!(
            !accounts
                .iter()
                .find(|account| account.id == 140)
                .unwrap()
                .is_primary
        );

        SqlxUserRepository::set_primary_mail_account(&pool, 17, 142)
            .await
            .unwrap();
        let accounts = SqlxUserRepository::list_mail_accounts(&pool, 17)
            .await
            .unwrap();
        assert!(accounts.iter().all(|account| !account.is_primary));
        let other_user_accounts = SqlxUserRepository::list_mail_accounts(&pool, 18)
            .await
            .unwrap();
        assert!(other_user_accounts[0].is_primary);
    }

    #[tokio::test]
    async fn repository_reports_totp_enabled_status() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        insert_user(&pool, 25, json!({})).await;
        insert_user(&pool, 26, json!({})).await;
        set_totp_secret(&pool, 26, Some("SECRET")).await;

        assert!(!SqlxUserRepository::totp_enabled(&pool, 25).await.unwrap());
        assert!(SqlxUserRepository::totp_enabled(&pool, 26).await.unwrap());
        set_totp_secret(&pool, 26, Some("")).await;
        assert!(!SqlxUserRepository::totp_enabled(&pool, 26).await.unwrap());
        set_totp_secret(&pool, 26, Some("0")).await;
        assert!(!SqlxUserRepository::totp_enabled(&pool, 26).await.unwrap());
    }

    #[tokio::test]
    async fn repository_enables_confirms_and_disables_totp() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        insert_user(&pool, 27, json!({})).await;

        let setup = SqlxUserRepository::begin_totp_setup(&pool, 27)
            .await
            .unwrap();
        assert!(setup.ok);
        assert!(setup.otpauth_uri.starts_with("otpauth://totp/Frickmail:"));

        let code = totp_code(&setup.secret, current_totp_counter() as u64).unwrap();
        let result = SqlxUserRepository::confirm_totp(&pool, 27, setup.secret.clone(), code)
            .await
            .unwrap();
        assert!(result.ok);
        assert!(SqlxUserRepository::totp_enabled(&pool, 27).await.unwrap());

        let err = SqlxUserRepository::begin_totp_setup(&pool, 27)
            .await
            .unwrap_err();
        assert_eq!(
            err.public_message(),
            "Two-factor authentication is already enabled. Disable it first."
        );

        let invalid = SqlxUserRepository::disable_totp(&pool, 27, "000000".to_string())
            .await
            .unwrap();
        assert!(!invalid.ok);
        assert_eq!(
            invalid.error.as_deref(),
            Some("A valid TOTP code is required to disable two-factor authentication.")
        );

        let code = totp_code(&setup.secret, current_totp_counter() as u64).unwrap();
        let result = SqlxUserRepository::disable_totp(&pool, 27, code)
            .await
            .unwrap();
        assert!(result.ok);
        assert!(!SqlxUserRepository::totp_enabled(&pool, 27).await.unwrap());
    }

    #[tokio::test]
    async fn repository_verifies_totp_login_codes_with_replay_protection() {
        let pool = sqlite_pool().await;
        create_totp_used_table(&pool).await;
        let secret = "JBSWY3DPEHPK3PXP";

        let missing =
            SqlxUserRepository::verify_totp_login_code(&pool, 28, secret, " ".to_string())
                .await
                .unwrap();
        assert!(!missing.ok);
        assert_eq!(missing.error.as_deref(), Some("Two-factor code required"));

        let invalid =
            SqlxUserRepository::verify_totp_login_code(&pool, 28, secret, "000000".to_string())
                .await
                .unwrap();
        assert!(!invalid.ok);
        assert_eq!(invalid.error.as_deref(), Some("Invalid two-factor code"));

        let code = totp_code(secret, current_totp_counter() as u64).unwrap();
        let first = SqlxUserRepository::verify_totp_login_code(&pool, 28, secret, code.clone())
            .await
            .unwrap();
        assert!(first.ok);

        let replay = SqlxUserRepository::verify_totp_login_code(&pool, 28, secret, code)
            .await
            .unwrap();
        assert!(!replay.ok);
        assert_eq!(
            replay.error.as_deref(),
            Some("Two-factor code already used")
        );

        let future_user_id = 29;
        let future_window = current_totp_counter() + 1;
        let future_code = totp_code(secret, future_window as u64).unwrap();
        let future = SqlxUserRepository::verify_totp_login_code(
            &pool,
            future_user_id,
            secret,
            future_code.clone(),
        )
        .await
        .unwrap();
        assert!(future.ok);
        assert_eq!(
            totp_used_window(&pool, future_user_id, &future_code).await,
            Some(future_window)
        );
    }

    #[tokio::test]
    async fn repository_accepts_only_one_concurrent_totp_login_use() {
        let pool = sqlite_pool().await;
        create_totp_used_table(&pool).await;
        let secret = "JBSWY3DPEHPK3PXP";
        let code = totp_code(secret, current_totp_counter() as u64).unwrap();

        let (first, second) = tokio::join!(
            SqlxUserRepository::verify_totp_login_code(&pool, 30, secret, code.clone()),
            SqlxUserRepository::verify_totp_login_code(&pool, 30, secret, code.clone())
        );

        let results = [first.unwrap(), second.unwrap()];
        assert_eq!(results.iter().filter(|result| result.ok).count(), 1);
        assert_eq!(results.iter().filter(|result| !result.ok).count(), 1);
        assert_eq!(
            results
                .iter()
                .find(|result| !result.ok)
                .and_then(|result| result.error.as_deref()),
            Some("Two-factor code already used")
        );
    }

    #[test]
    fn totp_code_matches_rfc_4226_sha1_vectors() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.into_iter().enumerate() {
            assert_eq!(totp_code(secret, counter as u64).unwrap(), code);
        }
    }

    #[test]
    fn totp_uri_encoding_matches_php_rawurlencode() {
        assert_eq!(
            url_encode("Frick Mail+User@example.com"),
            "Frick%20Mail%2BUser%40example.com"
        );
    }

    #[tokio::test]
    async fn repository_lists_mail_identities_for_one_account() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 12, json!({})).await;
        insert_mail_account(&pool, 110, 12, "Work", true).await;
        insert_mail_account(&pool, 111, 12, "Personal", false).await;
        insert_identity(&pool, 210, 12, 110, "Default", true).await;
        insert_identity(&pool, 211, 12, 110, "Alias", false).await;
        insert_identity(&pool, 212, 12, 111, "Other", true).await;

        let identities = SqlxUserRepository::list_mail_identities(&pool, 12, 110)
            .await
            .unwrap();

        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0].id, 210);
        assert_eq!(identities[0].account_id, 110);
        assert!(identities[0].is_default);
        assert_eq!(identities[1].id, 211);
        assert_eq!(identities[1].account_id, 110);
    }

    #[tokio::test]
    async fn repository_mutates_mail_identities_with_account_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 13, json!({})).await;
        insert_user(&pool, 14, json!({})).await;
        insert_mail_account(&pool, 120, 13, "Work", true).await;
        insert_mail_account(&pool, 121, 14, "OtherUser", true).await;
        insert_identity(&pool, 220, 13, 120, "Default", true).await;

        let id = SqlxUserRepository::add_mail_identity(
            &pool,
            13,
            super::NewMailIdentity {
                account_id: 120,
                name: " Alias ".to_string(),
                email: "alias@example.com".to_string(),
                reply_to: Some(" reply@example.com ".to_string()),
                is_default: true,
            },
        )
        .await
        .unwrap();

        let identities = SqlxUserRepository::list_mail_identities(&pool, 13, 120)
            .await
            .unwrap();
        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0].id, id);
        assert!(identities[0].is_default);
        assert_eq!(identities[0].name, "Alias");
        assert_eq!(identities[0].reply_to.as_deref(), Some("reply@example.com"));
        assert_eq!(identities[1].id, 220);
        assert!(!identities[1].is_default);

        SqlxUserRepository::delete_mail_identity(&pool, 14, id)
            .await
            .unwrap();
        assert_eq!(
            SqlxUserRepository::list_mail_identities(&pool, 13, 120)
                .await
                .unwrap()
                .len(),
            2
        );

        SqlxUserRepository::delete_mail_identity(&pool, 13, id)
            .await
            .unwrap();
        let identities = SqlxUserRepository::list_mail_identities(&pool, 13, 120)
            .await
            .unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].id, 220);

        let err = SqlxUserRepository::add_mail_identity(
            &pool,
            13,
            super::NewMailIdentity {
                account_id: 121,
                name: "Cross".to_string(),
                email: "cross@example.com".to_string(),
                reply_to: None,
                is_default: false,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.public_message(), "Account not found");
    }

    #[tokio::test]
    async fn repository_lists_and_mutates_mail_rules_with_account_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        create_mail_rule_tables(&pool).await;
        insert_user(&pool, 15, json!({})).await;
        insert_user(&pool, 16, json!({})).await;
        insert_mail_account(&pool, 130, 15, "Work", true).await;
        insert_mail_account(&pool, 131, 16, "OtherUser", true).await;
        insert_mail_rule(&pool, 300, 15, 130, "Move newsletters", true).await;
        insert_mail_rule(&pool, 301, 16, 131, "Other rule", true).await;

        let rules = SqlxUserRepository::list_mail_rules(&pool, 15, 130)
            .await
            .unwrap();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, 300);
        assert_eq!(rules[0].conditions_logic, "all");
        assert_eq!(rules[0].conditions[0]["field"], "from");
        assert_eq!(rules[0].actions[0]["type"], "move");
        assert!(rules[0].enabled);

        SqlxUserRepository::toggle_mail_rule(&pool, 15, 300, false)
            .await
            .unwrap();
        let rules = SqlxUserRepository::list_mail_rules(&pool, 15, 130)
            .await
            .unwrap();
        assert!(!rules[0].enabled);

        SqlxUserRepository::update_mail_rule_last_run(&pool, 16, 300)
            .await
            .unwrap();
        let rules = SqlxUserRepository::list_mail_rules(&pool, 15, 130)
            .await
            .unwrap();
        assert_eq!(rules[0].last_run, None);

        SqlxUserRepository::update_mail_rule_last_run(&pool, 15, 300)
            .await
            .unwrap();
        let rules = SqlxUserRepository::list_mail_rules(&pool, 15, 130)
            .await
            .unwrap();
        assert!(rules[0].last_run.is_some());

        SqlxUserRepository::delete_mail_rule(&pool, 16, 300)
            .await
            .unwrap();
        assert_eq!(
            SqlxUserRepository::list_mail_rules(&pool, 15, 130)
                .await
                .unwrap()
                .len(),
            1
        );

        SqlxUserRepository::delete_mail_rule(&pool, 15, 300)
            .await
            .unwrap();
        assert!(SqlxUserRepository::list_mail_rules(&pool, 15, 130)
            .await
            .unwrap()
            .is_empty());

        insert_mail_rule_with_null_json(&pool, 302, 15, 130, "Legacy nulls").await;
        let rules = SqlxUserRepository::list_mail_rules(&pool, 15, 130)
            .await
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].conditions, json!([]));
        assert_eq!(rules[0].conditions_logic, "all");
        assert_eq!(rules[0].actions, json!([]));

        insert_mail_rule_with_literal_null_json(&pool, 303, 15, 130, "Literal nulls").await;
        let rules = SqlxUserRepository::list_mail_rules(&pool, 15, 130)
            .await
            .unwrap();
        assert_eq!(rules[1].conditions, json!([]));
        assert_eq!(rules[1].actions, json!([]));

        let err = SqlxUserRepository::list_mail_rules(&pool, 15, 131)
            .await
            .unwrap_err();
        assert_eq!(err.public_message(), "Account not found");
    }

    #[tokio::test]
    async fn repository_adds_mail_rules_with_php_compatible_validation() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        create_mail_rule_tables(&pool).await;
        insert_user(&pool, 17, json!({})).await;
        insert_user(&pool, 18, json!({})).await;
        insert_mail_account(&pool, 140, 17, "Work", true).await;
        insert_mail_account(&pool, 141, 18, "OtherUser", true).await;

        let id = SqlxUserRepository::add_mail_rule(
            &pool,
            17,
            NewMailRule {
                account_id: 140,
                name: "  Flag invoices  ".to_string(),
                conditions: vec![json!({
                    "field": "subject",
                    "op": "contains",
                    "value": "invoice",
                })],
                conditions_logic: "bogus".to_string(),
                actions: vec![json!({"type": "flag"})],
            },
        )
        .await
        .unwrap();
        assert!(id > 0);

        let rules = SqlxUserRepository::list_mail_rules(&pool, 17, 140)
            .await
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "Flag invoices");
        assert_eq!(rules[0].conditions_logic, "all");
        assert_eq!(rules[0].conditions[0]["field"], "subject");
        assert_eq!(rules[0].actions[0]["type"], "flag");

        let err = SqlxUserRepository::add_mail_rule(
            &pool,
            17,
            NewMailRule {
                account_id: 140,
                name: "Bad condition".to_string(),
                conditions: vec![json!({
                    "field": "cc",
                    "op": "contains",
                    "value": "invoice",
                })],
                conditions_logic: "all".to_string(),
                actions: vec![json!({"type": "flag"})],
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.public_message(), "Invalid condition field");

        let err = SqlxUserRepository::add_mail_rule(
            &pool,
            17,
            NewMailRule {
                account_id: 140,
                name: "Bad move".to_string(),
                conditions: vec![json!({
                    "field": "from",
                    "op": "contains",
                    "value": "boss",
                })],
                conditions_logic: "all".to_string(),
                actions: vec![json!({"type": "move"})],
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.public_message(), "Move action requires a target folder");

        let err = SqlxUserRepository::add_mail_rule(
            &pool,
            17,
            NewMailRule {
                account_id: 140,
                name: "Bad move folder".to_string(),
                conditions: vec![json!({
                    "field": "from",
                    "op": "contains",
                    "value": "boss",
                })],
                conditions_logic: "all".to_string(),
                actions: vec![json!({
                    "type": "move",
                    "params": {"folder": "0"},
                })],
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.public_message(), "Move action requires a target folder");

        let err = SqlxUserRepository::add_mail_rule(
            &pool,
            17,
            NewMailRule {
                account_id: 141,
                name: "Cross account".to_string(),
                conditions: vec![json!({
                    "field": "from",
                    "op": "contains",
                    "value": "boss",
                })],
                conditions_logic: "all".to_string(),
                actions: vec![json!({"type": "flag"})],
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.public_message(), "Account not found");
    }

    #[tokio::test]
    async fn repository_updates_mail_account_settings_with_user_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 35, json!({})).await;
        insert_user(&pool, 36, json!({})).await;
        insert_mail_account(&pool, 172, 35, "Work", true).await;
        insert_mail_account(&pool, 173, 36, "OtherUser", true).await;

        let updated = SqlxUserRepository::update_mail_account_settings(
            &pool,
            35,
            172,
            &json!({"SentFolder": "Sent", "ArchiveFolder": "Archive"}),
        )
        .await
        .unwrap();
        assert!(updated);
        assert_eq!(
            mail_account_settings(&pool, 172).await,
            json!({"SentFolder": "Sent", "ArchiveFolder": "Archive"})
        );

        let updated = SqlxUserRepository::update_mail_account_settings(
            &pool,
            35,
            173,
            &json!({"SentFolder": "WrongUser"}),
        )
        .await
        .unwrap();
        assert!(!updated);
        assert_eq!(mail_account_settings(&pool, 173).await, json!({}));
    }

    #[tokio::test]
    async fn repository_updates_checkable_folders_atomically_and_preserves_settings() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 37, json!({})).await;
        insert_mail_account(&pool, 174, 37, "Work", true).await;
        sqlx::query("UPDATE frickmail_mail_accounts SET settings = ? WHERE user_id = ? AND id = ?")
            .bind(
                json!({
                    "SentFolder": "Sent",
                    "CheckableFolder": "[\"INBOX\"]"
                })
                .to_string(),
            )
            .bind(37_i64)
            .bind(174_i64)
            .execute(&pool)
            .await
            .unwrap();

        for _ in 0..2 {
            assert!(SqlxUserRepository::set_mail_account_checkable_folder(
                &pool, 37, 174, "Archive", true,
            )
            .await
            .unwrap());
        }
        let settings = mail_account_settings(&pool, 174).await;
        assert_eq!(settings["SentFolder"], "Sent");
        assert_eq!(settings["CheckableFolder"], "[\"INBOX\",\"Archive\"]");

        assert!(SqlxUserRepository::set_mail_account_checkable_folder(
            &pool, 37, 174, "Archive", false,
        )
        .await
        .unwrap());
        assert_eq!(
            mail_account_settings(&pool, 174).await["CheckableFolder"],
            "[\"INBOX\"]"
        );
    }

    #[tokio::test]
    async fn repository_renames_checkable_folder_subtree_with_user_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        insert_user(&pool, 38, json!({})).await;
        insert_user(&pool, 39, json!({})).await;
        insert_mail_account(&pool, 175, 38, "Work", true).await;
        insert_mail_account(&pool, 176, 39, "Other", true).await;
        sqlx::query("UPDATE frickmail_mail_accounts SET settings = ? WHERE user_id = ? AND id = ?")
            .bind(
                json!({
                    "CheckableFolder": [
                        "Projects",
                        "Projects/Active",
                        "Projects/Active",
                        "Projects-old"
                    ],
                    "TrashFolder": "Trash"
                })
                .to_string(),
            )
            .bind(38_i64)
            .bind(175_i64)
            .execute(&pool)
            .await
            .unwrap();

        assert!(SqlxUserRepository::rename_mail_account_checkable_folders(
            &pool, 38, 175, "Projects", "Work", "/", true,
        )
        .await
        .unwrap());
        let settings = mail_account_settings(&pool, 175).await;
        assert_eq!(settings["TrashFolder"], "Trash");
        assert_eq!(
            settings["CheckableFolder"],
            "[\"Work/Active\",\"Projects-old\",\"Work\"]"
        );

        assert!(!SqlxUserRepository::rename_mail_account_checkable_folders(
            &pool, 38, 176, "Projects", "Work", "/", true,
        )
        .await
        .unwrap());
        assert_eq!(mail_account_settings(&pool, 176).await, json!({}));
    }

    #[test]
    fn checkable_folder_helpers_normalize_legacy_values_and_respect_boundaries() {
        assert_eq!(
            super::checkable_folders_from_setting(Some(&json!("[\"INBOX\",\"Archive\"]"))),
            vec!["INBOX", "Archive"]
        );
        assert_eq!(
            super::checkable_folders_from_setting(Some(&json!(["INBOX", 7, "Archive"]))),
            vec!["INBOX", "Archive"]
        );
        assert!(super::checkable_folders_from_setting(Some(&json!("broken"))).is_empty());

        let mut folders = vec![
            "Old".to_string(),
            "Old/Child".to_string(),
            "Oldish".to_string(),
        ];
        super::rename_checkable_folder_subtree(&mut folders, "Old", "New", "/", false);
        assert_eq!(folders, vec!["New/Child", "Oldish"]);

        let mut flat = vec!["Old".to_string(), "Oldish".to_string()];
        super::rename_checkable_folder_subtree(&mut flat, "Old", "New", "", true);
        assert_eq!(flat, vec!["Oldish", "New"]);
    }

    #[tokio::test]
    async fn repository_lists_and_mutates_tasks_with_user_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_task_tables(&pool).await;
        insert_user(&pool, 19, json!({})).await;
        insert_user(&pool, 20, json!({})).await;
        insert_task(&pool, 400, 19, "Later", Some("2026-06-10"), false).await;
        insert_task(&pool, 401, 19, "Soon", Some("2026-06-01"), false).await;
        insert_task(&pool, 402, 19, "Done", None, true).await;
        insert_task(&pool, 403, 20, "Other user", Some("2026-06-01"), false).await;

        let tasks = SqlxUserRepository::list_tasks(&pool, 19, TaskFilter::All)
            .await
            .unwrap();
        assert_eq!(
            tasks.iter().map(|task| task.id).collect::<Vec<_>>(),
            vec![401, 400, 402]
        );
        assert!(!tasks[0].completed);
        assert_eq!(tasks[0].due_date.as_deref(), Some("2026-06-01"));

        let tasks = SqlxUserRepository::list_tasks(&pool, 19, TaskFilter::Pending)
            .await
            .unwrap();
        assert_eq!(
            tasks.iter().map(|task| task.id).collect::<Vec<_>>(),
            vec![401, 400]
        );

        let id = SqlxUserRepository::add_task(
            &pool,
            19,
            NewMailTask {
                title: "  New task  ".to_string(),
                notes: Some(String::new()),
                due_date: Some("2026-06-05".to_string()),
            },
        )
        .await
        .unwrap();
        assert!(id > 0);

        let tasks = SqlxUserRepository::list_tasks(&pool, 19, TaskFilter::Pending)
            .await
            .unwrap();
        let added = tasks.iter().find(|task| task.id == id).unwrap();
        assert_eq!(added.title, "New task");
        assert_eq!(added.notes, None);
        assert_eq!(added.due_date.as_deref(), Some("2026-06-05"));

        assert!(SqlxUserRepository::complete_task(&pool, 19, id, true)
            .await
            .unwrap());
        let tasks = SqlxUserRepository::list_tasks(&pool, 19, TaskFilter::Completed)
            .await
            .unwrap();
        assert!(tasks.iter().any(|task| task.id == id && task.completed));

        assert!(SqlxUserRepository::update_task(
            &pool,
            19,
            UpdateMailTask {
                id,
                title: " Updated ".to_string(),
                notes: Some("notes".to_string()),
                due_date: Some(String::new()),
            },
        )
        .await
        .unwrap());
        let tasks = SqlxUserRepository::list_tasks(&pool, 19, TaskFilter::Completed)
            .await
            .unwrap();
        let updated = tasks.iter().find(|task| task.id == id).unwrap();
        assert_eq!(updated.title, "Updated");
        assert_eq!(updated.notes.as_deref(), Some("notes"));
        assert_eq!(updated.due_date, None);

        assert!(!SqlxUserRepository::delete_task(&pool, 20, id)
            .await
            .unwrap());
        assert!(SqlxUserRepository::delete_task(&pool, 19, id)
            .await
            .unwrap());
        assert!(!SqlxUserRepository::complete_task(&pool, 20, 401, true)
            .await
            .unwrap());

        let err = SqlxUserRepository::add_task(
            &pool,
            19,
            NewMailTask {
                title: "  ".to_string(),
                notes: None,
                due_date: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.public_message(), "title is required");
    }

    #[tokio::test]
    async fn repository_upserts_and_deletes_push_subscriptions_with_user_scope() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_push_subscription_tables(&pool).await;
        insert_user(&pool, 21, json!({})).await;
        insert_user(&pool, 22, json!({})).await;

        SqlxUserRepository::upsert_push_subscription(
            &pool,
            21,
            PushSubscription {
                endpoint: "https://push.example/sub".to_string(),
                p256dh: "key-1".to_string(),
                auth_key: "auth-1".to_string(),
            },
        )
        .await
        .unwrap();
        SqlxUserRepository::upsert_push_subscription(
            &pool,
            21,
            PushSubscription {
                endpoint: "https://push.example/sub".to_string(),
                p256dh: "key-2".to_string(),
                auth_key: "auth-2".to_string(),
            },
        )
        .await
        .unwrap();
        SqlxUserRepository::upsert_push_subscription(
            &pool,
            22,
            PushSubscription {
                endpoint: "https://push.example/sub".to_string(),
                p256dh: "other-key".to_string(),
                auth_key: "other-auth".to_string(),
            },
        )
        .await
        .unwrap();

        assert_eq!(push_subscription_count(&pool, 21).await, 1);
        assert_eq!(
            push_subscription_auth(&pool, 21, "https://push.example/sub")
                .await
                .as_deref(),
            Some("auth-2")
        );
        let subscriptions = SqlxUserRepository::list_push_subscriptions(&pool, 21)
            .await
            .unwrap();
        assert_eq!(
            subscriptions,
            vec![PushSubscription {
                endpoint: "https://push.example/sub".to_string(),
                p256dh: "key-2".to_string(),
                auth_key: "auth-2".to_string(),
            }]
        );

        SqlxUserRepository::delete_push_subscription(
            &pool,
            21,
            "https://push.example/sub".to_string(),
        )
        .await
        .unwrap();
        assert_eq!(push_subscription_count(&pool, 21).await, 0);
        assert_eq!(push_subscription_count(&pool, 22).await, 1);

        let err = SqlxUserRepository::upsert_push_subscription(
            &pool,
            21,
            PushSubscription {
                endpoint: String::new(),
                p256dh: "key".to_string(),
                auth_key: "auth".to_string(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.public_message(), "Missing subscription fields");
    }

    #[tokio::test]
    async fn repository_gets_or_creates_persistent_vapid_key() {
        let pool = sqlite_pool().await;
        create_app_settings_table(&pool).await;

        let public_key = SqlxUserRepository::get_or_create_vapid_public_key(&pool)
            .await
            .unwrap();
        assert!(!public_key.is_empty());

        let stored = app_setting(&pool, VAPID_SETTING_KEY).await.unwrap();
        let bundle: VapidKeyBundle = serde_json::from_str(&stored).unwrap();
        assert_eq!(bundle.public_b64u, public_key);
        assert!(bundle.private_pem.contains("BEGIN PRIVATE KEY"));

        let second = SqlxUserRepository::get_or_create_vapid_public_key(&pool)
            .await
            .unwrap();
        assert_eq!(second, public_key);
    }

    #[tokio::test]
    async fn repository_reuses_existing_vapid_key_bundle() {
        let pool = sqlite_pool().await;
        create_app_settings_table(&pool).await;
        let existing = VapidKeyBundle {
            public_b64u: "existing-public-key".to_string(),
            private_pem: "existing-private-pem".to_string(),
        };
        insert_app_setting(
            &pool,
            VAPID_SETTING_KEY,
            &serde_json::to_string(&existing).unwrap(),
        )
        .await;

        let public_key = SqlxUserRepository::get_or_create_vapid_public_key(&pool)
            .await
            .unwrap();
        assert_eq!(public_key, "existing-public-key");
    }

    #[tokio::test]
    async fn repository_lists_and_unlinks_oidc_identities_with_escrow_cleanup() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_oidc_identity_tables(&pool).await;
        insert_user(&pool, 23, json!({})).await;
        insert_user(&pool, 24, json!({})).await;
        set_oidc_escrow_key(&pool, 23, Some(vec![1, 2, 3])).await;
        insert_oidc_identity(&pool, 23, "provider-a", "subject-a", "2026-06-02 10:00:00").await;
        insert_oidc_identity(&pool, 23, "provider-b", "subject-b", "2026-06-01 10:00:00").await;
        insert_oidc_identity(
            &pool,
            24,
            "provider-a",
            "other-subject",
            "2026-06-03 10:00:00",
        )
        .await;

        let links = SqlxUserRepository::list_oidc_links(&pool, 23, "  Company SSO  ")
            .await
            .unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].provider_hash, "provider-a");
        assert_eq!(links[0].provider_name, "Company SSO");
        assert_eq!(links[1].provider_hash, "provider-b");

        let links = SqlxUserRepository::list_oidc_links(&pool, 23, " ")
            .await
            .unwrap();
        assert_eq!(links[0].provider_name, "SSO");

        SqlxUserRepository::unlink_oidc_identity(&pool, 23, " provider-a ".to_string())
            .await
            .unwrap();
        assert_eq!(oidc_identity_count(&pool, 23).await, 1);
        assert!(SqlxUserRepository::find_by_id(&pool, 23)
            .await
            .unwrap()
            .unwrap()
            .oidc_escrow_key
            .is_some());
        assert_eq!(oidc_identity_count(&pool, 24).await, 1);

        SqlxUserRepository::unlink_oidc_identity(&pool, 23, "provider-b".to_string())
            .await
            .unwrap();
        assert_eq!(oidc_identity_count(&pool, 23).await, 0);
        assert!(SqlxUserRepository::find_by_id(&pool, 23)
            .await
            .unwrap()
            .unwrap()
            .oidc_escrow_key
            .is_none());

        let err = SqlxUserRepository::unlink_oidc_identity(&pool, 23, " ".to_string())
            .await
            .unwrap_err();
        assert_eq!(err.public_message(), "provider_hash required");
    }

    #[tokio::test]
    async fn repository_lists_and_deletes_smime_certs_without_secret_material() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_smime_cert_tables(&pool).await;
        insert_user(&pool, 31, json!({})).await;
        insert_user(&pool, 32, json!({})).await;
        insert_smime_cert(
            &pool,
            101,
            31,
            301,
            "signer@example.com",
            "fp-new",
            Some("CN=Signer"),
            Some(vec![1, 2, 3]),
            "2026-06-02 10:00:00",
        )
        .await;
        insert_smime_cert(
            &pool,
            102,
            31,
            302,
            "public@example.com",
            "fp-old",
            None,
            None,
            "2026-06-01 10:00:00",
        )
        .await;
        insert_smime_cert(
            &pool,
            104,
            31,
            304,
            "empty-key@example.com",
            "fp-empty",
            Some("CN=Empty"),
            Some(Vec::new()),
            "2026-05-31 10:00:00",
        )
        .await;
        insert_smime_cert(
            &pool,
            103,
            32,
            303,
            "other@example.com",
            "fp-other",
            Some("CN=Other"),
            Some(vec![9]),
            "2026-06-03 10:00:00",
        )
        .await;

        let certs = SqlxUserRepository::list_smime_certs(&pool, 31)
            .await
            .unwrap();
        assert_eq!(certs.len(), 3);
        assert_eq!(certs[0].id, 101);
        assert_eq!(certs[0].account_id, 301);
        assert_eq!(certs[0].email, "signer@example.com");
        assert_eq!(certs[0].fingerprint, "fp-new");
        assert_eq!(certs[0].subject, "CN=Signer");
        assert!(certs[0].has_key);
        assert_eq!(certs[1].id, 102);
        assert_eq!(certs[1].subject, "");
        assert!(!certs[1].has_key);
        assert_eq!(certs[2].id, 104);
        assert!(!certs[2].has_key);

        assert!(!SqlxUserRepository::delete_smime_cert(&pool, 31, 103)
            .await
            .unwrap());
        assert_eq!(smime_cert_count(&pool, 32).await, 1);
        assert!(SqlxUserRepository::delete_smime_cert(&pool, 31, 102)
            .await
            .unwrap());
        assert_eq!(smime_cert_count(&pool, 31).await, 2);
    }

    #[tokio::test]
    async fn smime_compose_signing_material_is_scoped_to_its_mail_account() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_smime_cert_tables(&pool).await;
        insert_user(&pool, 35, json!({})).await;
        insert_smime_cert(
            &pool,
            105,
            35,
            305,
            "same@example.com",
            "first",
            None,
            Some(vec![1]),
            "2026-06-01 00:00:00",
        )
        .await;
        insert_smime_cert(
            &pool,
            106,
            35,
            306,
            "same@example.com",
            "second",
            None,
            Some(vec![2]),
            "2026-06-02 00:00:00",
        )
        .await;
        sqlx::query("UPDATE frickmail_smime_certs SET cert_pem = ? WHERE id = ?")
            .bind("account-305")
            .bind(105_i64)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE frickmail_smime_certs SET cert_pem = ? WHERE id = ?")
            .bind("account-306")
            .bind(106_i64)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            super::fetch_smime_signing_material(&pool, 35, Some(305), "same@example.com")
                .await
                .unwrap()
                .unwrap()
                .cert_pem,
            "account-305"
        );
        assert_eq!(
            super::fetch_smime_signing_material(&pool, 35, Some(306), "same@example.com")
                .await
                .unwrap()
                .unwrap()
                .cert_pem,
            "account-306"
        );
    }

    #[tokio::test]
    async fn repository_imports_smime_cert_from_public_pem() {
        let pool = sqlite_pool().await;
        create_users_table(&pool, "TEXT").await;
        create_mail_account_tables(&pool).await;
        create_smime_cert_tables(&pool).await;
        insert_user(&pool, 33, json!({})).await;
        insert_user(&pool, 34, json!({})).await;
        insert_mail_account(&pool, 305, 33, "Work", true).await;
        insert_mail_account(&pool, 306, 34, "Other", true).await;

        let result = SqlxUserRepository::import_smime_cert(
            &pool,
            33,
            NewSmimeCert {
                account_id: 305,
                pem: format!("\n{}\n", test_smime_cert_pem("signer@example.com")),
            },
        )
        .await
        .unwrap();

        assert!(result.ok);
        assert!(result.id > 0);
        assert_eq!(result.email, "signer@example.com");
        assert_eq!(result.fingerprint.matches(':').count(), 19);
        assert!(result.not_after.is_some());

        let certs = SqlxUserRepository::list_smime_certs(&pool, 33)
            .await
            .unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].id, result.id);
        assert_eq!(certs[0].account_id, 305);
        assert_eq!(certs[0].email, "signer@example.com");
        assert_eq!(certs[0].fingerprint, result.fingerprint);
        assert!(certs[0].subject.contains("CN=signer@example.com"));
        assert!(!certs[0].has_key);

        let stored_pem = smime_cert_pem(&pool, result.id).await;
        assert!(stored_pem.contains("BEGIN CERTIFICATE"));
        assert!(!stored_pem.contains("PRIVATE KEY"));

        let oversized = SqlxUserRepository::import_smime_cert(
            &pool,
            33,
            NewSmimeCert {
                account_id: 305,
                pem: "x".repeat(super::SMIME_CERT_PEM_MAX_BYTES + 1),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            oversized.public_message(),
            "S/MIME certificate exceeds the safety limit"
        );

        let wrong_user = SqlxUserRepository::import_smime_cert(
            &pool,
            33,
            NewSmimeCert {
                account_id: 306,
                pem: test_smime_cert_pem("other@example.com"),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(wrong_user.public_message(), "Account not found");

        let invalid = SqlxUserRepository::import_smime_cert(
            &pool,
            33,
            NewSmimeCert {
                account_id: 305,
                pem: "not a certificate".to_string(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(invalid.public_message(), "Invalid PEM certificate");

        let combined = SqlxUserRepository::import_smime_cert(
            &pool,
            33,
            NewSmimeCert {
                account_id: 305,
                pem: format!(
                    "{}\n{}",
                    test_smime_cert_pem("combined@example.com"),
                    test_private_key_pem()
                ),
            },
        )
        .await
        .unwrap();
        let stored_combined_pem = smime_cert_pem(&pool, combined.id).await;
        assert!(stored_combined_pem.contains("BEGIN CERTIFICATE"));
        assert!(!stored_combined_pem.contains("PRIVATE KEY"));
    }

    async fn sqlite_pool() -> AnyPool {
        sqlx::any::install_default_drivers();
        AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    fn test_user(id: i64, settings: Value) -> super::FrickmailUser {
        super::FrickmailUser {
            id,
            username: format!("user{id}"),
            email: Some(format!("user{id}@example.com")),
            password_hash: "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$BKy6gHf7a1YF9iq3VbwpiV6FyboHjrVmgMu+wf8tBY4".to_string(),
            kdf_salt: vec![1_u8; KDF_SALT_BYTES],
            settings,
            totp_secret: None,
            oidc_escrow_key: None,
        }
    }

    async fn create_users_table(pool: &AnyPool, settings_type: &str) {
        let sql = format!(
            "CREATE TABLE frickmail_users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT,
                password_hash TEXT NOT NULL,
                kdf_salt BLOB NOT NULL,
                settings {settings_type} NOT NULL DEFAULT '{{}}',
                totp_secret TEXT,
                oidc_escrow_key BLOB,
                updated_at TEXT
            )"
        );
        sqlx::query(&sql).execute(pool).await.unwrap();
    }

    async fn create_mail_account_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_mail_accounts (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                email TEXT NOT NULL,
                type TEXT NOT NULL,
                imap_host TEXT,
                imap_port INTEGER,
                imap_secure TEXT,
                smtp_host TEXT,
                smtp_port INTEGER,
                smtp_secure TEXT,
                login TEXT,
                encrypted_password BLOB,
                encrypted_oauth_refresh_token BLOB,
                oauth_tenant TEXT,
                settings TEXT NOT NULL DEFAULT '{}',
                is_primary BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TEXT,
                updated_at TEXT
            )",
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "CREATE TABLE frickmail_identities (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                reply_to TEXT,
                is_default BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TEXT
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_mail_rule_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_rules (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                conditions TEXT,
                actions TEXT,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                last_run TEXT,
                created_at TEXT,
                updated_at TEXT
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_message_index_table(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_message_index (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                folder TEXT NOT NULL,
                imap_uid INTEGER NOT NULL,
                message_id TEXT,
                subject TEXT,
                from_addr TEXT,
                from_name TEXT,
                date_ts TEXT,
                snippet TEXT
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_password_reset_table(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_password_resets (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_totp_used_table(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_totp_used (
                user_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                \"window\" INTEGER NOT NULL,
                used_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, code, \"window\")
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn totp_used_window(pool: &AnyPool, user_id: i64, code: &str) -> Option<i64> {
        sqlx::query("SELECT \"window\" FROM frickmail_totp_used WHERE user_id = ? AND code = ?")
            .bind(user_id)
            .bind(code)
            .fetch_optional(pool)
            .await
            .unwrap()
            .map(|row| row.try_get("window").unwrap())
    }

    async fn create_task_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_tasks (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                notes TEXT,
                due_date TEXT,
                completed BOOLEAN NOT NULL DEFAULT FALSE,
                completed_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_push_subscription_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_push_subscriptions (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                endpoint TEXT NOT NULL,
                p256dh TEXT NOT NULL,
                auth_key TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, endpoint)
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_app_settings_table(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_app_settings (
                setting_key VARCHAR(191) PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_oidc_identity_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_oidc_identities (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                provider_hash TEXT NOT NULL,
                subject TEXT NOT NULL,
                linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(provider_hash, subject)
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_smime_cert_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_smime_certs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                encrypted_key_pem BLOB,
                fingerprint TEXT NOT NULL,
                subject TEXT,
                not_before TEXT,
                not_after TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_user(pool: &AnyPool, id: i64, settings: Value) {
        sqlx::query(
            "INSERT INTO frickmail_users
                (id, username, email, password_hash, kdf_salt, settings, totp_secret, oidc_escrow_key, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(format!("user{id}"))
        .bind(format!("user{id}@example.com"))
        .bind("$argon2id$v=19$m=65536,t=3,p=1$placeholder")
        .bind(vec![1_u8, 2, 3, 4])
        .bind(settings.to_string())
        .bind(None::<String>)
        .bind(None::<Vec<u8>>)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_mail_account(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        label: &str,
        is_primary: bool,
    ) {
        let local = label.to_ascii_lowercase();
        sqlx::query(
            "INSERT INTO frickmail_mail_accounts
                (id, user_id, label, email, type, imap_host, imap_port, imap_secure,
                 smtp_host, smtp_port, smtp_secure, login, encrypted_password,
                 encrypted_oauth_refresh_token, oauth_tenant, is_primary, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(user_id)
        .bind(label)
        .bind(format!("{local}@example.com"))
        .bind("imap")
        .bind("imap.example.com")
        .bind(993_i64)
        .bind("SSL")
        .bind("smtp.example.com")
        .bind(465_i64)
        .bind("SSL")
        .bind(format!("{local}@example.com"))
        .bind(vec![1_u8, 2, 3])
        .bind(None::<Vec<u8>>)
        .bind(None::<String>)
        .bind(is_primary)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_identity(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        account_id: i64,
        name: &str,
        is_default: bool,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_identities
                (id, account_id, user_id, name, email, reply_to, is_default, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(account_id)
        .bind(user_id)
        .bind(name)
        .bind(format!("{}@example.com", name.to_ascii_lowercase()))
        .bind(None::<String>)
        .bind(is_default)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_message_index(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
        folder: &str,
        imap_uid: i64,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_message_index
                (user_id, account_id, folder, imap_uid, subject)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(account_id)
        .bind(folder)
        .bind(imap_uid)
        .bind("Indexed message")
        .execute(pool)
        .await
        .unwrap();
    }

    struct SearchMessageSeed<'a> {
        id: i64,
        user_id: i64,
        account_id: i64,
        folder: &'a str,
        imap_uid: i64,
        message_id: Option<&'a str>,
        subject: Option<&'a str>,
        from_addr: Option<&'a str>,
        from_name: Option<&'a str>,
        date_ts: Option<&'a str>,
        snippet: Option<&'a str>,
    }

    async fn insert_search_message(pool: &AnyPool, message: SearchMessageSeed<'_>) {
        sqlx::query(
            "INSERT INTO frickmail_message_index
                (id, user_id, account_id, folder, imap_uid, message_id, subject,
                 from_addr, from_name, date_ts, snippet)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(message.id)
        .bind(message.user_id)
        .bind(message.account_id)
        .bind(message.folder)
        .bind(message.imap_uid)
        .bind(message.message_id)
        .bind(message.subject)
        .bind(message.from_addr)
        .bind(message.from_name)
        .bind(message.date_ts)
        .bind(message.snippet)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn set_oauth_refresh_token(pool: &AnyPool, account_id: i64, token: Vec<u8>) {
        sqlx::query(
            "UPDATE frickmail_mail_accounts
             SET encrypted_oauth_refresh_token = ?
             WHERE id = ?",
        )
        .bind(token)
        .bind(account_id)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_password_reset(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        token_hash: &str,
        expires_at: &str,
        used_at: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_password_resets
                (id, user_id, token_hash, expires_at, used_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .bind(used_at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn account_credentials_are_null(pool: &AnyPool, account_id: i64) -> bool {
        sqlx::query(
            "SELECT encrypted_password, encrypted_oauth_refresh_token
             FROM frickmail_mail_accounts
             WHERE id = ?",
        )
        .bind(account_id)
        .fetch_one(pool)
        .await
        .map(|row| {
            let password: Option<Vec<u8>> = row.try_get("encrypted_password").unwrap();
            let token: Option<Vec<u8>> = row.try_get("encrypted_oauth_refresh_token").unwrap();
            password.is_none() && token.is_none()
        })
        .unwrap()
    }

    async fn account_encrypted_password(pool: &AnyPool, account_id: i64) -> Option<Vec<u8>> {
        sqlx::query("SELECT encrypted_password FROM frickmail_mail_accounts WHERE id = ?")
            .bind(account_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("encrypted_password"))
            .unwrap()
    }

    async fn account_oauth_refresh_token(pool: &AnyPool, account_id: i64) -> Option<Vec<u8>> {
        sqlx::query(
            "SELECT encrypted_oauth_refresh_token FROM frickmail_mail_accounts WHERE id = ?",
        )
        .bind(account_id)
        .fetch_one(pool)
        .await
        .and_then(|row| row.try_get("encrypted_oauth_refresh_token"))
        .unwrap()
    }

    async fn account_type(pool: &AnyPool, account_id: i64) -> String {
        sqlx::query("SELECT type FROM frickmail_mail_accounts WHERE id = ?")
            .bind(account_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("type"))
            .unwrap()
    }

    async fn password_reset_used_at(pool: &AnyPool, reset_id: i64) -> Option<String> {
        sqlx::query("SELECT used_at FROM frickmail_password_resets WHERE id = ?")
            .bind(reset_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("used_at"))
            .unwrap()
    }

    async fn active_password_reset_count(pool: &AnyPool, user_id: i64) -> i64 {
        sqlx::query(
            "SELECT COUNT(*) AS count FROM frickmail_password_resets
             WHERE user_id = ? AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .and_then(|row| row.try_get("count"))
        .unwrap()
    }

    async fn mail_account_count(pool: &AnyPool, user_id: i64) -> i64 {
        sqlx::query("SELECT COUNT(*) AS count FROM frickmail_mail_accounts WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("count"))
            .unwrap()
    }

    async fn mail_account_settings(pool: &AnyPool, account_id: i64) -> Value {
        let settings: String =
            sqlx::query("SELECT settings FROM frickmail_mail_accounts WHERE id = ?")
                .bind(account_id)
                .fetch_one(pool)
                .await
                .and_then(|row| row.try_get("settings"))
                .unwrap();
        serde_json::from_str(&settings).unwrap()
    }

    async fn message_index_count(pool: &AnyPool, user_id: i64, account_id: i64) -> i64 {
        sqlx::query(
            "SELECT COUNT(*) AS count FROM frickmail_message_index
             WHERE user_id = ? AND account_id = ?",
        )
        .bind(user_id)
        .bind(account_id)
        .fetch_one(pool)
        .await
        .and_then(|row| row.try_get("count"))
        .unwrap()
    }

    async fn set_totp_secret(pool: &AnyPool, user_id: i64, secret: Option<&str>) {
        sqlx::query("UPDATE frickmail_users SET totp_secret = ? WHERE id = ?")
            .bind(secret)
            .bind(user_id)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn insert_mail_rule(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        account_id: i64,
        name: &str,
        enabled: bool,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_rules
                (id, user_id, account_id, name, conditions, actions, enabled, last_run, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(user_id)
        .bind(account_id)
        .bind(name)
        .bind(json!({
            "conditions": [
                {"field": "from", "op": "contains", "value": "newsletter"}
            ],
            "conditions_logic": "all"
        }).to_string())
        .bind(json!([
            {"type": "move", "params": {"folder": "Newsletters"}}
        ]).to_string())
        .bind(enabled)
        .bind(None::<String>)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_mail_rule_with_null_json(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        account_id: i64,
        name: &str,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_rules
                (id, user_id, account_id, name, conditions, actions, enabled, last_run, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(user_id)
        .bind(account_id)
        .bind(name)
        .bind(None::<String>)
        .bind(None::<String>)
        .bind(true)
        .bind(None::<String>)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_mail_rule_with_literal_null_json(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        account_id: i64,
        name: &str,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_rules
                (id, user_id, account_id, name, conditions, actions, enabled, last_run, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(user_id)
        .bind(account_id)
        .bind(name)
        .bind("null")
        .bind("null")
        .bind(true)
        .bind(None::<String>)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_task(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        title: &str,
        due_date: Option<&str>,
        completed: bool,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_tasks
                (id, user_id, title, notes, due_date, completed, completed_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(user_id)
        .bind(title)
        .bind(None::<String>)
        .bind(due_date)
        .bind(completed)
        .bind(if completed {
            Some("2026-06-01 10:00:00")
        } else {
            None
        })
        .execute(pool)
        .await
        .unwrap();
    }

    async fn push_subscription_count(pool: &AnyPool, user_id: i64) -> i64 {
        sqlx::query("SELECT COUNT(*) AS count FROM frickmail_push_subscriptions WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("count"))
            .unwrap()
    }

    async fn push_subscription_auth(
        pool: &AnyPool,
        user_id: i64,
        endpoint: &str,
    ) -> Option<String> {
        sqlx::query(
            "SELECT auth_key FROM frickmail_push_subscriptions WHERE user_id = ? AND endpoint = ?",
        )
        .bind(user_id)
        .bind(endpoint)
        .fetch_optional(pool)
        .await
        .unwrap()
        .map(|row| row.try_get("auth_key").unwrap())
    }

    async fn app_setting(pool: &AnyPool, key: &str) -> Option<String> {
        sqlx::query("SELECT setting_value FROM frickmail_app_settings WHERE setting_key = ?")
            .bind(key)
            .fetch_optional(pool)
            .await
            .unwrap()
            .map(|row| row.try_get("setting_value").unwrap())
    }

    async fn insert_app_setting(pool: &AnyPool, key: &str, value: &str) {
        sqlx::query(
            "INSERT INTO frickmail_app_settings (setting_key, setting_value) VALUES (?, ?)",
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn set_oidc_escrow_key(pool: &AnyPool, user_id: i64, value: Option<Vec<u8>>) {
        sqlx::query("UPDATE frickmail_users SET oidc_escrow_key = ? WHERE id = ?")
            .bind(value)
            .bind(user_id)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn insert_oidc_identity(
        pool: &AnyPool,
        user_id: i64,
        provider_hash: &str,
        subject: &str,
        linked_at: &str,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_oidc_identities
                (user_id, provider_hash, subject, linked_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(provider_hash)
        .bind(subject)
        .bind(linked_at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn oidc_identity_count(pool: &AnyPool, user_id: i64) -> i64 {
        sqlx::query("SELECT COUNT(*) AS count FROM frickmail_oidc_identities WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("count"))
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_smime_cert(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        account_id: i64,
        email: &str,
        fingerprint: &str,
        subject: Option<&str>,
        encrypted_key_pem: Option<Vec<u8>>,
        created_at: &str,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_smime_certs
                (id, user_id, account_id, email, cert_pem, encrypted_key_pem,
                 fingerprint, subject, not_before, not_after, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(user_id)
        .bind(account_id)
        .bind(email)
        .bind("-----BEGIN CERTIFICATE-----\nredacted\n-----END CERTIFICATE-----")
        .bind(encrypted_key_pem)
        .bind(fingerprint)
        .bind(subject)
        .bind(Some("2026-01-01 00:00:00"))
        .bind(Some("2027-01-01 00:00:00"))
        .bind(created_at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn smime_cert_count(pool: &AnyPool, user_id: i64) -> i64 {
        sqlx::query("SELECT COUNT(*) AS count FROM frickmail_smime_certs WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("count"))
            .unwrap()
    }

    async fn smime_cert_pem(pool: &AnyPool, cert_id: i64) -> String {
        sqlx::query("SELECT cert_pem FROM frickmail_smime_certs WHERE id = ?")
            .bind(cert_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("cert_pem"))
            .unwrap()
    }

    fn test_smime_cert_pem(email: &str) -> String {
        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, email).unwrap();
        name.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, email)
            .unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();
        let san = SubjectAlternativeName::new()
            .email(email)
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();

        String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
    }

    fn test_private_key_pem() -> String {
        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();
        String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap()
    }
}
