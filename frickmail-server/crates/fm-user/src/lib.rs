use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Algorithm, Argon2, Params, Version,
};
use fm_core::{FrickmailError, Result, UserSession};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Number, Value};
use sqlx::{AnyPool, Row};
use std::collections::HashMap;

pub const KDF_SALT_BYTES: usize = 16;
pub const CREDENTIAL_KEY_BYTES: usize = 32;
pub const KDF_OPSLIMIT: u32 = 3;
pub const KDF_MEMLIMIT_KIB: u32 = 65_536;
pub const DUMMY_PASSWORD_HASH: &str =
    "$argon2id$v=19$m=65536,t=4,p=1$TTJYNUVsNlE5Q1RwTzZacQ$AnMUliGcTz3HHGhxmAib/d0fPagGYhpUa1uQxLPgyeg";

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
pub struct OidcLink {
    pub provider_hash: String,
    pub provider_name: String,
    pub linked_at: Option<String>,
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
    value.and_then(|value| if value.is_empty() { None } else { Some(value) })
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
    use serde_json::{json, Value};
    use sqlx::{any::AnyPoolOptions, AnyPool, Row};

    use super::{
        clean_preferences_patch, derive_credential_key, normalize_username,
        preferences_from_settings, verify_login_password, verify_password, FrickmailMe,
        NewMailRule, NewMailTask, PushSubscription, SqlxUserRepository, TaskFilter, UpdateMailTask,
        CREDENTIAL_KEY_BYTES, DUMMY_PASSWORD_HASH, KDF_SALT_BYTES,
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
                settings {settings_type} NOT NULL,
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
}
