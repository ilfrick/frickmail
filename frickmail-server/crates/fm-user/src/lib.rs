use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Algorithm, Argon2, Params, Version,
};
use fm_core::{FrickmailError, Result, UserSession};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Number, Value};
use sqlx::{AnyPool, Row};

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
    use sqlx::{any::AnyPoolOptions, AnyPool};

    use super::{
        clean_preferences_patch, derive_credential_key, normalize_username,
        preferences_from_settings, verify_login_password, verify_password, FrickmailMe,
        SqlxUserRepository, CREDENTIAL_KEY_BYTES, DUMMY_PASSWORD_HASH, KDF_SALT_BYTES,
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
}
