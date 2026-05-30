use fm_core::{FrickmailError, Result, UserSession};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{AnyPool, Row};

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
}

pub fn normalize_username(username: &str) -> String {
    username.trim().to_ascii_lowercase()
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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sqlx::{any::AnyPoolOptions, AnyPool};

    use super::{normalize_username, FrickmailMe, SqlxUserRepository};
    use fm_core::UserSession;

    #[test]
    fn username_normalization_matches_php_login_flow() {
        assert_eq!(normalize_username("  Nicola.EXAMPLE  "), "nicola.example");
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

    async fn sqlite_pool() -> AnyPool {
        sqlx::any::install_default_drivers();
        AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }
}
