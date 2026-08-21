use fm_core::{FrickmailConfig, FrickmailError, Result};
use sqlx::{any::AnyPoolOptions, AnyPool};

pub fn connect_lazy(config: &FrickmailConfig) -> Result<Option<AnyPool>> {
    let Some(database_url) = config
        .database_url
        .as_ref()
        .filter(|url| !url.trim().is_empty())
    else {
        return Ok(None);
    };

    sqlx::any::install_default_drivers();

    AnyPoolOptions::new()
        .max_connections(10)
        .connect_lazy(database_url)
        .map(Some)
        .map_err(|err| FrickmailError::Upstream(format!("database config error: {err}")))
}

pub async fn verify_connection(pool: &AnyPool) -> Result<()> {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|err| FrickmailError::Upstream(format!("database connection failed: {err}")))
}

/// Additive runtime schema needed by Rust-native routes.  The legacy image
/// historically performed this work in its PHP entrypoint; keeping migrations
/// here makes the Rust container self-sufficient during the strangler phase.
pub async fn ensure_runtime_schema(pool: &AnyPool) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(|err| {
        FrickmailError::Upstream(format!("runtime schema migration failed: {err}"))
    })?;
    let backend = conn.backend_name().to_string();
    let table = match backend.as_str() {
        "MySQL" => {
            "CREATE TABLE IF NOT EXISTS frickmail_read_receipt_cache (\
            user_id BIGINT NOT NULL, \
            account_id BIGINT NOT NULL, \
            folder_hash CHAR(40) NOT NULL, \
            imap_uid BIGINT NOT NULL, \
            expires_at BIGINT NOT NULL, \
            PRIMARY KEY (user_id, account_id, folder_hash, imap_uid), \
            INDEX idx_fm_read_receipt_cache_expiry (user_id, account_id, expires_at)\
        )"
        }
        _ => {
            "CREATE TABLE IF NOT EXISTS frickmail_read_receipt_cache (\
            user_id BIGINT NOT NULL, \
            account_id BIGINT NOT NULL, \
            folder_hash CHAR(40) NOT NULL, \
            imap_uid BIGINT NOT NULL, \
            expires_at BIGINT NOT NULL, \
            PRIMARY KEY (user_id, account_id, folder_hash, imap_uid)\
        )"
        }
    };
    sqlx::query(table)
        .execute(&mut *conn)
        .await
        .map_err(|err| {
            FrickmailError::Upstream(format!("runtime schema migration failed: {err}"))
        })?;
    if backend != "MySQL" {
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_fm_read_receipt_cache_expiry \
             ON frickmail_read_receipt_cache(user_id, account_id, expires_at)",
        )
        .execute(&mut *conn)
        .await
        .map_err(|err| {
            FrickmailError::Upstream(format!("runtime schema migration failed: {err}"))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    #[tokio::test]
    async fn runtime_schema_creates_read_receipt_cache_on_sqlite() {
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("sqlite pool");

        ensure_runtime_schema(&pool).await.expect("runtime schema");
        ensure_runtime_schema(&pool)
            .await
            .expect("runtime schema is idempotent");
        let row = sqlx::query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='frickmail_read_receipt_cache'",
        )
        .fetch_one(&pool)
        .await
        .expect("read receipt cache table");
        assert_eq!(row.get::<String, _>("name"), "frickmail_read_receipt_cache");
    }
}
