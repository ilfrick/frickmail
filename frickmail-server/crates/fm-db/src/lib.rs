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
