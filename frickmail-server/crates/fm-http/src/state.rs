use std::{sync::Arc, time::Duration};

use deadpool_redis::{Config as RedisConfig, Pool as RedisPool, Runtime};
use fm_core::FrickmailConfig;
use sqlx::AnyPool;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: FrickmailConfig,
    db_pool: Option<AnyPool>,
    redis_pool: Option<RedisPool>,
    bridge_client: reqwest::Client,
}

impl AppState {
    pub fn new(config: FrickmailConfig) -> Self {
        Self::with_db_pool(config, None)
    }

    pub fn with_db_pool(config: FrickmailConfig, db_pool: Option<AnyPool>) -> Self {
        let redis_pool = (config.cache.enable
            && config.cache.server_uids
            && !config.redis_url.trim().is_empty())
        .then(|| {
            RedisConfig::from_url(config.redis_url.clone())
                .create_pool(Some(Runtime::Tokio1))
                .ok()
        })
        .flatten();
        let bridge_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build PHP bridge HTTP client");

        Self {
            inner: Arc::new(AppStateInner {
                config,
                db_pool,
                redis_pool,
                bridge_client,
            }),
        }
    }

    pub fn config(&self) -> &FrickmailConfig {
        &self.inner.config
    }

    pub fn bridge_client(&self) -> &reqwest::Client {
        &self.inner.bridge_client
    }

    pub fn db_pool(&self) -> Option<&AnyPool> {
        self.inner.db_pool.as_ref()
    }

    pub(crate) fn redis_pool(&self) -> Option<&RedisPool> {
        self.inner.redis_pool.as_ref()
    }
}
