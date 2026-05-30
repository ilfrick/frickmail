use std::{sync::Arc, time::Duration};

use fm_core::FrickmailConfig;
use sqlx::AnyPool;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: FrickmailConfig,
    db_pool: Option<AnyPool>,
    bridge_client: reqwest::Client,
}

impl AppState {
    pub fn new(config: FrickmailConfig) -> Self {
        Self::with_db_pool(config, None)
    }

    pub fn with_db_pool(config: FrickmailConfig, db_pool: Option<AnyPool>) -> Self {
        let bridge_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build PHP bridge HTTP client");

        Self {
            inner: Arc::new(AppStateInner {
                config,
                db_pool,
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
}
