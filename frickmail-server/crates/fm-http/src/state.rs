use std::{sync::Arc, time::Duration};

use fm_core::FrickmailConfig;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: FrickmailConfig,
    bridge_client: reqwest::Client,
}

impl AppState {
    pub fn new(config: FrickmailConfig) -> Self {
        let bridge_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build PHP bridge HTTP client");

        Self {
            inner: Arc::new(AppStateInner {
                config,
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
}
