use std::sync::Arc;

use fm_core::FrickmailConfig;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: FrickmailConfig,
}

impl AppState {
    pub fn new(config: FrickmailConfig) -> Self {
        Self {
            inner: Arc::new(AppStateInner { config }),
        }
    }

    pub fn config(&self) -> &FrickmailConfig {
        &self.inner.config
    }
}
