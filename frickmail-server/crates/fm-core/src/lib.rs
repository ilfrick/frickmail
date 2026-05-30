pub mod auth;
pub mod config;
pub mod error;
pub mod json;
pub mod plugin;

pub use auth::{AuthToken, UserSession};
pub use config::FrickmailConfig;
pub use error::{ErrorBody, FrickmailError, Result};
pub use json::{ApiEnvelope, HealthResponse};
