use http::StatusCode;
use serde::Serialize;

pub type Result<T> = std::result::Result<T, FrickmailError>;

#[derive(Debug, thiserror::Error)]
pub enum FrickmailError {
    #[error("{message}")]
    Config {
        message: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("invalid config field {field}: {message}")]
    InvalidConfig {
        field: &'static str,
        message: String,
    },
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Upstream(String),
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}

impl FrickmailError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) | Self::InvalidConfig { .. } => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            Self::Config { .. } | Self::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }

    pub fn public_message(&self) -> String {
        match self {
            Self::Config { message, .. } => message.clone(),
            _ => self.to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    #[serde(rename = "Result")]
    pub result: bool,
    #[serde(rename = "ErrorMessage")]
    pub error_message: String,
}
