use serde::Deserialize;
use url::Url;

use crate::{FrickmailError, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct FrickmailConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_static_root")]
    pub static_root: String,
    #[serde(default)]
    pub php_bridge_url: Option<String>,
    #[serde(default = "default_database_url")]
    pub database_url: Option<String>,
    #[serde(default = "default_redis_url")]
    pub redis_url: String,
    #[serde(default)]
    pub oidc: OidcConfig,
    #[serde(default)]
    pub mail: MailDefaults,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct OidcConfig {
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    #[serde(default = "default_oidc_provider_name")]
    pub provider_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MailDefaults {
    #[serde(default = "default_imap_host")]
    pub imap_host: String,
    #[serde(default = "default_imap_port")]
    pub imap_port: u16,
    #[serde(default = "default_smtp_host")]
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
}

impl Default for MailDefaults {
    fn default() -> Self {
        Self {
            imap_host: default_imap_host(),
            imap_port: default_imap_port(),
            smtp_host: default_smtp_host(),
            smtp_port: default_smtp_port(),
        }
    }
}

impl FrickmailConfig {
    pub fn from_env() -> Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::Environment::with_prefix("FRICKMAIL").separator("__"))
            .build()
            .map_err(|source| FrickmailError::Config {
                message: "failed to build config from environment".to_string(),
                source: Box::new(source),
            })?;

        let config = cfg
            .try_deserialize::<Self>()
            .map_err(|source| FrickmailError::Config {
                message: "failed to deserialize Frickmail config".to_string(),
                source: Box::new(source),
            })?;

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        Url::parse(&self.base_url).map_err(|err| FrickmailError::InvalidConfig {
            field: "base_url",
            message: err.to_string(),
        })?;

        if let Some(url) = &self.php_bridge_url {
            Url::parse(url).map_err(|err| FrickmailError::InvalidConfig {
                field: "php_bridge_url",
                message: err.to_string(),
            })?;
        }

        Ok(())
    }
}

fn default_bind_addr() -> String {
    "0.0.0.0:8888".to_string()
}

fn default_base_url() -> String {
    "http://localhost:8888".to_string()
}

fn default_static_root() -> String {
    "/workspace/frickmail-static".to_string()
}

fn default_database_url() -> Option<String> {
    None
}

fn default_redis_url() -> String {
    "redis://redis:6379/0".to_string()
}

fn default_oidc_provider_name() -> String {
    "SSO".to_string()
}

fn default_imap_host() -> String {
    "imap.example.com".to_string()
}

fn default_imap_port() -> u16 {
    993
}

fn default_smtp_host() -> String {
    "smtp.example.com".to_string()
}

fn default_smtp_port() -> u16 {
    587
}
