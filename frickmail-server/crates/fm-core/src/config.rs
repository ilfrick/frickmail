use std::env;

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
    pub open_signup: bool,
    #[serde(default)]
    pub oidc: OidcConfig,
    #[serde(default)]
    pub mail: MailDefaults,
    #[serde(default)]
    pub frickmail_user: FrickmailUserConfig,
    #[serde(default)]
    pub transactional_smtp: TransactionalSmtpConfig,
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

#[derive(Debug, Clone, Deserialize)]
pub struct TransactionalSmtpConfig {
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_transactional_smtp_port")]
    pub port: u16,
    #[serde(default = "default_transactional_smtp_secure")]
    pub secure: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_transactional_smtp_from")]
    pub from: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FrickmailUserConfig {
    #[serde(default = "default_frickmail_user_allow_export")]
    pub allow_export: bool,
    #[serde(default = "default_export_folder_max_messages")]
    pub export_folder_max_messages: usize,
    #[serde(default = "default_export_folder_max_bytes")]
    pub export_folder_max_bytes: usize,
}

impl Default for FrickmailUserConfig {
    fn default() -> Self {
        Self {
            allow_export: default_frickmail_user_allow_export(),
            export_folder_max_messages: default_export_folder_max_messages(),
            export_folder_max_bytes: default_export_folder_max_bytes(),
        }
    }
}

impl Default for TransactionalSmtpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: default_transactional_smtp_port(),
            secure: default_transactional_smtp_secure(),
            user: String::new(),
            password: String::new(),
            from: default_transactional_smtp_from(),
        }
    }
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

        let mut config =
            cfg.try_deserialize::<Self>()
                .map_err(|source| FrickmailError::Config {
                    message: "failed to deserialize Frickmail config".to_string(),
                    source: Box::new(source),
                })?;

        if config.database_url.is_none() {
            config.database_url = legacy_frickmail_database_url();
        }
        if let Some(open_signup) = legacy_open_signup() {
            config.open_signup = open_signup;
        }
        config.transactional_smtp.merge_legacy_env();

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

        if self.frickmail_user.export_folder_max_messages == 0 {
            return Err(FrickmailError::InvalidConfig {
                field: "frickmail_user.export_folder_max_messages",
                message: "must be greater than zero".to_string(),
            });
        }
        if self.frickmail_user.export_folder_max_bytes == 0 {
            return Err(FrickmailError::InvalidConfig {
                field: "frickmail_user.export_folder_max_bytes",
                message: "must be greater than zero".to_string(),
            });
        }

        Ok(())
    }
}

impl TransactionalSmtpConfig {
    pub fn is_configured(&self) -> bool {
        !self.host.trim().is_empty()
    }

    fn merge_legacy_env(&mut self) {
        if let Ok(host) = env::var("FRICKMAIL_SMTP_HOST") {
            self.host = host;
        }
        if let Ok(port) = env::var("FRICKMAIL_SMTP_PORT") {
            if let Ok(port) = port.parse() {
                self.port = port;
            }
        }
        if let Ok(secure) = env::var("FRICKMAIL_SMTP_SECURE") {
            self.secure = secure;
        }
        if let Ok(user) = env::var("FRICKMAIL_SMTP_USER") {
            self.user = user;
        }
        if let Ok(password) = env::var("FRICKMAIL_SMTP_PASSWORD") {
            self.password = password;
        }
        if let Ok(from) = env::var("FRICKMAIL_SMTP_FROM") {
            self.from = from;
        }
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

fn legacy_open_signup() -> Option<bool> {
    let value = env::var("FRICKMAIL_OPEN_SIGNUP").ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        _ => None,
    }
}

fn legacy_frickmail_database_url() -> Option<String> {
    // The current release entrypoint provisions PostgreSQL from these legacy
    // variables. MySQL/SQLite installs should set FRICKMAIL__DATABASE_URL.
    let password = env::var("FRICKMAIL_DB_PASSWORD")
        .ok()
        .filter(|password| !password.is_empty())?;
    let host = env::var("FRICKMAIL_DB_HOST").unwrap_or_else(|_| "db".to_string());
    let port = env::var("FRICKMAIL_DB_PORT").unwrap_or_else(|_| "5432".to_string());
    let name = env::var("FRICKMAIL_DB_NAME").unwrap_or_else(|_| "frickmail".to_string());
    let user = env::var("FRICKMAIL_DB_USER").unwrap_or_else(|_| "frickmail".to_string());

    Some(format!(
        "postgres://{}:{}@{}:{}/{}",
        url_encode(&user),
        url_encode(&password),
        host,
        port,
        url_encode_path_segment(&name)
    ))
}

fn url_encode(input: &str) -> String {
    url::form_urlencoded::byte_serialize(input.as_bytes()).collect()
}

fn url_encode_path_segment(input: &str) -> String {
    input
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            byte => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
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

fn default_transactional_smtp_port() -> u16 {
    587
}

fn default_transactional_smtp_secure() -> String {
    "tls".to_string()
}

fn default_transactional_smtp_from() -> String {
    "no-reply@frickmail.local".to_string()
}

fn default_frickmail_user_allow_export() -> bool {
    true
}

fn default_export_folder_max_messages() -> usize {
    5_000
}

fn default_export_folder_max_bytes() -> usize {
    25 * 1024 * 1024
}
