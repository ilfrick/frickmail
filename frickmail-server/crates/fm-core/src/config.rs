use std::{collections::HashMap, env};

use serde::{de::Error as _, Deserialize, Deserializer};
use url::{Host, Url};

use crate::{FrickmailError, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct FrickmailConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_static_root")]
    pub static_root: String,
    #[serde(default = "default_tmp_dir")]
    pub tmp_dir: String,
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
    pub cache: FrickmailCacheConfig,
    #[serde(default)]
    pub frickmail_user: FrickmailUserConfig,
    #[serde(default)]
    pub transactional_smtp: TransactionalSmtpConfig,
    #[serde(default)]
    pub hibp: HibpConfig,
    #[serde(default)]
    pub demo_account: DemoAccountConfig,
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
    #[serde(default = "default_fetch_new_messages")]
    pub fetch_new_messages: bool,
    #[serde(default = "default_message_list_fast_simple_search")]
    pub message_list_fast_simple_search: bool,
    #[serde(default)]
    pub message_list_permanent_filter: String,
    #[serde(default = "default_message_list_limit")]
    pub message_list_limit: u32,
    #[serde(
        default,
        deserialize_with = "deserialize_message_list_domain_overrides"
    )]
    pub message_list_domain_overrides: HashMap<String, MessageListDomainOverride>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MessageListDomainOverride {
    pub fast_simple_search: Option<bool>,
    pub permanent_filter: Option<String>,
    pub message_list_limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FrickmailCacheConfig {
    #[serde(default = "default_cache_enable")]
    pub enable: bool,
    #[serde(default = "default_cache_index")]
    pub index: String,
    #[serde(default = "default_cache_fast_cache_index")]
    pub fast_cache_index: String,
    #[serde(default = "default_cache_http_expires")]
    pub http_expires: i64,
    #[serde(default = "default_cache_server_uids")]
    pub server_uids: bool,
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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct HibpConfig {
    #[serde(default)]
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DemoAccountConfig {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub recipient_delimiter: String,
}

impl DemoAccountConfig {
    pub fn is_demo_sender(&self, account_email: &str) -> bool {
        !self.email.trim().is_empty()
            && self.email.trim().eq_ignore_ascii_case(account_email.trim())
    }

    fn recipient_pattern(&self) -> Option<String> {
        let email = self.email.trim();
        if email.is_empty()
            || !email.bytes().all(|byte| byte.is_ascii())
            || email.chars().any(char::is_control)
        {
            return None;
        }

        let escaped_email = regex::escape(email);
        let delimiter = self.recipient_delimiter.trim();
        let pattern = if delimiter.is_empty() || !delimiter.bytes().all(|byte| byte.is_ascii()) {
            escaped_email
        } else {
            let escaped_delimiter = regex::escape(delimiter);
            escaped_email.replacen('@', &format!("({escaped_delimiter}.+)?@"), 1)
        };

        Some(format!("^{pattern}$"))
    }

    pub fn allows_recipient(&self, address: &str) -> bool {
        self.recipient_pattern()
            .and_then(|pattern| regex::Regex::new(&pattern).ok())
            .is_some_and(|regex| regex.is_match(address))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FrickmailUserConfig {
    #[serde(default = "default_frickmail_user_allow_export")]
    pub allow_export: bool,
    #[serde(default)]
    pub allow_message_append: bool,
    #[serde(default = "default_frickmail_user_smime_enabled")]
    pub smime_enabled: bool,
    #[serde(default = "default_export_folder_max_messages")]
    pub export_folder_max_messages: usize,
    #[serde(default = "default_export_folder_max_bytes")]
    pub export_folder_max_bytes: usize,
}

impl Default for FrickmailUserConfig {
    fn default() -> Self {
        Self {
            allow_export: default_frickmail_user_allow_export(),
            allow_message_append: false,
            smime_enabled: default_frickmail_user_smime_enabled(),
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
            fetch_new_messages: default_fetch_new_messages(),
            message_list_fast_simple_search: default_message_list_fast_simple_search(),
            message_list_permanent_filter: String::new(),
            message_list_limit: default_message_list_limit(),
            message_list_domain_overrides: HashMap::new(),
        }
    }
}

impl MailDefaults {
    fn message_list_domain_override(&self, email: &str) -> Option<&MessageListDomainOverride> {
        let domain = email
            .rsplit_once('@')
            .map(|(_, domain)| legacy_ascii_domain(domain))
            .unwrap_or_default();
        self.message_list_domain_overrides
            .iter()
            .find(|(pattern, _)| !pattern.contains('*') && pattern.eq_ignore_ascii_case(&domain))
            .map(|(_, value)| value)
            .or_else(|| {
                let mut patterns = self
                    .message_list_domain_overrides
                    .iter()
                    .filter(|(pattern, _)| pattern.contains('*'))
                    .collect::<Vec<_>>();
                patterns.sort_unstable_by(|left, right| right.0.cmp(left.0));
                patterns
                    .into_iter()
                    .find(|(pattern, _)| legacy_domain_pattern_matches(pattern, &domain))
                    .map(|(_, value)| value)
            })
    }

    pub fn message_list_search_settings(&self, email: &str) -> (bool, String) {
        let domain_override = self.message_list_domain_override(email);

        let fast_simple_search = self.message_list_fast_simple_search
            && domain_override
                .and_then(|value| value.fast_simple_search)
                .unwrap_or(true);
        let domain_filter = domain_override
            .and_then(|value| value.permanent_filter.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let permanent_filter = domain_filter
            .unwrap_or_else(|| self.message_list_permanent_filter.trim())
            .to_string();
        (fast_simple_search, permanent_filter)
    }

    pub fn message_list_limit(&self, email: &str) -> u32 {
        self.message_list_domain_override(email)
            .and_then(|value| value.message_list_limit)
            .unwrap_or(self.message_list_limit)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MessageListDomainOverridesInput {
    Map(HashMap<String, MessageListDomainOverride>),
    Json(String),
}

fn deserialize_message_list_domain_overrides<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<String, MessageListDomainOverride>, D::Error>
where
    D: Deserializer<'de>,
{
    match MessageListDomainOverridesInput::deserialize(deserializer)? {
        MessageListDomainOverridesInput::Map(overrides) => Ok(overrides),
        MessageListDomainOverridesInput::Json(raw) if raw.trim().is_empty() => Ok(HashMap::new()),
        MessageListDomainOverridesInput::Json(raw) => {
            serde_json::from_str(&raw).map_err(D::Error::custom)
        }
    }
}

fn legacy_ascii_domain(domain: &str) -> String {
    let domain = domain.trim();
    Host::parse(domain)
        .map(|host| host.to_string().to_ascii_lowercase())
        .unwrap_or_else(|_| domain.to_ascii_lowercase())
}

fn legacy_domain_pattern_matches(pattern: &str, domain: &str) -> bool {
    if !pattern.contains('*') {
        return pattern.eq_ignore_ascii_case(domain);
    }
    let pattern = pattern.to_ascii_lowercase();
    let mut remainder = domain;
    for segment in pattern.split('*').filter(|segment| !segment.is_empty()) {
        let Some(offset) = remainder.find(segment) else {
            return false;
        };
        remainder = &remainder[offset + segment.len()..];
    }
    true
}

impl Default for FrickmailCacheConfig {
    fn default() -> Self {
        Self {
            enable: default_cache_enable(),
            index: default_cache_index(),
            fast_cache_index: default_cache_fast_cache_index(),
            http_expires: default_cache_http_expires(),
            server_uids: default_cache_server_uids(),
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
        if self.cache.http_expires < 0 {
            return Err(FrickmailError::InvalidConfig {
                field: "cache.http_expires",
                message: "must be greater than or equal to zero".to_string(),
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

fn default_tmp_dir() -> String {
    "/tmp/frickmail".to_string()
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

fn default_fetch_new_messages() -> bool {
    true
}

fn default_message_list_fast_simple_search() -> bool {
    true
}

fn default_message_list_limit() -> u32 {
    10_000
}

fn default_cache_index() -> String {
    "v1".to_string()
}

fn default_cache_enable() -> bool {
    true
}

fn default_cache_fast_cache_index() -> String {
    "v1".to_string()
}

fn default_cache_http_expires() -> i64 {
    3600
}

fn default_cache_server_uids() -> bool {
    true
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

fn default_frickmail_user_smime_enabled() -> bool {
    true
}

fn default_export_folder_max_messages() -> usize {
    5_000
}

fn default_export_folder_max_bytes() -> usize {
    25 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::{DemoAccountConfig, FrickmailCacheConfig, MailDefaults, MessageListDomainOverride};
    use std::collections::HashMap;

    #[test]
    fn message_list_domain_overrides_match_legacy_precedence() {
        let mail = MailDefaults {
            message_list_fast_simple_search: true,
            message_list_permanent_filter: "  NOT FLAGGED  ".to_string(),
            message_list_domain_overrides: serde_json::from_str::<
                HashMap<String, MessageListDomainOverride>,
            >(
                r#"{
                "*": {"permanent_filter": "SEEN"},
                "*.example.com": {"fast_simple_search": false},
                "mail.example.com": {
                    "fast_simple_search": true,
                    "permanent_filter": "  ANSWERED  ",
                    "message_list_limit": 25000
                },
                "xn--bcher-kva.de": {
                    "permanent_filter": "UNSEEN"
                }
            }"#,
            )
            .unwrap(),
            ..Default::default()
        };

        assert_eq!(
            mail.message_list_search_settings("alice@mail.example.com"),
            (true, "ANSWERED".to_string())
        );
        assert_eq!(
            mail.message_list_search_settings("alice@MAIL.EXAMPLE.COM"),
            (true, "ANSWERED".to_string())
        );
        assert_eq!(
            mail.message_list_search_settings("alice@other.example.com"),
            (false, "NOT FLAGGED".to_string())
        );
        assert_eq!(
            mail.message_list_search_settings("alice@elsewhere.test"),
            (true, "SEEN".to_string())
        );
        assert_eq!(
            mail.message_list_search_settings("alice@bücher.de"),
            (true, "UNSEEN".to_string())
        );
        assert_eq!(mail.message_list_limit("alice@mail.example.com"), 25_000);
        assert_eq!(mail.message_list_limit("alice@other.example.com"), 10_000);
    }

    #[test]
    fn global_fast_search_disable_cannot_be_overridden_by_domain() {
        let mail = MailDefaults {
            message_list_fast_simple_search: false,
            message_list_domain_overrides: serde_json::from_str::<
                HashMap<String, MessageListDomainOverride>,
            >(
                r#"{
                "example.com": {"fast_simple_search": true}
            }"#,
            )
            .unwrap(),
            ..Default::default()
        };

        assert!(!mail.message_list_search_settings("alice@example.com").0);
    }

    #[test]
    fn malformed_message_list_domain_overrides_are_rejected() {
        assert!(serde_json::from_value::<MailDefaults>(serde_json::json!({
            "message_list_domain_overrides": "{not-json"
        }))
        .is_err());
    }

    #[test]
    fn message_list_limit_defaults_to_mailso_value_and_allows_disable() {
        let defaults = serde_json::from_value::<MailDefaults>(serde_json::json!({})).unwrap();
        assert_eq!(defaults.message_list_limit("alice@example.com"), 10_000);

        let disabled = serde_json::from_value::<MailDefaults>(serde_json::json!({
            "message_list_limit": 0
        }))
        .unwrap();
        assert_eq!(disabled.message_list_limit("alice@example.com"), 0);
    }

    #[test]
    fn cache_defaults_match_legacy_server_uid_cache_settings() {
        let cache = serde_json::from_value::<FrickmailCacheConfig>(serde_json::json!({})).unwrap();

        assert!(cache.enable);
        assert_eq!(cache.fast_cache_index, "v1");
        assert!(cache.server_uids);
    }

    #[test]
    fn demo_account_recipient_pattern_matches_legacy_plugin() {
        let config = DemoAccountConfig {
            email: "demo@example.com".to_string(),
            recipient_delimiter: String::new(),
        };
        assert!(config.allows_recipient("demo@example.com"));
        assert!(!config.allows_recipient("Demo+tag@example.com"));

        let delimited = DemoAccountConfig {
            email: "demo@example.com".to_string(),
            recipient_delimiter: "+".to_string(),
        };
        assert!(delimited.allows_recipient("demo@example.com"));
        assert!(delimited.allows_recipient("demo+anything@example.com"));
        assert!(!delimited.allows_recipient("other@example.com"));

        let unsafe_config = DemoAccountConfig {
            email: "demo\n@example.com".to_string(),
            recipient_delimiter: String::new(),
        };
        assert_eq!(unsafe_config.recipient_pattern(), None);
    }
}
