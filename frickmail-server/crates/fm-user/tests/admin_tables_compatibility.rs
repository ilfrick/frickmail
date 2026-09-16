//! Cross-backend integration tests for the admin tables (`frickmail_domains`
//! and `frickmail_app_settings` writes), gated like `fm-db`'s
//! `schema_compatibility.rs`: each backend runs only when its `FM_TEST_*_URL`
//! environment variable is set (the Docker dev service provides PostgreSQL
//! and MySQL, sqlite runs on a temporary file).
//!
//! These tests exercise the real backend SQL triplets (DDL, placeholders,
//! boolean encoding) behind `SqlxUserRepository`, which unit tests only cover
//! on SQLite. Domain names are unique per run so repeated runs against a
//! persistent database never collide (tables are never dropped).

use std::sync::OnceLock;

use fm_user::{NewMailDomain, SqlxUserRepository};
use sqlx::{any::AnyPoolOptions, AnyPool};

static DRIVERS: OnceLock<()> = OnceLock::new();

fn ensure_drivers() {
    DRIVERS.get_or_init(|| {
        sqlx::any::install_default_drivers();
    });
}

fn db_url(backend: &str) -> Option<String> {
    let key = match backend {
        "mysql" => "FM_TEST_MYSQL_URL",
        "postgres" => "FM_TEST_POSTGRES_URL",
        "sqlite" => "FM_TEST_SQLITE_URL",
        _ => return None,
    };
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

async fn connect(url: &str) -> AnyPool {
    AnyPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .unwrap_or_else(|e| panic!("failed to connect to {url}: {e}"))
}

/// Unique run tag; domain names embed it so reruns never collide.
fn run_tag() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("t{}", nanos % 10_000_000)
}

fn test_domain(name: &str) -> NewMailDomain {
    NewMailDomain {
        name: name.to_string(),
        disabled: false,
        imap_host: Some("imap.example.com".to_string()),
        imap_port: Some(993),
        imap_secure: Some("SSL".to_string()),
        smtp_host: Some("smtp.example.com".to_string()),
        smtp_port: Some(465),
        smtp_secure: Some("SSL".to_string()),
    }
}

async fn exercise_backend(pool: &AnyPool) {
    let tag = run_tag();
    let domain_name = format!("{tag}.example.com");
    let alias_name = format!("a{tag}.example.com");

    // Domains CRUD round-trip through the real backend triplet.
    let saved = SqlxUserRepository::save_domain(pool, test_domain(&domain_name))
        .await
        .expect("save domain");
    assert_eq!(saved.name, domain_name);
    assert!(!saved.disabled);

    let loaded = SqlxUserRepository::get_domain(pool, &domain_name)
        .await
        .expect("get domain")
        .expect("domain present");
    assert_eq!(loaded.imap_host.as_deref(), Some("imap.example.com"));
    assert_eq!(loaded.imap_port, Some(993));
    assert_eq!(loaded.smtp_port, Some(465));

    let listed = SqlxUserRepository::list_domains(pool)
        .await
        .expect("list domains");
    assert!(listed.iter().any(|domain| domain.name == domain_name));

    // Resolution, aliasing, and disable flow.
    let resolved =
        SqlxUserRepository::resolve_domain_for_email(pool, &format!("alice@{domain_name}"))
            .await
            .expect("resolve domain")
            .expect("domain resolves");
    assert_eq!(resolved.name, domain_name);

    let alias = SqlxUserRepository::save_domain_alias(pool, &domain_name, &alias_name)
        .await
        .expect("save alias");
    assert_eq!(alias.alias_of.as_deref(), Some(domain_name.as_str()));
    let via_alias =
        SqlxUserRepository::resolve_domain_for_email(pool, &format!("bob@{alias_name}"))
            .await
            .expect("resolve alias")
            .expect("alias resolves");
    assert_eq!(via_alias.name, domain_name);

    SqlxUserRepository::set_domain_disabled(pool, &domain_name, true)
        .await
        .expect("disable domain")
        .expect("domain present");
    assert!(
        SqlxUserRepository::resolve_domain_for_email(pool, &format!("alice@{domain_name}"))
            .await
            .expect("resolve disabled")
            .is_none()
    );
    SqlxUserRepository::set_domain_disabled(pool, &domain_name, false)
        .await
        .expect("re-enable domain");

    // Deleting the target removes its aliases.
    assert!(SqlxUserRepository::delete_domain(pool, &domain_name)
        .await
        .expect("delete domain"));
    assert!(SqlxUserRepository::get_domain(pool, &alias_name)
        .await
        .expect("get alias")
        .is_none());

    // Application settings KV round-trip through the real backend triplet.
    let key = format!("admin_override:compat_{tag}");
    assert!(SqlxUserRepository::get_app_setting_value(pool, &key)
        .await
        .expect("get missing setting")
        .is_none());
    SqlxUserRepository::set_app_setting_value(pool, &key, "true".to_string())
        .await
        .expect("set setting");
    assert_eq!(
        SqlxUserRepository::get_app_setting_value(pool, &key)
            .await
            .expect("get setting")
            .as_deref(),
        Some("true")
    );
    // Batch write commits atomically.
    let key2 = format!("admin_override:compat2_{tag}");
    SqlxUserRepository::set_app_setting_values(
        pool,
        &[(&key, "false".to_string()), (&key2, "77".to_string())],
    )
    .await
    .expect("batch set settings");
    assert_eq!(
        SqlxUserRepository::get_app_setting_value(pool, &key)
            .await
            .expect("get updated setting")
            .as_deref(),
        Some("false")
    );
    assert_eq!(
        SqlxUserRepository::get_app_setting_value(pool, &key2)
            .await
            .expect("get second setting")
            .as_deref(),
        Some("77")
    );
    assert!(SqlxUserRepository::delete_app_setting_value(pool, &key)
        .await
        .expect("delete setting"));
    assert!(!SqlxUserRepository::delete_app_setting_value(pool, &key)
        .await
        .expect("delete missing setting"));
    SqlxUserRepository::delete_app_setting_value(pool, &key2)
        .await
        .expect("delete second setting");
}

#[tokio::test]
async fn sqlite_admin_tables_flow() {
    ensure_drivers();
    let Some(url) = db_url("sqlite") else {
        eprintln!("skipping sqlite admin tables test (FM_TEST_SQLITE_URL not set)");
        return;
    };
    exercise_backend(&connect(&url).await).await;
}

#[tokio::test]
async fn postgres_admin_tables_flow() {
    ensure_drivers();
    let Some(url) = db_url("postgres") else {
        eprintln!("skipping PostgreSQL admin tables test (FM_TEST_POSTGRES_URL not set)");
        return;
    };
    exercise_backend(&connect(&url).await).await;
}

#[tokio::test]
async fn mysql_admin_tables_flow() {
    ensure_drivers();
    let Some(url) = db_url("mysql") else {
        eprintln!("skipping MySQL admin tables test (FM_TEST_MYSQL_URL not set)");
        return;
    };
    exercise_backend(&connect(&url).await).await;
}
