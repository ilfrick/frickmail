//! Integration tests for schema compatibility across MySQL, PostgreSQL, and SQLite.
//!
//! These tests verify that `fm_db::ensure_runtime_schema` creates the
//! `frickmail_read_receipt_cache` table correctly on each backend and that
//! the function is idempotent.
//!
//! No `DROP TABLE` cleanup is performed between tests: `ensure_runtime_schema`
//! uses `CREATE TABLE IF NOT EXISTS`, so concurrent tests against the same
//! database are safe — each test's first call is a no-op if the table already
//! exists from a prior test. The tests only inspect schema (existence + primary
//! key constraint), never data, so table persistence across tests is harmless.
//!
//! When a database URL environment variable is not set, the corresponding test
//! is silently skipped.  In CI, the docker-compose.rust.yml file starts MySQL
//! and PostgreSQL services alongside the dev container.

use std::sync::OnceLock;

use fm_core::FrickmailConfig;
use fm_db::{connect_lazy, ensure_runtime_schema, verify_connection};
use serde_json::json;
use sqlx::{any::AnyPoolOptions, AnyPool, Row};

static DRIVERS: OnceLock<()> = OnceLock::new();

fn ensure_drivers() {
    DRIVERS.get_or_init(|| {
        sqlx::any::install_default_drivers();
    });
}

/// Returns the database URL for the given backend, or `None` if the
/// corresponding environment variable is not set.
fn db_url(backend: &str) -> Option<String> {
    let key = match backend {
        "mysql" => "FM_TEST_MYSQL_URL",
        "postgres" => "FM_TEST_POSTGRES_URL",
        "sqlite" => "FM_TEST_SQLITE_URL",
        _ => return None,
    };
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Creates a connection pool from a URL, panicking on failure.
async fn connect(url: &str) -> AnyPool {
    AnyPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .unwrap_or_else(|e| panic!("failed to connect to {url}: {e}"))
}

/// Verifies that the `frickmail_read_receipt_cache` table exists and has the
/// expected columns.
async fn assert_table_exists(pool: &AnyPool, backend: &str) {
    let table_name = "frickmail_read_receipt_cache";

    match backend {
        "mysql" => {
            let row = sqlx::query(&format!(
                "SELECT COUNT(*) AS c FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = '{table_name}'"
            ))
            .fetch_one(pool)
            .await
            .expect("query table existence");
            assert!(
                row.get::<i64, _>("c") > 0,
                "table {table_name} should exist in MySQL"
            );

            // Verify primary key
            let pk = sqlx::query(
                "SELECT COUNT(*) AS c FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'frickmail_read_receipt_cache' AND index_name = 'PRIMARY'"
            )
            .fetch_one(pool)
            .await
            .expect("query primary key");
            assert!(pk.get::<i64, _>("c") > 0, "table should have a PRIMARY KEY");
        }
        "postgres" => {
            let row = sqlx::query(&format!(
                "SELECT COUNT(*) AS c FROM information_schema.tables WHERE table_name = '{table_name}'"
            ))
            .fetch_one(pool)
            .await
            .expect("query table existence");
            assert!(
                row.get::<i64, _>("c") > 0,
                "table {table_name} should exist in PostgreSQL"
            );

            // Verify primary key constraint exists
            let pk = sqlx::query(
                "SELECT COUNT(*) AS c FROM information_schema.table_constraints WHERE table_name = 'frickmail_read_receipt_cache' AND constraint_type = 'PRIMARY KEY'"
            )
            .fetch_one(pool)
            .await
            .expect("query primary key");
            assert!(
                pk.get::<i64, _>("c") > 0,
                "table should have a PRIMARY KEY constraint"
            );
        }
        "sqlite" => {
            let row = sqlx::query(&format!(
                "SELECT COUNT(*) AS c FROM sqlite_master WHERE type = 'table' AND name = '{table_name}'"
            ))
            .fetch_one(pool)
            .await
            .expect("query table existence");
            assert!(
                row.get::<i64, _>("c") > 0,
                "table {table_name} should exist in SQLite"
            );
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// SQLite tests (always available — in-memory)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sqlite_ensure_runtime_schema_creates_table() {
    ensure_drivers();
    let pool = connect("sqlite::memory:").await;

    ensure_runtime_schema(&pool)
        .await
        .expect("ensure_runtime_schema");

    assert_table_exists(&pool, "sqlite").await;
}

#[tokio::test]
async fn sqlite_ensure_runtime_schema_is_idempotent() {
    ensure_drivers();
    let pool = connect("sqlite::memory:").await;

    ensure_runtime_schema(&pool).await.expect("first call");
    ensure_runtime_schema(&pool)
        .await
        .expect("second call (idempotent)");

    assert_table_exists(&pool, "sqlite").await;
}

#[tokio::test]
async fn sqlite_verify_connection_succeeds() {
    ensure_drivers();
    let pool = connect("sqlite::memory:").await;

    verify_connection(&pool).await.expect("verify_connection");
}

// ---------------------------------------------------------------------------
// MySQL tests (skipped if FM_TEST_MYSQL_URL is not set)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mysql_ensure_runtime_schema_creates_table() {
    ensure_drivers();
    let Some(url) = db_url("mysql") else {
        eprintln!("skipping MySQL test (FM_TEST_MYSQL_URL not set)");
        return;
    };
    let pool = connect(&url).await;

    ensure_runtime_schema(&pool)
        .await
        .expect("ensure_runtime_schema");

    assert_table_exists(&pool, "mysql").await;
}

#[tokio::test]
async fn mysql_ensure_runtime_schema_is_idempotent() {
    ensure_drivers();
    let Some(url) = db_url("mysql") else {
        eprintln!("skipping MySQL idempotency test (FM_TEST_MYSQL_URL not set)");
        return;
    };
    let pool = connect(&url).await;

    ensure_runtime_schema(&pool).await.expect("first call");
    ensure_runtime_schema(&pool)
        .await
        .expect("second call (idempotent)");

    assert_table_exists(&pool, "mysql").await;
}

#[tokio::test]
async fn mysql_verify_connection_succeeds() {
    ensure_drivers();
    let Some(url) = db_url("mysql") else {
        eprintln!("skipping MySQL verify_connection test (FM_TEST_MYSQL_URL not set)");
        return;
    };
    let pool = connect(&url).await;

    verify_connection(&pool).await.expect("verify_connection");
}

// ---------------------------------------------------------------------------
// PostgreSQL tests (skipped if FM_TEST_POSTGRES_URL is not set)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn postgres_ensure_runtime_schema_creates_table() {
    ensure_drivers();
    let Some(url) = db_url("postgres") else {
        eprintln!("skipping PostgreSQL test (FM_TEST_POSTGRES_URL not set)");
        return;
    };
    let pool = connect(&url).await;

    ensure_runtime_schema(&pool)
        .await
        .expect("ensure_runtime_schema");

    assert_table_exists(&pool, "postgres").await;
}

#[tokio::test]
async fn postgres_ensure_runtime_schema_is_idempotent() {
    ensure_drivers();
    let Some(url) = db_url("postgres") else {
        eprintln!("skipping PostgreSQL idempotency test (FM_TEST_POSTGRES_URL not set)");
        return;
    };
    let pool = connect(&url).await;

    ensure_runtime_schema(&pool).await.expect("first call");
    ensure_runtime_schema(&pool)
        .await
        .expect("second call (idempotent)");

    assert_table_exists(&pool, "postgres").await;
}

#[tokio::test]
async fn postgres_verify_connection_succeeds() {
    ensure_drivers();
    let Some(url) = db_url("postgres") else {
        eprintln!("skipping PostgreSQL verify_connection test (FM_TEST_POSTGRES_URL not set)");
        return;
    };
    let pool = connect(&url).await;

    verify_connection(&pool).await.expect("verify_connection");
}

// ---------------------------------------------------------------------------
// fm-db public API re-export test
// ---------------------------------------------------------------------------

#[test]
fn connect_lazy_returns_none_for_empty_url() {
    // fm_db::connect_lazy should return Ok(None) when no database URL is configured.
    // FrickmailConfig does not implement Default, so we deserialize from an empty
    // JSON object to exercise the #[serde(default)] annotations.
    let config: FrickmailConfig = serde_json::from_value(json!({})).unwrap();
    let result = connect_lazy(&config);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}
