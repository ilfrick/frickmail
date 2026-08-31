//! Cross-backend integration tests for the native address book storage,
//! gated like `fm-db`'s `schema_compatibility.rs`: each backend runs only
//! when its `FM_TEST_*_URL` environment variable is set (the Docker dev
//! service provides PostgreSQL and MySQL, sqlite always runs).

use std::sync::OnceLock;

use fm_user::address_book::{self, property_type, AddressBookContact, AddressBookProperty};
use sqlx::{any::AnyPoolOptions, AnyPool, Row};

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

/// Each run uses a fresh user id so repeated runs against a persistent
/// database never collide (the tests never drop tables). The value must fit
/// the legacy PostgreSQL `integer` column.
fn unique_user_id() -> i64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    2_000_000_000_i64 + (nanos % 100_000_000)
}

fn contact(uid: &str, display: &str, email: &str) -> AddressBookContact {
    AddressBookContact {
        id: 0,
        uid: uid.to_string(),
        display: display.to_string(),
        properties: vec![
            AddressBookProperty::new(property_type::FULLNAME, display),
            AddressBookProperty::new(property_type::LAST_NAME, "Lovelace"),
            AddressBookProperty::new(property_type::FIRST_NAME, "Ada"),
            AddressBookProperty::new(property_type::EMAIL, email),
            AddressBookProperty::new(
                property_type::JCARD,
                format!("[\"vcard\",[[\"fn\",{{}},\"text\",\"{display}\"]]]"),
            ),
        ],
    }
}

async fn exercise_backend(pool: &AnyPool) {
    let user_id = unique_user_id();
    address_book::ensure_address_book_schema(pool)
        .await
        .expect("ensure_address_book_schema");
    let probe = pool.acquire().await.unwrap();
    let backend = probe.backend_name().to_string();
    drop(probe);
    // sqlx `any` passes SQL verbatim: PostgreSQL needs numbered placeholders.
    let ph = |index: usize| -> String {
        if backend == "PostgreSQL" {
            format!("${index}")
        } else {
            "?".to_string()
        }
    };

    // Insert assigns a numeric id and writes all property rows.
    let contact_id = address_book::save_contact(
        pool,
        user_id,
        &contact("ab-uid-1", "Ada Lovelace", "ada@example.com"),
    )
    .await
    .expect("insert contact");
    assert!(contact_id > 0);

    // UID lookup finds the contact while it is not deleted.
    let found = address_book::get_contact_id_by_uid(pool, user_id, "ab-uid-1")
        .await
        .expect("get_contact_id_by_uid");
    assert_eq!(found, Some(contact_id));

    // Update keeps the same id, preserves the email usage frequency, and
    // replaces the property rows exactly once per property.
    sqlx::query(&format!(
        "UPDATE rainloop_ab_properties SET prop_frec = {} WHERE id_contact = {} AND prop_type = {}",
        ph(1),
        ph(2),
        ph(3)
    ))
    .bind(7_i64)
    .bind(contact_id)
    .bind(property_type::EMAIL)
    .execute(pool)
    .await
    .unwrap();
    let mut updated = contact("ab-uid-1", "Ada King", "ada@example.com");
    updated.id = contact_id;
    let updated_id = address_book::save_contact(pool, user_id, &updated)
        .await
        .expect("update contact");
    assert_eq!(updated_id, contact_id);

    let frec: i64 = sqlx::query(&format!(
        "SELECT prop_frec FROM rainloop_ab_properties WHERE id_contact = {} AND prop_type = {} AND prop_value = {}",
        ph(1),
        ph(2),
        ph(3)
    ))
    .bind(contact_id)
    .bind(property_type::EMAIL)
    .bind("ada@example.com")
    .fetch_one(pool)
    .await
    .unwrap()
    .try_get("prop_frec")
    .unwrap();
    assert_eq!(frec, 7, "email usage frequency must survive an update");

    let prop_count: i64 = sqlx::query(&format!(
        "SELECT COUNT(*) AS n FROM rainloop_ab_properties WHERE id_contact = {}",
        ph(1)
    ))
    .bind(contact_id)
    .fetch_one(pool)
    .await
    .unwrap()
    .try_get("n")
    .unwrap();
    assert_eq!(
        prop_count, 5,
        "property rows must be replaced, not duplicated"
    );

    let summaries = address_book::list_contact_summaries(pool, user_id, 0, 100)
        .await
        .expect("list_contact_summaries");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].display, "Ada King");

    // Deduplication helper path: a duplicate UID row is soft-deleted.
    address_book::save_contact(
        pool,
        user_id,
        &contact("ab-uid-1", "Duplicate", "dupe@example.com"),
    )
    .await
    .expect("insert duplicate");
    let dupes = address_book::list_contact_summaries(pool, user_id, 0, 100)
        .await
        .unwrap();
    let duplicate_ids: Vec<i64> = dupes
        .iter()
        .filter(|summary| summary.display == "Duplicate")
        .map(|summary| summary.id)
        .collect();
    assert_eq!(duplicate_ids.len(), 1);

    assert!(address_book::delete_contacts(pool, user_id, &duplicate_ids)
        .await
        .unwrap());
    let survivors = address_book::list_contact_summaries(pool, user_id, 0, 100)
        .await
        .unwrap();
    assert_eq!(survivors.len(), 1);
    assert_eq!(survivors[0].display, "Ada King");

    // The soft-deleted duplicate no longer appears in listings; the kept
    // row still resolves the shared UID.
    let deleted_lookup = address_book::get_contact_id_by_uid(&pool, user_id, "ab-uid-1")
        .await
        .unwrap();
    assert_eq!(deleted_lookup, Some(contact_id));

    // User scoping: another user sees nothing.
    let other = address_book::list_contact_summaries(pool, user_id + 1, 0, 100)
        .await
        .unwrap();
    assert!(other.is_empty());
}

#[tokio::test]
async fn sqlite_address_book_flow() {
    ensure_drivers();
    let Some(url) = db_url("sqlite") else {
        eprintln!("skipping sqlite address book test (FM_TEST_SQLITE_URL not set)");
        return;
    };
    exercise_backend(&connect(&url).await).await;
}

#[tokio::test]
async fn postgres_address_book_flow() {
    ensure_drivers();
    let Some(url) = db_url("postgres") else {
        eprintln!("skipping PostgreSQL address book test (FM_TEST_POSTGRES_URL not set)");
        return;
    };
    exercise_backend(&connect(&url).await).await;
}

#[tokio::test]
async fn mysql_address_book_flow() {
    ensure_drivers();
    let Some(url) = db_url("mysql") else {
        eprintln!("skipping MySQL address book test (FM_TEST_MYSQL_URL not set)");
        return;
    };
    exercise_backend(&connect(&url).await).await;
}
