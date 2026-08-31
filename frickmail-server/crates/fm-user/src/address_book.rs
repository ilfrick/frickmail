//! Native Personal Address Book (PAB) storage that shares the legacy PHP
//! `rainloop_ab_contacts` / `rainloop_ab_properties` schema and row semantics
//! (see SnappyMail's `RainLoop\Providers\AddressBook\PdoAddressBook`), so the
//! PHP compatibility runtime and the Rust server read and write the same
//! contact data during the strangler phase.
//!
//! Storage model (PHP parity):
//! - `rainloop_ab_contacts`: one row per contact (`id_contact_str` is the
//!   vCard UID, `display` is the FN value, `deleted` is a soft-delete flag).
//! - `rainloop_ab_properties`: one row per vCard property. The complete vCard
//!   is persisted as a jCard JSON blob under `prop_type = 251` (`JCARD`),
//!   alongside flattened typed properties (full name, N parts, email, phone,
//!   web page). `prop_value_lower` holds the lowercased value for search and
//!   `prop_frec` the usage frequency of email properties.

use crate::{db_error, FrickmailError, Result};
use sqlx::{AnyPool, Connection, Row};

/// `RainLoop\Providers\AddressBook\Enumerations\PropertyType` values used by
/// the native writer.
pub mod property_type {
    pub const FIRST_NAME: i64 = 15;
    pub const LAST_NAME: i64 = 16;
    pub const MIDDLE_NAME: i64 = 17;
    pub const NAME_PREFIX: i64 = 20;
    pub const NAME_SUFFIX: i64 = 21;
    pub const FULLNAME: i64 = 10;
    pub const EMAIL: i64 = 30;
    pub const PHONE: i64 = 31;
    pub const WEB_PAGE: i64 = 32;
    pub const JCARD: i64 = 251;
}

/// One flattened vCard property row to persist.
#[derive(Clone, Debug, PartialEq)]
pub struct AddressBookProperty {
    pub ptype: i64,
    pub type_str: String,
    pub value: String,
}

impl AddressBookProperty {
    pub fn new(ptype: i64, value: impl Into<String>) -> Self {
        Self {
            ptype,
            type_str: String::new(),
            value: value.into(),
        }
    }
}

/// A contact to persist. On update, `id` must carry the existing numeric id;
/// on insert it stays `0` and the assigned id is returned.
#[derive(Clone, Debug, Default)]
pub struct AddressBookContact {
    pub id: i64,
    pub uid: String,
    pub display: String,
    pub properties: Vec<AddressBookProperty>,
}

/// Paginated contact summaries used by deduplication (PHP `GetContacts`).
#[derive(Clone, Debug)]
pub struct AddressBookContactSummary {
    pub id: i64,
    pub uid: String,
    pub display: String,
}
/// Creates the legacy address book tables when missing. PostgreSQL's
/// `CREATE TABLE IF NOT EXISTS` is not concurrency-safe (duplicate key on
/// `pg_type` when two sessions race), so the migration runs under a
/// session-level advisory lock like `fm_db::ensure_runtime_schema`. A cheap
/// probe query skips the DDL round-trips once the tables exist, so request
/// handlers can call this on every request.
pub async fn ensure_address_book_schema(pool: &AnyPool) -> Result<()> {
    // A successful probe implies the tables exist (they are created together).
    let probe = sqlx::query("SELECT 1 AS ok FROM rainloop_ab_contacts LIMIT 1")
        .fetch_optional(pool)
        .await;
    if probe.is_ok() {
        return Ok(());
    }

    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    let postgres = backend == "PostgreSQL";
    if postgres {
        sqlx::query("SELECT pg_advisory_lock(67410229184)")
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;
    }

    let outcome = async {
        let statements: Vec<&str> = match backend.as_str() {
            "MySQL" => vec![
                "CREATE TABLE IF NOT EXISTS rainloop_ab_contacts (\
                    id_contact BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\
                    id_contact_str VARCHAR(128) NOT NULL DEFAULT '',\
                    id_user BIGINT UNSIGNED NOT NULL,\
                    display VARCHAR(255) NOT NULL DEFAULT '',\
                    changed BIGINT UNSIGNED NOT NULL DEFAULT 0,\
                    deleted TINYINT UNSIGNED NOT NULL DEFAULT 0,\
                    etag VARCHAR(128) NOT NULL DEFAULT '',\
                    PRIMARY KEY(id_contact),\
                    INDEX id_user_rainloop_ab_contacts_index (id_user)\
                )",
                "CREATE TABLE IF NOT EXISTS rainloop_ab_properties (\
                    id_prop BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\
                    id_contact BIGINT UNSIGNED NOT NULL,\
                    id_user BIGINT UNSIGNED NOT NULL,\
                    prop_type TINYINT UNSIGNED NOT NULL,\
                    prop_type_str VARCHAR(255) NOT NULL DEFAULT '',\
                    prop_value MEDIUMTEXT NOT NULL,\
                    prop_value_lower MEDIUMTEXT NOT NULL,\
                    prop_value_custom MEDIUMTEXT NOT NULL,\
                    prop_frec BIGINT UNSIGNED NOT NULL DEFAULT 0,\
                    PRIMARY KEY(id_prop),\
                    INDEX id_user_rainloop_ab_properties_index (id_user),\
                    INDEX id_user_id_contact_rainloop_ab_properties_index (id_user, id_contact),\
                    INDEX id_contact_prop_type_rainloop_ab_properties_index (id_contact, prop_type)\
                )",
            ],
            "PostgreSQL" => vec![
                "CREATE TABLE IF NOT EXISTS rainloop_ab_contacts (\
                    id_contact bigserial PRIMARY KEY,\
                    id_contact_str varchar(128) NOT NULL DEFAULT '',\
                    id_user integer NOT NULL,\
                    display varchar(255) NOT NULL DEFAULT '',\
                    changed integer NOT NULL DEFAULT 0,\
                    deleted integer NOT NULL DEFAULT 0,\
                    etag varchar(128) NOT NULL DEFAULT ''\
                )",
                "CREATE INDEX IF NOT EXISTS id_user_rainloop_ab_contacts_index ON rainloop_ab_contacts (id_user)",
                "CREATE TABLE IF NOT EXISTS rainloop_ab_properties (\
                    id_prop bigserial PRIMARY KEY,\
                    id_contact integer NOT NULL,\
                    id_user integer NOT NULL,\
                    prop_type integer NOT NULL,\
                    prop_type_str varchar(255) NOT NULL DEFAULT '',\
                    prop_value text NOT NULL DEFAULT '',\
                    prop_value_lower text NOT NULL DEFAULT '',\
                    prop_value_custom text NOT NULL DEFAULT '',\
                    prop_frec integer NOT NULL DEFAULT 0\
                )",
                "CREATE INDEX IF NOT EXISTS id_user_rainloop_ab_properties_index ON rainloop_ab_properties (id_user)",
                "CREATE INDEX IF NOT EXISTS id_user_id_contact_rainloop_ab_properties_index ON rainloop_ab_properties (id_user, id_contact)",
            ],
            _ => vec![
                "CREATE TABLE IF NOT EXISTS rainloop_ab_contacts (\
                    id_contact integer NOT NULL PRIMARY KEY,\
                    id_contact_str text NOT NULL DEFAULT '',\
                    id_user integer NOT NULL,\
                    display text NOT NULL DEFAULT '',\
                    changed integer NOT NULL DEFAULT 0,\
                    deleted integer NOT NULL DEFAULT 0,\
                    etag text NOT NULL DEFAULT ''\
                )",
                "CREATE INDEX IF NOT EXISTS id_user_rainloop_ab_contacts_index ON rainloop_ab_contacts (id_user)",
                "CREATE TABLE IF NOT EXISTS rainloop_ab_properties (\
                    id_prop integer NOT NULL PRIMARY KEY,\
                    id_contact integer NOT NULL,\
                    id_user integer NOT NULL,\
                    prop_type integer NOT NULL,\
                    prop_type_str text NOT NULL DEFAULT '',\
                    prop_value text NOT NULL DEFAULT '',\
                    prop_value_lower text NOT NULL DEFAULT '',\
                    prop_value_custom text NOT NULL DEFAULT '',\
                    prop_frec integer NOT NULL DEFAULT 0\
                )",
                "CREATE INDEX IF NOT EXISTS id_user_rainloop_ab_properties_index ON rainloop_ab_properties (id_user)",
                "CREATE INDEX IF NOT EXISTS id_user_id_contact_rainloop_ab_properties_index ON rainloop_ab_properties (id_user, id_contact)",
            ],
        };
        for statement in statements {
            sqlx::query(statement)
                .execute(&mut *conn)
                .await
                .map_err(db_error)?;
        }
        Ok(())
    }
    .await;

    if postgres {
        let _ = sqlx::query("SELECT pg_advisory_unlock(67410229184)")
            .execute(&mut *conn)
            .await;
    }

    outcome
}

/// Returns the bound placeholder for the given 1-based parameter index:
/// `$n` for PostgreSQL, `?` for MySQL and SQLite. sqlx's `any` driver passes
/// SQL verbatim to the backend, so PostgreSQL requires numbered placeholders.
fn ab_placeholder(backend: &str, index: usize) -> String {
    if backend == "PostgreSQL" {
        format!("${index}")
    } else {
        "?".to_string()
    }
}

/// Decodes a text column portably: MySQL reports TEXT/MEDIUMTEXT as BLOB
/// through the `any` driver, which strict `String` decoding rejects.
fn row_string(row: &sqlx::any::AnyRow, column: &str) -> Result<String> {
    if let Ok(value) = row.try_get::<String, _>(column) {
        return Ok(value);
    }
    let bytes: Vec<u8> = row.try_get(column).map_err(db_error)?;
    String::from_utf8(bytes).map_err(|_| {
        FrickmailError::Upstream(format!("address book column {column} is not valid UTF-8"))
    })
}

/// Returns the numeric contact id for a vCard UID (`id_contact_str`), the
/// upsert key used by `ContactSave` in PHP (`GetContactByID($uid, true)`).
pub async fn get_contact_id_by_uid(pool: &AnyPool, user_id: i64, uid: &str) -> Result<Option<i64>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let query = format!(
        "SELECT id_contact FROM rainloop_ab_contacts \
         WHERE id_user = {u} AND id_contact_str = {p1} AND deleted = 0",
        u = ab_placeholder(&backend, 1),
        p1 = ab_placeholder(&backend, 2),
    );
    let row = sqlx::query(&query)
        .bind(user_id)
        .bind(uid)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_error)?;
    Ok(row.and_then(|row| row.try_get::<i64, _>("id_contact").ok()))
}

/// Preserves email usage frequencies across property rewrites, matching the
/// PHP `getContactFreq` behaviour in `ContactSave` (read BEFORE the old
/// property rows are deleted — afterwards the map would always be empty).
async fn get_contact_email_freq(
    conn: &mut sqlx::AnyConnection,
    backend: &str,
    user_id: i64,
    contact_id: i64,
) -> Result<std::collections::HashMap<String, i64>> {
    let query = format!(
        "SELECT prop_value, prop_frec FROM rainloop_ab_properties \
         WHERE id_user = {u} AND id_contact = {c} AND prop_type = {t}",
        u = ab_placeholder(backend, 1),
        c = ab_placeholder(backend, 2),
        t = ab_placeholder(backend, 3),
    );
    let rows = sqlx::query(&query)
        .bind(user_id)
        .bind(contact_id)
        .bind(property_type::EMAIL)
        .fetch_all(conn)
        .await
        .map_err(db_error)?;
    let mut freq = std::collections::HashMap::new();
    for row in rows {
        let value = row_string(&row, "prop_value")?;
        let frec: i64 = row.try_get("prop_frec").map_err(db_error)?;
        freq.insert(value, frec);
    }
    Ok(freq)
}

async fn insert_contact_row(
    conn: &mut sqlx::AnyConnection,
    backend: &str,
    user_id: i64,
    uid: &str,
    display: &str,
    changed: i64,
) -> Result<i64> {
    if matches!(backend, "PostgreSQL" | "SQLite") {
        let query = format!(
            "INSERT INTO rainloop_ab_contacts (id_user, id_contact_str, display, changed, etag) \
             VALUES ({u}, {p1}, {p2}, {p3}, '') RETURNING id_contact",
            u = ab_placeholder(backend, 1),
            p1 = ab_placeholder(backend, 2),
            p2 = ab_placeholder(backend, 3),
            p3 = ab_placeholder(backend, 4),
        );
        return sqlx::query(&query)
            .bind(user_id)
            .bind(uid)
            .bind(display)
            .bind(changed)
            .fetch_one(conn)
            .await
            .and_then(|row| row.try_get::<i64, _>("id_contact"))
            .map_err(db_error);
    }

    sqlx::query(
        "INSERT INTO rainloop_ab_contacts (id_user, id_contact_str, display, changed, etag) \
         VALUES (?, ?, ?, ?, '')",
    )
    .bind(user_id)
    .bind(uid)
    .bind(display)
    .bind(changed)
    .execute(conn)
    .await
    .map_err(db_error)?
    .last_insert_id()
    .ok_or_else(|| {
        FrickmailError::Upstream(
            "address book database error: inserted contact id is unavailable".to_string(),
        )
    })
}

async fn write_properties(
    conn: &mut sqlx::AnyConnection,
    backend: &str,
    user_id: i64,
    contact_id: i64,
    contact: &AddressBookContact,
    freq: &std::collections::HashMap<String, i64>,
) -> Result<()> {
    for property in &contact.properties {
        let frec = if property.ptype == property_type::EMAIL {
            freq.get(&property.value).copied().unwrap_or(0)
        } else {
            0
        };
        let query = format!(
            "INSERT INTO rainloop_ab_properties \
             (id_contact, id_user, prop_type, prop_type_str, prop_value, prop_value_lower, prop_value_custom, prop_frec) \
             VALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {p7}, {p8})",
            p1 = ab_placeholder(backend, 1),
            p2 = ab_placeholder(backend, 2),
            p3 = ab_placeholder(backend, 3),
            p4 = ab_placeholder(backend, 4),
            p5 = ab_placeholder(backend, 5),
            p6 = ab_placeholder(backend, 6),
            p7 = ab_placeholder(backend, 7),
            p8 = ab_placeholder(backend, 8),
        );
        sqlx::query(&query)
            .bind(contact_id)
            .bind(user_id)
            .bind(property.ptype)
            .bind(&property.type_str)
            .bind(&property.value)
            .bind(property.value.to_lowercase())
            .bind("")
            .bind(frec)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;
    }
    Ok(())
}

/// Inserts or updates a contact plus its property rows with the exact
/// `PdoAddressBook::ContactSave` semantics: update rewrites the contact row
/// and replaces all properties (preserving email frequencies read BEFORE the
/// delete); insert assigns a new numeric id. The whole write runs in one
/// transaction so a failure cannot strand a propertyless contact row.
pub async fn save_contact(
    pool: &AnyPool,
    user_id: i64,
    contact: &AddressBookContact,
) -> Result<i64> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let changed = chrono::Utc::now().timestamp();

    let mut tx = conn.begin().await.map_err(db_error)?;

    let contact_id = if contact.id > 0 {
        sqlx::query(&format!(
            "UPDATE rainloop_ab_contacts \
             SET id_contact_str = {p1}, display = {p2}, changed = {p3}, etag = '' \
             WHERE id_user = {p4} AND id_contact = {p5}",
            p1 = ab_placeholder(&backend, 1),
            p2 = ab_placeholder(&backend, 2),
            p3 = ab_placeholder(&backend, 3),
            p4 = ab_placeholder(&backend, 4),
            p5 = ab_placeholder(&backend, 5),
        ))
        .bind(&contact.uid)
        .bind(&contact.display)
        .bind(changed)
        .bind(user_id)
        .bind(contact.id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        let freq = get_contact_email_freq(&mut tx, &backend, user_id, contact.id).await?;
        sqlx::query(&format!(
            "DELETE FROM rainloop_ab_properties WHERE id_user = {u} AND id_contact = {c}",
            u = ab_placeholder(&backend, 1),
            c = ab_placeholder(&backend, 2),
        ))
        .bind(user_id)
        .bind(contact.id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        write_properties(&mut tx, &backend, user_id, contact.id, contact, &freq).await?;
        contact.id
    } else {
        let contact_id = insert_contact_row(
            &mut tx,
            &backend,
            user_id,
            &contact.uid,
            &contact.display,
            changed,
        )
        .await?;
        write_properties(
            &mut tx,
            &backend,
            user_id,
            contact_id,
            contact,
            &std::collections::HashMap::new(),
        )
        .await?;
        contact_id
    };

    tx.commit().await.map_err(db_error)?;
    Ok(contact_id)
}

/// Deletes property rows and soft-deletes the contact rows, matching
/// `PdoAddressBook::DeleteContacts` (deleted = 1 keeps CardDAV history).
pub async fn delete_contacts(pool: &AnyPool, user_id: i64, contact_ids: &[i64]) -> Result<bool> {
    let ids: Vec<i64> = contact_ids.iter().copied().filter(|id| *id > 0).collect();
    if ids.is_empty() {
        return Ok(false);
    }
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();

    for id in &ids {
        sqlx::query(&format!(
            "DELETE FROM rainloop_ab_properties WHERE id_user = {u} AND id_contact = {c}",
            u = ab_placeholder(&backend, 1),
            c = ab_placeholder(&backend, 2),
        ))
        .bind(user_id)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;
        sqlx::query(&format!(
            "UPDATE rainloop_ab_contacts SET deleted = 1, changed = {c} \
             WHERE id_user = {u} AND id_contact = {i}",
            c = ab_placeholder(&backend, 1),
            u = ab_placeholder(&backend, 2),
            i = ab_placeholder(&backend, 3),
        ))
        .bind(chrono::Utc::now().timestamp())
        .bind(user_id)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;
    }
    Ok(true)
}

/// Lists non-deleted contact summaries ordered by numeric id, the stable
/// order deduplication relies on ("keep the lowest id").
pub async fn list_contact_summaries(
    pool: &AnyPool,
    user_id: i64,
    offset: i64,
    limit: i64,
) -> Result<Vec<AddressBookContactSummary>> {
    let mut conn = pool.acquire().await.map_err(db_error)?;
    let backend = conn.backend_name().to_string();
    let query = format!(
        "SELECT id_contact, id_contact_str, display FROM rainloop_ab_contacts \
         WHERE id_user = {u} AND deleted = 0 ORDER BY id_contact LIMIT {l} OFFSET {o}",
        u = ab_placeholder(&backend, 1),
        l = ab_placeholder(&backend, 2),
        o = ab_placeholder(&backend, 3),
    );
    let rows = sqlx::query(&query)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_error)?;
    rows.iter()
        .map(|row| {
            Ok(AddressBookContactSummary {
                id: row.try_get("id_contact").map_err(db_error)?,
                uid: row_string(row, "id_contact_str")?,
                display: row_string(row, "display")?,
            })
        })
        .collect()
}

/// Builds a jCard JSON document (`["vcard", [...properties]]`) matching
/// Sabre/VObject's `jsonSerialize` output for the vCards the PHP plugin
/// creates, stored as the `JCARD` property value.
///
/// `properties` yields `(name, values)` pairs in insertion order with
/// lowercase names and empty parameter objects, like the PHP writer. All
/// values use the jCard `text` value type.
pub fn build_jcard<'a, I, V>(properties: I) -> String
where
    I: IntoIterator<Item = (&'a str, V)>,
    V: IntoIterator<Item = &'a str>,
{
    build_jcard_typed(
        properties
            .into_iter()
            .map(|(name, values)| (name, "text", values)),
    )
}

/// Like [`build_jcard`] with an explicit jCard value type per property
/// (`text`, `date`, ...), matching Sabre's per-property `getValueType()`.
pub fn build_jcard_typed<'a, I, V>(properties: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a str, V)>,
    V: IntoIterator<Item = &'a str>,
{
    let mut json = String::from("[\"vcard\",[");
    for (index, (name, value_type, values)) in properties.into_iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        json.push_str(&format!("[\"{name}\",{{}},\"{value_type}\""));
        for value in values {
            json.push(',');
            json.push_str(&serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string()));
        }
        json.push(']');
    }
    json.push_str("]]");
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jcard_matches_sabre_shape() {
        let jcard = build_jcard([
            ("version", vec!["4.0"]),
            ("uid", vec!["manual:abc"]),
            ("fn", vec!["Ada Lovelace"]),
            ("email", vec!["ada@example.com"]),
            ("n", vec!["Lovelace", "Ada", "", "", ""]),
        ]);
        assert_eq!(
            jcard,
            "[\"vcard\",[\
             [\"version\",{},\"text\",\"4.0\"],\
             [\"uid\",{},\"text\",\"manual:abc\"],\
             [\"fn\",{},\"text\",\"Ada Lovelace\"],\
             [\"email\",{},\"text\",\"ada@example.com\"],\
             [\"n\",{},\"text\",\"Lovelace\",\"Ada\",\"\",\"\",\"\"]\
             ]]"
        );
    }

    #[test]
    fn jcard_escapes_values() {
        let jcard = build_jcard([("fn", vec!["Quote \" and \\ backslash"])]);
        assert!(jcard.contains("Quote \\\" and \\\\ backslash"));
    }
}
