//! Native `JsonAddContact` and `JsonDeduplicateContacts` plugin hooks,
//! replacing the PHP `contacts-sync` plugin's local address book operations
//! in Frickmail mode (provider fetching for `JsonContactsSync` follows in a
//! later slice; that action stays a 501 compatibility fallback until then).
//!
//! Parity notes versus the PHP plugin:
//! - Errors return as `Result.error` inside a 200 envelope, matching the PHP
//!   plugin's response style.
//! - The "address book is not active" errors are intentionally absent: the
//!   native PAB storage is always available (no admin provider toggle).
//! - The manual-contact UID uses `manual:` plus 32 random hex characters
//!   (matching the PHP `md5` length) instead of `md5(email . microtime)`.

use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

use super::{json_result_error, json_value_envelope, load_session_user, payload_string};
use crate::AppState;
use fm_user::address_book::{self, property_type, AddressBookContact, AddressBookProperty};

const DEDUPE_PAGE_SIZE: i64 = 500;
const DEDUPE_MAX_CONTACTS: i64 = 50_000;

/// Validates an email address like the PHP plugin's `FILTER_VALIDATE_EMAIL`
/// usage (single @, non-empty local part, dotted domain, no whitespace).
fn contact_email_valid(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty() || email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if email.matches('@').count() != 1 {
        return false;
    }
    domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
}

/// Splits a display name into the vCard `N` value components following the
/// PHP plugin: family = the remainder after the first space, given = the
/// first word. Returns `None` when the name equals the email (no N written).
fn contact_name_parts(name: &str, email: &str) -> Option<(String, String)> {
    if name == email {
        return None;
    }
    match name.split_once(' ') {
        Some((given, family)) => Some((family.to_string(), given.to_string())),
        None => Some((String::new(), name.to_string())),
    }
}

fn contacts_error_envelope(original_action: &str, message: &str) -> axum::response::Response {
    json_value_envelope(
        axum::http::StatusCode::OK,
        original_action,
        json!({ "Result": { "error": message } }),
    )
}

fn contacts_result_envelope(original_action: &str, result: Value) -> axum::response::Response {
    json_value_envelope(
        axum::http::StatusCode::OK,
        original_action,
        json!({ "Result": result }),
    )
}

pub async fn native_json_add_contact(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> axum::response::Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return contacts_error_envelope(original_action, "not authenticated");
    };
    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let email = payload_string(payload, "email")
        .unwrap_or_default()
        .trim()
        .to_string();
    let name = payload_string(payload, "name")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| email.clone());
    if !contact_email_valid(&email) {
        return contacts_error_envelope(original_action, "invalid email address");
    }

    if let Err(err) = address_book::ensure_address_book_schema(pool).await {
        return json_result_error(original_action, &err.public_message());
    }

    // PHP: `manual:` . md5(email . microtime(true)) — 32 hex characters.
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    let uid = format!(
        "manual:{}",
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );

    // Property rows are written in the PHP `VCardToProperties` order: the
    // JCARD blob first, then FULLNAME, then the N parts, then EMAIL. The
    // jCard itself keeps the vCard insertion order (VERSION, UID, FN, EMAIL,
    // N) and intentionally stores a flat `N` without PHP's `X-CRYPTO`
    // property; Sabre's jCard reader treats both shapes identically.
    let mut jcard: Vec<(String, Vec<String>)> = vec![
        ("version".to_string(), vec!["4.0".to_string()]),
        ("uid".to_string(), vec![uid.clone()]),
        ("fn".to_string(), vec![name.clone()]),
        ("email".to_string(), vec![email.clone()]),
    ];
    let mut properties: Vec<AddressBookProperty> = Vec::new();
    if let Some((family, given)) = contact_name_parts(&name, &email) {
        jcard.push((
            "n".to_string(),
            vec![
                family.clone(),
                given.clone(),
                String::new(),
                String::new(),
                String::new(),
            ],
        ));
    }
    // PHP yields the full vCard JSON blob first (Legacy::VCardToProperties).
    properties.push(AddressBookProperty::new(
        property_type::JCARD,
        address_book::build_jcard(
            jcard
                .iter()
                .map(|(name, values)| (name.as_str(), values.iter().map(String::as_str))),
        ),
    ));
    properties.push(AddressBookProperty::new(
        property_type::FULLNAME,
        name.clone(),
    ));
    if let Some((family, given)) = contact_name_parts(&name, &email) {
        for (ptype, value) in [
            (property_type::LAST_NAME, family),
            (property_type::FIRST_NAME, given),
        ] {
            if !value.is_empty() {
                properties.push(AddressBookProperty::new(ptype, value));
            }
        }
    }
    properties.push(AddressBookProperty::new(
        property_type::EMAIL,
        email.clone(),
    ));

    let contact = AddressBookContact {
        id: 0,
        uid,
        display: name.clone(),
        properties,
    };
    match address_book::save_contact(pool, user.user_id, &contact).await {
        Ok(_contact_id) => contacts_result_envelope(
            original_action,
            json!({
                "ok": true,
                "email": email,
                "name": name,
            }),
        ),
        Err(err) => contacts_error_envelope(original_action, &err.public_message()),
    }
}

pub async fn native_json_deduplicate_contacts(
    state: &AppState,
    original_action: &str,
    _payload: &Value,
    session: &fm_session::Session,
) -> axum::response::Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return contacts_error_envelope(original_action, "not authenticated");
    };
    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    if let Err(err) = address_book::ensure_address_book_schema(pool).await {
        return json_result_error(original_action, &err.public_message());
    }

    // Scan all contacts in pages of 500 ordered by numeric id and delete
    // later duplicates sharing the same UID (or, when the UID is empty, the
    // same display name) — keeping the first (lowest) id like PHP.
    let mut seen = std::collections::HashSet::new();
    let mut to_delete: Vec<i64> = Vec::new();
    let mut offset = 0_i64;
    loop {
        let page = match address_book::list_contact_summaries(
            pool,
            user.user_id,
            offset,
            DEDUPE_PAGE_SIZE,
        )
        .await
        {
            Ok(page) => page,
            Err(err) => {
                return contacts_error_envelope(original_action, &err.public_message());
            }
        };
        let page_len = page.len() as i64;
        for summary in page {
            let key = if summary.uid.is_empty() {
                format!("__name__{}", summary.display)
            } else {
                summary.uid.clone()
            };
            if !seen.insert(key) {
                to_delete.push(summary.id);
            }
        }
        if page_len < DEDUPE_PAGE_SIZE {
            break;
        }
        offset += DEDUPE_PAGE_SIZE;
        if offset >= DEDUPE_MAX_CONTACTS {
            break;
        }
    }

    let mut removed = 0_usize;
    if !to_delete.is_empty() {
        match address_book::delete_contacts(pool, user.user_id, &to_delete).await {
            Ok(true) => removed = to_delete.len(),
            Ok(false) => {}
            Err(err) => {
                return contacts_error_envelope(original_action, &err.public_message());
            }
        }
    }

    contacts_result_envelope(
        original_action,
        json!({
            "removed": removed,
            "ok": true,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_validation_matches_php_filter_usage() {
        assert!(contact_email_valid("user@example.com"));
        assert!(contact_email_valid("a.b+tag@sub.domain.io"));
        assert!(!contact_email_valid("no-at-sign"));
        assert!(!contact_email_valid("user@"));
        assert!(!contact_email_valid("@example.com"));
        assert!(!contact_email_valid("user example.com"));
        assert!(!contact_email_valid("user@dom.ain."));
        assert!(!contact_email_valid("user@do..ain.com"));
        assert!(!contact_email_valid("us er@example.com"));
        assert!(!contact_email_valid("user@@example.com"));
    }

    #[test]
    fn name_parts_follow_php_explode_rules() {
        // Two words: given = first, family = remainder.
        assert_eq!(
            contact_name_parts("Ada Lovelace", "ada@example.com"),
            Some(("Lovelace".to_string(), "Ada".to_string()))
        );
        // Three words: family keeps the remainder.
        assert_eq!(
            contact_name_parts("Ada King Lovelace", "ada@example.com"),
            Some(("King Lovelace".to_string(), "Ada".to_string()))
        );
        // Single word: empty family.
        assert_eq!(
            contact_name_parts("Madonna", "madonna@example.com"),
            Some((String::new(), "Madonna".to_string()))
        );
        // Name equal to the email: no N property.
        assert_eq!(
            contact_name_parts("user@example.com", "user@example.com"),
            None
        );
    }
}
