//! Native `JsonAddContact`, `JsonDeduplicateContacts`, and `JsonContactsSync`
//! plugin hooks, replacing the PHP `contacts-sync` plugin in Frickmail mode.
//!
//! Parity notes versus the PHP plugin:
//! - Errors return as `Result.error` inside a 200 envelope, matching the PHP
//!   plugin's response style.
//! - The "address book is not active" errors are intentionally absent: the
//!   native PAB storage is always available (no admin provider toggle).
//! - The manual-contact UID uses `manual:` plus 32 random hex characters
//!   (matching the PHP `md5` length) instead of `md5(email . microtime)`.
//! - The sync fetches Gmail People API / Microsoft Graph contacts with the
//!   selected account's refresh token (`account_type` selects the provider),
//!   refreshing with the Graph contacts scope, upserting by `gmail:` /
//!   `o365:` provider UIDs, and following `@odata.nextLink` only inside the
//!   Graph root (SSRF-safe; PHP followed it blindly).

use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use std::future::Future;

use super::calendar::{
    calendar_account_context, calendar_bearer_token, calendar_http_via_reqwest,
    CalendarAccountContext, CalendarFetchError, CalendarHttpMethod, CalendarHttpRequest,
    CalendarHttpResponse,
};
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

// ── JsonContactsSync: provider fetching ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use std::time::{Duration, Instant};

const CONTACTS_ACTION_DEADLINE: Duration = Duration::from_secs(60);
const CONTACTS_MAX_PAGES: usize = 50;
/// PHP refreshes with the Graph contacts scope (plus `offline_access`).
const O365_CONTACTS_SCOPES: &str = "https://graph.microsoft.com/Contacts.Read offline_access";
const GMAIL_PEOPLE_BASE: &str = "https://people.googleapis.com/v1/people/me/connections";
const O365_GRAPH_CONTACTS_URL: &str = "https://graph.microsoft.com/v1.0/me/contacts?$top=100";

/// Truncates an upstream body for error messages like the PHP plugin's
/// `substr((string) $body, 0, 200)`.
fn contacts_body_snippet(json: &Value) -> String {
    let body = json.to_string();
    body.chars().take(200).collect()
}

fn contacts_string_list(items: Option<&Value>, key: &str) -> Vec<String> {
    items
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get(key))
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Google person → contact, mirroring the PHP `savePersonAsContact`.
/// Returns `None` when neither a display name nor an email is available.
fn contacts_contact_from_google(person: &Value, uid: &str) -> Option<AddressBookContact> {
    let name = person.pointer("/names/0");
    let display_name = name
        .and_then(|n| n.get("displayName"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let composed = name.map(|n| {
        let given = n
            .get("givenName")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let family = n
            .get("familyName")
            .and_then(Value::as_str)
            .unwrap_or_default();
        format!("{given} {family}").trim().to_string()
    });
    let mut full_name = display_name.or(composed).unwrap_or_default();
    if full_name.is_empty() {
        full_name = person
            .pointer("/emailAddresses/0/value")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
    }
    if full_name.is_empty() {
        return None;
    }

    let emails: Vec<String> = contacts_string_list(person.get("emailAddresses"), "value");
    let phones: Vec<String> = contacts_string_list(person.get("phoneNumbers"), "value");

    let mut jcard: Vec<(String, Vec<String>)> = vec![
        ("version".to_string(), vec!["4.0".to_string()]),
        ("uid".to_string(), vec![uid.to_string()]),
        ("fn".to_string(), vec![full_name.clone()]),
    ];
    let mut properties: Vec<AddressBookProperty> = vec![AddressBookProperty::new(
        property_type::FULLNAME,
        full_name.clone(),
    )];
    if let Some(name) = name {
        let value = |key: &str| {
            name.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        // vCard N order: family, given, middle, prefix, suffix.
        let parts = vec![
            value("familyName"),
            value("givenName"),
            value("middleName"),
            value("honorificPrefix"),
            value("honorificSuffix"),
        ];
        jcard.push(("n".to_string(), parts.clone()));
        for (ptype, part_index) in [
            (property_type::LAST_NAME, 0_usize),
            (property_type::FIRST_NAME, 1),
            (property_type::MIDDLE_NAME, 2),
            (property_type::NAME_PREFIX, 3),
            (property_type::NAME_SUFFIX, 4),
        ] {
            if !parts[part_index].is_empty() {
                properties.push(AddressBookProperty::new(ptype, parts[part_index].clone()));
            }
        }
    }
    for email in &emails {
        jcard.push(("email".to_string(), vec![email.clone()]));
        properties.push(AddressBookProperty::new(
            property_type::EMAIL,
            email.clone(),
        ));
    }
    for phone in &phones {
        jcard.push(("tel".to_string(), vec![phone.clone()]));
        properties.push(AddressBookProperty::new(
            property_type::PHONE,
            phone.clone(),
        ));
    }
    for organization in person
        .get("organizations")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let org = organization
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !org.is_empty() {
            jcard.push(("org".to_string(), vec![org.to_string()]));
        }
        let title = organization
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !title.is_empty() {
            jcard.push(("title".to_string(), vec![title.to_string()]));
        }
    }
    for address in person
        .get("addresses")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let formatted = address
            .get("formattedValue")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !formatted.is_empty() {
            jcard.push((
                "adr".to_string(),
                vec![
                    String::new(),
                    String::new(),
                    formatted.to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ],
            ));
        }
    }
    let birthday = person.pointer("/birthdays/0/date").filter(|date| {
        date.get("year").is_some() && date.get("month").is_some() && date.get("day").is_some()
    });
    if let Some(date) = birthday {
        let bday = format!(
            "{:04}-{:02}-{:02}",
            date.get("year").and_then(Value::as_i64).unwrap_or_default(),
            date.get("month")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
            date.get("day").and_then(Value::as_i64).unwrap_or_default(),
        );
        jcard.push(("bday".to_string(), vec![bday]));
    }

    // PHP VCardToProperties order: JCARD blob, FULLNAME, N parts, EMAIL, TEL
    // (ORG/TITLE/ADR/BDAY live only inside the jCard blob).
    let jcard_blob = address_book::build_jcard_typed(jcard.iter().map(|(name, values)| {
        let value_type = if name == "bday" { "date" } else { "text" };
        (name.as_str(), value_type, values.iter().map(String::as_str))
    }));
    let mut ordered = vec![AddressBookProperty::new(property_type::JCARD, jcard_blob)];
    ordered.extend(properties);

    Some(AddressBookContact {
        id: 0,
        uid: uid.to_string(),
        display: full_name,
        properties: ordered,
    })
}

/// Microsoft Graph contact → contact, mirroring the PHP `saveGraphContact`.
fn contacts_contact_from_graph(entry: &Value, uid: &str) -> Option<AddressBookContact> {
    let display_name = entry
        .get("displayName")
        .and_then(Value::as_str)
        .map(str::to_string);
    let composed = || {
        let given = entry
            .get("givenName")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let surname = entry
            .get("surname")
            .and_then(Value::as_str)
            .unwrap_or_default();
        format!("{given} {surname}").trim().to_string()
    };
    let mut full_name = display_name.unwrap_or_else(composed);
    if full_name.is_empty() {
        full_name = entry
            .pointer("/emailAddresses/0/address")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
    }
    if full_name.is_empty() {
        return None;
    }

    let mut emails: Vec<String> = Vec::new();
    for email in entry
        .get("emailAddresses")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        if let Some(address) = email.get("address").and_then(Value::as_str) {
            if !address.is_empty() {
                emails.push(address.to_string());
            }
        }
    }
    let mut phones: Vec<String> = Vec::new();
    for key in ["businessPhones", "homePhones", "mobilePhone"] {
        match entry.get(key) {
            Some(Value::String(phone)) if !phone.is_empty() => phones.push(phone.clone()),
            Some(Value::Array(items)) => {
                for phone in items {
                    if let Some(phone) = phone.as_str() {
                        if !phone.is_empty() {
                            phones.push(phone.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let value = |key: &str| {
        entry
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let surname = value("surname");
    let given = value("givenName");
    let middle = value("middleName");

    let mut jcard: Vec<(String, Vec<String>)> = vec![
        ("version".to_string(), vec!["4.0".to_string()]),
        ("uid".to_string(), vec![uid.to_string()]),
        ("fn".to_string(), vec![full_name.clone()]),
        (
            "n".to_string(),
            vec![
                surname.clone(),
                given.clone(),
                middle.clone(),
                String::new(),
                String::new(),
            ],
        ),
    ];
    let mut properties: Vec<AddressBookProperty> = vec![AddressBookProperty::new(
        property_type::FULLNAME,
        full_name.clone(),
    )];
    for (ptype, part) in [
        (property_type::LAST_NAME, surname),
        (property_type::FIRST_NAME, given),
        (property_type::MIDDLE_NAME, middle),
    ] {
        if !part.is_empty() {
            properties.push(AddressBookProperty::new(ptype, part));
        }
    }
    for email in &emails {
        jcard.push(("email".to_string(), vec![email.clone()]));
        properties.push(AddressBookProperty::new(
            property_type::EMAIL,
            email.clone(),
        ));
    }
    for phone in &phones {
        jcard.push(("tel".to_string(), vec![phone.clone()]));
        properties.push(AddressBookProperty::new(
            property_type::PHONE,
            phone.clone(),
        ));
    }
    let company = value("companyName");
    if !company.is_empty() {
        jcard.push(("org".to_string(), vec![company]));
    }
    let job_title = value("jobTitle");
    if !job_title.is_empty() {
        jcard.push(("title".to_string(), vec![job_title]));
    }
    let birthday = value("birthday");
    if !birthday.is_empty() {
        jcard.push((
            "bday".to_string(),
            vec![birthday.chars().take(10).collect::<String>()],
        ));
    }

    let jcard_blob = address_book::build_jcard_typed(jcard.iter().map(|(name, values)| {
        let value_type = if name == "bday" { "date" } else { "text" };
        (name.as_str(), value_type, values.iter().map(String::as_str))
    }));
    let mut ordered = vec![AddressBookProperty::new(property_type::JCARD, jcard_blob)];
    ordered.extend(properties);

    Some(AddressBookContact {
        id: 0,
        uid: uid.to_string(),
        display: full_name,
        properties: ordered,
    })
}

/// Upserts one provider contact by its provider UID and reports whether it
/// was saved (mirroring the PHP save-count semantics, which count updates).
async fn contacts_upsert(
    pool: &sqlx::AnyPool,
    user_id: i64,
    contact: AddressBookContact,
) -> Result<bool, String> {
    if contact.uid.is_empty() {
        return Ok(false);
    }
    let existing = address_book::get_contact_id_by_uid(pool, user_id, &contact.uid)
        .await
        .map_err(|err| err.public_message())?;
    let mut contact = contact;
    if let Some(id) = existing {
        contact.id = id;
    }
    address_book::save_contact(pool, user_id, &contact)
        .await
        .map(|_| true)
        .map_err(|err| err.public_message())
}

/// Fetches one provider page or returns the PHP-style HTTP error message.
async fn contacts_fetch_page<F, Fut>(
    fetcher: &F,
    bearer: &str,
    url: &str,
) -> Result<CalendarHttpResponse, String>
where
    F: Fn(CalendarHttpRequest) -> Fut,
    Fut: Future<Output = Result<CalendarHttpResponse, CalendarFetchError>>,
{
    let response = fetcher(CalendarHttpRequest {
        method: CalendarHttpMethod::Get,
        url: url.to_string(),
        bearer: Some(bearer.to_string()),
        json_body: None,
        form_body: None,
    })
    .await
    .map_err(|err| err.public_message())?;
    if response.status != 200 {
        return Err(format!(
            "HTTP {} GET {url}: {}",
            response.status,
            contacts_body_snippet(&response.json)
        ));
    }
    Ok(response)
}

/// Syncs Google People API connections into the address book, mirroring the
/// PHP `syncGmail` (page size 200, fixed person fields, next-page tokens).
async fn contacts_sync_google<F, Fut>(
    pool: &sqlx::AnyPool,
    user_id: i64,
    _context: &CalendarAccountContext,
    bearer: &str,
    deadline: Instant,
    fetcher: &F,
) -> Result<i64, String>
where
    F: Fn(CalendarHttpRequest) -> Fut,
    Fut: Future<Output = Result<CalendarHttpResponse, CalendarFetchError>>,
{
    let mut count: i64 = 0;
    let mut page_token = String::new();
    for _page in 0..CONTACTS_MAX_PAGES {
        if Instant::now() >= deadline {
            return Err("Contacts sync deadline exceeded".to_string());
        }
        let mut url = format!(
            "{GMAIL_PEOPLE_BASE}?pageSize=200&personFields=names,emailAddresses,phoneNumbers,addresses,organizations,birthdays"
        );
        if !page_token.is_empty() {
            url.push_str(&format!(
                "&pageToken={}",
                url::form_urlencoded::byte_serialize(page_token.as_bytes()).collect::<String>()
            ));
        }
        let response = contacts_fetch_page(fetcher, bearer, &url).await?;
        for person in response
            .json
            .get("connections")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let uid = format!(
                "gmail:{}",
                person
                    .get("resourceName")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            );
            if let Some(contact) = contacts_contact_from_google(person, &uid) {
                if contacts_upsert(pool, user_id, contact).await? {
                    count += 1;
                }
            }
        }
        page_token = response
            .json
            .get("nextPageToken")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if page_token.is_empty() {
            return Ok(count);
        }
    }
    // Page budget exhausted; like the legacy client the sync simply stops.
    Ok(count)
}

/// Syncs Microsoft Graph contacts into the address book, mirroring the PHP
/// `syncO365` ($top=100 pages following `@odata.nextLink`), with the
/// SSRF-safe restriction that next links must stay inside the Graph root.
async fn contacts_sync_graph<F, Fut>(
    pool: &sqlx::AnyPool,
    user_id: i64,
    _context: &CalendarAccountContext,
    bearer: &str,
    deadline: Instant,
    fetcher: &F,
) -> Result<i64, String>
where
    F: Fn(CalendarHttpRequest) -> Fut,
    Fut: Future<Output = Result<CalendarHttpResponse, CalendarFetchError>>,
{
    let mut count: i64 = 0;
    let mut url = O365_GRAPH_CONTACTS_URL.to_string();
    for _page in 0..CONTACTS_MAX_PAGES {
        if Instant::now() >= deadline {
            return Err("Contacts sync deadline exceeded".to_string());
        }
        let response = contacts_fetch_page(fetcher, bearer, &url).await?;
        for entry in response
            .json
            .get("value")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let uid = format!(
                "o365:{}",
                entry.get("id").and_then(Value::as_str).unwrap_or_default()
            );
            if let Some(contact) = contacts_contact_from_graph(entry, &uid) {
                if contacts_upsert(pool, user_id, contact).await? {
                    count += 1;
                }
            }
        }
        let next_link = response
            .json
            .get("@odata.nextLink")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if next_link.is_empty() {
            return Ok(count);
        }
        if !next_link.starts_with("https://graph.microsoft.com/") {
            return Err("Invalid Microsoft Graph next link".to_string());
        }
        url = next_link;
    }
    Ok(count)
}

pub async fn native_json_contacts_sync(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> axum::response::Response {
    native_json_contacts_sync_with_fetcher(state, original_action, payload, session, &|request| {
        calendar_http_via_reqwest(request)
    })
    .await
}

pub async fn native_json_contacts_sync_with_fetcher<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    fetcher: &F,
) -> axum::response::Response
where
    F: Fn(CalendarHttpRequest) -> Fut,
    Fut: Future<Output = Result<CalendarHttpResponse, CalendarFetchError>>,
{
    let context: CalendarAccountContext = match calendar_account_context(
        state,
        original_action,
        payload,
        session,
        "Contacts",
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };
    if let Err(err) = address_book::ensure_address_book_schema(pool).await {
        return json_result_error(original_action, &err.public_message());
    }
    let bearer = match calendar_bearer_token(&context, fetcher, O365_CONTACTS_SCOPES).await {
        Ok(token) => token,
        Err(message) => return contacts_error_envelope(original_action, &message),
    };

    let deadline = Instant::now() + CONTACTS_ACTION_DEADLINE;
    let sync_result = match context.provider.as_str() {
        "gmail" => {
            contacts_sync_google(pool, context.user_id, &context, &bearer, deadline, fetcher).await
        }
        "o365" => {
            contacts_sync_graph(pool, context.user_id, &context, &bearer, deadline, fetcher).await
        }
        _ => Ok(0),
    };
    let count = match sync_result {
        Ok(count) => count,
        Err(message) => return contacts_error_envelope(original_action, &message),
    };

    contacts_result_envelope(
        original_action,
        json!({
            "count": count,
            "email": context.email,
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

    #[test]
    fn google_person_maps_all_provider_fields() {
        let person = json!({
            "resourceName": "people/c123",
            "names": [{
                "displayName": "Ada Lovelace",
                "givenName": "Ada",
                "familyName": "Lovelace",
                "middleName": "King",
                "honorificPrefix": "Dr"
            }],
            "emailAddresses": [{"value": "ada@example.com"}, {"value": "ada@work.com"}],
            "phoneNumbers": [{"value": "+39 010 123"}],
            "organizations": [{"name": "Analytical Engines", "title": "Countess"}],
            "addresses": [{"formattedValue": "12 St James's Square, London"}],
            "birthdays": [{"date": {"year": 1815, "month": 12, "day": 10}}]
        });
        let contact = contacts_contact_from_google(&person, "gmail:people/c123")
            .expect("contact with display name");
        assert_eq!(contact.uid, "gmail:people/c123");
        assert_eq!(contact.display, "Ada Lovelace");

        let types: Vec<i64> = contact.properties.iter().map(|p| p.ptype).collect();
        // JCARD, FULLNAME, N parts (prefix only; no empty suffix), EMAIL, TEL.
        assert_eq!(
            types,
            vec![
                property_type::JCARD,
                property_type::FULLNAME,
                property_type::LAST_NAME,
                property_type::FIRST_NAME,
                property_type::MIDDLE_NAME,
                property_type::NAME_PREFIX,
                property_type::EMAIL,
                property_type::EMAIL,
                property_type::PHONE,
            ]
        );
        let jcard = &contact
            .properties
            .iter()
            .find(|p| p.ptype == property_type::JCARD)
            .unwrap()
            .value;
        assert!(jcard.contains("\"org\",{},\"text\",\"Analytical Engines\""));
        assert!(jcard.contains("\"title\",{},\"text\",\"Countess\""));
        assert!(jcard.contains(
            "\"adr\",{},\"text\",\"\",\"\",\"12 St James's Square, London\",\"\",\"\",\"\""
        ));
        assert!(jcard.contains("\"bday\",{},\"date\",\"1815-12-10\""));
        // Typed rows stop at TEL: ORG/TITLE/ADR/BDAY live only in the jCard.
        assert_eq!(*types.last().unwrap(), property_type::PHONE);
    }

    #[test]
    fn google_person_falls_back_to_first_email_and_skips_empty() {
        let fallback = json!({
            "resourceName": "people/c1",
            "emailAddresses": [{"value": "only@example.com"}]
        });
        let contact = contacts_contact_from_google(&fallback, "gmail:people/c1").unwrap();
        assert_eq!(contact.display, "only@example.com");
        assert_eq!(contact.uid, "gmail:people/c1");

        // Without names and emails the person is skipped (PHP returns false).
        assert!(contacts_contact_from_google(
            &json!({"resourceName": "people/c2"}),
            "gmail:people/c2"
        )
        .is_none());
    }

    #[test]
    fn graph_entry_maps_fields_including_phone_shapes() {
        let entry = json!({
            "id": "AAMkAAA=",
            "displayName": "Grace Hopper",
            "givenName": "Grace",
            "surname": "Hopper",
            "middleName": "Brewster",
            "emailAddresses": [{"address": "grace@navy.mil"}],
            "businessPhones": ["+1 555 0100"],
            "mobilePhone": "+1 555 0199",
            "companyName": "US Navy",
            "jobTitle": "Rear Admiral",
            "birthday": "1906-12-09T00:00:00Z"
        });
        let contact = contacts_contact_from_graph(&entry, "o365:AAMkAAA=").unwrap();
        assert_eq!(contact.uid, "o365:AAMkAAA=");
        assert_eq!(contact.display, "Grace Hopper");

        let types: Vec<i64> = contact.properties.iter().map(|p| p.ptype).collect();
        assert_eq!(
            types,
            vec![
                property_type::JCARD,
                property_type::FULLNAME,
                property_type::LAST_NAME,
                property_type::FIRST_NAME,
                property_type::MIDDLE_NAME,
                property_type::EMAIL,
                property_type::PHONE,
                property_type::PHONE,
            ]
        );
        let jcard = &contact
            .properties
            .iter()
            .find(|p| p.ptype == property_type::JCARD)
            .unwrap()
            .value;
        assert!(jcard.contains("\"org\",{},\"text\",\"US Navy\""));
        assert!(jcard.contains("\"title\",{},\"text\",\"Rear Admiral\""));
        assert!(jcard.contains("\"bday\",{},\"date\",\"1906-12-09\""));
    }
}
