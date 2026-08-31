//! Native calendar proxy for the `JsonCalendar*` plugin hooks, replacing the
//! PHP `calendar` plugin in Frickmail mode.
//!
//! The PHP plugin proxies Google Calendar and Microsoft Graph with the mail
//! account's OAuth2 refresh token. This module mirrors its request building
//! and response mapping so the legacy frontend keeps working unchanged:
//!
//! - Calendar plugin errors are returned inside the legacy envelope as
//!   `Result.error` with HTTP 200, like the PHP catch block.
//! - Gmail sends no scope on refresh; Graph sends the calendar scope plus
//!   `offline_access` (matching the PHP plugin).
//! - Intentional fix: O365 event *updates* address the raw Graph event id,
//!   not the composite `calendar:id` the legacy PHP PATCH used (which could
//!   never match a Graph event id).

use std::future::Future;

use serde_json::{json, Value};

use super::{
    decrypt_account_secret, graph_tenant, json_result_error, json_value_envelope,
    load_session_credential_key, load_session_user, payload_bool, payload_string,
    resolve_message_body_account_id, SqlxUserRepository,
};
use crate::AppState;
use fm_core::FrickmailError;
use fm_user::MailAccountConnectionSecret;

const CALENDAR_FETCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
/// Aggregate bound across all sequential provider requests of one action so
/// a many-calendar request cannot keep the handler alive indefinitely.
const CALENDAR_ACTION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
const CALENDAR_MAX_CALENDARS: usize = 50;
const CALENDAR_MAX_EVENTS: usize = 2000;
const GMAIL_CALENDAR_API_ROOT: &str = "https://www.googleapis.com/calendar/v3";
const O365_GRAPH_API_ROOT: &str = "https://graph.microsoft.com/v1.0";
const O365_CALENDAR_SCOPES: &str = "https://graph.microsoft.com/Calendars.ReadWrite offline_access";
const DEFAULT_CALENDAR_COLOR: &str = "#4a90e2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalendarHttpMethod {
    Get,
    Post,
    Patch,
    Delete,
}

/// A single outbound HTTP request of the calendar proxy flow, mirroring the
/// PHP plugin's `http()` helper shape so the pure request-building logic can
/// be tested without network access.
///
/// The manual `Debug` redacts the bearer token and form body, which carry
/// the account's OAuth credentials, so accidental logging cannot leak them.
#[derive(Clone, PartialEq)]
pub struct CalendarHttpRequest {
    pub method: CalendarHttpMethod,
    pub url: String,
    pub bearer: Option<String>,
    pub json_body: Option<Value>,
    pub form_body: Option<Vec<(String, String)>>,
}

impl std::fmt::Debug for CalendarHttpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CalendarHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("bearer", &self.bearer.as_ref().map(|_| "[redacted]"))
            .field("json_body", &self.json_body)
            .field("form_body", &self.form_body.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct CalendarHttpResponse {
    pub status: u16,
    pub json: Value,
}

/// Resolved OAuth2 context of the selected mail account for calendar access.
pub struct CalendarAccountContext {
    pub provider: String,
    pub refresh_token: String,
    pub tenant: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

pub type CalendarFetchError = FrickmailError;

/// Performs one outbound calendar HTTP request. Production passes
/// `calendar_http_via_reqwest`; tests substitute capturing fetchers.
pub async fn calendar_http_via_reqwest(
    request: CalendarHttpRequest,
) -> Result<CalendarHttpResponse, CalendarFetchError> {
    let client = reqwest::Client::builder()
        .timeout(CALENDAR_FETCH_DEADLINE)
        .build()
        .map_err(|err| FrickmailError::Upstream(format!("Calendar client setup failed: {err}")))?;
    let method = match request.method {
        CalendarHttpMethod::Get => reqwest::Method::GET,
        CalendarHttpMethod::Post => reqwest::Method::POST,
        CalendarHttpMethod::Patch => reqwest::Method::PATCH,
        CalendarHttpMethod::Delete => reqwest::Method::DELETE,
    };
    let mut request_builder = client
        .request(method, &request.url)
        .header("Accept", "application/json");
    if let Some(bearer) = &request.bearer {
        request_builder = request_builder.bearer_auth(bearer);
    }
    if let Some(json_body) = &request.json_body {
        request_builder = request_builder.json(json_body);
    }
    if let Some(form_body) = &request.form_body {
        request_builder = request_builder.form(form_body);
    }
    let response = request_builder
        .send()
        .await
        .map_err(|err| FrickmailError::Upstream(format!("Calendar request failed: {err}")))?;
    let status = response.status().as_u16();
    // The PHP helper decodes JSON and falls back to `['raw' => body]`; the
    // native mapping only reads JSON fields, so unparsable bodies map to null.
    let json = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok(CalendarHttpResponse { status, json })
}

/// Percent-encodes a URL path segment exactly like PHP `rawurlencode`
/// (RFC 3986: unreserved characters stay literal).
fn calendar_path_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Removes HTML tags like PHP `strip_tags` (bounded, tag-only scanner; used
/// for Graph `bodyPreview`, which is plain text in practice).
fn calendar_strip_tags(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Extracts a provider API error message like the PHP plugin:
/// `error.message`, then `error_description`, then `error` when a string.
fn calendar_api_error_message(json: &Value) -> Option<String> {
    json.pointer("/error/message")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            json.get("error_description")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            json.get("error")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
        })
}

/// Splits a frontend event reference into `(calendar_id, raw_event_id)`
/// following the PHP plugin's `_raw_id` / `_calendar` / composite-id rules.
///
/// Save and delete differ subtly (PHP parity): save prefills the raw id from
/// `id` before the composite split (making the split unreachable), while
/// delete only splits a composite `id` when `_raw_id` is absent.
fn calendar_event_target(payload: &Value, save_mode: bool) -> (String, String) {
    let id = payload_string(payload, "id").unwrap_or_default();
    let raw_id_param = payload_string(payload, "_raw_id").unwrap_or_default();
    let calendar_param = payload_string(payload, "_calendar").unwrap_or_default();

    let mut calendar = if calendar_param.is_empty() {
        "primary".to_string()
    } else {
        calendar_param
    };
    let mut raw_id = if save_mode {
        if raw_id_param.is_empty() {
            id.clone()
        } else {
            raw_id_param
        }
    } else {
        raw_id_param
    };
    if raw_id.is_empty() {
        if let Some((cal, raw)) = id.split_once(':') {
            calendar = cal.to_string();
            raw_id = raw.to_string();
        }
    }
    if raw_id.is_empty() {
        raw_id = id;
    }
    (calendar, raw_id)
}

/// Builds the OAuth2 refresh request for the account's provider, mirroring
/// the PHP plugin's token calls (Gmail sends no scope; Graph sends the
/// calendar scope plus `offline_access`). Empty client secrets are omitted
/// like the PHP OAuth2 client with an empty secret.
fn calendar_token_request(context: &CalendarAccountContext) -> CalendarHttpRequest {
    let mut form = vec![
        ("client_id".to_string(), context.client_id.clone()),
        ("refresh_token".to_string(), context.refresh_token.clone()),
        ("grant_type".to_string(), "refresh_token".to_string()),
    ];
    if context.provider == "o365" {
        form.push(("scope".to_string(), O365_CALENDAR_SCOPES.to_string()));
    }
    if let Some(secret) = context
        .client_secret
        .as_deref()
        .filter(|secret| !secret.trim().is_empty())
    {
        form.push(("client_secret".to_string(), secret.to_string()));
    }
    let url = if context.provider == "gmail" {
        "https://accounts.google.com/o/oauth2/token".to_string()
    } else {
        format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            tenant = context.tenant
        )
    };
    CalendarHttpRequest {
        method: CalendarHttpMethod::Post,
        url,
        bearer: None,
        json_body: None,
        form_body: Some(form),
    }
}

/// Extracts the access token from a token-endpoint response, mirroring the
/// PHP `refreshToken` error message on failure.
fn calendar_access_token(response: &CalendarHttpResponse) -> Result<String, String> {
    if response.status == 200 {
        if let Some(token) = response
            .json
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.trim().is_empty())
        {
            return Ok(token.to_string());
        }
    }
    let detail = calendar_api_error_message(&response.json).unwrap_or_else(|| "unknown".into());
    Err(format!("refresh_token exchange failed: {detail}"))
}

fn calendar_error_envelope(original_action: &str, message: &str) -> axum::response::Response {
    json_value_envelope(
        axum::http::StatusCode::OK,
        original_action,
        json!({
            "Result": {
                "error": message
            }
        }),
    )
}

fn calendar_result_envelope(original_action: &str, result: Value) -> axum::response::Response {
    json_value_envelope(
        axum::http::StatusCode::OK,
        original_action,
        json!({ "Result": result }),
    )
}

/// Resolves the OAuth2 calendar context of the explicit or selected mail
/// account (provider, decrypted refresh token, and provider credentials).
async fn calendar_account_context(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Result<CalendarAccountContext, axum::response::Response> {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return Err(response),
    }) else {
        return Err(json_result_error(original_action, "Not authenticated"));
    };
    let Some(pool) = state.db_pool() else {
        return Err(json_result_error(
            original_action,
            "Frickmail database is not configured",
        ));
    };
    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(key) => key,
        Err(response) => return Err(response),
    };
    let account_id = match resolve_message_body_account_id(payload, session, original_action).await
    {
        Ok(account_id) => account_id,
        Err(response) => return Err(response),
    };
    let account: MailAccountConnectionSecret =
        match SqlxUserRepository::get_mail_account_connection_secret(pool, user.user_id, account_id)
            .await
        {
            Ok(Some(account)) => account,
            Ok(None) => {
                return Err(json_result_error(original_action, "Account not found"));
            }
            Err(err) => return Err(json_result_error(original_action, &err.public_message())),
        };

    let provider = match account.account_type.as_str() {
        "gmail" => "gmail",
        "o365" => "o365",
        _ => {
            return Err(calendar_error_envelope(
                original_action,
                "Calendar requires a Gmail or Office 365 account",
            ));
        }
    };
    let Some(blob) = account.encrypted_oauth_refresh_token.as_deref() else {
        return Err(calendar_error_envelope(
            original_action,
            "No OAuth2 refresh token — sign in with Gmail/Microsoft via the OAuth2 popup first.",
        ));
    };
    let refresh_token = match decrypt_account_secret(blob, &credential_key) {
        Ok(Some(token)) if !token.trim().is_empty() => token,
        Ok(_) => {
            return Err(calendar_error_envelope(
                original_action,
                "No OAuth2 refresh token — sign in with Gmail/Microsoft via the OAuth2 popup first.",
            ));
        }
        Err(err) => return Err(json_result_error(original_action, &err.public_message())),
    };

    let config = state.config();
    let (client_id, client_secret, tenant) = match provider {
        "gmail" => {
            let client_id = config
                .oauth2
                .gmail
                .client_id
                .as_deref()
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    calendar_error_envelope(original_action, "Gmail client_id not configured")
                })?;
            (
                client_id.to_string(),
                config.oauth2.gmail.client_secret.clone(),
                "common".to_string(),
            )
        }
        _ => {
            let client_id = config
                .oauth2
                .o365
                .client_id
                .as_deref()
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    calendar_error_envelope(original_action, "O365 client_id not configured")
                })?;
            let tenant = graph_tenant(
                account
                    .oauth_tenant
                    .as_deref()
                    .filter(|tenant| !tenant.trim().is_empty())
                    .unwrap_or("common"),
            )
            .map_err(|err| json_result_error(original_action, &err.public_message()))?;
            (
                client_id.to_string(),
                config.oauth2.o365.client_secret.clone(),
                tenant,
            )
        }
    };

    Ok(CalendarAccountContext {
        provider: provider.to_string(),
        refresh_token,
        tenant,
        client_id,
        client_secret,
    })
}

/// Refreshes the provider access token through the fetcher.
async fn calendar_bearer_token<F, Fut>(
    context: &CalendarAccountContext,
    fetcher: &F,
) -> Result<String, String>
where
    F: Fn(CalendarHttpRequest) -> Fut,
    Fut: Future<Output = Result<CalendarHttpResponse, CalendarFetchError>>,
{
    let response = fetcher(calendar_token_request(context))
        .await
        .map_err(|err| format!("refresh_token exchange failed: {}", err.public_message()))?;
    calendar_access_token(&response)
}

fn calendar_query(pairs: &[(&str, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

/// Reproduces the PHP defaults `first day of this month` .. `last day of
/// next month` in UTC: `Y-m-d\T00:00:00\Z` .. `Y-m-d\T23:59:59\Z`.
fn calendar_default_window() -> (String, String) {
    use chrono::Datelike;
    let now = chrono::Utc::now().date_naive();
    let first_this_month = now.with_day(1).unwrap_or(now);
    let (after_next_year, after_next_month) = if first_this_month.month() >= 11 {
        (
            first_this_month.year() + 1,
            first_this_month.month() + 2 - 12,
        )
    } else {
        (first_this_month.year(), first_this_month.month() + 2)
    };
    let first_after_next = chrono::NaiveDate::from_ymd_opt(after_next_year, after_next_month, 1)
        .unwrap_or(first_this_month);
    let last_next_month = first_after_next - chrono::Duration::days(1);
    (
        format!("{first_this_month}T00:00:00Z"),
        format!("{last_next_month}T23:59:59Z"),
    )
}

/// Builds the Google calendar-list request.
fn calendar_list_google_request(bearer: &str) -> CalendarHttpRequest {
    CalendarHttpRequest {
        method: CalendarHttpMethod::Get,
        url: format!("{GMAIL_CALENDAR_API_ROOT}/users/me/calendarList?maxResults=100"),
        bearer: Some(bearer.to_string()),
        json_body: None,
        form_body: None,
    }
}

/// Builds the Graph calendar-list request.
fn calendar_list_graph_request(bearer: &str) -> CalendarHttpRequest {
    CalendarHttpRequest {
        method: CalendarHttpMethod::Get,
        url: format!("{O365_GRAPH_API_ROOT}/me/calendars?$top=50"),
        bearer: Some(bearer.to_string()),
        json_body: None,
        form_body: None,
    }
}

fn calendar_from_google(item: &Value) -> Value {
    let id = item.get("id").and_then(Value::as_str).unwrap_or_default();
    let name = item
        .get("summary")
        .and_then(Value::as_str)
        .or_else(|| item.get("id").and_then(Value::as_str))
        .unwrap_or_default();
    let color = item
        .get("backgroundColor")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_CALENDAR_COLOR);
    json!({
        "id": id,
        "name": name,
        "color": color,
        "primary": item.get("primary").and_then(Value::as_bool).unwrap_or(false),
    })
}

fn calendar_from_graph(item: &Value) -> Value {
    let id = item.get("id").and_then(Value::as_str).unwrap_or_default();
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| item.get("id").and_then(Value::as_str))
        .unwrap_or_default();
    json!({
        "id": id,
        "name": name,
        "color": DEFAULT_CALENDAR_COLOR,
        "primary": item
            .get("isDefaultCalendar")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// Parses the `calendar_ids` parameter: a JSON-encoded array string from the
/// legacy JS (or a direct JSON array), defaulting to `["primary"]` like PHP.
fn calendar_ids_from_payload(payload: &Value) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    match payload.get("calendar_ids") {
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(id) = item.as_str() {
                    ids.push(id.to_string());
                }
            }
        }
        Some(Value::String(encoded)) => {
            if let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<Value>(encoded) {
                for item in items {
                    if let Some(id) = item.as_str() {
                        ids.push(id.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    let ids: Vec<String> = ids.into_iter().map(|id| id.trim().to_string()).collect();
    let ids: Vec<String> = ids.into_iter().filter(|id| !id.is_empty()).collect();
    if ids.is_empty() {
        vec!["primary".to_string()]
    } else {
        ids
    }
}

/// Builds the Google per-calendar events requests.
fn calendar_events_google_requests(
    bearer: &str,
    calendar_ids: &[String],
    start: &str,
    end: &str,
) -> Vec<CalendarHttpRequest> {
    let query = calendar_query(&[
        ("timeMin", start.to_string()),
        ("timeMax", end.to_string()),
        ("singleEvents", "true".to_string()),
        ("orderBy", "startTime".to_string()),
        ("maxResults", "250".to_string()),
    ]);
    calendar_ids
        .iter()
        .map(|calendar_id| CalendarHttpRequest {
            method: CalendarHttpMethod::Get,
            url: format!(
                "{GMAIL_CALENDAR_API_ROOT}/calendars/{encoded}/events?{query}",
                encoded = calendar_path_encode(calendar_id)
            ),
            bearer: Some(bearer.to_string()),
            json_body: None,
            form_body: None,
        })
        .collect()
}

/// Builds the Graph calendarview requests: the default `primary` calendar
/// uses `/me/calendarview`, explicit ids use per-calendar views.
fn calendar_events_graph_requests(
    bearer: &str,
    calendar_ids: &[String],
    start: &str,
    end: &str,
) -> Vec<CalendarHttpRequest> {
    if calendar_ids.len() == 1 && calendar_ids[0] == "primary" {
        let query = calendar_query(&[
            ("startDateTime", start.to_string()),
            ("endDateTime", end.to_string()),
            ("$top", "250".to_string()),
            ("$orderby", "start/dateTime".to_string()),
        ]);
        return vec![CalendarHttpRequest {
            method: CalendarHttpMethod::Get,
            url: format!("{O365_GRAPH_API_ROOT}/me/calendarview?{query}"),
            bearer: Some(bearer.to_string()),
            json_body: None,
            form_body: None,
        }];
    }
    calendar_ids
        .iter()
        .map(|calendar_id| {
            let query = calendar_query(&[
                ("startDateTime", start.to_string()),
                ("endDateTime", end.to_string()),
                ("$top", "250".to_string()),
            ]);
            CalendarHttpRequest {
                method: CalendarHttpMethod::Get,
                url: format!(
                    "{O365_GRAPH_API_ROOT}/me/calendars/{encoded}/calendarview?{query}",
                    encoded = calendar_path_encode(calendar_id)
                ),
                bearer: Some(bearer.to_string()),
                json_body: None,
                form_body: None,
            }
        })
        .collect()
}

fn calendar_event_from_google(event: &Value, calendar_id: &str) -> Value {
    let raw_id = event.get("id").and_then(Value::as_str).unwrap_or_default();
    let start_date = event
        .pointer("/start/date")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let start_date_time = event
        .pointer("/start/dateTime")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let end_date_time = event
        .pointer("/end/dateTime")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let end_date = event
        .pointer("/end/date")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let start = start_date_time.clone().or_else(|| start_date.clone());
    let end = end_date_time.clone().or_else(|| end_date.clone());
    json!({
        "id": format!("{calendar_id}:{raw_id}"),
        "_raw_id": raw_id,
        "_calendar": calendar_id,
        "title": event.get("summary").and_then(Value::as_str).unwrap_or("(no title)"),
        "start": start.unwrap_or_default(),
        "end": end.unwrap_or_default(),
        "allDay": start_date.is_some() && start_date_time.is_none(),
        "description": event.get("description").and_then(Value::as_str).unwrap_or_default(),
        "location": event.get("location").and_then(Value::as_str).unwrap_or_default(),
        "provider": "gmail",
    })
}

fn calendar_event_from_graph(event: &Value, calendar_id: &str) -> Value {
    let raw_id = event.get("id").and_then(Value::as_str).unwrap_or_default();
    json!({
        "id": format!("{calendar_id}:{raw_id}"),
        "_raw_id": raw_id,
        "_calendar": calendar_id,
        "title": event.get("subject").and_then(Value::as_str).unwrap_or("(no title)"),
        "start": event.pointer("/start/dateTime").and_then(Value::as_str).unwrap_or_default(),
        "end": event.pointer("/end/dateTime").and_then(Value::as_str).unwrap_or_default(),
        "allDay": event.get("isAllDay").and_then(Value::as_bool).unwrap_or(false),
        "description": calendar_strip_tags(
            event.pointer("/bodyPreview").and_then(Value::as_str).unwrap_or_default(),
        ),
        "location": event
            .pointer("/location/displayName")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "provider": "o365",
    })
}

fn calendar_value_string(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Validated save payload of a calendar event.
#[derive(Clone, Debug)]
struct CalendarSaveEvent {
    title: String,
    start: String,
    end: String,
    description: String,
    location: String,
    all_day: bool,
}

/// Builds the Google save request (PATCH when a raw id exists, else POST).
fn calendar_save_google_request(
    bearer: &str,
    calendar_id: &str,
    raw_id: &str,
    event: &CalendarSaveEvent,
) -> CalendarHttpRequest {
    let (start_value, end_value) = if event.all_day {
        (
            json!({ "date": event.start.chars().take(10).collect::<String>() }),
            json!({ "date": event.end.chars().take(10).collect::<String>() }),
        )
    } else {
        (
            json!({ "dateTime": event.start }),
            json!({ "dateTime": event.end }),
        )
    };
    let base = format!(
        "{GMAIL_CALENDAR_API_ROOT}/calendars/{encoded}/events",
        encoded = calendar_path_encode(calendar_id)
    );
    let url = if raw_id.is_empty() {
        base
    } else {
        format!("{base}/{raw}", raw = calendar_path_encode(raw_id))
    };
    CalendarHttpRequest {
        method: if raw_id.is_empty() {
            CalendarHttpMethod::Post
        } else {
            CalendarHttpMethod::Patch
        },
        url,
        bearer: Some(bearer.to_string()),
        json_body: Some(json!({
            "summary": event.title,
            "description": event.description,
            "location": event.location,
            "start": start_value,
            "end": end_value,
        })),
        form_body: None,
    }
}

/// Builds the Graph save request (PATCH when an id exists, else POST). Unlike
/// the legacy PHP PATCH, this addresses the raw Graph event id.
fn calendar_save_graph_request(
    bearer: &str,
    raw_id: &str,
    event: &CalendarSaveEvent,
) -> CalendarHttpRequest {
    let base = format!("{O365_GRAPH_API_ROOT}/me/events");
    let url = if raw_id.is_empty() {
        base
    } else {
        format!("{base}/{raw}", raw = calendar_path_encode(raw_id))
    };
    CalendarHttpRequest {
        method: if raw_id.is_empty() {
            CalendarHttpMethod::Post
        } else {
            CalendarHttpMethod::Patch
        },
        url,
        bearer: Some(bearer.to_string()),
        json_body: Some(json!({
            "subject": event.title,
            "body": { "contentType": "text", "content": event.description },
            "location": { "displayName": event.location },
            "isAllDay": event.all_day,
            "start": { "dateTime": event.start, "timeZone": "UTC" },
            "end": { "dateTime": event.end, "timeZone": "UTC" },
        })),
        form_body: None,
    }
}

fn calendar_delete_google_request(
    bearer: &str,
    calendar_id: &str,
    raw_id: &str,
) -> CalendarHttpRequest {
    CalendarHttpRequest {
        method: CalendarHttpMethod::Delete,
        url: format!(
            "{GMAIL_CALENDAR_API_ROOT}/calendars/{cal}/events/{raw}",
            cal = calendar_path_encode(calendar_id),
            raw = calendar_path_encode(raw_id)
        ),
        bearer: Some(bearer.to_string()),
        json_body: None,
        form_body: None,
    }
}

fn calendar_delete_graph_request(bearer: &str, raw_id: &str) -> CalendarHttpRequest {
    CalendarHttpRequest {
        method: CalendarHttpMethod::Delete,
        url: format!(
            "{O365_GRAPH_API_ROOT}/me/events/{raw}",
            raw = calendar_path_encode(raw_id)
        ),
        bearer: Some(bearer.to_string()),
        json_body: None,
        form_body: None,
    }
}

pub async fn native_frickmail_calendar_list(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> axum::response::Response {
    native_frickmail_calendar_list_with_fetcher(
        state,
        original_action,
        payload,
        session,
        &|request| calendar_http_via_reqwest(request),
    )
    .await
}

pub async fn native_frickmail_calendar_list_with_fetcher<F, Fut>(
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
    let context = match calendar_account_context(state, original_action, payload, session).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let bearer = match calendar_bearer_token(&context, fetcher).await {
        Ok(token) => token,
        Err(message) => return calendar_error_envelope(original_action, &message),
    };

    let request = match context.provider.as_str() {
        "gmail" => calendar_list_google_request(&bearer),
        _ => calendar_list_graph_request(&bearer),
    };
    let response = match fetcher(request).await {
        Ok(response) => response,
        Err(err) => {
            return calendar_error_envelope(original_action, &err.public_message());
        }
    };
    if response.status != 200 {
        let detail = calendar_api_error_message(&response.json)
            .unwrap_or_else(|| format!("HTTP {}", response.status));
        let message = if context.provider == "gmail" {
            format!(
                "Google Calendar API: {detail} — make sure the Google Calendar API is enabled in your Google Cloud project."
            )
        } else {
            format!("Microsoft Graph: {detail}")
        };
        return calendar_error_envelope(original_action, &message);
    }

    let source = if context.provider == "gmail" {
        response.json.get("items").cloned().unwrap_or(Value::Null)
    } else {
        response.json.get("value").cloned().unwrap_or(Value::Null)
    };
    let mut calendars = Vec::new();
    if let Some(items) = source.as_array() {
        for item in items.iter().take(CALENDAR_MAX_CALENDARS) {
            calendars.push(if context.provider == "gmail" {
                calendar_from_google(item)
            } else {
                calendar_from_graph(item)
            });
        }
    }
    calendar_result_envelope(
        original_action,
        json!({
            "calendars": calendars,
            "provider": context.provider,
        }),
    )
}

pub async fn native_frickmail_calendar_events(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> axum::response::Response {
    native_frickmail_calendar_events_with_fetcher(
        state,
        original_action,
        payload,
        session,
        &|request| calendar_http_via_reqwest(request),
    )
    .await
}

pub async fn native_frickmail_calendar_events_with_fetcher<F, Fut>(
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
    let context = match calendar_account_context(state, original_action, payload, session).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let bearer = match calendar_bearer_token(&context, fetcher).await {
        Ok(token) => token,
        Err(message) => return calendar_error_envelope(original_action, &message),
    };

    // PHP defaults: the first day of the current month through the last day
    // of next month (UTC). The legacy JS always sends explicit bounds.
    let (default_start, default_end) = calendar_default_window();
    let start = payload_string(payload, "start")
        .filter(|s| !s.is_empty())
        .unwrap_or(default_start);
    let end = payload_string(payload, "end")
        .filter(|s| !s.is_empty())
        .unwrap_or(default_end);
    let calendar_ids = calendar_ids_from_payload(payload);
    if calendar_ids.len() > CALENDAR_MAX_CALENDARS {
        return calendar_error_envelope(original_action, "Too many calendar ids");
    }
    let action_deadline = std::time::Instant::now() + CALENDAR_ACTION_DEADLINE;

    let requests = match context.provider.as_str() {
        "gmail" => calendar_events_google_requests(&bearer, &calendar_ids, &start, &end),
        _ => calendar_events_graph_requests(&bearer, &calendar_ids, &start, &end),
    };

    let mut events: Vec<Value> = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        if std::time::Instant::now() >= action_deadline {
            return calendar_error_envelope(original_action, "Calendar request deadline exceeded");
        }
        let calendar_id = calendar_ids
            .get(index)
            .cloned()
            .unwrap_or_else(|| "primary".to_string());
        let response = match fetcher(request.clone()).await {
            Ok(response) => response,
            Err(err) => {
                return calendar_error_envelope(original_action, &err.public_message());
            }
        };
        if response.status != 200 {
            let message = match context.provider.as_str() {
                "gmail" => {
                    let detail = calendar_api_error_message(&response.json)
                        .unwrap_or_else(|| format!("HTTP {}", response.status));
                    format!(
                        "Google Calendar API ({calendar_id}): {detail} — make sure the Google Calendar API is enabled in your Google Cloud project and the token has the calendar scope (re-authorize if needed)."
                    )
                }
                _ if calendar_ids.len() == 1 && calendar_ids[0] == "primary" => {
                    format!("Graph calendarview: HTTP {}", response.status)
                }
                _ => format!(
                    "Graph calendarview ({calendar_id}): HTTP {}",
                    response.status
                ),
            };
            return calendar_error_envelope(original_action, &message);
        }
        let source = if context.provider == "gmail" {
            response.json.get("items").cloned().unwrap_or(Value::Null)
        } else {
            response.json.get("value").cloned().unwrap_or(Value::Null)
        };
        if let Some(items) = source.as_array() {
            for item in items {
                if events.len() >= CALENDAR_MAX_EVENTS {
                    break;
                }
                events.push(if context.provider == "gmail" {
                    calendar_event_from_google(item, &calendar_id)
                } else {
                    calendar_event_from_graph(item, &calendar_id)
                });
            }
        }
    }

    // PHP merges events from multiple calendars and sorts by start string.
    events.sort_by(|a, b| {
        a.get("start")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(b.get("start").and_then(Value::as_str).unwrap_or_default())
    });

    calendar_result_envelope(
        original_action,
        json!({
            "events": events,
            "provider": context.provider,
        }),
    )
}

pub async fn native_frickmail_calendar_save(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> axum::response::Response {
    native_frickmail_calendar_save_with_fetcher(
        state,
        original_action,
        payload,
        session,
        &|request| calendar_http_via_reqwest(request),
    )
    .await
}

pub async fn native_frickmail_calendar_save_with_fetcher<F, Fut>(
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
    let context = match calendar_account_context(state, original_action, payload, session).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    // PHP validates the required fields before refreshing the token.
    let title = payload_string(payload, "title").unwrap_or_default();
    let start = payload_string(payload, "start").unwrap_or_default();
    let end = payload_string(payload, "end").unwrap_or_default();
    let description = payload_string(payload, "description").unwrap_or_default();
    let location = payload_string(payload, "location").unwrap_or_default();
    let all_day = payload_bool(payload, "allDay");
    if title.is_empty() || start.is_empty() || end.is_empty() {
        return calendar_error_envelope(original_action, "title/start/end required");
    }
    let bearer = match calendar_bearer_token(&context, fetcher).await {
        Ok(token) => token,
        Err(message) => return calendar_error_envelope(original_action, &message),
    };
    let (calendar_id, raw_id) = calendar_event_target(payload, true);
    let submitted_id = payload_string(payload, "id").unwrap_or_default();
    let event = CalendarSaveEvent {
        title,
        start,
        end,
        description,
        location,
        all_day,
    };

    let request = match context.provider.as_str() {
        "gmail" => calendar_save_google_request(&bearer, &calendar_id, &raw_id, &event),
        _ => calendar_save_graph_request(&bearer, &raw_id, &event),
    };
    let response = match fetcher(request).await {
        Ok(response) => response,
        Err(err) => {
            return calendar_error_envelope(original_action, &err.public_message());
        }
    };
    if response.status >= 300 {
        let detail = calendar_api_error_message(&response.json)
            .unwrap_or_else(|| format!("HTTP {}", response.status));
        return calendar_error_envelope(original_action, &detail);
    }

    let created_id = calendar_value_string(response.json.get("id"));
    let id = if created_id.is_empty() {
        submitted_id
    } else {
        created_id
    };
    calendar_result_envelope(original_action, json!({ "ok": true, "id": id }))
}

pub async fn native_frickmail_calendar_delete(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> axum::response::Response {
    native_frickmail_calendar_delete_with_fetcher(
        state,
        original_action,
        payload,
        session,
        &|request| calendar_http_via_reqwest(request),
    )
    .await
}

pub async fn native_frickmail_calendar_delete_with_fetcher<F, Fut>(
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
    let context = match calendar_account_context(state, original_action, payload, session).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let bearer = match calendar_bearer_token(&context, fetcher).await {
        Ok(token) => token,
        Err(message) => return calendar_error_envelope(original_action, &message),
    };

    let (calendar_id, raw_id) = calendar_event_target(payload, false);
    if raw_id.is_empty() {
        return calendar_error_envelope(original_action, "id required");
    }

    let request = match context.provider.as_str() {
        "gmail" => calendar_delete_google_request(&bearer, &calendar_id, &raw_id),
        _ => calendar_delete_graph_request(&bearer, &raw_id),
    };
    let response = match fetcher(request).await {
        Ok(response) => response,
        Err(err) => {
            return calendar_error_envelope(original_action, &err.public_message());
        }
    };
    // PHP tolerates 410 Gone like a successful delete.
    if response.status >= 300 && response.status != 410 {
        return calendar_error_envelope(original_action, &format!("HTTP {}", response.status));
    }
    calendar_result_envelope(original_action, json!({ "ok": true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_encode_matches_rawurlencode() {
        assert_eq!(calendar_path_encode("primary"), "primary");
        assert_eq!(calendar_path_encode("a b/c?d#e"), "a%20b%2Fc%3Fd%23e");
        assert_eq!(calendar_path_encode("safe-._~text"), "safe-._~text");
        assert_eq!(calendar_path_encode("ü"), "%C3%BC");
    }

    #[test]
    fn strip_tags_removes_tags_only() {
        assert_eq!(calendar_strip_tags("<b>bold</b> text"), "bold text");
        assert_eq!(calendar_strip_tags("a < 3 > 2"), "a  2");
        assert_eq!(calendar_strip_tags("plain"), "plain");
    }

    #[test]
    fn api_error_message_prefers_nested_message() {
        assert_eq!(
            calendar_api_error_message(&json!({"error": {"message": "boom"}})),
            Some("boom".to_string())
        );
        assert_eq!(
            calendar_api_error_message(&json!({"error_description": "desc"})),
            Some("desc".to_string())
        );
        assert_eq!(
            calendar_api_error_message(&json!({"error": "invalid_grant"})),
            Some("invalid_grant".to_string())
        );
        assert_eq!(calendar_api_error_message(&json!({})), None);
    }

    #[test]
    fn event_target_follows_php_fallback_rules() {
        // _raw_id wins, composite split skipped.
        let (cal, raw) = calendar_event_target(
            &json!({
                "id": "primary:AAMkAAA",
                "_raw_id": "AAMkBBB",
                "_calendar": "work",
            }),
            true,
        );
        assert_eq!(cal, "work");
        assert_eq!(raw, "AAMkBBB");

        // Save: _raw_id is prefilled from id, so the composite split never
        // fires (PHP parity) — the bare id is used as-is.
        let (cal, raw) = calendar_event_target(
            &json!({
                "id": "family:AAMkCCC",
                "_raw_id": "",
                "_calendar": "family",
            }),
            true,
        );
        assert_eq!(cal, "family");
        assert_eq!(raw, "family:AAMkCCC");

        // Save without _calendar defaults to primary.
        let (cal, raw) = calendar_event_target(&json!({ "id": "AAMkDDD" }), true);
        assert_eq!(cal, "primary");
        assert_eq!(raw, "AAMkDDD");

        // Delete: a composite id is split when _raw_id is absent.
        let (cal, raw) = calendar_event_target(
            &json!({
                "id": "family:AAMkCCC",
                "_raw_id": "",
                "_calendar": "",
            }),
            false,
        );
        assert_eq!(cal, "family");
        assert_eq!(raw, "AAMkCCC");

        // Delete without any id fails the required check upstream.
        let (cal, raw) = calendar_event_target(&json!({ "id": "AAMkDDD" }), false);
        assert_eq!(cal, "primary");
        assert_eq!(raw, "AAMkDDD");
    }

    #[test]
    fn calendar_ids_default_to_primary() {
        assert_eq!(
            calendar_ids_from_payload(&json!({})),
            vec!["primary".to_string()]
        );
        assert_eq!(
            calendar_ids_from_payload(&json!({"calendar_ids": "[\"a\",\" b \",\"\"]"})),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            calendar_ids_from_payload(&json!({"calendar_ids": ["x", "y"]})),
            vec!["x".to_string(), "y".to_string()]
        );
        assert_eq!(
            calendar_ids_from_payload(&json!({"calendar_ids": "not json"})),
            vec!["primary".to_string()]
        );
    }

    #[test]
    fn token_request_gmail_omits_scope_and_empty_secret() {
        let context = CalendarAccountContext {
            provider: "gmail".to_string(),
            refresh_token: "refresh-1".to_string(),
            tenant: "common".to_string(),
            client_id: "id-1".to_string(),
            client_secret: Some("   ".to_string()),
        };
        let request = calendar_token_request(&context);
        assert_eq!(request.url, "https://accounts.google.com/o/oauth2/token");
        let form = request.form_body.unwrap();
        assert!(!form.iter().any(|(key, _)| key == "scope"));
        assert!(!form.iter().any(|(key, _)| key == "client_secret"));
        assert!(form.contains(&("grant_type".to_string(), "refresh_token".to_string())));
    }

    #[test]
    fn token_request_graph_uses_tenant_and_calendar_scope() {
        let context = CalendarAccountContext {
            provider: "o365".to_string(),
            refresh_token: "refresh-2".to_string(),
            tenant: "contoso.onmicrosoft.com".to_string(),
            client_id: "id-2".to_string(),
            client_secret: Some("secret-2".to_string()),
        };
        let request = calendar_token_request(&context);
        assert_eq!(
            request.url,
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"
        );
        let form = request.form_body.unwrap();
        assert!(form.contains(&(
            "scope".to_string(),
            "https://graph.microsoft.com/Calendars.ReadWrite offline_access".to_string()
        )));
        assert!(form.contains(&("client_secret".to_string(), "secret-2".to_string())));
    }

    #[test]
    fn access_token_extraction_and_error_message() {
        let ok = CalendarHttpResponse {
            status: 200,
            json: json!({"access_token": "at-1"}),
        };
        assert_eq!(calendar_access_token(&ok).unwrap(), "at-1");

        let error = CalendarHttpResponse {
            status: 400,
            json: json!({"error": "invalid_grant", "error_description": "Token has been expired."}),
        };
        let message = calendar_access_token(&error).unwrap_err();
        assert_eq!(
            message,
            "refresh_token exchange failed: Token has been expired."
        );
    }

    #[test]
    fn calendar_list_mapping_matches_php_fields() {
        let google = calendar_from_google(&json!({
            "id": "cal-1",
            "summary": "Work",
            "backgroundColor": "#3f51b5",
            "primary": true
        }));
        assert_eq!(google["id"], "cal-1");
        assert_eq!(google["name"], "Work");
        assert_eq!(google["color"], "#3f51b5");
        assert_eq!(google["primary"], true);

        let google_minimal = calendar_from_google(&json!({"id": "cal-2"}));
        assert_eq!(google_minimal["name"], "cal-2");
        assert_eq!(google_minimal["color"], "#4a90e2");
        assert_eq!(google_minimal["primary"], false);

        let graph = calendar_from_graph(&json!({
            "id": "AAMkAG",
            "name": "Calendar",
            "isDefaultCalendar": true
        }));
        assert_eq!(graph["id"], "AAMkAG");
        assert_eq!(graph["name"], "Calendar");
        assert_eq!(graph["color"], "#4a90e2");
        assert_eq!(graph["primary"], true);
    }

    #[test]
    fn google_event_mapping_detects_all_day_and_composite_id() {
        let timed = calendar_event_from_google(
            &json!({
                "id": "ev-1",
                "summary": "Standup",
                "start": {"dateTime": "2026-09-01T09:00:00Z"},
                "end": {"dateTime": "2026-09-01T09:15:00Z"},
                "description": "daily",
                "location": "room 1"
            }),
            "primary",
        );
        assert_eq!(timed["id"], "primary:ev-1");
        assert_eq!(timed["_raw_id"], "ev-1");
        assert_eq!(timed["start"], "2026-09-01T09:00:00Z");
        assert_eq!(timed["allDay"], false);
        assert_eq!(timed["provider"], "gmail");

        let all_day = calendar_event_from_google(
            &json!({
                "id": "ev-2",
                "start": {"date": "2026-09-02"},
                "end": {"date": "2026-09-03"}
            }),
            "family",
        );
        assert_eq!(all_day["id"], "family:ev-2");
        assert_eq!(all_day["start"], "2026-09-02");
        assert_eq!(all_day["allDay"], true);
        assert_eq!(all_day["title"], "(no title)");
    }

    #[test]
    fn graph_event_mapping_strips_body_tags() {
        let event = calendar_event_from_graph(
            &json!({
                "id": "AAMkXYZ",
                "subject": "Review",
                "start": {"dateTime": "2026-09-04T10:00:00Z"},
                "end": {"dateTime": "2026-09-04T11:00:00Z"},
                "isAllDay": false,
                "bodyPreview": "<i>notes</i> here",
                "location": {"displayName": "Teams"}
            }),
            "primary",
        );
        assert_eq!(event["id"], "primary:AAMkXYZ");
        assert_eq!(event["description"], "notes here");
        assert_eq!(event["location"], "Teams");
        assert_eq!(event["allDay"], false);
        assert_eq!(event["provider"], "o365");
    }

    #[test]
    fn google_events_requests_encode_calendar_ids_and_query() {
        let requests = calendar_events_google_requests("tok", &["work cal".to_string()], "S", "E");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url,
            "https://www.googleapis.com/calendar/v3/calendars/work%20cal/events?timeMin=S&timeMax=E&singleEvents=true&orderBy=startTime&maxResults=250"
        );
        assert_eq!(requests[0].bearer.as_deref(), Some("tok"));
    }

    #[test]
    fn graph_events_requests_use_calendarview_shapes() {
        let default_request =
            calendar_events_graph_requests("tok", &["primary".to_string()], "S", "E");
        assert_eq!(default_request.len(), 1);
        assert!(default_request[0]
            .url
            .starts_with("https://graph.microsoft.com/v1.0/me/calendarview?"));
        assert!(default_request[0].url.contains("%24top=250"));
        assert!(default_request[0]
            .url
            .contains("%24orderby=start%2FdateTime"));

        let per_calendar = calendar_events_graph_requests(
            "tok",
            &["primary".to_string(), "AAMkAG".to_string()],
            "S",
            "E",
        );
        assert_eq!(per_calendar.len(), 2);
        assert!(per_calendar[1]
            .url
            .starts_with("https://graph.microsoft.com/v1.0/me/calendars/AAMkAG/calendarview?"));
        assert!(!per_calendar[1].url.contains("orderby"));
    }

    #[test]
    fn save_requests_match_provider_shapes() {
        let event = |title: &str, start: &str, end: &str, all_day: bool| CalendarSaveEvent {
            title: title.to_string(),
            start: start.to_string(),
            end: end.to_string(),
            description: "desc".to_string(),
            location: "loc".to_string(),
            all_day,
        };
        let gmail = calendar_save_google_request(
            "tok",
            "work cal",
            "ev-1",
            &event(
                "Title",
                "2026-09-01T09:00:00Z",
                "2026-09-01T10:00:00Z",
                false,
            ),
        );
        assert_eq!(gmail.method, CalendarHttpMethod::Patch);
        assert_eq!(
            gmail.url,
            "https://www.googleapis.com/calendar/v3/calendars/work%20cal/events/ev-1"
        );
        assert_eq!(
            gmail.json_body.as_ref().unwrap()["start"]["dateTime"],
            "2026-09-01T09:00:00Z"
        );

        let gmail_new = calendar_save_google_request(
            "tok",
            "primary",
            "",
            &event("T", "2026-09-01", "2026-09-02", true),
        );
        assert_eq!(gmail_new.method, CalendarHttpMethod::Post);
        assert_eq!(
            gmail_new.url,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events"
        );
        assert_eq!(
            gmail_new.json_body.as_ref().unwrap()["start"]["date"],
            "2026-09-01"
        );
        assert_eq!(
            gmail_new.json_body.as_ref().unwrap()["end"]["date"],
            "2026-09-02"
        );

        let graph =
            calendar_save_graph_request("tok", "AAMk/b+XYZ=", &event("Title", "S", "E", false));
        assert_eq!(graph.method, CalendarHttpMethod::Patch);
        assert_eq!(
            graph.url,
            "https://graph.microsoft.com/v1.0/me/events/AAMk%2Fb%2BXYZ%3D"
        );
        assert_eq!(
            graph.json_body.as_ref().unwrap()["start"]["timeZone"],
            "UTC"
        );
        assert_eq!(
            graph.json_body.as_ref().unwrap()["body"]["contentType"],
            "text"
        );
    }

    #[test]
    fn delete_requests_encode_ids() {
        let gmail = calendar_delete_google_request("tok", "work cal", "ev-1");
        assert_eq!(gmail.method, CalendarHttpMethod::Delete);
        assert_eq!(
            gmail.url,
            "https://www.googleapis.com/calendar/v3/calendars/work%20cal/events/ev-1"
        );

        let graph = calendar_delete_graph_request("tok", "AAMk/b+XYZ=");
        assert_eq!(
            graph.url,
            "https://graph.microsoft.com/v1.0/me/events/AAMk%2Fb%2BXYZ%3D"
        );
    }

    #[test]
    fn default_window_spans_this_and_next_month() {
        let (start, end) = calendar_default_window();
        assert!(start.ends_with("T00:00:00Z"));
        assert!(end.ends_with("T23:59:59Z"));
        let start_date =
            chrono::NaiveDate::parse_from_str(&start[..10], "%Y-%m-%d").expect("start date");
        let end_date = chrono::NaiveDate::parse_from_str(&end[..10], "%Y-%m-%d").expect("end date");
        use chrono::Datelike;
        assert_eq!(start_date.day(), 1);
        // The end must be the last day of the following month: one to two
        // month lengths after the first of this month.
        let days = (end_date - start_date).num_days();
        assert!((58..=62).contains(&days), "unexpected window span: {days}");
    }

    #[test]
    fn request_debug_redacts_credentials() {
        let context = CalendarAccountContext {
            provider: "o365".to_string(),
            refresh_token: "refresh-secret-value".to_string(),
            tenant: "contoso.onmicrosoft.com".to_string(),
            client_id: "id-2".to_string(),
            client_secret: Some("client-secret-value".to_string()),
        };
        let request = calendar_token_request(&context);
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("refresh-secret-value"));
        assert!(!rendered.contains("client-secret-value"));
        assert!(rendered.contains("[redacted]"));
    }
}
