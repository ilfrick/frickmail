use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Bytes},
    extract::{OriginalUri, Request as AxumRequest, State},
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE, USER_AGENT},
        HeaderMap, Method, StatusCode, Uri,
    },
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use fm_core::{plugin::PluginRequest, ApiEnvelope, ErrorBody, FrickmailError, HealthResponse};
use fm_plugin_compat::{
    bridge_unimplemented, is_compat_hook, normalize_plugin_action, ActionNameError,
};
use fm_user::{FrickmailMe, NewMailIdentity, SqlxUserRepository};
use serde_json::{json, Map, Value};
use tower::ServiceBuilder;
use tower_http::{compression::CompressionLayer, services::ServeDir, trace::TraceLayer};

use crate::AppState;

const INVALID_INPUT_ARGUMENT: u16 = 903;
const UNKNOWN_ERROR: u16 = 999;
const JSON_BODY_LIMIT_BYTES: usize = 64 * 1024 * 1024;

pub fn build_router(state: AppState) -> Router {
    let static_root = state.config().static_root.clone();

    Router::new()
        .route("/", get(root_get).post(json_api))
        .route("/health", get(health))
        .route("/version", get(version))
        .nest_service("/static", ServeDir::new(static_root))
        .fallback(fallback)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(fm_session::session_layer()),
        )
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "frickmail-server",
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn version() -> Json<ApiEnvelope<serde_json::Value>> {
    Json(ApiEnvelope::ok(json!({
        "name": "Frickmail",
        "backend": "rust",
        "version": env!("CARGO_PKG_VERSION")
    })))
}

async fn shell() -> Response {
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Frickmail</title>
</head>
<body>
  <main>
    <h1>Frickmail Rust migration server</h1>
    <p>The Rust backend is active. Mail UI/API migration is in progress.</p>
  </main>
</body>
</html>"#,
    )
        .into_response()
}

async fn root_get(
    State(state): State<AppState>,
    session: fm_session::Session,
    OriginalUri(uri): OriginalUri,
    request: AxumRequest,
) -> Response {
    if is_legacy_json_request(&uri) {
        return json_api_request(state, uri, request, session).await;
    }

    shell().await
}

async fn json_api(
    State(state): State<AppState>,
    session: fm_session::Session,
    OriginalUri(uri): OriginalUri,
    request: AxumRequest,
) -> Response {
    json_api_request(state, uri, request, session).await
}

async fn json_api_request(
    state: AppState,
    uri: Uri,
    request: AxumRequest,
    session: fm_session::Session,
) -> Response {
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let headers = parts.headers;
    let query = query_map(&uri);
    let body = match to_bytes(body, JSON_BODY_LIMIT_BYTES).await {
        Ok(body) => body,
        Err(err) => {
            return json_value_envelope(
                StatusCode::OK,
                "",
                compat_error(
                    INVALID_INPUT_ARGUMENT,
                    format!("Invalid or oversized request body: {err}"),
                ),
            )
        }
    };

    let request = match plugin_request_from_http(&query, &headers, &body, legacy_json_action(&uri))
    {
        Ok(request) => {
            if let Some(response) = bridge_json_request(
                &state,
                &method,
                &uri,
                &headers,
                body.clone(),
                &request.action,
            )
            .await
            {
                return response;
            }
            request
        }
        Err(error) => return json_value_envelope(StatusCode::OK, "", error),
    };

    let action = match normalize_plugin_action(&request.action) {
        Ok(action) => action.to_string(),
        Err(error) => {
            return json_value_envelope(
                StatusCode::OK,
                &request.action,
                compat_error(INVALID_INPUT_ARGUMENT, action_error_message(error)),
            )
        }
    };

    if is_compat_hook(&action) {
        if let Some(response) =
            native_compat_response(&state, &action, &request.action, &request.payload, &session)
                .await
        {
            return response;
        }

        let response = bridge_unimplemented(PluginRequest {
            action: action.clone(),
            payload: request.payload,
        });
        return json_value_envelope(StatusCode::OK, &request.action, response);
    }

    json_value_envelope(
        StatusCode::OK,
        &request.action,
        compat_error(
            UNKNOWN_ERROR,
            format!("Frickmail action '{}' is not registered", request.action),
        ),
    )
}

fn is_legacy_json_request(uri: &Uri) -> bool {
    uri.query()
        .is_some_and(|query| query.starts_with("/Json/") || query.starts_with("?/Json/"))
}

fn query_map(uri: &Uri) -> HashMap<String, String> {
    uri.query()
        .and_then(|query| serde_urlencoded::from_str(query).ok())
        .unwrap_or_default()
}

fn legacy_json_action(uri: &Uri) -> Option<String> {
    let query = uri.query()?;
    if !is_legacy_json_request(uri) {
        return None;
    }

    let action = query
        .split_once("/0/")
        .map(|(_, tail)| tail)
        .unwrap_or_default()
        .trim_start_matches('/');
    let action = action.split(['/', '&']).next().unwrap_or_default().trim();

    if action.is_empty() {
        None
    } else {
        Some(action.to_string())
    }
}

async fn fallback() -> Response {
    error_response(FrickmailError::NotFound("route".to_string()))
}

fn error_response(error: FrickmailError) -> Response {
    let status = error.status();
    let body = ErrorBody {
        result: false,
        error_message: error.public_message(),
    };
    (status, Json(body)).into_response()
}

async fn bridge_json_request(
    state: &AppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
    action: &str,
) -> Option<Response> {
    let bridge_url = state.config().php_bridge_url.as_deref()?;
    let target = match bridge_target_url(bridge_url, uri) {
        Ok(target) => target,
        Err(err) => {
            return Some(json_value_envelope(
                StatusCode::OK,
                action,
                compat_error(UNKNOWN_ERROR, format!("Invalid PHP bridge URL: {err}")),
            ))
        }
    };

    let response = state
        .bridge_client()
        .request(method.clone(), target)
        .headers(forward_headers(headers))
        .body(body)
        .send()
        .await;

    let response = match response {
        Ok(response) => response,
        Err(err) => {
            return Some(json_value_envelope(
                StatusCode::OK,
                action,
                compat_error(UNKNOWN_ERROR, format!("PHP bridge request failed: {err}")),
            ))
        }
    };

    let status = response.status();
    let content_type = response.headers().get(CONTENT_TYPE).cloned();
    let set_cookies = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(err) => {
            return Some(json_value_envelope(
                StatusCode::OK,
                action,
                compat_error(UNKNOWN_ERROR, format!("PHP bridge response failed: {err}")),
            ))
        }
    };

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    for cookie in set_cookies {
        builder = builder.header(SET_COOKIE, cookie);
    }

    Some(
        builder
            .body(axum::body::Body::from(body))
            .unwrap_or_else(|err| {
                json_value_envelope(
                    StatusCode::OK,
                    action,
                    compat_error(UNKNOWN_ERROR, format!("PHP bridge response failed: {err}")),
                )
            }),
    )
}

async fn native_compat_response(
    state: &AppState,
    action: &str,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Option<Response> {
    match action {
        "FrickmailMe" => Some(native_frickmail_me(state, original_action, session).await),
        "FrickmailGetPrefs" => {
            Some(native_frickmail_get_prefs(state, original_action, session).await)
        }
        "FrickmailSetPrefs" => {
            Some(native_frickmail_set_prefs(state, original_action, payload, session).await)
        }
        "FrickmailListAccounts" => {
            Some(native_frickmail_list_accounts(state, original_action, session).await)
        }
        "FrickmailListIdentities" => {
            Some(native_frickmail_list_identities(state, original_action, payload, session).await)
        }
        "FrickmailAddIdentity" => {
            Some(native_frickmail_add_identity(state, original_action, payload, session).await)
        }
        "FrickmailDeleteIdentity" => {
            Some(native_frickmail_delete_identity(state, original_action, payload, session).await)
        }
        "FrickmailSetDefaultIdentity" => Some(
            native_frickmail_set_default_identity(state, original_action, payload, session).await,
        ),
        "FrickmailListRules" => {
            Some(native_frickmail_list_rules(state, original_action, payload, session).await)
        }
        "FrickmailDeleteRule" => {
            Some(native_frickmail_delete_rule(state, original_action, payload, session).await)
        }
        "FrickmailToggleRule" => {
            Some(native_frickmail_toggle_rule(state, original_action, payload, session).await)
        }
        _ => None,
    }
}

async fn native_frickmail_me(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
) -> Response {
    let result = match load_session_user(state, original_action, session).await {
        Ok(Some(user_session)) => FrickmailMe::from_session(&user_session),
        Ok(None) => FrickmailMe::anonymous(),
        Err(response) => return response,
    };

    json_value_envelope(
        StatusCode::OK,
        original_action,
        json!({
            "Result": result
        }),
    )
}

async fn native_frickmail_get_prefs(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
) -> Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    match SqlxUserRepository::preferences(pool, user.user_id).await {
        Ok(Some(prefs)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "prefs": prefs
                }
            }),
        ),
        Ok(None) => json_result_error(original_action, "Not authenticated"),
        Err(err) => json_value_envelope(
            StatusCode::OK,
            original_action,
            compat_error(UNKNOWN_ERROR, err.public_message()),
        ),
    }
}

async fn native_frickmail_set_prefs(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let patch = payload.get("prefs").unwrap_or(&Value::Null);
    match SqlxUserRepository::update_preferences(pool, user.user_id, patch).await {
        Ok(Some(prefs)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "prefs": prefs
                }
            }),
        ),
        Ok(None) => json_result_error(original_action, "Not authenticated"),
        Err(err) => json_value_envelope(
            StatusCode::OK,
            original_action,
            compat_error(UNKNOWN_ERROR, err.public_message()),
        ),
    }
}

async fn native_frickmail_list_accounts(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
) -> Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    match SqlxUserRepository::list_mail_accounts(pool, user.user_id).await {
        Ok(accounts) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "accounts": accounts
                }
            }),
        ),
        Err(err) => json_value_envelope(
            StatusCode::OK,
            original_action,
            compat_error(UNKNOWN_ERROR, err.public_message()),
        ),
    }
}

async fn native_frickmail_list_identities(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let account_id = payload_i64(payload, "account_id");
    match SqlxUserRepository::list_mail_identities(pool, user.user_id, account_id).await {
        Ok(identities) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "identities": identities
                }
            }),
        ),
        Err(err) => json_value_envelope(
            StatusCode::OK,
            original_action,
            compat_error(UNKNOWN_ERROR, err.public_message()),
        ),
    }
}

async fn native_frickmail_add_identity(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let identity = NewMailIdentity {
        account_id: payload_i64(payload, "account_id"),
        name: payload_string(payload, "name").unwrap_or_default(),
        email: payload_string(payload, "email").unwrap_or_default(),
        reply_to: payload_optional_string(payload, "reply_to"),
        is_default: payload_bool(payload, "is_default"),
    };

    match SqlxUserRepository::add_mail_identity(pool, user.user_id, identity).await {
        Ok(id) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "id": id
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_delete_identity(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    match SqlxUserRepository::delete_mail_identity(pool, user.user_id, payload_i64(payload, "id"))
        .await
    {
        Ok(()) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_set_default_identity(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    match SqlxUserRepository::set_default_mail_identity(
        pool,
        user.user_id,
        payload_i64(payload, "id"),
    )
    .await
    {
        Ok(()) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_list_rules(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    match SqlxUserRepository::list_mail_rules(
        pool,
        user.user_id,
        payload_i64(payload, "account_id"),
    )
    .await
    {
        Ok(rules) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "rules": rules
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_delete_rule(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    match SqlxUserRepository::delete_mail_rule(pool, user.user_id, payload_i64(payload, "id")).await
    {
        Ok(()) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_toggle_rule(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    match SqlxUserRepository::toggle_mail_rule(
        pool,
        user.user_id,
        payload_i64(payload, "id"),
        payload_bool(payload, "enabled"),
    )
    .await
    {
        Ok(()) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn load_session_user(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
) -> std::result::Result<Option<fm_core::UserSession>, Response> {
    let user = session
        .get::<fm_core::UserSession>(fm_session::USER_SESSION_KEY)
        .await
        .map_err(|err| {
            json_value_envelope(
                StatusCode::OK,
                original_action,
                compat_error(
                    UNKNOWN_ERROR,
                    format!("Frickmail session read failed: {err}"),
                ),
            )
        })?;

    let Some(user_session) = user else {
        return Ok(None);
    };

    let Some(pool) = state.db_pool() else {
        return Ok(Some(user_session));
    };

    match SqlxUserRepository::find_by_id(pool, user_session.user_id).await {
        Ok(Some(user)) => Ok(Some(fm_core::UserSession {
            user_id: user.id,
            username: user.username,
            email: user.email,
        })),
        Ok(None) => {
            session
                .remove::<fm_core::UserSession>(fm_session::USER_SESSION_KEY)
                .await
                .map_err(|err| {
                    json_value_envelope(
                        StatusCode::OK,
                        original_action,
                        compat_error(
                            UNKNOWN_ERROR,
                            format!("Frickmail stale session cleanup failed: {err}"),
                        ),
                    )
                })?;
            Ok(None)
        }
        Err(err) => Err(json_value_envelope(
            StatusCode::OK,
            original_action,
            compat_error(UNKNOWN_ERROR, err.public_message()),
        )),
    }
}

fn json_result_error(action: &str, error: &str) -> Response {
    json_value_envelope(
        StatusCode::OK,
        action,
        json!({
            "Result": {
                "ok": false,
                "error": error
            }
        }),
    )
}

fn bridge_target_url(bridge_url: &str, uri: &Uri) -> Result<String, url::ParseError> {
    let mut target = url::Url::parse(bridge_url)?;
    target.set_query(uri.query());
    Ok(target.to_string())
}

fn forward_headers(headers: &HeaderMap) -> HeaderMap {
    let mut forwarded = HeaderMap::new();
    for name in [CONTENT_TYPE, COOKIE, AUTHORIZATION, ACCEPT, USER_AGENT] {
        if let Some(value) = headers.get(&name) {
            forwarded.insert(name, value.clone());
        }
    }
    if let Some(value) = headers.get("x-requested-with") {
        forwarded.insert("x-requested-with", value.clone());
    }
    if let Some(value) = headers.get("x-sm-token") {
        forwarded.insert("x-sm-token", value.clone());
    }
    if let Some(value) = headers.get("x-frickmail-session") {
        forwarded.insert("x-frickmail-session", value.clone());
    }
    forwarded
}

fn plugin_request_from_http(
    query: &HashMap<String, String>,
    headers: &HeaderMap,
    body: &[u8],
    legacy_action: Option<String>,
) -> Result<PluginRequest, Value> {
    let mut payload = map_to_value(query);
    let mut action = query
        .get("_action")
        .or_else(|| query.get("Action"))
        .cloned()
        .unwrap_or_default();

    if !body.is_empty() {
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        if content_type_contains(content_type, "multipart/form-data") {
            if action.is_empty() {
                action = multipart_action(content_type, body).unwrap_or_default();
            }
            payload = merge_payload(payload, body_metadata(content_type));
        } else {
            let body_payload = if content_type_contains(content_type, "application/json") {
                serde_json::from_slice::<Value>(body).map_err(|err| {
                    compat_error(INVALID_INPUT_ARGUMENT, format!("Invalid JSON body: {err}"))
                })?
            } else if content_type.is_empty()
                || content_type_contains(content_type, "application/x-www-form-urlencoded")
            {
                let form = serde_urlencoded::from_bytes::<HashMap<String, String>>(body).map_err(
                    |err| compat_error(INVALID_INPUT_ARGUMENT, format!("Invalid form body: {err}")),
                )?;
                map_to_value(&form)
            } else {
                body_metadata(content_type)
            };

            if action.is_empty() {
                action = body_payload
                    .get("_action")
                    .or_else(|| body_payload.get("Action"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
            }
            payload = merge_payload(payload, body_payload);
        }
    }

    if action.is_empty() {
        action = legacy_action.unwrap_or_default();
    }

    if action.is_empty() {
        return Err(compat_error(INVALID_INPUT_ARGUMENT, "Action unknown"));
    }

    Ok(PluginRequest { action, payload })
}

fn content_type_contains(content_type: &str, needle: &str) -> bool {
    content_type
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn multipart_action(content_type: &str, body: &[u8]) -> Option<String> {
    let boundary = multipart_boundary(content_type)?;
    let delimiter = format!("--{boundary}");
    let body = String::from_utf8_lossy(body);

    for part in body.split(&delimiter).skip(1) {
        if part.starts_with("--") {
            break;
        }

        let part = part
            .trim_start_matches("\r\n")
            .trim_start_matches('\n')
            .trim_end_matches("\r\n")
            .trim_end_matches('\n');
        let Some((headers, value)) = split_multipart_part(part) else {
            continue;
        };

        if multipart_field_name(headers)
            .is_some_and(|name| name.eq_ignore_ascii_case("Action") || name == "_action")
        {
            let action = value.trim();
            if !action.is_empty() {
                return Some(action.to_string());
            }
        }
    }

    None
}

fn multipart_boundary(content_type: &str) -> Option<String> {
    content_type.split(';').find_map(|segment| {
        let segment = segment.trim();
        let boundary = segment.strip_prefix("boundary=")?;
        Some(boundary.trim_matches('"').to_string())
    })
}

fn split_multipart_part(part: &str) -> Option<(&str, &str)> {
    part.split_once("\r\n\r\n")
        .or_else(|| part.split_once("\n\n"))
}

fn multipart_field_name(headers: &str) -> Option<&str> {
    headers
        .lines()
        .find(|line| {
            line.to_ascii_lowercase()
                .starts_with("content-disposition:")
        })
        .and_then(|line| {
            line.split(';').find_map(|attribute| {
                let attribute = attribute.trim();
                let name = attribute.strip_prefix("name=")?;
                Some(name.trim_matches('"'))
            })
        })
}

fn map_to_value(map: &HashMap<String, String>) -> Value {
    let mut object = Map::new();
    for (key, value) in map {
        object.insert(key.clone(), Value::String(value.clone()));
    }
    Value::Object(object)
}

fn body_metadata(content_type: &str) -> Value {
    let mut object = Map::new();
    object.insert(
        "_body_content_type".to_string(),
        Value::String(content_type.to_string()),
    );
    Value::Object(object)
}

fn merge_payload(mut left: Value, right: Value) -> Value {
    match (&mut left, right) {
        (Value::Object(left), Value::Object(right)) => {
            left.extend(right);
            Value::Object(left.clone())
        }
        (_, right) => right,
    }
}

fn compat_error(code: u16, message: impl Into<String>) -> Value {
    json!({
        "Result": false,
        "code": code,
        "message": message.into()
    })
}

fn payload_i64(payload: &Value, key: &str) -> i64 {
    match payload.get(key) {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| {
                number
                    .as_u64()
                    .map(|value| value.min(i64::MAX as u64) as i64)
            })
            .or_else(|| number.as_f64().map(|value| value as i64))
            .unwrap_or_default(),
        Some(Value::Bool(value)) => i64::from(*value),
        Some(Value::String(value)) => value.trim().parse::<i64>().unwrap_or_default(),
        _ => 0,
    }
}

fn payload_string(payload: &Value, key: &str) -> Option<String> {
    match payload.get(key) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        Some(Value::Bool(value)) => Some(if *value { "1" } else { "" }.to_string()),
        _ => None,
    }
}

fn payload_optional_string(payload: &Value, key: &str) -> Option<String> {
    payload_string(payload, key).and_then(|value| if value.is_empty() { None } else { Some(value) })
}

fn payload_bool(payload: &Value, key: &str) -> bool {
    match payload.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::Null) | None => false,
        Some(Value::Number(number)) => number.as_i64().unwrap_or_default() != 0,
        Some(Value::String(value)) => {
            let value = value.trim();
            !value.is_empty() && value != "0"
        }
        _ => true,
    }
}

fn action_error_message(error: ActionNameError) -> &'static str {
    match error {
        ActionNameError::Empty => "Action unknown",
        ActionNameError::DoublePluginPrefix => "Invalid plugin action prefix",
    }
}

fn json_value_envelope(status: StatusCode, action: &str, mut body: Value) -> Response {
    if let Value::Object(object) = &mut body {
        if !action.is_empty() {
            object
                .entry("Action")
                .or_insert_with(|| Value::String(action.to_string()));
        }
        object
            .entry("epoch")
            .or_insert_with(|| Value::from(current_epoch()));
    }
    (status, Json(body)).into_response()
}

fn current_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use axum::{
        body::{to_bytes, Body},
        extract::{Request as AxumRequest, State},
        http::{Method, Request, StatusCode, Uri},
        response::IntoResponse,
        routing::any,
        Json, Router,
    };
    use fm_core::{FrickmailConfig, UserSession};
    use fm_session::{MemoryStore, Session, USER_SESSION_KEY};
    use serde_json::{json, Value};
    use sqlx::{any::AnyPoolOptions, AnyPool};
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use super::{legacy_json_action, SqlxUserRepository, JSON_BODY_LIMIT_BYTES};
    use crate::{build_router, AppState};

    #[derive(Debug, Clone, Default)]
    struct BridgeCapture {
        method: String,
        uri: String,
        content_type: Option<String>,
        cookie: Option<String>,
        x_sm_token: Option<String>,
        body: String,
    }

    #[tokio::test]
    async fn root_get_serves_shell_for_non_json_requests() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Frickmail Rust migration server"));
    }

    #[tokio::test]
    async fn json_api_accepts_plugin_form_action() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("Action=PluginFrickmailMe&XToken=test"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["authenticated"], false);
        assert_eq!(body["Action"], "PluginFrickmailMe");
        assert!(body["epoch"].as_u64().is_some());
    }

    #[tokio::test]
    async fn json_api_accepts_query_action() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/?_action=FrickmailListAccounts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
        assert_eq!(body["Action"], "FrickmailListAccounts");
    }

    #[tokio::test]
    async fn json_api_accepts_legacy_json_url_shape() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/?/Json/&q[]=/0/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("Action=PluginFrickmailGetPrefs"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
        assert_eq!(body["Action"], "PluginFrickmailGetPrefs");
    }

    #[tokio::test]
    async fn json_api_extracts_legacy_get_action_without_bridge() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/?/Json/&q[]=/0/FrickmailMe/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["authenticated"], false);
        assert_eq!(body["Action"], "FrickmailMe");
    }

    #[tokio::test]
    async fn json_api_serves_native_frickmail_me_without_bridge() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("Action=PluginFrickmailMe"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["authenticated"], false);
        assert_eq!(body["Action"], "PluginFrickmailMe");
        assert!(body["epoch"].as_u64().is_some());
    }

    #[tokio::test]
    async fn native_frickmail_me_reloads_session_user_from_db() {
        let pool = user_db_pool().await;
        seed_user(&pool, 42, "fresh", Some("fresh@example.com")).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = test_session();
        session
            .insert(
                USER_SESSION_KEY,
                UserSession {
                    user_id: 42,
                    username: "stale".to_string(),
                    email: None,
                },
            )
            .await
            .unwrap();

        let response = super::native_frickmail_me(&state, "FrickmailMe", &session).await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["authenticated"], true);
        assert_eq!(body["Result"]["username"], "fresh");
        assert_eq!(body["Result"]["email"], "fresh@example.com");
    }

    #[tokio::test]
    async fn native_frickmail_me_clears_session_when_db_user_is_deleted() {
        let pool = user_db_pool().await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = test_session();
        session
            .insert(
                USER_SESSION_KEY,
                UserSession {
                    user_id: 404,
                    username: "deleted".to_string(),
                    email: Some("deleted@example.com".to_string()),
                },
            )
            .await
            .unwrap();

        let response = super::native_frickmail_me(&state, "FrickmailMe", &session).await;
        let body = read_json(response).await;
        let session_user = session.get::<UserSession>(USER_SESSION_KEY).await.unwrap();

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["authenticated"], false);
        assert!(session_user.is_none());
    }

    #[tokio::test]
    async fn native_frickmail_get_prefs_reads_existing_settings() {
        let pool = user_db_pool().await;
        seed_user_with_settings(
            &pool,
            43,
            "prefs",
            Some("prefs@example.com"),
            json!({"tasks_default_tab":"pending","unified_inbox_limit":80}),
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(43, "stale", None).await;

        let response =
            super::native_frickmail_get_prefs(&state, "FrickmailGetPrefs", &session).await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["prefs"]["tasks_default_tab"], "pending");
        assert_eq!(body["Result"]["prefs"]["unified_inbox_limit"], 80);
        assert_eq!(body["Result"]["prefs"]["notifications_poll_interval"], 60);
    }

    #[tokio::test]
    async fn native_frickmail_set_prefs_validates_and_persists_patch() {
        let pool = user_db_pool().await;
        seed_user_with_settings(
            &pool,
            44,
            "prefs-set",
            Some("prefs-set@example.com"),
            json!({"tasks_default_tab":"pending","custom":"preserve"}),
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(44, "prefs-set", None).await;

        let response = super::native_frickmail_set_prefs(
            &state,
            "FrickmailSetPrefs",
            &json!({
                "prefs": {
                    "notifications_poll_interval": 5,
                    "smime_auto_sign": "0",
                    "tasks_default_tab": "invalid",
                    "notifications_accounts": ["1", "bad", 3],
                    "unknown": true
                }
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        let user = SqlxUserRepository::find_by_id(&pool, 44)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["prefs"]["notifications_poll_interval"], 30);
        assert_eq!(body["Result"]["prefs"]["smime_auto_sign"], false);
        assert_eq!(body["Result"]["prefs"]["tasks_default_tab"], "pending");
        assert_eq!(
            body["Result"]["prefs"]["notifications_accounts"],
            json!([1, 0, 3])
        );
        assert_eq!(user.settings["custom"], "preserve");
        assert!(user.settings.get("unknown").is_none());
    }

    #[tokio::test]
    async fn native_frickmail_list_accounts_returns_safe_account_metadata() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 45, "accounts", Some("accounts@example.com")).await;
        seed_mail_account(&pool, 300, 45, "Primary", true).await;
        seed_mail_account(&pool, 301, 45, "Secondary", false).await;
        seed_identity(&pool, 400, 45, 300, "Sender", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(45, "accounts", None).await;

        let response =
            super::native_frickmail_list_accounts(&state, "FrickmailListAccounts", &session).await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["accounts"].as_array().unwrap().len(), 2);
        assert_eq!(body["Result"]["accounts"][0]["id"], 300);
        assert_eq!(body["Result"]["accounts"][0]["label"], "Primary");
        assert_eq!(
            body["Result"]["accounts"][0]["email"],
            "primary@example.com"
        );
        assert_eq!(body["Result"]["accounts"][0]["type"], "imap");
        assert_eq!(body["Result"]["accounts"][0]["is_primary"], true);
        assert_eq!(body["Result"]["accounts"][0]["identities"][0]["id"], 400);
        assert!(body["Result"]["accounts"][0]
            .get("encrypted_password")
            .is_none());
        assert!(body["Result"]["accounts"][0]
            .get("encrypted_oauth_refresh_token")
            .is_none());
    }

    #[tokio::test]
    async fn native_frickmail_list_identities_returns_account_scoped_identities() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 46, "identities", Some("identities@example.com")).await;
        seed_mail_account(&pool, 310, 46, "Primary", true).await;
        seed_mail_account(&pool, 311, 46, "Secondary", false).await;
        seed_identity(&pool, 410, 46, 310, "Default", true).await;
        seed_identity(&pool, 411, 46, 310, "Alias", false).await;
        seed_identity(&pool, 412, 46, 311, "Other", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(46, "identities", None).await;

        let response = super::native_frickmail_list_identities(
            &state,
            "FrickmailListIdentities",
            &json!({"account_id": 310}),
            &session,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["identities"].as_array().unwrap().len(), 2);
        assert_eq!(body["Result"]["identities"][0]["id"], 410);
        assert_eq!(body["Result"]["identities"][0]["account_id"], 310);
        assert_eq!(body["Result"]["identities"][0]["is_default"], true);
        assert_eq!(body["Result"]["identities"][1]["id"], 411);
        assert_eq!(body["Action"], "FrickmailListIdentities");
    }

    #[tokio::test]
    async fn native_frickmail_identity_mutations_match_plugin_shape() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(
            &pool,
            47,
            "identity-writes",
            Some("identity-writes@example.com"),
        )
        .await;
        seed_mail_account(&pool, 320, 47, "Primary", true).await;
        seed_identity(&pool, 420, 47, 320, "Default", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(47, "identity-writes", None).await;

        let response = super::native_frickmail_add_identity(
            &state,
            "FrickmailAddIdentity",
            &json!({
                "account_id": 320,
                "name": " Alias ",
                "email": "alias@example.com",
                "reply_to": " reply@example.com ",
                "is_default": true
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        let id = body["Result"]["id"].as_i64().unwrap();
        assert_eq!(body["Result"]["ok"], true);

        let response = super::native_frickmail_list_identities(
            &state,
            "FrickmailListIdentities",
            &json!({"account_id": 320}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["identities"][0]["id"], id);
        assert_eq!(body["Result"]["identities"][0]["name"], "Alias");
        assert_eq!(
            body["Result"]["identities"][0]["reply_to"],
            "reply@example.com"
        );
        assert_eq!(body["Result"]["identities"][0]["is_default"], true);
        assert_eq!(body["Result"]["identities"][1]["id"], 420);
        assert_eq!(body["Result"]["identities"][1]["is_default"], false);

        let response = super::native_frickmail_set_default_identity(
            &state,
            "FrickmailSetDefaultIdentity",
            &json!({"id": 420}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);

        let response = super::native_frickmail_delete_identity(
            &state,
            "FrickmailDeleteIdentity",
            &json!({"id": id}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);

        let response = super::native_frickmail_list_identities(
            &state,
            "FrickmailListIdentities",
            &json!({"account_id": 320}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["identities"].as_array().unwrap().len(), 1);
        assert_eq!(body["Result"]["identities"][0]["id"], 420);
        assert_eq!(body["Result"]["identities"][0]["is_default"], true);
    }

    #[tokio::test]
    async fn native_frickmail_rule_list_toggle_delete_match_plugin_shape() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_mail_rule_tables(&pool).await;
        seed_user(&pool, 48, "rules", Some("rules@example.com")).await;
        seed_mail_account(&pool, 330, 48, "Primary", true).await;
        seed_mail_rule(&pool, 430, 48, 330, "Move newsletters", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(48, "rules", None).await;

        let response = super::native_frickmail_list_rules(
            &state,
            "FrickmailListRules",
            &json!({"account_id": 330}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["rules"].as_array().unwrap().len(), 1);
        assert_eq!(body["Result"]["rules"][0]["id"], 430);
        assert_eq!(body["Result"]["rules"][0]["enabled"], true);
        assert_eq!(body["Result"]["rules"][0]["conditions_logic"], "all");
        assert_eq!(body["Result"]["rules"][0]["conditions"][0]["field"], "from");
        assert_eq!(body["Result"]["rules"][0]["actions"][0]["type"], "move");

        let response = super::native_frickmail_toggle_rule(
            &state,
            "FrickmailToggleRule",
            &json!({"id": 430, "enabled": "0"}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);

        let response = super::native_frickmail_list_rules(
            &state,
            "FrickmailListRules",
            &json!({"account_id": 330}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["rules"][0]["enabled"], false);

        let response = super::native_frickmail_delete_rule(
            &state,
            "FrickmailDeleteRule",
            &json!({"id": 430}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);

        let response = super::native_frickmail_list_rules(
            &state,
            "FrickmailListRules",
            &json!({"account_id": 330}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert!(body["Result"]["rules"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn json_api_reports_unknown_action_without_transport_failure() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"Action":"PluginDoesNotExist"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 999);
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("PluginDoesNotExist"));
        assert_eq!(body["Action"], "PluginDoesNotExist");
    }

    #[tokio::test]
    async fn json_api_rejects_double_plugin_prefix_once() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("Action=PluginPluginFrickmailMe"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 903);
        assert_eq!(body["Action"], "PluginPluginFrickmailMe");
    }

    #[tokio::test]
    async fn json_api_accepts_multipart_action_field() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "multipart/form-data; boundary=frickmail")
                    .body(Body::from(
                        "--frickmail\r\n\
                         Content-Disposition: form-data; name=\"Action\"\r\n\
                         \r\n\
                         PluginJsonAdminRestoreData\r\n\
                         --frickmail\r\n\
                         Content-Disposition: form-data; name=\"backup\"; filename=\"backup.json\"\r\n\
                         Content-Type: application/json\r\n\
                         \r\n\
                         {}\r\n\
                         --frickmail--\r\n",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 501);
        assert_eq!(body["Action"], "PluginJsonAdminRestoreData");
    }

    #[tokio::test]
    async fn json_api_keeps_multipart_without_action_in_json_envelope() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "multipart/form-data; boundary=frickmail")
                    .body(Body::from(
                        "--frickmail\r\n\
                         Content-Disposition: form-data; name=\"backup\"; filename=\"backup.json\"\r\n\
                         Content-Type: application/json\r\n\
                         \r\n\
                         {}\r\n\
                         --frickmail--\r\n",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 903);
        assert_eq!(body["message"], "Action unknown");
    }

    #[tokio::test]
    async fn json_api_forwards_to_php_bridge_when_configured() {
        let (bridge_url, capture) = spawn_bridge().await;

        let response = app_with_bridge(bridge_url)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/?/Json/&q[]=/0/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", "FrickmailAuth=abc")
                    .header("x-sm-token", "csrf-token")
                    .body(Body::from("Action=PluginFrickmailMe&XToken=test"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("set-cookie")
                .and_then(|value| value.to_str().ok()),
            Some("FrickmailAuth=bridge; Path=/; HttpOnly")
        );
        let body = read_json(response).await;
        assert_eq!(body["Result"]["bridge"], true);
        assert_eq!(body["Action"], "PluginFrickmailMe");

        let capture = capture.lock().unwrap().clone();
        assert_eq!(capture.method, "POST");
        assert_eq!(capture.uri, "/?/Json/&q[]=/0/");
        assert_eq!(
            capture.content_type.as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(capture.cookie.as_deref(), Some("FrickmailAuth=abc"));
        assert_eq!(capture.x_sm_token.as_deref(), Some("csrf-token"));
        assert_eq!(capture.body, "Action=PluginFrickmailMe&XToken=test");
    }

    #[tokio::test]
    async fn json_api_forwards_legacy_get_to_php_bridge_when_configured() {
        let (bridge_url, capture) = spawn_bridge().await;

        let response = app_with_bridge(bridge_url)
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/?/Json/&q[]=/0/MessageList/&q[]=/payload")
                    .header("x-sm-token", "csrf-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"]["bridge"], true);
        assert_eq!(body["Action"], "MessageList");

        let capture = capture.lock().unwrap().clone();
        assert_eq!(capture.method, "GET");
        assert_eq!(capture.uri, "/?/Json/&q[]=/0/MessageList/&q[]=/payload");
        assert_eq!(capture.x_sm_token.as_deref(), Some("csrf-token"));
    }

    #[tokio::test]
    async fn json_api_forwards_multipart_to_php_bridge_when_configured() {
        let (bridge_url, capture) = spawn_bridge().await;
        let body = "--frickmail\r\n\
                    Content-Disposition: form-data; name=\"Action\"\r\n\
                    \r\n\
                    PluginJsonAdminRestoreData\r\n\
                    --frickmail\r\n\
                    Content-Disposition: form-data; name=\"backup\"; filename=\"backup.json\"\r\n\
                    Content-Type: application/json\r\n\
                    \r\n\
                    {}\r\n\
                    --frickmail--\r\n";

        let response = app_with_bridge(bridge_url)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "multipart/form-data; boundary=frickmail")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"]["bridge"], true);
        assert_eq!(body["Action"], "PluginJsonAdminRestoreData");

        let capture = capture.lock().unwrap().clone();
        assert_eq!(
            capture.content_type.as_deref(),
            Some("multipart/form-data; boundary=frickmail")
        );
        assert!(capture.body.contains("PluginJsonAdminRestoreData"));
    }

    #[tokio::test]
    async fn json_api_forwards_large_multipart_to_php_bridge() {
        let (bridge_url, capture) = spawn_bridge().await;
        let large_payload = "x".repeat(2 * 1024 * 1024 + 1);
        let body = format!(
            "--frickmail\r\n\
             Content-Disposition: form-data; name=\"Action\"\r\n\
             \r\n\
             PluginJsonAdminRestoreData\r\n\
             --frickmail\r\n\
             Content-Disposition: form-data; name=\"backup\"; filename=\"large.json\"\r\n\
             Content-Type: application/json\r\n\
             \r\n\
             {large_payload}\r\n\
             --frickmail--\r\n"
        );

        let response = app_with_bridge(bridge_url)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "multipart/form-data; boundary=frickmail")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"]["bridge"], true);
        assert_eq!(body["Action"], "PluginJsonAdminRestoreData");

        let capture = capture.lock().unwrap().clone();
        assert!(capture.body.len() > 2 * 1024 * 1024);
    }

    #[tokio::test]
    async fn json_api_reports_php_bridge_connection_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bridge_url = format!("http://{}/", listener.local_addr().unwrap());
        drop(listener);

        let response = app_with_bridge(Some(bridge_url))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("Action=PluginFrickmailMe"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 999);
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("PHP bridge request failed"));
        assert_eq!(body["Action"], "PluginFrickmailMe");
    }

    fn app() -> axum::Router {
        app_with_bridge(None)
    }

    fn app_with_bridge(php_bridge_url: Option<String>) -> axum::Router {
        build_router(AppState::new(test_config(php_bridge_url)))
    }

    fn test_config(php_bridge_url: Option<String>) -> FrickmailConfig {
        FrickmailConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            base_url: "http://localhost:8888".to_string(),
            static_root: "/workspace/frickmail-static".to_string(),
            php_bridge_url,
            database_url: None,
            redis_url: "redis://redis:6379/0".to_string(),
            oidc: Default::default(),
            mail: Default::default(),
        }
    }

    fn test_session() -> Session {
        Session::new(None, Arc::new(MemoryStore::default()), None)
    }

    async fn authenticated_session(user_id: i64, username: &str, email: Option<&str>) -> Session {
        let session = test_session();
        session
            .insert(
                USER_SESSION_KEY,
                UserSession {
                    user_id,
                    username: username.to_string(),
                    email: email.map(ToOwned::to_owned),
                },
            )
            .await
            .unwrap();
        session
    }

    async fn user_db_pool() -> AnyPool {
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::query(
            "CREATE TABLE frickmail_users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT,
                password_hash TEXT NOT NULL,
                kdf_salt BLOB NOT NULL,
                settings TEXT NOT NULL,
                totp_secret TEXT,
                oidc_escrow_key BLOB,
                updated_at TEXT
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    async fn create_mail_account_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_mail_accounts (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                email TEXT NOT NULL,
                type TEXT NOT NULL,
                imap_host TEXT,
                imap_port INTEGER,
                imap_secure TEXT,
                smtp_host TEXT,
                smtp_port INTEGER,
                smtp_secure TEXT,
                login TEXT,
                encrypted_password BLOB,
                encrypted_oauth_refresh_token BLOB,
                oauth_tenant TEXT,
                is_primary BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TEXT,
                updated_at TEXT
            )",
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "CREATE TABLE frickmail_identities (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                reply_to TEXT,
                is_default BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TEXT
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_mail_rule_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_rules (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                conditions TEXT NOT NULL,
                actions TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                last_run TEXT,
                created_at TEXT,
                updated_at TEXT
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_user(pool: &AnyPool, id: i64, username: &str, email: Option<&str>) {
        seed_user_with_settings(pool, id, username, email, json!({})).await;
    }

    async fn seed_user_with_settings(
        pool: &AnyPool,
        id: i64,
        username: &str,
        email: Option<&str>,
        settings: Value,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_users
                (id, username, email, password_hash, kdf_salt, settings, totp_secret, oidc_escrow_key, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(username)
        .bind(email.map(ToOwned::to_owned))
        .bind("$argon2id$v=19$m=65536,t=3,p=1$placeholder")
        .bind(vec![1_u8, 2, 3, 4])
        .bind(settings.to_string())
        .bind(None::<String>)
        .bind(None::<Vec<u8>>)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_mail_account(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        label: &str,
        is_primary: bool,
    ) {
        let local = label.to_ascii_lowercase();
        sqlx::query(
            "INSERT INTO frickmail_mail_accounts
                (id, user_id, label, email, type, imap_host, imap_port, imap_secure,
                 smtp_host, smtp_port, smtp_secure, login, encrypted_password,
                 encrypted_oauth_refresh_token, oauth_tenant, is_primary, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(user_id)
        .bind(label)
        .bind(format!("{local}@example.com"))
        .bind("imap")
        .bind("imap.example.com")
        .bind(993_i64)
        .bind("SSL")
        .bind("smtp.example.com")
        .bind(465_i64)
        .bind("SSL")
        .bind(format!("{local}@example.com"))
        .bind(vec![1_u8, 2, 3])
        .bind(None::<Vec<u8>>)
        .bind(None::<String>)
        .bind(is_primary)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_identity(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        account_id: i64,
        name: &str,
        is_default: bool,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_identities
                (id, account_id, user_id, name, email, reply_to, is_default, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(account_id)
        .bind(user_id)
        .bind(name)
        .bind(format!("{}@example.com", name.to_ascii_lowercase()))
        .bind(None::<String>)
        .bind(is_default)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_mail_rule(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        account_id: i64,
        name: &str,
        enabled: bool,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_rules
                (id, user_id, account_id, name, conditions, actions, enabled, last_run, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(user_id)
        .bind(account_id)
        .bind(name)
        .bind(json!({
            "conditions": [
                {"field": "from", "op": "contains", "value": "newsletter"}
            ],
            "conditions_logic": "all"
        }).to_string())
        .bind(json!([
            {"type": "move", "params": {"folder": "Newsletters"}}
        ]).to_string())
        .bind(enabled)
        .bind(None::<String>)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn spawn_bridge() -> (Option<String>, Arc<Mutex<BridgeCapture>>) {
        let capture = Arc::new(Mutex::new(BridgeCapture::default()));
        let app = Router::new()
            .route("/", any(capture_bridge_request))
            .with_state(capture.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (Some(format!("http://{addr}/")), capture)
    }

    async fn capture_bridge_request(
        State(capture): State<Arc<Mutex<BridgeCapture>>>,
        uri: Uri,
        request: AxumRequest,
    ) -> impl IntoResponse {
        let (parts, body) = request.into_parts();
        let headers = parts.headers;
        let body = to_bytes(body, JSON_BODY_LIMIT_BYTES).await.unwrap();

        *capture.lock().unwrap() = BridgeCapture {
            method: parts.method.to_string(),
            uri: uri.to_string(),
            content_type: headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            cookie: headers
                .get("cookie")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            x_sm_token: headers
                .get("x-sm-token")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            body: String::from_utf8_lossy(&body).to_string(),
        };

        (
            [("set-cookie", "FrickmailAuth=bridge; Path=/; HttpOnly")],
            Json(json!({
                "Result": {
                    "bridge": true
                },
                "Action": form_action(&body)
                    .or_else(|| legacy_json_action(&uri))
                    .unwrap_or_default()
            })),
        )
    }

    fn form_action(body: &[u8]) -> Option<String> {
        serde_urlencoded::from_bytes::<HashMap<String, String>>(body)
            .ok()
            .and_then(|form| form.get("Action").cloned())
            .or_else(|| {
                String::from_utf8_lossy(body)
                    .lines()
                    .find(|line| line.trim_start().starts_with("Plugin"))
                    .map(|line| line.trim().to_string())
            })
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }
}
