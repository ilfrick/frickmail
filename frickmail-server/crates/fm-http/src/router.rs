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
use fm_user::{FrickmailMe, SqlxUserRepository};
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
            native_compat_response(&state, &action, &request.action, &session).await
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
    session: &fm_session::Session,
) -> Option<Response> {
    match action {
        "FrickmailMe" => Some(native_frickmail_me(state, original_action, session).await),
        _ => None,
    }
}

async fn native_frickmail_me(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
) -> Response {
    let user = match session
        .get::<fm_core::UserSession>(fm_session::USER_SESSION_KEY)
        .await
    {
        Ok(user) => user,
        Err(err) => {
            return json_value_envelope(
                StatusCode::OK,
                original_action,
                compat_error(
                    UNKNOWN_ERROR,
                    format!("Frickmail session read failed: {err}"),
                ),
            )
        }
    };

    let result = match user {
        Some(user_session) => {
            if let Some(pool) = state.db_pool() {
                match SqlxUserRepository::find_by_id(pool, user_session.user_id).await {
                    Ok(Some(user)) => FrickmailMe::from_user(&user),
                    Ok(None) => {
                        if let Err(err) = session
                            .remove::<fm_core::UserSession>(fm_session::USER_SESSION_KEY)
                            .await
                        {
                            return json_value_envelope(
                                StatusCode::OK,
                                original_action,
                                compat_error(
                                    UNKNOWN_ERROR,
                                    format!("Frickmail stale session cleanup failed: {err}"),
                                ),
                            );
                        }
                        FrickmailMe::anonymous()
                    }
                    Err(err) => {
                        return json_value_envelope(
                            StatusCode::OK,
                            original_action,
                            compat_error(UNKNOWN_ERROR, err.public_message()),
                        )
                    }
                }
            } else {
                FrickmailMe::from_session(&user_session)
            }
        }
        None => FrickmailMe::anonymous(),
    };

    json_value_envelope(
        StatusCode::OK,
        original_action,
        json!({
            "Result": result
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

    use super::{legacy_json_action, JSON_BODY_LIMIT_BYTES};
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
        assert_eq!(body["code"], 501);
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
        assert_eq!(body["code"], 501);
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
                oidc_escrow_key BLOB
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    async fn seed_user(pool: &AnyPool, id: i64, username: &str, email: Option<&str>) {
        sqlx::query(
            "INSERT INTO frickmail_users
                (id, username, email, password_hash, kdf_salt, settings, totp_secret, oidc_escrow_key)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(username)
        .bind(email.map(ToOwned::to_owned))
        .bind("$argon2id$v=19$m=65536,t=3,p=1$placeholder")
        .bind(vec![1_u8, 2, 3, 4])
        .bind("{}")
        .bind(None::<String>)
        .bind(None::<Vec<u8>>)
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
