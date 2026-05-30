use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::State,
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use fm_core::{plugin::PluginRequest, ApiEnvelope, ErrorBody, FrickmailError, HealthResponse};
use fm_plugin_compat::{
    bridge_unimplemented, is_compat_hook, normalize_plugin_action, ActionNameError,
};
use serde_json::{json, Map, Value};
use tower::ServiceBuilder;
use tower_http::{compression::CompressionLayer, services::ServeDir, trace::TraceLayer};

use crate::AppState;

const INVALID_INPUT_ARGUMENT: u16 = 903;
const UNKNOWN_ERROR: u16 = 999;

pub fn build_router(state: AppState) -> Router {
    let static_root = state.config().static_root.clone();

    Router::new()
        .route("/", get(shell).post(json_api))
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

async fn shell(State(state): State<AppState>) -> Response {
    if state.config().php_bridge_url.is_some() {
        return error_response(not_implemented(
            "PHP bridge proxy is declared but not implemented in this slice",
        ));
    }

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

async fn json_api(
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request = match plugin_request_from_http(&query, &headers, &body) {
        Ok(request) => request,
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

async fn fallback() -> Response {
    error_response(FrickmailError::NotFound("route".to_string()))
}

fn not_implemented(feature: &'static str) -> FrickmailError {
    FrickmailError::NotImplemented(feature)
}

fn error_response(error: FrickmailError) -> Response {
    let status = error.status();
    let body = ErrorBody {
        result: false,
        error_message: error.public_message(),
    };
    (status, Json(body)).into_response()
}

fn plugin_request_from_http(
    query: &HashMap<String, String>,
    headers: &HeaderMap,
    body: &[u8],
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
    use axum::{
        body::{to_bytes, Body},
        http::{Method, Request, StatusCode},
    };
    use fm_core::FrickmailConfig;
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::{build_router, AppState};

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
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 501);
        assert!(body["message"].as_str().unwrap().contains("FrickmailMe"));
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

    fn app() -> axum::Router {
        let config = FrickmailConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            base_url: "http://localhost:8888".to_string(),
            static_root: "/workspace/frickmail-static".to_string(),
            php_bridge_url: None,
            database_url: None,
            redis_url: "redis://redis:6379/0".to_string(),
            oidc: Default::default(),
            mail: Default::default(),
        };
        build_router(AppState::new(config))
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }
}
