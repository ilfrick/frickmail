use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use fm_core::{ApiEnvelope, ErrorBody, FrickmailError, HealthResponse};
use serde_json::json;
use tower::ServiceBuilder;
use tower_http::{compression::CompressionLayer, services::ServeDir, trace::TraceLayer};

use crate::AppState;

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

async fn json_api() -> Response {
    error_response(not_implemented("Frickmail JSON API dispatcher"))
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
