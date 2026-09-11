//! Stable Rust-owned API under `/api/frickmail/v1` (Phase 9).
//!
//! Framework-agnostic JSON over real HTTP status codes, replacing the legacy
//! `/?/Json/` dispatcher (HTTP 200 envelopes with numeric codes) screen by
//! screen. Contract rules for this tree:
//!
//! - Success is `{"version":"v1","data":…}` with HTTP 200.
//! - Failure is `{"version":"v1","error":{"code":…,"message":…}}` with a
//!   matching HTTP status (401 unauthenticated, 404 unknown path, …).
//! - Additive fields never bump the version; breaking changes do.
//! - Only safe (GET/HEAD) routes exist so far, so no connection-token CSRF
//!   check applies here. The first state-changing route must enforce the
//!   same token contract as the legacy dispatcher.
//! - Authentication reuses the `FrickmailSession` cookie session; nothing
//!   here mints or rotates session state.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde_json::json;

use crate::AppState;
use fm_core::{ApiV1Envelope, ApiV1Error, UserSession};

/// Routes served under `/api/frickmail/v1`. Takes the shared `AppState` so
/// the mount in `build_router_with_session` stays a one-liner.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/session", get(session))
        .fallback(unknown_path)
        .method_not_allowed_fallback(v1_method_not_allowed)
}

async fn health() -> Json<ApiV1Envelope<serde_json::Value>> {
    Json(ApiV1Envelope::ok(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

/// Returns the currently authenticated session user, if any. Reads session
/// state only: an absent or unreadable session is a 401/500, never a login
/// attempt and never a mutation.
async fn session(session: fm_session::Session) -> Response {
    let stored = match session
        .get::<UserSession>(fm_session::USER_SESSION_KEY)
        .await
    {
        Ok(stored) => stored,
        Err(_) => {
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "session_error",
                "Frickmail session read failed",
            )
        }
    };
    let Some(user) = stored else {
        return v1_error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "No authenticated Frickmail session",
        );
    };
    (
        StatusCode::OK,
        Json(ApiV1Envelope::ok(json!({
            "authenticated": true,
            "user": {
                "id": user.user_id,
                "username": user.username,
                "email": user.email,
            },
        }))),
    )
        .into_response()
}

async fn unknown_path() -> Response {
    v1_error(
        StatusCode::NOT_FOUND,
        "not_found",
        "Unknown /api/frickmail/v1 path",
    )
}

async fn v1_method_not_allowed() -> Response {
    v1_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "Only safe methods are served by /api/frickmail/v1 so far",
    )
}

fn v1_error(status: StatusCode, code: &'static str, message: &str) -> Response {
    (status, Json(ApiV1Error::new(code, message))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use tower::ServiceExt;

    use crate::AppState;
    use fm_core::FrickmailConfig;

    fn api_app() -> Router {
        Router::new()
            .nest("/api/frickmail/v1", super::routes())
            .layer(fm_session::session_layer(
                fm_session::AppSessionStore::Memory(fm_session::MemoryStore::default()),
            ))
            .with_state(AppState::new(test_api_config()))
    }

    fn test_api_config() -> FrickmailConfig {
        FrickmailConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            base_url: "http://localhost:8888".to_string(),
            static_root: "/workspace/frickmail-static".to_string(),
            tmp_dir: "/tmp/frickmail-api-v1".to_string(),
            php_bridge_url: None,
            database_url: None,
            redis_url: "redis://redis:6379/0".to_string(),
            app_salt: Some("test-app-salt-for-api-v1".to_string()),
            open_signup: false,
            oidc: Default::default(),
            oauth2: Default::default(),
            mail: Default::default(),
            cache: Default::default(),
            frickmail_user: Default::default(),
            transactional_smtp: Default::default(),
            hibp: Default::default(),
            demo_account: Default::default(),
            change_password: Default::default(),
            private_data_dir: None,
            admin: Default::default(),
            security: Default::default(),
        }
    }

    async fn read_json(response: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn v1_health_reports_versioned_ok() {
        let body = read_json(
            api_app()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/api/frickmail/v1/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;

        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["status"], "ok");
        assert!(body["data"]["version"].is_string());
        assert!(body.get("error").is_none());
    }

    #[tokio::test]
    async fn v1_session_rejects_anonymous_callers() {
        let response = api_app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["error"]["code"], "unauthenticated");
    }

    #[tokio::test]
    async fn v1_unknown_paths_return_json_not_found() {
        let response = api_app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["error"]["code"], "not_found");
    }

    #[tokio::test]
    async fn v1_wrong_method_returns_json_envelope() {
        let response = api_app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["error"]["code"], "method_not_allowed");
    }
}
