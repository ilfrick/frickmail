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
//! - Authentication reuses the `FrickmailSession` cookie session. The login
//!   route always requires the connection token via the `X-SM-Token` header
//!   (header-only by design; the legacy `XToken` form field stays on the old
//!   dispatcher), bootstrapped from anonymous `GET /session` exactly like
//!   legacy AppData. Request bodies are strict JSON: unlike the legacy
//!   dispatcher, numbers/bools are not coerced to strings.
//!
//! Intentional deviation from legacy `FrickmailLogin`: no mail-account
//! bridge probing happens here. v1 separates authentication (this route)
//! from account validation (account routes read the stored credential key
//! on first use).

use axum::{
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::json;

use super::NativeLoginOutcome;
use super::{
    constant_time_equal, expected_connection_token, native_login_authenticate,
    native_login_establish_session,
};
use crate::AppState;
use fm_core::{ApiV1Envelope, ApiV1Error, UserSession};

/// Routes served under `/api/frickmail/v1`. Takes the shared `AppState` so
/// the mount in `build_router_with_session` stays a one-liner.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/session", get(session))
        .route("/login", post(login))
        .route("/accounts", get(accounts))
        .fallback(unknown_path)
        .method_not_allowed_fallback(v1_method_not_allowed)
}

async fn health() -> Json<ApiV1Envelope<serde_json::Value>> {
    Json(ApiV1Envelope::ok(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

/// Returns the currently authenticated session user, if any.
///
/// Anonymous callers additionally receive the bootstrapped `csrf_token` they
/// must echo back on `POST /login` (mirroring legacy AppData, which mints
/// the token secret on bootstrap). Authenticated callers receive the token
/// for their current scope, read without mutating session state. A store
/// failure is a 500, never a login attempt and never a user mutation.
async fn session(state: axum::extract::State<AppState>, session: fm_session::Session) -> Response {
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
        let token = match super::ensure_connection_token(&state, &session, None).await {
            Ok(token) => token,
            Err(_) => {
                return v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session_error",
                    "Frickmail session write failed",
                );
            }
        };
        return (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({
                "authenticated": false,
                "csrf_token": token,
            }))),
        )
            .into_response();
    };
    let mut data = json!({
        "authenticated": true,
        "user": {
            "id": user.user_id,
            "username": user.username,
            "email": user.email,
        },
    });
    if let Ok(Some(token)) = super::expected_connection_token(&session).await {
        data["csrf_token"] = json!(token);
    }
    (StatusCode::OK, Json(ApiV1Envelope::ok(data))).into_response()
}

async fn unknown_path() -> Response {
    v1_error(
        StatusCode::NOT_FOUND,
        "not_found",
        "Unknown /api/frickmail/v1 path",
    )
}

/// Lists the authenticated user's mail accounts with safe metadata and
/// inline identities, reusing the exact repository query as legacy
/// `FrickmailListAccounts`. The returned `MailAccount` shape carries no
/// secrets by construction (passwords and tokens live in the separate
/// `MailAccountConnectionSecret` type, which is never serialized here).
async fn accounts(state: axum::extract::State<AppState>, session: fm_session::Session) -> Response {
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
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    match fm_user::SqlxUserRepository::list_mail_accounts(pool, user.user_id).await {
        Ok(accounts) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "accounts": accounts }))),
        )
            .into_response(),
        Err(err) => {
            tracing::warn!("v1 accounts listing failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail accounts listing failed",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    totp_code: Option<String>,
}

/// Authenticates with username/password (+TOTP when the account requires it)
/// through the exact core shared with legacy `FrickmailLogin`, then rotates
/// the session id and stores the user session plus credential key.
///
/// Unknown users and wrong passwords are indistinguishable (401
/// `invalid_credentials` either way: dummy-hash comparison, no enumeration).
/// TOTP-gated accounts without a valid code get HTTP 200 with
/// `requires_totp` — possession of valid primary credentials is not an
/// error. No mail-account bridge probing happens here by design.
async fn login(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Response {
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid login request",
        );
    };

    if let Err(response) = v1_login_csrf(&state, &session, &headers).await {
        return response;
    }

    let outcome = match native_login_authenticate(
        pool,
        &request.username,
        &request.password,
        request.totp_code.as_deref().unwrap_or_default(),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(message) => {
            tracing::warn!("v1 login authentication failed: {message}");
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail login failed",
            );
        }
    };
    match outcome {
        NativeLoginOutcome::Authenticated(credentials) => {
            if let Err(message) = native_login_establish_session(&session, &credentials).await {
                tracing::warn!("v1 login session setup failed: {message}");
                return v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Frickmail login failed",
                );
            }
            (
                StatusCode::OK,
                Json(ApiV1Envelope::ok(json!({
                    "authenticated": true,
                    "user": {
                        "id": credentials.user_id,
                        "username": credentials.username,
                        "email": credentials.email,
                    },
                }))),
            )
                .into_response()
        }
        NativeLoginOutcome::TotpRequired { error } => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({
                "authenticated": false,
                "requires_totp": true,
                "error": error,
            }))),
        )
            .into_response(),
        NativeLoginOutcome::Rejected => v1_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Invalid username or password",
        ),
    }
}

/// Connection-token check for the login route. Unlike the read-only GET
/// helper, login always requires the token once CSRF is enabled: legacy
/// `FrickmailLogin` POSTs 403 without one, and the bootstrap (`GET
/// /api/frickmail/v1/session`, legacy AppData) always mints a secret first.
/// Only the `X-SM-Token` header is honored (intentional: v1 is strict JSON,
/// while the legacy `XToken` form field stays on the old dispatcher).
async fn v1_login_csrf(
    state: &AppState,
    session: &fm_session::Session,
    headers: &axum::http::HeaderMap,
) -> Result<(), Response> {
    if !state.config().security.csrf_enabled || state.config().php_bridge_url.is_some() {
        return Ok(());
    }
    let expected = match expected_connection_token(session).await {
        Ok(expected) => expected,
        Err(_) => {
            return Err(v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "session_error",
                "Frickmail session read failed",
            ));
        }
    };
    let valid = expected.is_some_and(|expected| {
        headers
            .get("x-sm-token")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|supplied| !supplied.is_empty())
            .is_some_and(|supplied| constant_time_equal(supplied.as_bytes(), expected.as_bytes()))
    });
    if valid {
        Ok(())
    } else {
        Err(v1_error(
            StatusCode::FORBIDDEN,
            "invalid_token",
            "Invalid or missing connection token",
        ))
    }
}

async fn v1_method_not_allowed() -> Response {
    v1_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "Method not allowed for this /api/frickmail/v1 path",
    )
}

fn v1_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
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
    async fn v1_session_bootstraps_csrf_token_for_anonymous_callers() {
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

        assert_eq!(response.status(), StatusCode::OK);
        let cookie = session_cookie(&response);
        assert!(!cookie.is_empty());
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["authenticated"], false);
        let token = body["data"]["csrf_token"].as_str().unwrap();
        assert!(token.starts_with("0-"), "{token}");
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

    async fn login_db_pool() -> sqlx::AnyPool {
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
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
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS frickmail_totp_used (
                user_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                \"window\" INTEGER NOT NULL,
                used_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, code, \"window\")
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
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
                settings TEXT NOT NULL DEFAULT '{}',
                is_primary BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TEXT,
                updated_at TEXT
            )",
        )
        .execute(&pool)
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
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    async fn seed_login_user(
        pool: &sqlx::AnyPool,
        id: i64,
        username: &str,
        password: &str,
        totp_secret: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_users
                (id, username, email, password_hash, kdf_salt, settings, totp_secret, oidc_escrow_key, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(username)
        .bind(format!("{username}@example.com"))
        .bind(fm_user::hash_login_password(password).unwrap())
        .bind(vec![9_u8; fm_user::KDF_SALT_BYTES])
        .bind("{}")
        .bind(totp_secret.map(ToOwned::to_owned))
        .bind(None::<Vec<u8>>)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_mail_account(pool: &sqlx::AnyPool, id: i64, user_id: i64, label: &str) {
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
        .bind(true)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_identity(pool: &sqlx::AnyPool, id: i64, user_id: i64, account_id: i64) {
        sqlx::query(
            "INSERT INTO frickmail_identities
                (id, account_id, user_id, name, email, reply_to, is_default, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(account_id)
        .bind(user_id)
        .bind("Sender")
        .bind("sender@example.com")
        .bind(None::<String>)
        .bind(true)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn login_as(
        app: Router,
        cookie: &str,
        token: &str,
        username: &str,
        password: &str,
    ) -> String {
        let response = app
            .oneshot(login_request(
                cookie,
                Some(token),
                serde_json::json!({"username": username, "password": password}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        session_cookie(&response)
    }

    #[tokio::test]
    async fn v1_accounts_lists_safe_metadata_for_authenticated_users() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 201, "v1acct", "correct-horse", None).await;
        seed_mail_account(&pool, 300, 201, "Primary").await;
        seed_mail_account(&pool, 301, 201, "Secondary").await;
        seed_identity(&pool, 400, 201, 300).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1acct", "correct-horse").await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/accounts")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        let accounts = body["data"]["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0]["email"], "primary@example.com");
        assert_eq!(accounts[0]["identities"].as_array().unwrap().len(), 1);
        assert_eq!(accounts[0]["identities"][0]["email"], "sender@example.com");
        let serialized = body.to_string();
        assert!(!serialized.contains("encrypted_password"));
        assert!(!serialized.contains("AQID"));
    }

    #[tokio::test]
    async fn v1_accounts_rejects_anonymous_callers() {
        let pool = login_db_pool().await;
        let app = login_app(pool);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/accounts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "unauthenticated");
    }
    fn login_app(pool: sqlx::AnyPool) -> Router {
        Router::new()
            .nest("/api/frickmail/v1", super::routes())
            .layer(fm_session::session_layer(
                fm_session::AppSessionStore::Memory(fm_session::MemoryStore::default()),
            ))
            .with_state(AppState::with_db_pool(test_api_config(), Some(pool)))
    }

    /// Bootstraps an anonymous session: returns the session cookie plus the
    /// minted CSRF token, exactly like legacy AppData bootstrap.
    async fn bootstrap_csrf(app: Router) -> (String, String) {
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = session_cookie(&response);
        let token = read_json(response).await["data"]["csrf_token"]
            .as_str()
            .unwrap()
            .to_string();
        (cookie, token)
    }

    fn login_request(cookie: &str, token: Option<&str>, body: serde_json::Value) -> Request<Body> {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/frickmail/v1/login")
            .header("content-type", "application/json")
            .header("cookie", cookie);
        if let Some(token) = token {
            request = request.header("x-sm-token", token);
        }
        request.body(Body::from(body.to_string())).unwrap()
    }

    fn session_cookie(response: &Response) -> String {
        response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn v1_login_authenticates_and_establishes_session() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 101, "v1user", "correct-horse", None).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;

        let response = app
            .clone()
            .oneshot(login_request(
                &cookie,
                Some(&token),
                serde_json::json!({"username": "v1user", "password": "correct-horse"}),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let cookie = session_cookie(&response);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["authenticated"], true);
        assert_eq!(body["data"]["user"]["id"], 101);
        assert_eq!(body["data"]["user"]["username"], "v1user");
        assert_eq!(body["data"]["user"]["email"], "v1user@example.com");

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/session")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["authenticated"], true);
        assert_eq!(body["data"]["user"]["id"], 101);
        assert_eq!(body["data"]["user"]["username"], "v1user");
        assert!(body["data"]["user"].get("password_hash").is_none());
    }

    #[tokio::test]
    async fn v1_login_rejects_tokenless_logins() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 105, "v1bare", "correct-horse", None).await;
        let app = login_app(pool);

        // No bootstrap happened on this session, so no token exists and the
        // login must be rejected like legacy tokenless login POSTs.
        let response = app
            .oneshot(login_request(
                "",
                None,
                serde_json::json!({"username": "v1bare", "password": "correct-horse"}),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_token");
    }

    #[tokio::test]
    async fn v1_login_rejects_unknown_users_and_wrong_passwords_identically() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 102, "v1other", "correct-horse", None).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;

        for username in ["nosuchuser", "v1other"] {
            let response = app
                .clone()
                .oneshot(login_request(
                    &cookie,
                    Some(&token),
                    serde_json::json!({"username": username, "password": "wrong"}),
                ))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body = read_json(response).await;
            assert_eq!(body["version"], "v1");
            assert_eq!(body["error"]["code"], "invalid_credentials");
            assert_eq!(body["error"]["message"], "Invalid username or password");
        }
    }

    #[tokio::test]
    async fn v1_login_requires_totp_for_totp_accounts() {
        let pool = login_db_pool().await;
        seed_login_user(
            &pool,
            103,
            "v1totp",
            "correct-horse",
            Some("JBSWY3DPEHPK3PXP"),
        )
        .await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;

        let response = app
            .oneshot(login_request(
                &cookie,
                Some(&token),
                serde_json::json!({"username": "v1totp", "password": "correct-horse"}),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["authenticated"], false);
        assert_eq!(body["data"]["requires_totp"], true);
    }

    #[tokio::test]
    async fn v1_login_enforces_token_once_bootstrapped() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 104, "v1csrf", "correct-horse", None).await;
        let app = crate::build_router(AppState::with_db_pool(test_api_config(), Some(pool)));

        let bootstrap = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/?/AppData/0/12345/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = session_cookie(&bootstrap);
        let token = read_json(bootstrap).await["System"]["token"]
            .as_str()
            .unwrap()
            .to_string();

        let login = |cookie: &str, token: Option<&str>| {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/login")
                .header("content-type", "application/json")
                .header("cookie", cookie);
            if let Some(token) = token {
                request = request.header("x-sm-token", token);
            }
            request
                .body(Body::from(
                    serde_json::json!({"username": "v1csrf", "password": "wrong"}).to_string(),
                ))
                .unwrap()
        };

        let response = app
            .clone()
            .oneshot(login(&cookie, Some("wrong-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_token");

        // The valid token passes CSRF and reaches authentication (401 here
        // because the password is wrong, proving the check passed).
        let response = app.oneshot(login(&cookie, Some(&token))).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_credentials");
    }

    fn test_totp_counter() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() / 30)
            .unwrap_or_default()
    }

    fn test_totp_code(secret: &str, counter: u64) -> String {
        let key = data_encoding::BASE32_NOPAD
            .decode(secret.trim().to_ascii_uppercase().as_bytes())
            .unwrap();
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&key).unwrap();
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = (digest[19] & 0x0f) as usize;
        let value = (((digest[offset] & 0x7f) as u32) << 24)
            | ((digest[offset + 1] as u32) << 16)
            | ((digest[offset + 2] as u32) << 8)
            | (digest[offset + 3] as u32);
        format!("{:06}", value % 1_000_000)
    }

    #[tokio::test]
    async fn v1_login_accepts_valid_totp_and_rejects_replay() {
        let pool = login_db_pool().await;
        seed_login_user(
            &pool,
            106,
            "v1totpok",
            "correct-horse",
            Some("JBSWY3DPEHPK3PXP"),
        )
        .await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let code = test_totp_code("JBSWY3DPEHPK3PXP", test_totp_counter());

        let response = app
            .clone()
            .oneshot(login_request(
                &cookie,
                Some(&token),
                serde_json::json!({
                    "username": "v1totpok",
                    "password": "correct-horse",
                    "totp_code": code,
                }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let cookie = session_cookie(&response);
        let body = read_json(response).await;
        assert_eq!(body["data"]["authenticated"], true);
        assert_eq!(body["data"]["user"]["id"], 106);

        // Replaying the same code must fail TOTP like the legacy login does.
        let response = app
            .oneshot(login_request(
                &cookie,
                Some(&token),
                serde_json::json!({
                    "username": "v1totpok",
                    "password": "correct-horse",
                    "totp_code": code,
                }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["authenticated"], false);
        assert_eq!(body["data"]["requires_totp"], true);
    }
}
