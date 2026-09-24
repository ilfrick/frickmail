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
    routing::{delete, get, post, put},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

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
        .route("/accounts", get(accounts).post(add_account))
        .route("/accounts/{id}", put(update_account).delete(delete_account))
        .route("/accounts/{id}/primary", post(set_primary_account))
        .route("/identities", get(identities).post(add_identity))
        .route("/identities/{id}", delete(delete_identity))
        .route("/identities/{id}/default", post(set_default_identity))
        .route("/switch-account", post(switch_account))
        .route("/logout", post(logout))
        .route("/admin/login", post(admin_login))
        .route("/admin/logout", post(admin_logout))
        .route(
            "/admin/domains",
            get(admin_list_domains).post(admin_save_domain),
        )
        .route("/admin/domains/aliases", post(admin_save_domain_alias))
        .route(
            "/admin/domains/{name}",
            get(admin_get_domain).delete(admin_delete_domain),
        )
        .route("/admin/domains/{name}/disable", post(admin_disable_domain))
        .route(
            "/admin/settings",
            get(admin_get_settings).put(admin_set_settings),
        )
        .route("/admin/settings/{name}", delete(admin_reset_setting))
        .route("/avatar", get(avatar))
        .route("/contacts", get(contacts).post(add_contact))
        .route("/contacts/deduplicate", post(deduplicate_contacts))
        .route("/contacts/{id}", delete(delete_contact))
        .route("/messages", get(messages))
        .route("/messages/{uid}", get(message))
        .route("/send", post(send))
        .route("/preferences", get(get_preferences).put(set_preferences))
        .route("/rules", get(rules))
        .route("/tasks", get(tasks))
        .route("/folders", get(folders))
        .route("/search", get(search))
        .route("/unified-inbox", get(unified_inbox))
        .route("/oauth/providers", get(oauth_providers))
        .route("/security/totp", get(totp_status))
        .route("/security/totp/setup", post(totp_setup))
        .route("/security/totp/confirm", post(totp_confirm))
        .route("/security/totp/disable", post(totp_disable))
        .route("/security/password", post(change_password))
        .route(
            "/smime/certs",
            get(smime_certs)
                .post(smime_import_cert)
                .delete(smime_delete_cert),
        )
        .route("/smime/p12", post(smime_import_p12))
        .route("/calendars", get(calendars))
        .route(
            "/calendars/events",
            get(calendar_events)
                .post(calendar_save_event)
                .delete(calendar_delete_event),
        )
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
                "is_admin": v1_require_admin(&session).await.is_ok(),
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
    data["is_admin"] = json!(v1_require_admin(&session).await.is_ok());
    if let Ok(Some(selected)) = session
        .get::<fm_core::SelectedMailAccountSession>(fm_session::SELECTED_ACCOUNT_SESSION_KEY)
        .await
    {
        data["selected_account_id"] = json!(selected.account_id);
    } else {
        data["selected_account_id"] = json!(null);
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

/// Guards future v1 admin endpoints: the session must carry the operator
/// flag established by `POST /admin/login`. Anything else is 403, including
/// authenticated non-admin sessions.
async fn v1_require_admin(session: &fm_session::Session) -> Result<(), Response> {
    match session.get::<bool>(fm_session::ADMIN_SESSION_KEY).await {
        Ok(Some(true)) => Ok(()),
        Ok(_) => Err(v1_error(
            StatusCode::FORBIDDEN,
            "admin_forbidden",
            "Operator authentication required",
        )),
        Err(_) => Err(v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session_error",
            "Frickmail session read failed",
        )),
    }
}

#[derive(Debug, Deserialize, Default)]
struct AdminLoginRequest {
    #[serde(default)]
    token: String,
}

/// Establishes operator authentication from the configured admin token
/// hash (`FRICKMAIL__ADMIN__TOKEN_HASH`), the same trust root as the
/// backup/restore gate — deliberately not the legacy login/password
/// scheme. Argon2 verification runs off the async worker; unknown and wrong
/// tokens are indistinguishable 401s. Rotate the session id first so a
/// pre-login session cannot be fixed.
async fn admin_login(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<Json<AdminLoginRequest>, JsonRejection>,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let Ok(Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid admin login request",
        );
    };
    let token_hash = state
        .config()
        .admin
        .token_hash
        .as_deref()
        .map(str::trim)
        .filter(|token_hash| !token_hash.is_empty());
    let Some(token_hash) = token_hash else {
        return v1_error(
            StatusCode::FORBIDDEN,
            "admin_disabled",
            "Operator authentication is not configured",
        );
    };
    let token = request.token.trim().to_string();
    if token.is_empty() || token.len() > 1024 {
        return v1_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Invalid operator token",
        );
    }
    let authorized = tokio::task::spawn_blocking({
        let token_hash = token_hash.to_string();
        move || fm_user::verify_password_hash(&token, &token_hash).unwrap_or(false)
    })
    .await
    .unwrap_or(false);
    if !authorized {
        return v1_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Invalid operator token",
        );
    }
    if let Err(err) = session.cycle_id().await {
        tracing::warn!("v1 admin login rotation failed: {err}");
        return v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Frickmail admin login failed",
        );
    }
    if let Err(err) = session.insert(fm_session::ADMIN_SESSION_KEY, true).await {
        tracing::warn!("v1 admin login store failed: {err}");
        return v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Frickmail admin login failed",
        );
    }
    (
        StatusCode::OK,
        Json(ApiV1Envelope::ok(json!({ "authenticated": true }))),
    )
        .into_response()
}

/// Requires an operator session and a configured database, returning the
/// pool or the response to send. Keeps every admin domain handler on one
/// auth/database/CSRF shape.
async fn v1_admin_pool(
    state: &AppState,
    session: &fm_session::Session,
    headers: Option<&axum::http::HeaderMap>,
) -> Result<sqlx::AnyPool, Response> {
    v1_require_admin(session).await?;
    if let Some(headers) = headers {
        v1_require_token(state, session, headers).await?;
    }
    let Some(pool) = state.db_pool() else {
        return Err(v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        ));
    };
    Ok(pool.clone())
}

fn v1_domain_error(err: fm_core::FrickmailError, action: &str) -> Response {
    match err {
        fm_core::FrickmailError::BadRequest(message) => v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            format!("Frickmail domain {action} failed: {message}"),
        ),
        err => {
            tracing::warn!("v1 domain {action} failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Frickmail domain {action} failed"),
            )
        }
    }
}

/// Lists admin-managed mail domains. Operator-only; GET, so no CSRF check.
async fn admin_list_domains(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
) -> Response {
    let pool = match v1_admin_pool(&state, &session, None).await {
        Ok(pool) => pool,
        Err(response) => return response,
    };
    match fm_user::SqlxUserRepository::list_domains(&pool).await {
        Ok(domains) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "domains": domains }))),
        )
            .into_response(),
        Err(err) => v1_domain_error(err, "listing"),
    }
}

/// Returns one admin-managed mail domain. Operator-only; GET, so no CSRF check.
async fn admin_get_domain(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    name: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
) -> Response {
    let pool = match v1_admin_pool(&state, &session, None).await {
        Ok(pool) => pool,
        Err(response) => return response,
    };
    let Ok(axum::extract::Path(name)) = name else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid domain path",
        );
    };
    match fm_user::SqlxUserRepository::get_domain(&pool, &name).await {
        Ok(Some(domain)) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "domain": domain }))),
        )
            .into_response(),
        Ok(None) => v1_error(
            StatusCode::NOT_FOUND,
            "domain_not_found",
            "Mail domain not found",
        ),
        Err(err) => v1_domain_error(err, "lookup"),
    }
}

#[derive(Debug, Deserialize, Default)]
struct DomainRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    imap_host: Option<String>,
    #[serde(default)]
    imap_port: Option<i64>,
    #[serde(default)]
    imap_secure: Option<String>,
    #[serde(default)]
    smtp_host: Option<String>,
    #[serde(default)]
    smtp_port: Option<i64>,
    #[serde(default)]
    smtp_secure: Option<String>,
}

/// Creates or replaces an admin-managed mail domain template. Operator-only
/// with CSRF; strict JSON, so numbers/bools are never coerced.
async fn admin_save_domain(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<Json<DomainRequest>, JsonRejection>,
) -> Response {
    let pool = match v1_admin_pool(&state, &session, Some(&headers)).await {
        Ok(pool) => pool,
        Err(response) => return response,
    };
    let Ok(Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid domain body",
        );
    };
    match fm_user::SqlxUserRepository::save_domain(
        &pool,
        fm_user::NewMailDomain {
            name: request.name,
            disabled: request.disabled,
            imap_host: request.imap_host,
            imap_port: request.imap_port,
            imap_secure: request.imap_secure,
            smtp_host: request.smtp_host,
            smtp_port: request.smtp_port,
            smtp_secure: request.smtp_secure,
        },
    )
    .await
    {
        Ok(domain) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "domain": domain }))),
        )
            .into_response(),
        Err(err) => v1_domain_error(err, "save"),
    }
}

/// Deletes an admin-managed mail domain and its aliases. Operator-only with
/// CSRF; unknown names are 404 so operators can distinguish typos.
async fn admin_delete_domain(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    name: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
) -> Response {
    let pool = match v1_admin_pool(&state, &session, Some(&headers)).await {
        Ok(pool) => pool,
        Err(response) => return response,
    };
    let Ok(axum::extract::Path(name)) = name else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid domain path",
        );
    };
    match fm_user::SqlxUserRepository::get_domain(&pool, &name).await {
        Ok(None) => v1_error(
            StatusCode::NOT_FOUND,
            "domain_not_found",
            "Mail domain not found",
        ),
        Ok(Some(_)) => match fm_user::SqlxUserRepository::delete_domain(&pool, &name).await {
            Ok(_) => (
                StatusCode::OK,
                Json(ApiV1Envelope::ok(json!({ "deleted": true }))),
            )
                .into_response(),
            Err(err) => v1_domain_error(err, "delete"),
        },
        Err(err) => v1_domain_error(err, "lookup"),
    }
}

#[derive(Debug, Deserialize)]
struct DomainDisableRequest {
    disabled: bool,
}

/// Enables or disables a domain template. Operator-only with CSRF; disabled
/// templates are skipped by connection resolution.
async fn admin_disable_domain(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    name: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    body: Result<Json<DomainDisableRequest>, JsonRejection>,
) -> Response {
    let pool = match v1_admin_pool(&state, &session, Some(&headers)).await {
        Ok(pool) => pool,
        Err(response) => return response,
    };
    let (Ok(axum::extract::Path(name)), Ok(Json(request))) = (name, body) else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid domain disable request",
        );
    };
    match fm_user::SqlxUserRepository::set_domain_disabled(&pool, &name, request.disabled).await {
        Ok(Some(domain)) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "domain": domain }))),
        )
            .into_response(),
        Ok(None) => v1_error(
            StatusCode::NOT_FOUND,
            "domain_not_found",
            "Mail domain not found",
        ),
        Err(err) => v1_domain_error(err, "disable"),
    }
}

#[derive(Debug, Deserialize)]
struct DomainAliasRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    alias: String,
}

/// Points an alias name at an existing domain template. Operator-only with
/// CSRF; aliases never shadow real domain rows.
async fn admin_save_domain_alias(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<Json<DomainAliasRequest>, JsonRejection>,
) -> Response {
    let pool = match v1_admin_pool(&state, &session, Some(&headers)).await {
        Ok(pool) => pool,
        Err(response) => return response,
    };
    let Ok(Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid domain alias body",
        );
    };
    match fm_user::SqlxUserRepository::save_domain_alias(&pool, &request.name, &request.alias).await
    {
        Ok(domain) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "domain": domain }))),
        )
            .into_response(),
        Err(err) => v1_domain_error(err, "alias save"),
    }
}

/// Returns the effective value and provenance (`database` override vs
/// `environment` default) of every curated admin setting. Operator-only;
/// GET, so no CSRF check.
async fn admin_get_settings(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
) -> Response {
    if let Err(response) = v1_admin_pool(&state, &session, None).await {
        return response;
    }
    let mut settings = serde_json::Map::new();
    for schema in super::ADMIN_SETTING_SCHEMA {
        let effective = super::admin_setting_effective(&state, schema).await;
        settings.insert(
            schema.name.to_string(),
            json!({ "value": effective.value, "source": effective.source }),
        );
    }
    (
        StatusCode::OK,
        Json(ApiV1Envelope::ok(json!({ "settings": settings }))),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct AdminSettingsRequest {
    settings: std::collections::HashMap<String, Value>,
}

/// Replaces curated admin settings atomically: every entry is validated
/// first (unknown keys, wrong JSON types, and out-of-bounds integers are
/// 400), then all rows commit in one transaction. Operator-only with CSRF.
async fn admin_set_settings(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<Json<AdminSettingsRequest>, JsonRejection>,
) -> Response {
    let pool = match v1_admin_pool(&state, &session, Some(&headers)).await {
        Ok(pool) => pool,
        Err(response) => return response,
    };
    let Ok(Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid settings body",
        );
    };
    if request
        .settings
        .contains_key("external_auth.allow_provisioning")
    {
        if let Err(response) = v1_require_connection_token(&session, &headers).await {
            return response;
        }
    }
    if request.settings.is_empty() {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "No settings provided",
        );
    }
    let mut rows: Vec<(String, String)> = Vec::with_capacity(request.settings.len());
    for (name, value) in &request.settings {
        let Some(schema) = super::admin_setting_schema(name) else {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "unknown_setting",
                format!("Unknown admin setting '{name}'"),
            );
        };
        let canonical = match (&schema.kind, value) {
            (super::AdminSettingKind::Bool, Value::Bool(flag)) => flag.to_string(),
            (super::AdminSettingKind::BoundedInt { min, max }, Value::Number(number)) => {
                match number.as_u64() {
                    Some(int) if (*min..=*max).contains(&int) => int.to_string(),
                    _ => {
                        return v1_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            format!("Admin setting '{name}' is out of bounds"),
                        );
                    }
                }
            }
            _ => {
                return v1_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("Admin setting '{name}' has the wrong type"),
                );
            }
        };
        rows.push((format!("admin_override:{name}"), canonical));
    }
    let refs: Vec<(&str, String)> = rows
        .iter()
        .map(|(name, value)| (name.as_str(), value.clone()))
        .collect();
    match fm_user::SqlxUserRepository::set_app_setting_values(&pool, &refs).await {
        Ok(()) => admin_get_settings(state, session).await,
        Err(err) => {
            tracing::warn!("v1 settings save failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail settings save failed",
            )
        }
    }
}

/// Drops a database override so the environment default applies again.
/// Operator-only with CSRF; unknown keys are 400, keys without an override
/// are 404.
async fn admin_reset_setting(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    name: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
) -> Response {
    let pool = match v1_admin_pool(&state, &session, Some(&headers)).await {
        Ok(pool) => pool,
        Err(response) => return response,
    };
    let Ok(axum::extract::Path(name)) = name else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid setting path",
        );
    };
    if name == "external_auth.allow_provisioning" {
        if let Err(response) = v1_require_connection_token(&session, &headers).await {
            return response;
        }
    }
    if super::admin_setting_schema(&name).is_none() {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "unknown_setting",
            format!("Unknown admin setting '{name}'"),
        );
    }
    match fm_user::SqlxUserRepository::delete_app_setting_value(
        &pool,
        &format!("admin_override:{name}"),
    )
    .await
    {
        Ok(true) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "reset": true }))),
        )
            .into_response(),
        Ok(false) => v1_error(
            StatusCode::NOT_FOUND,
            "setting_not_overridden",
            format!("Admin setting '{name}' has no database override"),
        ),
        Err(err) => {
            tracing::warn!("v1 settings reset failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail settings reset failed",
            )
        }
    }
}

/// Clears operator authentication without touching the user session, so an
/// operator using webmail in the same browser stays signed in. Idempotent.
async fn admin_logout(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    if let Err(err) = session.remove::<bool>(fm_session::ADMIN_SESSION_KEY).await {
        tracing::warn!("v1 admin logout failed: {err}");
        return v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Frickmail admin logout failed",
        );
    }
    (
        StatusCode::OK,
        Json(ApiV1Envelope::ok(json!({ "logged_out": true }))),
    )
        .into_response()
}

/// Serves a sender avatar image: `GET /avatar?email=a@b.c&bimi=1`. Requires
/// an authenticated user session (never anonymous, never operator-only) so
/// the remote-fetch path cannot be used as an unauthenticated SSRF oracle.
/// `bimi=1` asserts DKIM validity and unlocks bundled service icons, like
/// the legacy plugin. 200 carries the bytes with a private day-long cache
/// lifetime; misses are 404, invalid emails 400. GET-only, so no CSRF check
/// applies.
async fn avatar(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    if let Err(response) = v1_session_user_id(&session).await {
        return response;
    }
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid avatar query",
        );
    };
    let Some(email) = params
        .get("email")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "An email query parameter is required",
        );
    };
    let Some(normalized) = super::avatar::normalize_avatar_email(&email) else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid email address",
        );
    };
    let bimi = params.get("bimi").is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    });
    match super::avatar::resolve_avatar(&state, &normalized, bimi).await {
        Some((mime, bytes)) => {
            let etag = super::avatar::avatar_cache_key(&normalized);
            (
                StatusCode::OK,
                [
                    (axum::http::header::CONTENT_TYPE, mime),
                    (
                        axum::http::header::CACHE_CONTROL,
                        format!(
                            "private, max-age={}",
                            super::avatar::AVATAR_CACHE_MAX_AGE_SECS
                        ),
                    ),
                    (axum::http::header::ETAG, format!("\"{etag}\"")),
                ],
                bytes,
            )
                .into_response()
        }
        None => v1_error(
            StatusCode::NOT_FOUND,
            "avatar_not_found",
            "No avatar found for this address",
        ),
    }
}

/// Lists the authenticated user's address-book contact summaries (id, uid,
/// display), reusing the exact repository query behind contact
/// deduplication. User-scoped storage with no secrets. Non-numeric
/// limit/offset fall back to defaults by design (lenient pagination).
/// GET-only, so no CSRF check applies.
async fn contacts(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    const DEFAULT_CONTACTS_LIMIT: i64 = 50;
    const MAX_CONTACTS_LIMIT: i64 = 200;

    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid contacts query",
        );
    };
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .map(|limit| limit.clamp(1, MAX_CONTACTS_LIMIT))
        .unwrap_or(DEFAULT_CONTACTS_LIMIT);
    let offset = params
        .get("offset")
        .and_then(|value| value.parse::<i64>().ok())
        .map(|offset| offset.max(0))
        .unwrap_or(0);
    match fm_user::address_book::list_contact_summaries(pool, user_id, offset, limit).await {
        Ok(contacts) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "contacts": contacts }))),
        )
            .into_response(),
        Err(err) => {
            tracing::warn!("v1 contacts listing failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail contacts listing failed",
            )
        }
    }
}

/// Maps a native legacy contacts response onto the v1 contract: a legacy
/// `Result` object with `ok:true` becomes 200 `data`; a legacy
/// `Result.error` becomes a classified 4xx/500 with a generic message.
/// Legacy error text never reaches v1 clients.
async fn map_contacts_response(response: Response) -> Response {
    if response.status() != StatusCode::OK {
        tracing::warn!(
            "v1 contacts request failed with legacy status {}",
            response.status().as_u16()
        );
        return v1_error(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            "Frickmail contacts request failed",
        );
    }
    let body = match axum::body::to_bytes(response.into_body(), 64 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return v1_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Frickmail contacts request failed",
            )
        }
    };
    let body: Value = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_) => {
            return v1_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Frickmail contacts request failed",
            )
        }
    };
    match body.get("Result") {
        Some(Value::Object(result)) if result.get("error").is_none() => {
            (StatusCode::OK, Json(ApiV1Envelope::ok(result))).into_response()
        }
        Some(result) => {
            let message = result
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if message == "invalid email address" {
                return v1_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Invalid contact request",
                );
            }
            tracing::warn!("v1 contacts request failed");
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail contacts request failed",
            )
        }
        _ => v1_error(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            "Frickmail contacts request failed",
        ),
    }
}

/// Request body for `POST /api/frickmail/v1/contacts`. Field names mirror
/// the legacy `JsonAddContact` payload; the name defaults to the address
/// server-side like the native hook.
#[derive(Debug, Deserialize, Default)]
struct ContactAddRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

/// Adds a manual contact, reusing the exact pipeline as legacy
/// `JsonAddContact` (validation, jCard-shaped rows, random `manual:`
/// UID). State-changing, so the connection token is required.
async fn add_contact(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<axum::extract::Json<ContactAddRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    if let Err(response) = v1_session_user_id(&session).await {
        return response;
    }
    if state.db_pool().is_none() {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    }
    let Ok(axum::extract::Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid contact body",
        );
    };
    let payload = json!({
        "name": request.name.unwrap_or_default(),
        "email": request.email.unwrap_or_default(),
    });
    let response =
        super::contacts::native_json_add_contact(&state, "JsonAddContact", &payload, &session)
            .await;
    map_contacts_response(response).await
}

/// Removes later duplicates sharing a UID (or display name), reusing the
/// exact pipeline as legacy `JsonDeduplicateContacts`. State-changing, so
/// the connection token is required.
async fn deduplicate_contacts(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    if let Err(response) = v1_session_user_id(&session).await {
        return response;
    }
    if state.db_pool().is_none() {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    }
    let response = super::contacts::native_json_deduplicate_contacts(
        &state,
        "JsonDeduplicateContacts",
        &json!({}),
        &session,
    )
    .await;
    map_contacts_response(response).await
}

/// Deletes one of the caller's contacts by address-book id. Unknown ids
/// 404 (the repository reports whether a row matched). State-changing, so
/// the connection token is required.
async fn delete_contact(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    path: Result<axum::extract::Path<i64>, axum::extract::rejection::PathRejection>,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Path(id)) = path else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid contact id",
        );
    };
    if let Err(err) = fm_user::address_book::ensure_address_book_schema(pool).await {
        tracing::warn!("v1 contacts schema check failed: {}", err.public_message());
        return v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Frickmail contacts request failed",
        );
    }
    let exists = match fm_user::address_book::contact_exists(pool, user_id, id).await {
        Ok(exists) => exists,
        Err(err) => {
            tracing::warn!("v1 contact lookup failed: {}", err.public_message());
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail contacts request failed",
            );
        }
    };
    if !exists {
        return v1_error(
            StatusCode::NOT_FOUND,
            "contact_not_found",
            "Contact not found",
        );
    }
    match fm_user::address_book::delete_contacts(pool, user_id, &[id]).await {
        Ok(true) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "deleted": true }))),
        )
            .into_response(),
        Ok(false) => v1_error(
            StatusCode::NOT_FOUND,
            "contact_not_found",
            "Contact not found",
        ),
        Err(err) => {
            tracing::warn!("v1 contact delete failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail contacts request failed",
            )
        }
    }
}

/// Maps a legacy send response onto the v1 contract: transport success
/// (HTTP 200 with `Result: true`) becomes 200 `{sent:true}`; legacy input
/// validation (`Result.ok == false`, no code field) becomes a generic 400;
/// everything else becomes a generic 502. Legacy error text never reaches
/// v1 clients; details stay server-side.
async fn map_send_response(response: Response) -> Response {
    if response.status() != StatusCode::OK {
        tracing::warn!(
            "v1 send failed with legacy status {}",
            response.status().as_u16()
        );
        return v1_error(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            "Mail message delivery failed",
        );
    }
    let body = match axum::body::to_bytes(response.into_body(), 64 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return v1_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Mail message delivery failed",
            )
        }
    };
    let body: Value = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_) => {
            return v1_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Mail message delivery failed",
            )
        }
    };
    if body.get("Result") == Some(&json!(true)) {
        return (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "sent": true }))),
        )
            .into_response();
    }
    if body.get("Result").and_then(|result| result.get("ok")) == Some(&json!(false))
        || body.get("code") == Some(&json!(903))
    {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid send request",
        );
    }
    tracing::warn!("v1 send failed without transport success");
    v1_error(
        StatusCode::BAD_GATEWAY,
        "upstream_error",
        "Mail message delivery failed",
    )
}

/// Sends a plain text/HTML message through the selected or explicit account,
/// reusing the exact compose/delivery pipeline as legacy `SendMessage`
/// (validation, MIME build, SMTP delivery, Sent filing). Attachments,
/// client PGP/SMIME payloads, and signing options stay on the legacy
/// dispatcher for now: v1 `SendRequest` carries only addressing plus
/// text/HTML bodies. State-changing, so the connection token is required.
async fn send(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<Json<SendRequest>, JsonRejection>,
) -> Response {
    send_with_sender_and_appender(
        &state,
        &session,
        body,
        &headers,
        &super::ProductionLegacySmtpSender,
        &super::ProductionLegacySentAppender,
        &super::ProductionOAuthTokenRefresher,
    )
    .await
}

#[derive(Debug, Deserialize, Default)]
struct SendRequest {
    #[serde(default)]
    account_id: Option<i64>,
    #[serde(default)]
    identity_id: Option<i64>,
    #[serde(default)]
    to: String,
    #[serde(default)]
    cc: Option<String>,
    #[serde(default)]
    bcc: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    html: Option<String>,
    #[serde(default = "default_send_save_to_sent")]
    save_to_sent: bool,
}

fn default_send_save_to_sent() -> bool {
    true
}

async fn send_with_sender_and_appender(
    state: &AppState,
    session: &fm_session::Session,
    body: Result<Json<SendRequest>, JsonRejection>,
    headers: &axum::http::HeaderMap,
    smtp_sender: &dyn super::LegacySmtpSender,
    sent_appender: &dyn super::LegacySentAppender,
    token_refresher: &dyn super::OAuthAccessTokenRefresher,
) -> Response {
    if let Err(response) = v1_require_token(state, session, headers).await {
        return response;
    }
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
    let Ok(Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid send request",
        );
    };
    if request.to.trim().is_empty() {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "At least one recipient is required",
        );
    }
    let account_id = match request.account_id.filter(|id| *id > 0) {
        Some(account_id) => account_id,
        None => match session
            .get::<fm_core::SelectedMailAccountSession>(fm_session::SELECTED_ACCOUNT_SESSION_KEY)
            .await
        {
            Ok(Some(selected)) if selected.account_id > 0 => selected.account_id,
            Ok(_) => {
                return v1_error(
                    StatusCode::BAD_REQUEST,
                    "account_required",
                    "An account_id or selected account is required",
                )
            }
            Err(_) => {
                return v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session_error",
                    "Frickmail session read failed",
                )
            }
        },
    };
    let sent_folder = match fm_user::SqlxUserRepository::get_mail_account_settings(
        pool,
        user.user_id,
        account_id,
    )
    .await
    {
        Ok(Some(settings)) => settings
            .get("SentFolder")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|folder| !folder.is_empty())
            .map(ToOwned::to_owned),
        Ok(None) => {
            return v1_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Mail account not found",
            )
        }
        Err(err) => {
            tracing::warn!("v1 send settings lookup failed: {}", err.public_message());
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail settings lookup failed",
            );
        }
    };
    let payload = json!({
        "account_id": account_id,
        "to": request.to,
        "cc": request.cc,
        "bcc": request.bcc,
        "subject": request.subject,
        "plain": request.text,
        "html": request.html,
    });
    let mut payload = payload;
    // Optional send-as identity: resolved server-side and scoped to the
    // sending account, so clients can never spoof arbitrary From
    // addresses. Display names follow the read-receipt convention
    // (`Name <email>`); a stored reply-to rides along.
    if let Some(identity_id) = request.identity_id.filter(|id| *id > 0) {
        let identities =
            match fm_user::SqlxUserRepository::list_mail_identities(pool, user.user_id, account_id)
                .await
            {
                Ok(identities) => identities,
                Err(err) => {
                    tracing::warn!("v1 send identity lookup failed: {}", err.public_message());
                    return v1_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "Frickmail settings lookup failed",
                    );
                }
            };
        let Some(identity) = identities
            .into_iter()
            .find(|identity| identity.id == identity_id)
        else {
            return v1_error(
                StatusCode::NOT_FOUND,
                "identity_not_found",
                "Sender identity not found",
            );
        };
        let name = identity.name.trim();
        let email = identity.email.trim();
        payload["from"] = if name.is_empty() {
            json!(email)
        } else {
            json!(format!("{name} <{email}>"))
        };
        if let Some(reply_to) = identity
            .reply_to
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            payload["replyTo"] = json!(reply_to);
        }
    }
    if request.save_to_sent {
        payload["saveFolder"] = json!(sent_folder.as_deref().unwrap_or("Sent"));
    }
    let response = super::native_send_message_inner_with_sender_and_sent_appender(
        state,
        "SendMessage",
        &payload,
        session,
        std::sync::Arc::new(std::sync::atomic::AtomicU8::new(super::SEND_PHASE_PRE_SMTP)),
        smtp_sender,
        sent_appender,
        token_refresher,
    )
    .await;
    map_send_response(response).await
}

/// Lists one account's IMAP folders, reusing the exact fetch as legacy
/// `Folders` (subscription discovery follows the account's stored
/// `HideUnsubscribed` setting, mirroring legacy). GET-only, so no CSRF
/// check applies.
async fn folders(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    folders_with_fetcher(
        &state,
        &session,
        query,
        super::MESSAGE_LIST_DEADLINE,
        |config, password, discover| async move {
            fm_imap::fetch_legacy_folders(config, &password, discover).await
        },
    )
    .await
}

async fn folders_with_fetcher<F, Fut>(
    state: &AppState,
    session: &fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
    fetch_deadline: std::time::Duration,
    fetcher: F,
) -> Response
where
    F: FnOnce(fm_imap::ImapConnectionConfig, String, bool) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<fm_imap::LegacyFolderCollection>>,
{
    let user_id = match v1_session_user_id(session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid folders query",
        );
    };
    let account_id = match params
        .get("account_id")
        .map(|value| value.parse::<i64>())
        .transpose()
        .ok()
        .flatten()
        .filter(|id| *id > 0)
    {
        Some(account_id) => account_id,
        None => match session
            .get::<fm_core::SelectedMailAccountSession>(fm_session::SELECTED_ACCOUNT_SESSION_KEY)
            .await
        {
            Ok(Some(selected)) if selected.account_id > 0 => selected.account_id,
            Ok(_) => {
                return v1_error(
                    StatusCode::BAD_REQUEST,
                    "account_required",
                    "An account_id query parameter or selected account is required",
                )
            }
            Err(_) => {
                return v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session_error",
                    "Frickmail session read failed",
                )
            }
        },
    };
    let credential_key = match v1_session_credential_key(session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };
    let settings =
        match fm_user::SqlxUserRepository::get_mail_account_settings(pool, user_id, account_id)
            .await
        {
            Ok(Some(settings)) => settings,
            Ok(None) => {
                return v1_error(
                    StatusCode::NOT_FOUND,
                    "account_not_found",
                    "Mail account not found",
                )
            }
            Err(err) => {
                tracing::warn!(
                    "v1 folders settings lookup failed: {}",
                    err.public_message()
                );
                return v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Frickmail settings lookup failed",
                );
            }
        };
    let discover_subscriptions = settings
        .get("HideUnsubscribed")
        .or_else(|| settings.get("hideUnsubscribed"))
        .is_some_and(super::legacy_php_truthy);
    let account = match fm_user::SqlxUserRepository::get_mail_account_connection_secret(
        pool, user_id, account_id,
    )
    .await
    {
        Ok(Some(account)) => account,
        Ok(None) => {
            return v1_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Mail account not found",
            )
        }
        Err(err) => {
            tracing::warn!("v1 folders account lookup failed: {}", err.public_message());
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail account lookup failed",
            );
        }
    };
    let password = match super::account_password(&account, &credential_key) {
        Ok(password) => password,
        Err(_) => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_account",
                "Mail account credentials are unavailable",
            )
        }
    };
    let imap_config = match super::imap_config_from_account_secret(&account) {
        Ok(config) => config,
        Err(err) => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_account",
                err.public_message(),
            )
        }
    };

    let result = tokio::time::timeout(
        fetch_deadline,
        fetcher(imap_config, password, discover_subscriptions),
    )
    .await
    .map_err(|_| fm_core::FrickmailError::Upstream("Folder list fetch timed out".to_string()));
    match result {
        Ok(Ok(collection)) => (StatusCode::OK, Json(ApiV1Envelope::ok(collection))).into_response(),
        Ok(Err(err)) | Err(err) => {
            tracing::warn!("v1 folders fetch failed: {}", err.public_message());
            v1_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Mail server folder listing failed",
            )
        }
    }
}

/// Destroys the session and expires the `FrickmailSession` cookie (via
/// `Session::flush`, which clears server-side data and emits the middleware
/// removal cookie), ending the authenticated session regardless of its
/// current state (idempotent: anonymous callers get the same success shape).
/// State-changing, so the connection token is required once bootstrapped —
/// exactly like the login route.
async fn logout(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    if let Err(err) = session.flush().await {
        tracing::warn!("v1 logout destroy failed: {err}");
        return v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Frickmail logout failed",
        );
    }
    (
        StatusCode::OK,
        Json(ApiV1Envelope::ok(json!({ "logged_out": true }))),
    )
        .into_response()
}

/// Lists the authenticated user's tasks, reusing the exact repository query
/// as legacy `FrickmailListTasks`. The optional `filter` query parameter
/// accepts `pending` or `completed` (anything else lists all, mirroring
/// legacy). The `MailTask` shape is user-scoped storage with no secrets.
/// GET-only, so no CSRF check applies.
async fn tasks(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid tasks query",
        );
    };
    let filter = match params.get("filter").map(String::as_str) {
        Some("pending") => fm_user::TaskFilter::Pending,
        Some("completed") => fm_user::TaskFilter::Completed,
        _ => fm_user::TaskFilter::All,
    };
    match fm_user::SqlxUserRepository::list_tasks(pool, user_id, filter).await {
        Ok(tasks) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "tasks": tasks }))),
        )
            .into_response(),
        Err(err) => {
            tracing::warn!("v1 tasks listing failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail tasks listing failed",
            )
        }
    }
}

/// Parses a v1 result-window limit the same way the legacy dispatcher
/// does (default 50, clamped to 1–100); the repository clamps again as a
/// backstop.
fn search_result_limit(params: &std::collections::HashMap<String, String>) -> i64 {
    params
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 100)
}

/// Full-text search over the user's indexed messages, mirroring legacy
/// `FrickmailSearch` (minimum query length and BadRequest mapping
/// included). Read-only.
async fn search(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid search query",
        );
    };
    let text = params.get("q").map(String::as_str).unwrap_or_default();
    let limit = search_result_limit(&params);
    match fm_user::SqlxUserRepository::search_messages(pool, user_id, text.to_string(), limit).await
    {
        Ok(results) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({
                "query": text.trim(),
                "results": results,
            }))),
        )
            .into_response(),
        Err(err) => {
            if matches!(err, fm_core::FrickmailError::BadRequest(_)) {
                return v1_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Invalid search request",
                );
            }
            tracing::warn!("v1 search failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail search failed",
            )
        }
    }
}

/// Merged cross-account inbox over indexed INBOX messages, mirroring
/// legacy `FrickmailUnifiedInbox`. Read-only.
async fn unified_inbox(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid unified inbox query",
        );
    };
    let limit = search_result_limit(&params);
    match fm_user::SqlxUserRepository::unified_inbox_messages(pool, user_id, limit).await {
        Ok(messages) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "messages": messages }))),
        )
            .into_response(),
        Err(err) => {
            tracing::warn!("v1 unified inbox failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail unified inbox failed",
            )
        }
    }
}

/// Maps S/MIME repository errors onto the v1 contract: `BadRequest` is a
/// client error (404 only for the unknown-account/cert cases), everything
/// else is a generic 500. Certificate text never reaches clients.
fn smime_error(message: &str, action: &'static str) -> Response {
    if message == "Account not found" {
        return v1_error(
            StatusCode::NOT_FOUND,
            "account_not_found",
            "Mail account not found",
        );
    }
    if message == "Certificate not found or already deleted" {
        return v1_error(
            StatusCode::NOT_FOUND,
            "certificate_not_found",
            "S/MIME certificate not found",
        );
    }
    tracing::warn!("v1 {action} failed: {message}");
    v1_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Frickmail S/MIME request failed",
    )
}

/// Lists the caller's S/MIME certificates (metadata only — key material
/// never leaves the server). Read-only.
async fn smime_certs(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
) -> Response {
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    match fm_user::SqlxUserRepository::list_smime_certs(pool, user_id).await {
        Ok(certs) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "certs": certs }))),
        )
            .into_response(),
        Err(err) => smime_error(&err.public_message(), "certificate listing"),
    }
}

/// Request body for `POST /api/frickmail/v1/smime/certs`: a base64 PEM
/// recipient certificate for the explicit account.
#[derive(Debug, Deserialize, Default)]
struct SmimeImportCertRequest {
    #[serde(default)]
    account_id: Option<i64>,
    #[serde(default)]
    pem_b64: Option<String>,
}

/// Imports a recipient S/MIME certificate, mirroring legacy
/// `FrickmailSmimeImportCert` validation (base64, size, PEM parse, email
/// extraction). State-changing, so the connection token is required.
async fn smime_import_cert(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<
        axum::extract::Json<SmimeImportCertRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid certificate body",
        );
    };
    let account_id = request.account_id.unwrap_or(0);
    let pem_b64 = request.pem_b64.unwrap_or_default();
    if pem_b64.trim().is_empty() {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid certificate request",
        );
    }
    use base64::Engine as _;
    let pem = match base64::engine::general_purpose::STANDARD.decode(pem_b64.trim()) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(value) => value,
            Err(_) => {
                return v1_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Invalid certificate request",
                )
            }
        },
        Err(_) => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid certificate request",
            )
        }
    };
    match fm_user::SqlxUserRepository::import_smime_cert(
        pool,
        user_id,
        fm_user::NewSmimeCert { account_id, pem },
    )
    .await
    {
        Ok(result) => (StatusCode::OK, Json(ApiV1Envelope::ok(json!(result)))).into_response(),
        Err(err) => match err {
            fm_core::FrickmailError::BadRequest(message) if message == "Account not found" => {
                v1_error(
                    StatusCode::NOT_FOUND,
                    "account_not_found",
                    "Mail account not found",
                )
            }
            fm_core::FrickmailError::BadRequest(_) => v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid certificate request",
            ),
            _ => smime_error(&err.public_message(), "certificate import"),
        },
    }
}

/// Request body for `POST /api/frickmail/v1/smime/p12`: a base64 PKCS#12
/// bundle (private key + certificate) encrypted under the session
/// credential key at rest.
#[derive(Debug, Deserialize, Default)]
struct SmimeImportP12Request {
    #[serde(default)]
    account_id: Option<i64>,
    #[serde(default)]
    p12_b64: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// Imports a PKCS#12 identity bundle, mirroring legacy
/// `FrickmailSmimeImportP12`. State-changing and key-bearing, so the
/// connection token is required.
async fn smime_import_p12(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<
        axum::extract::Json<SmimeImportP12Request>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let credential_key = match v1_session_credential_key(&session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid PKCS#12 body",
        );
    };
    let account_id = request.account_id.unwrap_or(0);
    use base64::Engine as _;
    let p12_der = match request.p12_b64.unwrap_or_default() {
        encoded if encoded.trim().is_empty() => Vec::new(),
        encoded => match base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
            Ok(bytes) => bytes,
            Err(_) => {
                return v1_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Invalid certificate request",
                )
            }
        },
    };
    match fm_user::SqlxUserRepository::import_smime_p12(
        pool,
        user_id,
        fm_user::NewSmimeP12 {
            account_id,
            p12_der,
            password: request.password.unwrap_or_default(),
        },
        &credential_key,
    )
    .await
    {
        Ok(result) => (StatusCode::OK, Json(ApiV1Envelope::ok(json!(result)))).into_response(),
        Err(err) => match err {
            fm_core::FrickmailError::BadRequest(message) if message == "Account not found" => {
                v1_error(
                    StatusCode::NOT_FOUND,
                    "account_not_found",
                    "Mail account not found",
                )
            }
            fm_core::FrickmailError::BadRequest(_) => v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid certificate request",
            ),
            _ => smime_error(&err.public_message(), "PKCS#12 import"),
        },
    }
}

/// Deletes one of the caller's S/MIME certificates. State-changing, so the
/// connection token is required.
async fn smime_delete_cert(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid certificate delete query",
        );
    };
    let id = params
        .get("id")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    match fm_user::SqlxUserRepository::delete_smime_cert(pool, user_id, id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "ok": true }))),
        )
            .into_response(),
        Ok(false) => v1_error(
            StatusCode::NOT_FOUND,
            "certificate_not_found",
            "S/MIME certificate not found",
        ),
        Err(err) => smime_error(&err.public_message(), "certificate delete"),
    }
}

/// Maps a TOTP action result onto the v1 contract: verified ok becomes
/// 200; a soft failure (wrong code) becomes a generic 400 without
/// leaking which half failed.
fn totp_result(result: fm_user::TotpActionResult) -> Response {
    if result.ok {
        (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "ok": true }))),
        )
            .into_response()
    } else {
        v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            result
                .error
                .or(result.message)
                .filter(|text| !text.trim().is_empty())
                .unwrap_or_else(|| "Invalid two-factor code".to_string()),
        )
    }
}

/// Reads two-factor status for the session user. Read-only.
async fn totp_status(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
) -> Response {
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    match fm_user::SqlxUserRepository::totp_enabled(pool, user_id).await {
        Ok(enabled) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "enabled": enabled }))),
        )
            .into_response(),
        Err(err) => {
            tracing::warn!("v1 totp status failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail two-factor request failed",
            )
        }
    }
}

/// Starts two-factor enrollment, storing the pending secret server-side
/// in the session exactly like legacy `FrickmailEnableTotp`. The secret
/// and QR material go back to the caller, so the connection token is
/// required.
async fn totp_setup(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    match fm_user::SqlxUserRepository::begin_totp_setup(pool, user_id).await {
        Ok(setup) => {
            if let Err(err) = session
                .insert(super::TOTP_PENDING_SESSION_KEY, setup.secret.clone())
                .await
            {
                tracing::warn!("v1 totp setup session write failed: {err}");
                return v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session_error",
                    "Frickmail session write failed",
                );
            }
            (
                StatusCode::OK,
                Json(ApiV1Envelope::ok(json!({
                    "secret": setup.secret,
                    "otpauth_uri": setup.otpauth_uri,
                    "qr_data_url": setup.qr_data_url,
                }))),
            )
                .into_response()
        }
        Err(err) => {
            tracing::warn!("v1 totp setup failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail two-factor request failed",
            )
        }
    }
}

/// Request body for the TOTP confirm/disable routes: the live code from
/// the authenticator app.
#[derive(Debug, Deserialize, Default)]
struct TotpCodeRequest {
    #[serde(default)]
    code: Option<String>,
}

/// Reads the pending enrollment secret or answers 400 when enrollment
/// was never started (mirroring legacy `FrickmailConfirmTotp`).
async fn totp_pending_secret(session: &fm_session::Session) -> Result<String, Response> {
    match session.get::<String>(super::TOTP_PENDING_SESSION_KEY).await {
        Ok(Some(secret)) => Ok(secret),
        Ok(None) => Err(v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "No pending two-factor setup",
        )),
        Err(_) => Err(v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session_error",
            "Frickmail session read failed",
        )),
    }
}

/// Confirms enrollment with a live code, clearing the pending secret on
/// success exactly like legacy `FrickmailConfirmTotp`. State-changing, so
/// the connection token is required.
async fn totp_confirm(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<axum::extract::Json<TotpCodeRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid two-factor body",
        );
    };
    let pending_secret = match totp_pending_secret(&session).await {
        Ok(pending_secret) => pending_secret,
        Err(response) => return response,
    };
    match fm_user::SqlxUserRepository::confirm_totp(
        pool,
        user_id,
        pending_secret,
        request.code.unwrap_or_default(),
    )
    .await
    {
        Ok(result) => {
            if result.ok {
                if let Err(err) = session
                    .remove::<String>(super::TOTP_PENDING_SESSION_KEY)
                    .await
                {
                    tracing::warn!("v1 totp confirm session cleanup failed: {err}");
                    return v1_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "session_error",
                        "Frickmail session cleanup failed",
                    );
                }
            }
            totp_result(result)
        }
        Err(err) => match err {
            fm_core::FrickmailError::BadRequest(_) => v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid two-factor request",
            ),
            _ => {
                tracing::warn!("v1 totp confirm failed: {}", err.public_message());
                v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Frickmail two-factor request failed",
                )
            }
        },
    }
}

/// Disables two-factor with a live code. State-changing, so the
/// connection token is required.
async fn totp_disable(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<axum::extract::Json<TotpCodeRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid two-factor body",
        );
    };
    match fm_user::SqlxUserRepository::disable_totp(pool, user_id, request.code.unwrap_or_default())
        .await
    {
        Ok(result) => totp_result(result),
        Err(err) => match err {
            fm_core::FrickmailError::BadRequest(_) => v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid two-factor request",
            ),
            _ => {
                tracing::warn!("v1 totp disable failed: {}", err.public_message());
                v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Frickmail two-factor request failed",
                )
            }
        },
    }
}

/// Request body for `POST /api/frickmail/v1/security/password`.
#[derive(Debug, Deserialize, Default)]
struct ChangePasswordRequest {
    #[serde(default)]
    current_password: Option<String>,
    #[serde(default)]
    new_password: Option<String>,
}

/// Changes the session user's login password through the exact policy
/// flow as legacy `ChangePassword` (length, strength, optional HIBP
/// breach check, current-password verification, account re-encryption).
/// Like the legacy action the session id rotates and the credential key
/// is dropped, so callers must sign in again afterwards. State-changing
/// and credential-bearing, so the connection token is required.
async fn change_password(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<
        axum::extract::Json<ChangePasswordRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid password body",
        );
    };
    if !state.config().change_password.enabled {
        return v1_error(
            StatusCode::FORBIDDEN,
            "unavailable",
            "Password change is unavailable",
        );
    }
    match super::change_login_password_checked(
        pool,
        &state.config().change_password,
        user_id,
        request.current_password.as_deref().unwrap_or_default(),
        request.new_password.unwrap_or_default(),
    )
    .await
    {
        Ok(()) => {}
        Err(super::ChangePasswordFailure::TooShort) => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "password_too_short",
                "New password is too short",
            )
        }
        Err(super::ChangePasswordFailure::TooWeak) => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "password_too_weak",
                "New password is too weak",
            )
        }
        Err(super::ChangePasswordFailure::Breached) => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "password_breached",
                "New password has been breached",
            )
        }
        Err(super::ChangePasswordFailure::BreachCheckUnavailable(_)) => {
            return v1_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Password breach check unavailable",
            )
        }
        Err(super::ChangePasswordFailure::WrongCurrentPassword) => {
            return v1_error(
                StatusCode::FORBIDDEN,
                "invalid_current_password",
                "Current password is incorrect",
            )
        }
        Err(super::ChangePasswordFailure::NoSuchUser) => {
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail password change failed",
            )
        }
        Err(super::ChangePasswordFailure::Upstream(_)) => {
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail password change failed",
            )
        }
    }
    if let Err(err) = session.cycle_id().await {
        tracing::warn!("v1 password change session rotation failed: {err}");
        return v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session_error",
            "Frickmail session rotation failed",
        );
    }
    if let Err(err) = session
        .remove::<String>(fm_session::CREDENTIAL_KEY_SESSION_KEY)
        .await
    {
        tracing::warn!("v1 password change credential reset failed: {err}");
        return v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session_error",
            "Frickmail credential session reset failed",
        );
    }
    (
        StatusCode::OK,
        Json(ApiV1Envelope::ok(json!({ "changed": true }))),
    )
        .into_response()
}

/// Lists the sign-in providers configured on the server for the v1 login
/// screen: Gmail and Microsoft OAuth2 plus generic OIDC, each only when
/// its client id AND secret (and issuer for OIDC) are configured.
/// Intentionally anonymous (the login screen needs it pre-auth) and free
/// of secrets — presence alone decides the list, and only the public
/// part-hook start URLs are exposed. Labels mirror the legacy plugins
/// (`provider_name` for OIDC, defaulting like the plugin default).
async fn oauth_providers(axum::extract::State(state): axum::extract::State<AppState>) -> Response {
    fn configured(values: &[&Option<String>]) -> bool {
        values
            .iter()
            .all(|value| value.as_deref().is_some_and(|text| !text.trim().is_empty()))
    }
    let config = state.config();
    let mut providers = Vec::new();
    if configured(&[
        &config.oauth2.gmail.client_id,
        &config.oauth2.gmail.client_secret,
    ]) {
        providers.push(json!({
            "id": "gmail",
            "label": "Google",
            "url": "/?StartLoginGMail",
        }));
    }
    if configured(&[
        &config.oauth2.o365.client_id,
        &config.oauth2.o365.client_secret,
    ]) {
        providers.push(json!({
            "id": "o365",
            "label": "Microsoft",
            "url": "/?StartLoginO365",
        }));
    }
    if configured(&[
        &config.oidc.issuer,
        &config.oidc.client_id,
        &config.oidc.client_secret,
    ]) {
        let name = config.oidc.provider_name.trim();
        providers.push(json!({
            "id": "oidc",
            "label": if name.is_empty() { "SSO".to_string() } else { name.to_string() },
            "url": "/?StartLoginOIDC",
        }));
    }
    (
        StatusCode::OK,
        Json(ApiV1Envelope::ok(json!({ "providers": providers }))),
    )
        .into_response()
}

/// Classifies a native legacy calendar `Result.error` message onto the v1
/// contract without leaking provider text to clients (details stay in
/// server logs via the caller's `tracing::warn!`, like `map_send_response`).
/// Session/account problems map to 401/404/400; provider rejections become
/// a generic 502.
fn calendar_error_status(message: &str) -> (StatusCode, &'static str, &'static str) {
    if message == "Not authenticated" {
        (
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "No authenticated Frickmail session",
        )
    } else if message == "Account not found" {
        (
            StatusCode::NOT_FOUND,
            "account_not_found",
            "Mail account not found",
        )
    } else if message == "Frickmail database is not configured" {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        )
    } else if message == "Account id required"
        || message == "title/start/end required"
        || message == "Too many calendar ids"
        || message == "id required"
        || message == "Calendar requires a Gmail or Office 365 account"
        || message.starts_with("No OAuth2 refresh token")
    {
        (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid calendar request",
        )
    } else {
        (
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            "Calendar provider request failed",
        )
    }
}

/// Maps a native legacy calendar response onto the v1 contract: a legacy
/// `Result` object without an `error` field becomes 200 `data`; a legacy
/// `Result.error` becomes a classified 4xx/502 with a generic message;
/// anything else becomes a generic 502. Legacy error text never reaches v1
/// clients.
async fn map_calendar_response(response: Response) -> Response {
    if response.status() != StatusCode::OK {
        tracing::warn!(
            "v1 calendar request failed with legacy status {}",
            response.status().as_u16()
        );
        return v1_error(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            "Calendar provider request failed",
        );
    }
    let body = match axum::body::to_bytes(response.into_body(), 64 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return v1_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Calendar provider request failed",
            )
        }
    };
    let body: Value = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_) => {
            return v1_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Calendar provider request failed",
            )
        }
    };
    match body.get("Result") {
        Some(Value::Object(result)) if result.get("error").is_none() => {
            (StatusCode::OK, Json(ApiV1Envelope::ok(result))).into_response()
        }
        Some(result) => {
            let message = result
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let (status, code, generic) = calendar_error_status(message);
            tracing::warn!("v1 calendar request failed: {code}");
            v1_error(status, code, generic)
        }
        _ => v1_error(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            "Calendar provider request failed",
        ),
    }
}

/// Builds the legacy calendar payload account selector: an explicit
/// `account_id` wins, otherwise the key is omitted so the legacy handler
/// falls back to the session-selected account.
fn calendar_account_payload(account_id: Option<i64>) -> Value {
    match account_id {
        Some(id) => json!({ "account_id": id }),
        None => json!({}),
    }
}

/// Lists the Gmail/Office 365 calendars of the selected or explicit
/// account, reusing the exact provider pipeline as legacy
/// `JsonCalendarList`. Read-only, so no connection token is required.
async fn calendars(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    calendars_with_fetcher(&state, &session, query, &|request| {
        super::calendar::calendar_http_via_reqwest(request)
    })
    .await
}

async fn calendars_with_fetcher<F, Fut>(
    state: &AppState,
    session: &fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
    fetcher: &F,
) -> Response
where
    F: Fn(super::calendar::CalendarHttpRequest) -> Fut,
    Fut: std::future::Future<
        Output = Result<super::calendar::CalendarHttpResponse, fm_core::FrickmailError>,
    >,
{
    if let Err(response) = v1_session_user_id(session).await {
        return response;
    }
    if state.db_pool().is_none() {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    }
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid calendars query",
        );
    };
    let account_id = params
        .get("account_id")
        .and_then(|value| value.parse::<i64>().ok());
    let payload = calendar_account_payload(account_id);
    let response = super::calendar::native_frickmail_calendar_list_with_fetcher(
        state,
        "JsonCalendarList",
        &payload,
        session,
        fetcher,
    )
    .await;
    map_calendar_response(response).await
}

/// Lists merged, start-sorted events across calendars, reusing the exact
/// provider pipeline as legacy `JsonCalendarEvents`. `calendar_ids` is a
/// comma-separated list (default `primary`); `start`/`end` default to the
/// legacy current-month-through-next-month window. Read-only.
async fn calendar_events(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    calendar_events_with_fetcher(&state, &session, query, &|request| {
        super::calendar::calendar_http_via_reqwest(request)
    })
    .await
}

async fn calendar_events_with_fetcher<F, Fut>(
    state: &AppState,
    session: &fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
    fetcher: &F,
) -> Response
where
    F: Fn(super::calendar::CalendarHttpRequest) -> Fut,
    Fut: std::future::Future<
        Output = Result<super::calendar::CalendarHttpResponse, fm_core::FrickmailError>,
    >,
{
    if let Err(response) = v1_session_user_id(session).await {
        return response;
    }
    if state.db_pool().is_none() {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    }
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid calendar events query",
        );
    };
    let mut payload = calendar_account_payload(
        params
            .get("account_id")
            .and_then(|value| value.parse::<i64>().ok()),
    );
    if let Some(ids) = params.get("calendar_ids") {
        let ids: Vec<String> = ids
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .collect();
        payload["calendar_ids"] = json!(ids);
    }
    for key in ["start", "end"] {
        if let Some(value) = params.get(key) {
            payload[key] = json!(value);
        }
    }
    let response = super::calendar::native_frickmail_calendar_events_with_fetcher(
        state,
        "JsonCalendarEvents",
        &payload,
        session,
        fetcher,
    )
    .await;
    map_calendar_response(response).await
}

/// Request body for `POST /api/frickmail/v1/calendars/events`. Field names
/// mirror the legacy `JsonCalendarSave` payload (`_calendar` stays
/// `calendar` here); `id` selects update mode, matching the legacy
/// composite `calendar:raw` convention. Required-field validation stays in
/// the native handler so both surfaces share it.
#[derive(Debug, Deserialize, Default)]
struct CalendarSaveRequest {
    #[serde(default)]
    account_id: Option<i64>,
    #[serde(default)]
    calendar: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    all_day: Option<bool>,
    #[serde(default)]
    id: Option<String>,
}

/// Creates or updates a calendar event through the selected or explicit
/// account, reusing the exact provider pipeline as legacy
/// `JsonCalendarSave`. State-changing, so the connection token is required.
async fn calendar_save_event(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<axum::extract::Json<CalendarSaveRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    calendar_save_event_with_fetcher(&state, &session, &headers, body, &|request| {
        super::calendar::calendar_http_via_reqwest(request)
    })
    .await
}

async fn calendar_save_event_with_fetcher<F, Fut>(
    state: &AppState,
    session: &fm_session::Session,
    headers: &axum::http::HeaderMap,
    body: Result<axum::extract::Json<CalendarSaveRequest>, axum::extract::rejection::JsonRejection>,
    fetcher: &F,
) -> Response
where
    F: Fn(super::calendar::CalendarHttpRequest) -> Fut,
    Fut: std::future::Future<
        Output = Result<super::calendar::CalendarHttpResponse, fm_core::FrickmailError>,
    >,
{
    if let Err(response) = v1_require_token(state, session, headers).await {
        return response;
    }
    if state.db_pool().is_none() {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    }
    let Ok(axum::extract::Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid calendar event body",
        );
    };
    let mut payload = calendar_account_payload(request.account_id);
    if let Some(calendar) = request.calendar {
        payload["_calendar"] = json!(calendar);
    }
    for (key, value) in [
        ("title", request.title),
        ("start", request.start),
        ("end", request.end),
        ("description", request.description),
        ("location", request.location),
        ("id", request.id),
    ] {
        if let Some(value) = value {
            payload[key] = json!(value);
        }
    }
    if let Some(all_day) = request.all_day {
        payload["allDay"] = json!(all_day);
    }
    let response = super::calendar::native_frickmail_calendar_save_with_fetcher(
        state,
        "JsonCalendarSave",
        &payload,
        session,
        fetcher,
    )
    .await;
    map_calendar_response(response).await
}

/// Deletes a calendar event through the selected or explicit account,
/// reusing the exact provider pipeline as legacy `JsonCalendarDelete`
/// (410 Gone counts as deleted). State-changing, so the connection token
/// is required.
async fn calendar_delete_event(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    calendar_delete_event_with_fetcher(&state, &session, &headers, query, &|request| {
        super::calendar::calendar_http_via_reqwest(request)
    })
    .await
}

async fn calendar_delete_event_with_fetcher<F, Fut>(
    state: &AppState,
    session: &fm_session::Session,
    headers: &axum::http::HeaderMap,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
    fetcher: &F,
) -> Response
where
    F: Fn(super::calendar::CalendarHttpRequest) -> Fut,
    Fut: std::future::Future<
        Output = Result<super::calendar::CalendarHttpResponse, fm_core::FrickmailError>,
    >,
{
    if let Err(response) = v1_require_token(state, session, headers).await {
        return response;
    }
    if state.db_pool().is_none() {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    }
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid calendar delete query",
        );
    };
    let mut payload = calendar_account_payload(
        params
            .get("account_id")
            .and_then(|value| value.parse::<i64>().ok()),
    );
    if let Some(id) = params.get("id") {
        payload["id"] = json!(id);
    }
    if let Some(calendar) = params.get("calendar") {
        payload["_calendar"] = json!(calendar);
    }
    let response = super::calendar::native_frickmail_calendar_delete_with_fetcher(
        state,
        "JsonCalendarDelete",
        &payload,
        session,
        fetcher,
    )
    .await;
    map_calendar_response(response).await
}

/// Query parameters for `GET /api/frickmail/v1/messages/{uid}`.
#[derive(Debug, Deserialize, Default)]
struct MessageQuery {
    #[serde(default)]
    folder: String,
    #[serde(default)]
    account_id: Option<i64>,
}

/// Reads one full message over IMAP, assembling the exact legacy
/// `Object/Message` value (shared `legacy_message_body_value`, including
/// signature auto-verification) inside v1 `data`. Thread expansion and HTTP
/// conditional caching stay on the legacy dispatcher for now.
async fn message(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    path: Result<axum::extract::Path<u32>, axum::extract::rejection::PathRejection>,
    query: Result<axum::extract::Query<MessageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    message_with_fetcher(
        &state,
        &session,
        path,
        query,
        super::MESSAGE_BODY_FETCH_DEADLINE,
        |config, password, folder, uid| async move {
            fm_imap::fetch_message_body_preview(config, &password, &folder, uid).await
        },
    )
    .await
}

async fn message_with_fetcher<F, Fut>(
    state: &AppState,
    session: &fm_session::Session,
    path: Result<axum::extract::Path<u32>, axum::extract::rejection::PathRejection>,
    query: Result<axum::extract::Query<MessageQuery>, axum::extract::rejection::QueryRejection>,
    fetch_deadline: std::time::Duration,
    fetcher: F,
) -> Response
where
    F: FnOnce(fm_imap::ImapConnectionConfig, String, String, u32) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Option<Vec<fm_imap::BodyPreviewPart>>>>,
{
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
    let Ok(axum::extract::Path(uid)) = path else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid message uid",
        );
    };
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid message query",
        );
    };
    if uid == 0 || params.folder.trim().is_empty() {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "A folder query parameter and nonzero uid are required",
        );
    }
    let account_id = match params.account_id.filter(|id| *id > 0) {
        Some(account_id) => account_id,
        None => match session
            .get::<fm_core::SelectedMailAccountSession>(fm_session::SELECTED_ACCOUNT_SESSION_KEY)
            .await
        {
            Ok(Some(selected)) if selected.account_id > 0 => selected.account_id,
            Ok(_) => {
                return v1_error(
                    StatusCode::BAD_REQUEST,
                    "account_required",
                    "An account_id query parameter or selected account is required",
                )
            }
            Err(_) => {
                return v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session_error",
                    "Frickmail session read failed",
                )
            }
        },
    };
    let credential_key = match v1_session_credential_key(session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };
    let account = match fm_user::SqlxUserRepository::get_mail_account_connection_secret(
        pool,
        user.user_id,
        account_id,
    )
    .await
    {
        Ok(Some(account)) => account,
        Ok(None) => {
            return v1_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Mail account not found",
            )
        }
        Err(err) => {
            tracing::warn!("v1 message account lookup failed: {}", err.public_message());
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail account lookup failed",
            );
        }
    };
    let password = match super::account_password(&account, &credential_key) {
        Ok(password) => password,
        Err(_) => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_account",
                "Mail account credentials are unavailable",
            )
        }
    };
    let imap_config = match super::imap_config_from_account_secret(&account) {
        Ok(config) => config,
        Err(err) => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_account",
                err.public_message(),
            )
        }
    };
    let auto_verify = super::effective_auto_verify_signatures(state).await;
    let pgp_verify_connection = auto_verify.then(|| {
        (
            imap_config.clone(),
            password.clone(),
            params.folder.clone(),
            uid,
        )
    });

    let result = tokio::time::timeout(
        fetch_deadline,
        fetcher(imap_config, password, params.folder.clone(), uid),
    )
    .await
    .map_err(|_| fm_core::FrickmailError::Upstream("Message fetch timed out".to_string()));
    let parts = match result {
        Ok(Ok(Some(parts))) => parts,
        Ok(Ok(None)) => {
            return v1_error(
                StatusCode::NOT_FOUND,
                "message_not_found",
                "Message not found",
            )
        }
        Ok(Err(err)) | Err(err) => {
            tracing::warn!("v1 message fetch failed: {}", err.public_message());
            return v1_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Mail server message fetch failed",
            );
        }
    };

    let pgp_signed = parts.iter().find_map(|part| {
        (!part.crypto.is_empty())
            .then_some(&part.crypto)
            .and_then(|crypto| crypto.pgp_signed.clone())
    });
    let (smime, pgp_fingerprint) =
        tokio::time::timeout(super::MESSAGE_AUTO_VERIFY_DEADLINE, async {
            tokio::join!(
                super::legacy_message_smime_auto_verify(&parts, auto_verify),
                async {
                    let (signed, connection) = match (pgp_signed, pgp_verify_connection) {
                        (Some(signed), Some((vconfig, vpassword, vfolder, vuid))) => {
                            (signed, (vconfig, vpassword, vfolder, vuid))
                        }
                        _ => return None,
                    };
                    super::legacy_message_pgp_auto_verify(
                        state,
                        user.user_id,
                        connection.0,
                        &connection.1,
                        &connection.2,
                        connection.3,
                        &signed,
                    )
                    .await
                }
            )
        })
        .await
        .unwrap_or_else(|_| {
            tracing::warn!(
                "v1 message auto-verification timed out; rendering unverified signatures"
            );
            (None, None)
        });
    let durable_receipt_suppressed =
        super::legacy_read_receipt_cached(pool, user.user_id, account_id, &params.folder, uid)
            .await
            .unwrap_or(false);
    match super::legacy_message_body_value(
        &params.folder,
        uid,
        parts,
        &[],
        &[],
        durable_receipt_suppressed,
        super::LegacyMessageAutoVerify {
            smime,
            pgp_fingerprint,
        },
    ) {
        Some(message) => (StatusCode::OK, Json(ApiV1Envelope::ok(message))).into_response(),
        None => v1_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unparseable_message",
            "Message body could not be parsed",
        ),
    }
}

/// Lists one mail account's filter rules, reusing the exact repository query
/// as legacy `FrickmailListRules`. Unlike identities (which return `[]` for
/// foreign accounts), the repository rejects unknown accounts, so those map
/// to 404 `account_not_found` here. The `MailRule` shape carries no secrets.
async fn rules(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    query: Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid rules query",
        );
    };
    let account_id = match params
        .get("account_id")
        .map(|value| value.parse::<i64>())
        .transpose()
        .ok()
        .flatten()
        .filter(|id| *id > 0)
    {
        Some(account_id) => account_id,
        None => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "A positive account_id query parameter is required",
            )
        }
    };
    match fm_user::SqlxUserRepository::list_mail_rules(pool, user_id, account_id).await {
        Ok(rules) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "rules": rules }))),
        )
            .into_response(),
        Err(fm_core::FrickmailError::BadRequest(message)) if message == "Account not found" => {
            v1_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Mail account not found",
            )
        }
        Err(err) => {
            tracing::warn!("v1 rules listing failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail rules listing failed",
            )
        }
    }
}

/// Reads the authenticated user's merged preferences, reusing the exact
/// repository query as legacy `FrickmailGetPrefs`. GET-only, so no CSRF
/// check applies.
async fn get_preferences(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
) -> Response {
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    match fm_user::SqlxUserRepository::preferences(pool, user_id).await {
        Ok(Some(prefs)) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "preferences": prefs }))),
        )
            .into_response(),
        Ok(None) => v1_error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "No authenticated Frickmail session",
        ),
        Err(err) => {
            tracing::warn!("v1 preferences lookup failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail preferences lookup failed",
            )
        }
    }
}

/// Applies a validated preferences patch, reusing the exact schema-driven
/// cleaning as legacy `FrickmailSetPrefs` (unknown keys dropped, values
/// clamped/coerced). State-changing, so the connection token is required.
async fn set_preferences(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(Json(body)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid preferences request",
        );
    };
    let patch = body.get("preferences").unwrap_or(&Value::Null);
    match fm_user::SqlxUserRepository::update_preferences(pool, user_id, patch).await {
        Ok(Some(prefs)) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "preferences": prefs }))),
        )
            .into_response(),
        Ok(None) => v1_error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "No authenticated Frickmail session",
        ),
        Err(err) => {
            tracing::warn!("v1 preferences update failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail preferences update failed",
            )
        }
    }
}

/// Resolves the session user id for v1 handlers: store failures are 500s,
/// absent sessions are 401s.
async fn v1_session_user_id(session: &fm_session::Session) -> Result<i64, Response> {
    match session
        .get::<UserSession>(fm_session::USER_SESSION_KEY)
        .await
    {
        Ok(Some(user)) => Ok(user.user_id),
        Ok(None) => Err(v1_error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "No authenticated Frickmail session",
        )),
        Err(_) => Err(v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session_error",
            "Frickmail session read failed",
        )),
    }
}

/// Reads and validates the session credential key, mirroring legacy
/// `load_session_credential_key` status mapping (store failure → 500,
/// missing or malformed key → 401).
async fn v1_session_credential_key(session: &fm_session::Session) -> Result<Vec<u8>, Response> {
    let encoded = match session
        .get::<String>(fm_session::CREDENTIAL_KEY_SESSION_KEY)
        .await
    {
        Ok(encoded) => encoded,
        Err(_) => {
            return Err(v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "session_error",
                "Frickmail session read failed",
            ));
        }
    };
    match encoded {
        Some(encoded) => {
            use base64::Engine as _;
            match base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .ok()
                .filter(|key| key.len() == fm_user::CREDENTIAL_KEY_BYTES)
            {
                Some(credential_key) => Ok(credential_key),
                None => Err(v1_error(
                    StatusCode::UNAUTHORIZED,
                    "unauthenticated",
                    "No authenticated Frickmail session",
                )),
            }
        }
        None => Err(v1_error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "No authenticated Frickmail session",
        )),
    }
}

/// Switches the selected mail account for this session, reusing the legacy
/// ownership check (`user_id`-scoped lookup), credential-material validation
/// (decryptable password / OAuth token, no network), and account-scoped
/// connection-token refresh. The fresh `csrf_token` is returned because
/// switched scopes invalidate the previous token.
///
/// Intentional deviation from legacy `FrickmailSwitchAccount`: no live
/// IMAP/OAuth probe happens here. v1 separates session selection from
/// transport health, which surfaces on first mailbox use instead.
async fn switch_account(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<Json<SwitchAccountRequest>, JsonRejection>,
) -> Response {
    // Token before identity, mirroring the legacy dispatcher (which rejects
    // tokenless POSTs before routing to the action handler).
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
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
    let Ok(Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid switch-account request",
        );
    };
    if request.account_id <= 0 {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "A positive account_id is required",
        );
    }
    let credential_key = match v1_session_credential_key(&session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };
    let account = match fm_user::SqlxUserRepository::get_mail_account_connection_secret(
        pool,
        user.user_id,
        request.account_id,
    )
    .await
    {
        Ok(Some(account)) => account,
        Ok(None) => {
            return v1_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Mail account not found",
            )
        }
        Err(err) => {
            tracing::warn!("v1 switch-account lookup failed: {}", err.public_message());
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail account lookup failed",
            );
        }
    };
    if let Err(message) = super::mail_account_bridge_validation(&account, &credential_key)
        .map(|_| ())
        .map_err(|err| err.public_message())
    {
        return v1_error(StatusCode::BAD_REQUEST, "invalid_account", message);
    }
    if let Err(err) = session
        .insert(
            fm_session::SELECTED_ACCOUNT_SESSION_KEY,
            fm_core::SelectedMailAccountSession {
                account_id: request.account_id,
            },
        )
        .await
    {
        tracing::warn!("v1 switch-account store failed: {err}");
        return v1_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Frickmail account switch failed",
        );
    }
    let token =
        match super::ensure_connection_token(&state, &session, Some(request.account_id)).await {
            Ok(token) => token,
            Err(_) => {
                return v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Frickmail account switch failed",
                );
            }
        };
    (
        StatusCode::OK,
        Json(ApiV1Envelope::ok(json!({
            "switched": true,
            "account": {
                "id": account.id,
                "email": account.email,
            },
            "csrf_token": token,
        }))),
    )
        .into_response()
}

/// Query parameters for `GET /api/frickmail/v1/messages`. Thread views are
/// not exposed yet (follow-up with the selected-thread UX); the remaining
/// fields mirror the legacy `MessageList` payload keys exactly so the
/// request builder below stays parity-by-construction.
#[derive(Debug, Default, Deserialize)]
struct MessagesQuery {
    #[serde(default)]
    folder: String,
    #[serde(default)]
    account_id: Option<i64>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    offset: Option<u32>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    sort: Option<String>,
}

/// Lists one mailbox folder over IMAP for the explicit or selected account,
/// reusing the legacy `MessageList` request normalization (limit clamping,
/// search/sort trimming, per-user hide-deleted and domain search settings).
/// Read-receipt durable suppression and HTTP conditional caching stay on the
/// legacy dispatcher for now; the UID cache is bypassed (correctness is
/// unaffected, only repeated full fetches cost more).
async fn messages(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    query: Result<axum::extract::Query<MessagesQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    messages_with_fetcher(
        &state,
        &session,
        query,
        super::MESSAGE_LIST_DEADLINE,
        |config, password, request| async move {
            fm_imap::fetch_legacy_message_list(config, &password, request).await
        },
    )
    .await
}

async fn messages_with_fetcher<F, Fut>(
    state: &AppState,
    session: &fm_session::Session,
    query: Result<axum::extract::Query<MessagesQuery>, axum::extract::rejection::QueryRejection>,
    fetch_deadline: std::time::Duration,
    fetcher: F,
) -> Response
where
    F: FnOnce(fm_imap::ImapConnectionConfig, String, fm_imap::LegacyMessageListRequest) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<fm_imap::LegacyMessageList>>,
{
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
    let Ok(axum::extract::Query(params)) = query else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid messages query",
        );
    };
    if params.folder.trim().is_empty() {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "A folder query parameter is required",
        );
    }
    let account_id = match params.account_id.filter(|id| *id > 0) {
        Some(account_id) => account_id,
        None => match session
            .get::<fm_core::SelectedMailAccountSession>(fm_session::SELECTED_ACCOUNT_SESSION_KEY)
            .await
        {
            Ok(Some(selected)) if selected.account_id > 0 => selected.account_id,
            Ok(_) => {
                return v1_error(
                    StatusCode::BAD_REQUEST,
                    "account_required",
                    "An account_id query parameter or selected account is required",
                )
            }
            Err(_) => {
                return v1_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session_error",
                    "Frickmail session read failed",
                )
            }
        },
    };
    let credential_key = match v1_session_credential_key(session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };
    let account = match fm_user::SqlxUserRepository::get_mail_account_connection_secret(
        pool,
        user.user_id,
        account_id,
    )
    .await
    {
        Ok(Some(account)) => account,
        Ok(None) => {
            return v1_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Mail account not found",
            )
        }
        Err(err) => {
            tracing::warn!(
                "v1 messages account lookup failed: {}",
                err.public_message()
            );
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail account lookup failed",
            );
        }
    };
    let password = match super::account_password(&account, &credential_key) {
        Ok(password) => password,
        Err(_) => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_account",
                "Mail account credentials are unavailable",
            )
        }
    };
    let imap_config = match super::imap_config_from_account_secret(&account) {
        Ok(config) => config,
        Err(err) => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_account",
                err.public_message(),
            )
        }
    };
    // Synthesize the legacy payload shape (omitting absent keys so the
    // shared normalization — limit defaults and clamping, search/sort
    // trimming — applies exactly as on the legacy dispatcher).
    let mut payload = serde_json::Map::new();
    payload.insert("folder".to_string(), json!(params.folder));
    if let Some(limit) = params.limit {
        payload.insert("limit".to_string(), json!(limit));
    }
    if let Some(offset) = params.offset {
        payload.insert("offset".to_string(), json!(offset));
    }
    if let Some(search) = params.search {
        payload.insert("search".to_string(), json!(search));
    }
    if let Some(sort) = params.sort {
        payload.insert("sort".to_string(), json!(sort));
    }
    let payload = Value::Object(payload);
    let mut request = match super::legacy_message_list_request_from_payload(&payload) {
        Ok(request) => request,
        Err(message) => return v1_error(StatusCode::BAD_REQUEST, "invalid_request", message),
    };
    request.hide_deleted = match fm_user::SqlxUserRepository::find_by_id(pool, user.user_id).await {
        Ok(Some(owner)) => super::legacy_message_list_hide_deleted_from_settings(&owner.settings),
        Ok(None) => {
            return v1_error(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "No authenticated Frickmail session",
            )
        }
        Err(err) => {
            tracing::warn!(
                "v1 messages settings lookup failed: {}",
                err.public_message()
            );
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail settings lookup failed",
            );
        }
    };
    (request.fast_simple_search, request.permanent_filter) = state
        .config()
        .mail
        .message_list_search_settings(&account.email);
    request.message_list_limit = state.config().mail.message_list_limit(&account.email);

    let result = tokio::time::timeout(fetch_deadline, fetcher(imap_config, password, request))
        .await
        .map_err(|_| fm_core::FrickmailError::Upstream("Message list fetch timed out".to_string()));
    match result {
        Ok(Ok(list)) => (StatusCode::OK, Json(ApiV1Envelope::ok(list))).into_response(),
        Ok(Err(err)) | Err(err) => {
            tracing::warn!("v1 messages fetch failed: {}", err.public_message());
            v1_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Mail server message listing failed",
            )
        }
    }
}

/// Lists one mail account's identities, reusing the exact repository query
/// as legacy `FrickmailListIdentities`. Scoping is strict (`user_id` plus
/// `account_id`, mirroring legacy): other users' accounts yield an empty
/// list, never an error and never foreign rows. The `MailIdentity` shape
/// carries no secrets.
async fn identities(
    state: axum::extract::State<AppState>,
    session: fm_session::Session,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
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
    let account_id = match params
        .get("account_id")
        .map(|value| value.parse::<i64>())
        .transpose()
        .ok()
        .flatten()
        .filter(|id| *id > 0)
    {
        Some(account_id) => account_id,
        None => {
            return v1_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "A positive account_id query parameter is required",
            )
        }
    };
    match fm_user::SqlxUserRepository::list_mail_identities(pool, user.user_id, account_id).await {
        Ok(identities) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "identities": identities }))),
        )
            .into_response(),
        Err(err) => {
            tracing::warn!("v1 identities listing failed: {}", err.public_message());
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail identities listing failed",
            )
        }
    }
}

/// Maps sender-identity repository errors onto the v1 contract: unknown
/// account/identity 404, validation problems 400, everything else 500
/// with a generic message.
fn identity_error(err: fm_core::FrickmailError, action: &'static str) -> Response {
    match err {
        fm_core::FrickmailError::BadRequest(message)
            if message == "Account not found" || message == "Identity not found" =>
        {
            v1_error(
                StatusCode::NOT_FOUND,
                if message == "Account not found" {
                    "account_not_found"
                } else {
                    "identity_not_found"
                },
                if message == "Account not found" {
                    "Mail account not found"
                } else {
                    "Sender identity not found"
                },
            )
        }
        fm_core::FrickmailError::BadRequest(_) => v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid sender identity request",
        ),
        _ => {
            tracing::warn!("v1 {action} failed");
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail sender identity request failed",
            )
        }
    }
}

/// Request body for `POST /api/frickmail/v1/identities`. Field names mirror
/// the legacy `FrickmailAddIdentity` payload; name and email are required
/// (the repository validates the rest).
#[derive(Debug, Deserialize, Default)]
struct MailIdentityWriteRequest {
    #[serde(default)]
    account_id: Option<i64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    reply_to: Option<String>,
    #[serde(default)]
    is_default: Option<bool>,
}

/// Adds a sender identity to one of the caller's accounts, reusing the
/// exact repository call as legacy `FrickmailAddIdentity`. State-changing,
/// so the connection token is required.
async fn add_identity(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<
        axum::extract::Json<MailIdentityWriteRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid sender identity body",
        );
    };
    match fm_user::SqlxUserRepository::add_mail_identity(
        pool,
        user_id,
        fm_user::NewMailIdentity {
            account_id: request.account_id.unwrap_or(0),
            name: request.name.unwrap_or_default(),
            email: request.email.unwrap_or_default(),
            reply_to: request.reply_to,
            is_default: request.is_default.unwrap_or(false),
        },
    )
    .await
    {
        Ok(id) => (StatusCode::OK, Json(ApiV1Envelope::ok(json!({ "id": id })))).into_response(),
        Err(err) => identity_error(err, "identity creation"),
    }
}

/// Deletes one of the caller's sender identities. Unknown ids 404 via a
/// user-scoped ownership check (the repository deletes by key without
/// confirming a row matched).
async fn delete_identity(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    path: Result<axum::extract::Path<i64>, axum::extract::rejection::PathRejection>,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Path(id)) = path else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid sender identity id",
        );
    };
    match fm_user::SqlxUserRepository::mail_identity_exists(pool, user_id, id).await {
        Ok(true) => {}
        Ok(false) => {
            return v1_error(
                StatusCode::NOT_FOUND,
                "identity_not_found",
                "Sender identity not found",
            )
        }
        Err(err) => {
            tracing::warn!("v1 identity lookup failed: {}", err.public_message());
            return v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail sender identity request failed",
            );
        }
    }
    match fm_user::SqlxUserRepository::delete_mail_identity(pool, user_id, id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "ok": true }))),
        )
            .into_response(),
        Err(err) => identity_error(err, "identity delete"),
    }
}

/// Marks one of the caller's sender identities default. Unknown ids 404
/// (the repository verifies ownership itself).
async fn set_default_identity(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    path: Result<axum::extract::Path<i64>, axum::extract::rejection::PathRejection>,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Path(id)) = path else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid sender identity id",
        );
    };
    match fm_user::SqlxUserRepository::set_default_mail_identity(pool, user_id, id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "ok": true }))),
        )
            .into_response(),
        Err(err) => identity_error(err, "set default identity"),
    }
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

/// Maps mail-account repository errors onto the v1 contract: unknown
/// accounts 404, validation problems 400, everything else 500 with a
/// generic message.
fn account_error(err: fm_core::FrickmailError, action: &'static str) -> Response {
    match err {
        fm_core::FrickmailError::BadRequest(message) if message == "Account not found" => v1_error(
            StatusCode::NOT_FOUND,
            "account_not_found",
            "Mail account not found",
        ),
        fm_core::FrickmailError::BadRequest(_) => v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid mail account request",
        ),
        _ => {
            tracing::warn!("v1 {action} failed");
            v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail mail account request failed",
            )
        }
    }
}

/// User-scoped existence check so unknown ids 404 instead of silently
/// succeeding (the repository deletes/updates by key without confirming
/// a row matched, mirroring legacy `ok:true` semantics).
async fn v1_own_account(
    pool: &sqlx::AnyPool,
    user_id: i64,
    account_id: i64,
) -> Result<bool, Response> {
    match fm_user::SqlxUserRepository::list_mail_accounts(pool, user_id).await {
        Ok(accounts) => Ok(accounts.iter().any(|account| account.id == account_id)),
        Err(err) => {
            tracing::warn!("v1 account lookup failed: {}", err.public_message());
            Err(v1_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Frickmail mail account request failed",
            ))
        }
    }
}

/// Request body for `POST /api/frickmail/v1/accounts`. Field names mirror
/// the legacy `FrickmailAddAccount` payload; `email` is the only required
/// field (the repository validates the rest).
#[derive(Debug, Deserialize, Default)]
struct MailAccountWriteRequest {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    account_type: Option<String>,
    #[serde(default)]
    imap_host: Option<String>,
    #[serde(default)]
    imap_port: Option<i64>,
    #[serde(default)]
    imap_secure: Option<String>,
    #[serde(default)]
    smtp_host: Option<String>,
    #[serde(default)]
    smtp_port: Option<i64>,
    #[serde(default)]
    smtp_secure: Option<String>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    is_primary: Option<bool>,
}

/// Adds a mail account, encrypting secrets with the session credential
/// key exactly like legacy `FrickmailAddAccount` (first account becomes
/// primary). Credential-bearing write, so the connection token is
/// required.
async fn add_account(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    body: Result<
        axum::extract::Json<MailAccountWriteRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let credential_key = match v1_session_credential_key(&session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid mail account body",
        );
    };
    match fm_user::SqlxUserRepository::add_mail_account(
        pool,
        user_id,
        fm_user::NewMailAccount {
            label: request.label,
            email: request.email.unwrap_or_default(),
            account_type: request.account_type.unwrap_or_else(|| "imap".to_string()),
            imap_host: request.imap_host,
            imap_port: request.imap_port,
            imap_secure: request.imap_secure,
            smtp_host: request.smtp_host,
            smtp_port: request.smtp_port,
            smtp_secure: request.smtp_secure,
            login: request.login,
            password: request.password,
            oauth_tenant: request.tenant,
            is_primary: request.is_primary.unwrap_or(false),
        },
        &credential_key,
    )
    .await
    {
        Ok(id) => (StatusCode::OK, Json(ApiV1Envelope::ok(json!({ "id": id })))).into_response(),
        Err(err) => account_error(err, "account creation"),
    }
}

/// Updates a mail account; an empty password preserves the stored one,
/// mirroring legacy `FrickmailUpdateAccount`. Unknown ids 404.
async fn update_account(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    path: Result<axum::extract::Path<i64>, axum::extract::rejection::PathRejection>,
    body: Result<
        axum::extract::Json<MailAccountWriteRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let credential_key = match v1_session_credential_key(&session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Path(id)) = path else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid mail account id",
        );
    };
    let Ok(axum::extract::Json(request)) = body else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid mail account body",
        );
    };
    match fm_user::SqlxUserRepository::update_mail_account(
        pool,
        user_id,
        fm_user::UpdateMailAccount {
            id,
            label: request.label,
            imap_host: request.imap_host,
            imap_port: request.imap_port,
            imap_secure: request.imap_secure,
            smtp_host: request.smtp_host,
            smtp_port: request.smtp_port,
            smtp_secure: request.smtp_secure,
            login: request.login,
            password: request.password,
        },
        &credential_key,
    )
    .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "ok": true }))),
        )
            .into_response(),
        Err(err) => account_error(err, "account update"),
    }
}

/// Deletes a mail account (and its indexed messages, like legacy
/// `FrickmailDeleteAccount`). Unknown ids 404 via an ownership check.
async fn delete_account(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    path: Result<axum::extract::Path<i64>, axum::extract::rejection::PathRejection>,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Path(id)) = path else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid mail account id",
        );
    };
    match v1_own_account(pool, user_id, id).await {
        Ok(true) => {}
        Ok(false) => {
            return v1_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Mail account not found",
            )
        }
        Err(response) => return response,
    }
    match fm_user::SqlxUserRepository::delete_mail_account(pool, user_id, id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "ok": true }))),
        )
            .into_response(),
        Err(err) => account_error(err, "account delete"),
    }
}

/// Marks an account primary. Unknown ids 404 via an ownership check.
async fn set_primary_account(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: fm_session::Session,
    headers: axum::http::HeaderMap,
    path: Result<axum::extract::Path<i64>, axum::extract::rejection::PathRejection>,
) -> Response {
    if let Err(response) = v1_require_token(&state, &session, &headers).await {
        return response;
    }
    let user_id = match v1_session_user_id(&session).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(pool) = state.db_pool() else {
        return v1_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unconfigured",
            "Frickmail database is not configured",
        );
    };
    let Ok(axum::extract::Path(id)) = path else {
        return v1_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid mail account id",
        );
    };
    match v1_own_account(pool, user_id, id).await {
        Ok(true) => {}
        Ok(false) => {
            return v1_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Mail account not found",
            )
        }
        Err(response) => return response,
    }
    match fm_user::SqlxUserRepository::set_primary_mail_account(pool, user_id, id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(ApiV1Envelope::ok(json!({ "ok": true }))),
        )
            .into_response(),
        Err(err) => account_error(err, "set primary"),
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

#[derive(Debug, Deserialize)]
struct SwitchAccountRequest {
    #[serde(default)]
    account_id: i64,
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

    if let Err(response) = v1_require_token(&state, &session, &headers).await {
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

/// Connection-token check for state-changing v1 routes. Unlike the read-only
/// GET helper, these always require the token once CSRF is enabled: legacy
/// POSTs 403 without one, and the bootstrap (`GET /api/frickmail/v1/session`,
/// legacy AppData) always mints a secret first.
/// Only the `X-SM-Token` header is honored (intentional: v1 is strict JSON,
/// while the legacy `XToken` form field stays on the old dispatcher).
async fn v1_require_token(
    state: &AppState,
    session: &fm_session::Session,
    headers: &axum::http::HeaderMap,
) -> Result<(), Response> {
    if !state.config().security.csrf_enabled || state.config().php_bridge_url.is_some() {
        return Ok(());
    }
    v1_require_connection_token(session, headers).await
}

async fn v1_require_connection_token(
    session: &fm_session::Session,
    headers: &axum::http::HeaderMap,
) -> Result<(), Response> {
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
    use base64::Engine as _;
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
            external_login_enabled: false,
            proxy_auth: Default::default(),
            remote_auto_login: Default::default(),
            cpanel_auto_login: Default::default(),
            external_sso: Default::default(),
            oidc: Default::default(),
            oauth2: Default::default(),
            mail: Default::default(),
            cache: Default::default(),
            frickmail_user: Default::default(),
            transactional_smtp: Default::default(),
            hibp: Default::default(),
            avatar: Default::default(),
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

    async fn read_body(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec()
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

    async fn seed_identity_full(
        pool: &sqlx::AnyPool,
        id: i64,
        user_id: i64,
        account_id: i64,
        name: &str,
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
        .bind(id == 401)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn v1_identities_lists_account_scoped_identities() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 301, "v1ident", "correct-horse", None).await;
        seed_mail_account(&pool, 500, 301, "Work").await;
        seed_identity_full(&pool, 401, 301, 500, "Sender").await;
        seed_identity_full(&pool, 402, 301, 500, "Alias").await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1ident", "correct-horse").await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/identities?account_id=500")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        let identities = body["data"]["identities"].as_array().unwrap();
        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0]["name"], "Sender");
        assert_eq!(identities[0]["email"], "sender@example.com");
        assert_eq!(identities[0]["account_id"], 500);
    }

    #[tokio::test]
    async fn v1_identities_isolates_foreign_accounts_and_validates_input() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 302, "v1owner", "correct-horse", None).await;
        seed_login_user(&pool, 303, "v1stranger", "correct-horse", None).await;
        seed_mail_account(&pool, 501, 302, "Owner").await;
        seed_identity_full(&pool, 403, 302, 501, "OwnerName").await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1stranger", "correct-horse").await;

        // Another user's account yields an empty list, never foreign rows.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/identities?account_id=501")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["identities"].as_array().unwrap().len(), 0);

        // Missing, non-numeric, and non-positive account ids are rejected.
        for uri in [
            "/api/frickmail/v1/identities",
            "/api/frickmail/v1/identities?account_id=abc",
            "/api/frickmail/v1/identities?account_id=0",
            "/api/frickmail/v1/identities?account_id=-5",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
            let body = read_json(response).await;
            assert_eq!(body["error"]["code"], "invalid_request", "{uri}");
        }

        // Anonymous callers are rejected.
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/identities?account_id=501")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    async fn seed_imap_account_with_password(
        pool: &sqlx::AnyPool,
        id: i64,
        user_id: i64,
        password: &[u8],
    ) {
        sqlx::query(
            "INSERT INTO frickmail_mail_accounts
                (id, user_id, label, email, type, imap_host, imap_port, imap_secure,
                 smtp_host, smtp_port, smtp_secure, login, encrypted_password,
                 encrypted_oauth_refresh_token, oauth_tenant, is_primary, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(user_id)
        .bind("Switchable")
        .bind("switchable@example.com")
        .bind("imap")
        .bind("imap.example.com")
        .bind(993_i64)
        .bind("SSL")
        .bind("smtp.example.com")
        .bind(465_i64)
        .bind("SSL")
        .bind("switchable@example.com")
        .bind(password.to_vec())
        .bind(None::<Vec<u8>>)
        .bind(None::<String>)
        .bind(true)
        .execute(pool)
        .await
        .unwrap();
    }

    fn switch_request(cookie: &str, token: Option<&str>, account_id: i64) -> Request<Body> {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/frickmail/v1/switch-account")
            .header("content-type", "application/json")
            .header("cookie", cookie);
        if let Some(token) = token {
            request = request.header("x-sm-token", token);
        }
        request
            .body(Body::from(
                serde_json::json!({"account_id": account_id}).to_string(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn v1_switch_account_switches_and_refreshes_token() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 401, "v1switch", "correct-horse", None).await;
        let credential_key =
            fm_user::derive_credential_key("correct-horse", &[9_u8; fm_user::KDF_SALT_BYTES])
                .unwrap();
        let blob = fm_user::encrypt_account_secret("imap-secret", &credential_key).unwrap();
        seed_imap_account_with_password(&pool, 600, 401, &blob).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1switch", "correct-horse").await;

        let response = app
            .clone()
            .oneshot(switch_request(&cookie, Some(&token), 600))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let cookie = session_cookie(&response);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["switched"], true);
        assert_eq!(body["data"]["account"]["id"], 600);
        assert_eq!(body["data"]["account"]["email"], "switchable@example.com");
        let switched_token = body["data"]["csrf_token"].as_str().unwrap();
        assert!(switched_token.starts_with("600-"), "{switched_token}");

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
        let body = read_json(response).await;
        assert_eq!(body["data"]["selected_account_id"], 600);
    }

    #[tokio::test]
    async fn v1_switch_account_rejects_unknown_foreign_and_broken_accounts() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 402, "v1switcher", "correct-horse", None).await;
        seed_login_user(&pool, 403, "v1bystander", "correct-horse", None).await;
        seed_mail_account(&pool, 601, 403, "Foreign").await;
        seed_mail_account(&pool, 602, 402, "Broken").await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1switcher", "correct-horse").await;

        // Unknown account id.
        let response = app
            .clone()
            .oneshot(switch_request(&cookie, Some(&token), 999_999))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "account_not_found");

        // Another user's account: scoped lookup finds nothing.
        let response = app
            .clone()
            .oneshot(switch_request(&cookie, Some(&token), 601))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "account_not_found");

        // Undecryptable stored credentials: dummy bytes cannot decode.
        let response = app
            .oneshot(switch_request(&cookie, Some(&token), 602))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_account");
    }

    #[tokio::test]
    async fn v1_switch_account_requires_auth_and_token() {
        let pool = login_db_pool().await;
        let app = login_app(pool);

        // Token is checked before identity, mirroring the legacy dispatcher:
        // even anonymous callers get 403 without a token.
        let response = app
            .clone()
            .oneshot(switch_request("", None, 600))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let response = app
            .clone()
            .oneshot(switch_request(&cookie, None, 600))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_token");

        // A valid token still cannot switch without an authenticated user.
        let response = app
            .oneshot(switch_request(&cookie, Some(&token), 600))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    fn test_message_list() -> fm_imap::LegacyMessageList {
        fm_imap::LegacyMessageList {
            folder: fm_imap::LegacyFolderInformation {
                id: None,
                name: "INBOX".to_string(),
                uid_next: Some(101),
                uid_validity: Some(1),
                total_emails: Some(2),
                unread_emails: Some(1),
                highest_modseq: None,
                append_limit: None,
                size: None,
                permanent_flags: Vec::new(),
                etag: "folder-etag".to_string(),
                messages_flags: None,
                new_messages: Vec::new(),
            },
            total_emails: 2,
            total_threads: None,
            offset: 0,
            limit: 10,
            search: String::new(),
            sort: String::new(),
            limited: false,
            thread_uid: 0,
            messages: Vec::new(),
        }
    }

    async fn authed_v1_session(user_id: i64, username: &str) -> fm_session::Session {
        use std::sync::Arc;
        let session =
            fm_session::Session::new(None, Arc::new(fm_session::MemoryStore::default()), None);
        session
            .insert(
                fm_session::USER_SESSION_KEY,
                fm_core::UserSession {
                    user_id,
                    username: username.to_string(),
                    email: Some(format!("{username}@example.com")),
                },
            )
            .await
            .unwrap();
        let credential_key =
            fm_user::derive_credential_key("correct-horse", &[9_u8; fm_user::KDF_SALT_BYTES])
                .unwrap();
        session
            .insert(
                fm_session::CREDENTIAL_KEY_SESSION_KEY,
                base64::engine::general_purpose::STANDARD.encode(credential_key),
            )
            .await
            .unwrap();
        session
    }

    #[tokio::test]
    async fn v1_messages_lists_folder_through_injected_fetcher() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 501, "v1mbox", "correct-horse", None).await;
        let credential_key =
            fm_user::derive_credential_key("correct-horse", &[9_u8; fm_user::KDF_SALT_BYTES])
                .unwrap();
        let blob = fm_user::encrypt_account_secret("imap-secret", &credential_key).unwrap();
        seed_imap_account_with_password(&pool, 700, 501, &blob).await;
        let state = AppState::with_db_pool(test_api_config(), Some(pool));
        let session = authed_v1_session(501, "v1mbox").await;

        let response = super::messages_with_fetcher(
            &state,
            &session,
            Ok(axum::extract::Query(super::MessagesQuery {
                folder: "INBOX".to_string(),
                account_id: Some(700),
                limit: None,
                offset: None,
                search: None,
                sort: None,
            })),
            std::time::Duration::from_secs(5),
            |config, _password, request| async move {
                assert_eq!(config.host, "imap.example.com");
                assert_eq!(request.mailbox, "INBOX");
                assert_eq!(request.limit, 10);
                Ok(test_message_list())
            },
        )
        .await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["total_emails"], 2);
        assert_eq!(body["data"]["folder"]["name"], "INBOX");
    }

    #[tokio::test]
    async fn v1_messages_maps_upstream_failures_to_bad_gateway() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 503, "v1mboxup", "correct-horse", None).await;
        let credential_key =
            fm_user::derive_credential_key("correct-horse", &[9_u8; fm_user::KDF_SALT_BYTES])
                .unwrap();
        let blob = fm_user::encrypt_account_secret("imap-secret", &credential_key).unwrap();
        seed_imap_account_with_password(&pool, 702, 503, &blob).await;
        let state = AppState::with_db_pool(test_api_config(), Some(pool));
        let session = authed_v1_session(503, "v1mboxup").await;

        let response = super::messages_with_fetcher(
            &state,
            &session,
            Ok(axum::extract::Query(super::MessagesQuery {
                folder: "INBOX".to_string(),
                account_id: Some(702),
                limit: None,
                offset: None,
                search: None,
                sort: None,
            })),
            std::time::Duration::from_secs(5),
            |_config, _password, _request| async move {
                Err(fm_core::FrickmailError::Upstream(
                    "imap.example.com: connection refused".to_string(),
                ))
            },
        )
        .await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["error"]["code"], "upstream_error");
        assert!(!body.to_string().contains("connection refused"));
    }

    #[tokio::test]
    async fn v1_messages_rejects_bad_requests() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 502, "v1mboxerr", "correct-horse", None).await;
        seed_mail_account(&pool, 701, 502, "Broken").await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1mboxerr", "correct-horse").await;

        // Missing folder.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/messages?account_id=701")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Malformed limit.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/messages?folder=INBOX&limit=abc")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_request");

        // Unknown account.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/messages?folder=INBOX&account_id=999999")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Undecryptable stored credentials (dummy seed bytes).
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/messages?folder=INBOX&account_id=701")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_account");

        // Anonymous callers are rejected.
        let pool = login_db_pool().await;
        let app = login_app(pool);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/messages?folder=INBOX")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn v1_preferences_round_trip_through_login() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 601, "v1prefs", "correct-horse", None).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1prefs", "correct-horse").await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/preferences")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert!(body["data"]["preferences"].is_object());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/frickmail/v1/preferences")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::from(
                        serde_json::json!({"preferences": {
                            "unified_inbox_limit": 80,
                            "bogus_key": "dropped",
                        }})
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["preferences"]["unified_inbox_limit"], 80);
        assert!(body["data"]["preferences"].get("bogus_key").is_none());

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/preferences")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;
        assert_eq!(body["data"]["preferences"]["unified_inbox_limit"], 80);
    }

    #[tokio::test]
    async fn v1_preferences_rejects_anonymous_and_tokenless_writes() {
        let pool = login_db_pool().await;
        let app = login_app(pool);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/preferences")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let (cookie, _) = bootstrap_csrf(app.clone()).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/frickmail/v1/preferences")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .body(Body::from(
                        serde_json::json!({"preferences": {"unified_inbox_limit": 80}}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_token");
    }

    async fn seed_mail_rule(pool: &sqlx::AnyPool, id: i64, user_id: i64, account_id: i64) {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS frickmail_rules (
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
        sqlx::query(
            "INSERT INTO frickmail_rules
                (id, user_id, account_id, name, conditions, actions, enabled, last_run, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(user_id)
        .bind(account_id)
        .bind("Archive newsletters")
        .bind("{\"conditions\": [], \"logic\": \"all\"}")
        .bind("{\"actions\": []}")
        .bind(true)
        .bind(None::<String>)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn v1_rules_lists_account_scoped_rules() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 701, "v1rules", "correct-horse", None).await;
        seed_mail_account(&pool, 800, 701, "Filtered").await;
        seed_mail_rule(&pool, 900, 701, 800).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1rules", "correct-horse").await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/rules?account_id=800")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        let rules = body["data"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["name"], "Archive newsletters");
        assert_eq!(rules[0]["account_id"], 800);
    }

    #[tokio::test]
    async fn v1_rules_rejects_unknown_foreign_and_bad_requests() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 702, "v1rulesother", "correct-horse", None).await;
        seed_login_user(&pool, 703, "v1rulesstranger", "correct-horse", None).await;
        seed_mail_account(&pool, 801, 702, "Owner").await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(
            app.clone(),
            &cookie,
            &token,
            "v1rulesstranger",
            "correct-horse",
        )
        .await;

        // Unknown and foreign accounts map to 404, never foreign rows.
        for uri in [
            "/api/frickmail/v1/rules?account_id=999999",
            "/api/frickmail/v1/rules?account_id=801",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            let body = read_json(response).await;
            assert_eq!(body["error"]["code"], "account_not_found", "{uri}");
        }

        // Missing and malformed account ids are 400s.
        for uri in [
            "/api/frickmail/v1/rules",
            "/api/frickmail/v1/rules?account_id=abc",
            "/api/frickmail/v1/rules?account_id=0",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }

        // Anonymous callers are rejected.
        let pool = login_db_pool().await;
        let app = login_app(pool);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/rules?account_id=801")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    fn test_message_parts() -> Vec<fm_imap::BodyPreviewPart> {
        vec![fm_imap::BodyPreviewPart {
            kind: fm_imap::BodyPartKind::RawMessage,
            raw: b"Subject: Single message\r\nFrom: Sender <sender@example.com>\r\n\r\nBody"
                .to_vec(),
            is_complete: true,
            flags: Vec::new(),
            crypto: Default::default(),
            metadata: Default::default(),
        }]
    }

    async fn message_test_state() -> (AppState, fm_session::Session, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 801, "v1msg", "correct-horse", None).await;
        let credential_key =
            fm_user::derive_credential_key("correct-horse", &[9_u8; fm_user::KDF_SALT_BYTES])
                .unwrap();
        let blob = fm_user::encrypt_account_secret("imap-secret", &credential_key).unwrap();
        seed_imap_account_with_password(&pool, 900, 801, &blob).await;
        let state = AppState::with_db_pool(test_api_config(), Some(pool));
        let session = authed_v1_session(801, "v1msg").await;
        let token = super::super::ensure_connection_token(&state, &session, Some(900))
            .await
            .unwrap();
        (state, session, token)
    }

    #[tokio::test]
    async fn v1_message_reads_single_message_through_injected_fetcher() {
        let (state, session, _) = message_test_state().await;

        let response = super::message_with_fetcher(
            &state,
            &session,
            Ok(axum::extract::Path(55)),
            Ok(axum::extract::Query(super::MessageQuery {
                folder: "INBOX".to_string(),
                account_id: Some(900),
            })),
            std::time::Duration::from_secs(5),
            |config, _password, folder, uid| async move {
                assert_eq!(config.host, "imap.example.com");
                assert_eq!(folder, "INBOX");
                assert_eq!(uid, 55);
                Ok(Some(test_message_parts()))
            },
        )
        .await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["subject"], "Single message");
        assert_eq!(body["data"]["uid"], 55);
        assert_eq!(body["data"]["from"][0]["email"], "sender@example.com");
    }

    #[tokio::test]
    async fn v1_message_maps_absent_and_unparseable_messages() {
        let (state, session, _) = message_test_state().await;
        let query = || {
            Ok(axum::extract::Query(super::MessageQuery {
                folder: "INBOX".to_string(),
                account_id: Some(900),
            }))
        };

        let response = super::message_with_fetcher(
            &state,
            &session,
            Ok(axum::extract::Path(56)),
            query(),
            std::time::Duration::from_secs(5),
            |_config, _password, _folder, _uid| async move { Ok(None) },
        )
        .await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "message_not_found");

        let response = super::message_with_fetcher(
            &state,
            &session,
            Ok(axum::extract::Path(57)),
            query(),
            std::time::Duration::from_secs(5),
            |_config, _password, _folder, _uid| async move {
                Ok(Some(vec![fm_imap::BodyPreviewPart {
                    kind: fm_imap::BodyPartKind::RawMessage,
                    raw: b"\x00\x01\x02".to_vec(),
                    is_complete: true,
                    flags: Vec::new(),
                    crypto: Default::default(),
                    metadata: Default::default(),
                }]))
            },
        )
        .await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "unparseable_message");
    }

    #[tokio::test]
    async fn v1_message_rejects_bad_requests_over_http() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 802, "v1msgerr", "correct-horse", None).await;
        seed_mail_account(&pool, 901, 802, "Broken").await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1msgerr", "correct-horse").await;

        // Missing folder.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/messages/60?account_id=901")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Non-numeric uid.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/messages/abc?folder=INBOX")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Zero uid.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/messages/0?folder=INBOX")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_request");

        // Unknown account.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/messages/60?folder=INBOX&account_id=999999")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Undecryptable stored credentials.
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/messages/60?folder=INBOX&account_id=901")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_account");
    }

    async fn seed_task(pool: &sqlx::AnyPool, user_id: i64, title: &str) -> i64 {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS frickmail_tasks (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                notes TEXT,
                due_date TEXT,
                completed BOOLEAN NOT NULL DEFAULT FALSE,
                completed_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(pool)
        .await
        .unwrap();
        fm_user::SqlxUserRepository::add_task(
            pool,
            user_id,
            fm_user::NewMailTask {
                title: title.to_string(),
                notes: None,
                due_date: None,
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn v1_tasks_lists_and_filters_user_tasks() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 901, "v1tasks", "correct-horse", None).await;
        seed_task(&pool, 901, "Buy milk").await;
        let done_id = seed_task(&pool, 901, "Done thing").await;
        fm_user::SqlxUserRepository::complete_task(&pool, 901, done_id, true)
            .await
            .unwrap();
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1tasks", "correct-horse").await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/tasks")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["tasks"].as_array().unwrap().len(), 2);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/tasks?filter=pending")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;
        let pending = body["data"]["tasks"].as_array().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["title"], "Buy milk");

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/tasks?filter=completed")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;
        let completed = body["data"]["tasks"].as_array().unwrap();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0]["title"], "Done thing");
    }

    #[tokio::test]
    async fn v1_tasks_rejects_anonymous_callers() {
        let pool = login_db_pool().await;
        let app = login_app(pool);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/tasks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn v1_logout_tears_down_authenticated_sessions() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1001, "v1logout", "correct-horse", None).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1logout", "correct-horse").await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/logout")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            set_cookie.contains("Max-Age=0"),
            "logout must expire the session cookie, got: {set_cookie}"
        );
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["logged_out"], true);

        // The pre-logout cookie no longer authenticates.
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/session")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;
        assert_eq!(body["data"]["authenticated"], false);
    }

    #[tokio::test]
    async fn v1_logout_is_idempotent_and_token_gated() {
        let pool = login_db_pool().await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;

        // Anonymous logout still succeeds (idempotent teardown).
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/logout")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["logged_out"], true);

        // Without a token it is rejected even though logout is idempotent.
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/logout")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_token");
    }

    fn test_folder_collection() -> fm_imap::LegacyFolderCollection {
        fm_imap::LegacyFolderCollection {
            folders: vec![fm_imap::LegacyFolder {
                name: "INBOX".to_string(),
                full_name: "INBOX".to_string(),
                delimiter: "/".to_string(),
                attributes: Vec::new(),
                metadata: std::collections::HashMap::new(),
                uid_next: Some(101),
                total_emails: Some(2),
                unread_emails: Some(1),
                id: None,
                size: None,
                role: None,
                etag: Some("folder-etag".to_string()),
            }],
            quota_usage: None,
            quota_limit: None,
            namespace: String::new(),
            namespaces: None,
            capabilities: vec!["IMAP4rev1".to_string()],
        }
    }

    async fn folders_test_state() -> (AppState, fm_session::Session) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1101, "v1folders", "correct-horse", None).await;
        let credential_key =
            fm_user::derive_credential_key("correct-horse", &[9_u8; fm_user::KDF_SALT_BYTES])
                .unwrap();
        let blob = fm_user::encrypt_account_secret("imap-secret", &credential_key).unwrap();
        seed_imap_account_with_password(&pool, 1100, 1101, &blob).await;
        let state = AppState::with_db_pool(test_api_config(), Some(pool));
        let session = authed_v1_session(1101, "v1folders").await;
        (state, session)
    }

    #[tokio::test]
    async fn v1_folders_lists_collection_through_injected_fetcher() {
        let (state, session) = folders_test_state().await;

        let response = super::folders_with_fetcher(
            &state,
            &session,
            Ok(axum::extract::Query(std::collections::HashMap::from([(
                "account_id".to_string(),
                "1100".to_string(),
            )]))),
            std::time::Duration::from_secs(5),
            |config, _password, discover| async move {
                assert_eq!(config.host, "imap.example.com");
                assert!(!discover);
                Ok(test_folder_collection())
            },
        )
        .await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["folders"][0]["name"], "INBOX");
        assert_eq!(body["data"]["folders"][0]["total_emails"], 2);
    }

    #[tokio::test]
    async fn v1_folders_enables_discovery_from_account_settings() {
        let (state, session) = folders_test_state().await;
        assert!(fm_user::SqlxUserRepository::update_mail_account_settings(
            state.db_pool().unwrap(),
            1101,
            1100,
            &serde_json::json!({ "HideUnsubscribed": "1" }),
        )
        .await
        .unwrap());

        let response = super::folders_with_fetcher(
            &state,
            &session,
            Ok(axum::extract::Query(std::collections::HashMap::from([(
                "account_id".to_string(),
                "1100".to_string(),
            )]))),
            std::time::Duration::from_secs(5),
            |_config, _password, discover| async move {
                assert!(discover);
                Ok(test_folder_collection())
            },
        )
        .await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn v1_folders_rejects_bad_requests_over_http() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1102, "v1folderserr", "correct-horse", None).await;
        seed_mail_account(&pool, 1101, 1102, "Broken").await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(
            app.clone(),
            &cookie,
            &token,
            "v1folderserr",
            "correct-horse",
        )
        .await;

        // Unknown account.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/folders?account_id=999999")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Missing account with no selection.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/folders")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Undecryptable stored credentials.
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/folders?account_id=1101")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_account");

        // Anonymous callers are rejected.
        let pool = login_db_pool().await;
        let app = login_app(pool);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/folders")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    struct RecordingSmtpSender {
        message: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl super::super::LegacySmtpSender for RecordingSmtpSender {
        async fn send(
            &self,
            _settings: &fm_smtp::SmtpSendSettings,
            _envelope: &lettre::address::Envelope,
            message: &[u8],
            _options: fm_smtp::SmtpDeliveryOptions,
        ) -> fm_core::Result<bool> {
            *self.message.lock().unwrap() = Some(message.to_vec());
            Ok(true)
        }
    }

    struct RecordingSentAppender {
        message: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl super::super::LegacySentAppender for RecordingSentAppender {
        #[allow(clippy::too_many_arguments)]
        async fn append_sent(
            &self,
            _state: &AppState,
            _pool: &sqlx::AnyPool,
            _user_id: i64,
            _account_id: i64,
            _config: &fm_imap::ImapConnectionConfig,
            _credentials: &fm_imap::ImapCredentials,
            _folder: &str,
            raw: &[u8],
        ) -> Result<(), String> {
            *self.message.lock().unwrap() = Some(raw.to_vec());
            Ok(())
        }
    }

    async fn send_test_state() -> (AppState, fm_session::Session, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1201, "v1send", "correct-horse", None).await;
        let credential_key =
            fm_user::derive_credential_key("correct-horse", &[9_u8; fm_user::KDF_SALT_BYTES])
                .unwrap();
        let blob = fm_user::encrypt_account_secret("imap-secret", &credential_key).unwrap();
        seed_imap_account_with_password(&pool, 1201, 1201, &blob).await;
        sqlx::query(
            "UPDATE frickmail_mail_accounts
             SET smtp_host = ?, smtp_port = ?, smtp_secure = ?
             WHERE id = ?",
        )
        .bind("8.8.8.8")
        .bind(25_i64)
        .bind("none")
        .bind(1201_i64)
        .execute(&pool)
        .await
        .unwrap();
        let state = AppState::with_db_pool(test_api_config(), Some(pool));
        let session = authed_v1_session(1201, "v1send").await;
        let token = super::super::ensure_connection_token(&state, &session, Some(1201))
            .await
            .unwrap();
        (state, session, token)
    }

    #[tokio::test]
    async fn v1_send_delivers_and_files_sent_copy() {
        let (state, session, token) = send_test_state().await;
        let sent = std::sync::Arc::new(std::sync::Mutex::new(None));
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-sm-token", token.parse().unwrap());

        let response = super::send_with_sender_and_appender(
            &state,
            &session,
            Ok(axum::extract::Json(super::SendRequest {
                account_id: Some(1201),
                identity_id: None,
                to: "recipient@example.net".to_string(),
                cc: None,
                bcc: None,
                subject: Some("Hello via v1".to_string()),
                text: Some("Body text".to_string()),
                html: None,
                save_to_sent: true,
            })),
            &headers,
            &RecordingSmtpSender {
                message: std::sync::Arc::clone(&sent),
            },
            &RecordingSentAppender {
                message: std::sync::Arc::clone(&stored),
            },
            &super::super::ProductionOAuthTokenRefresher,
        )
        .await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["sent"], true);

        let sent_text = String::from_utf8(sent.lock().unwrap().clone().unwrap()).unwrap();
        assert!(sent_text.contains("Hello via v1"), "{sent_text}");
        assert!(sent_text.contains("Body text"), "{sent_text}");
        let stored_text = String::from_utf8(stored.lock().unwrap().clone().unwrap()).unwrap();
        assert!(stored_text.contains("Hello via v1"), "{stored_text}");
        assert!(stored_text.contains("Body text"), "{stored_text}");
    }

    #[tokio::test]
    async fn v1_send_skips_sent_filing_when_disabled() {
        let (state, session, token) = send_test_state().await;
        let sent = std::sync::Arc::new(std::sync::Mutex::new(None));
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-sm-token", token.parse().unwrap());

        let response = super::send_with_sender_and_appender(
            &state,
            &session,
            Ok(axum::extract::Json(super::SendRequest {
                account_id: Some(1201),
                identity_id: None,
                to: "recipient@example.net".to_string(),
                cc: None,
                bcc: None,
                subject: Some("No filing".to_string()),
                text: Some("Body text".to_string()),
                html: None,
                save_to_sent: false,
            })),
            &headers,
            &RecordingSmtpSender {
                message: std::sync::Arc::clone(&sent),
            },
            &RecordingSentAppender {
                message: std::sync::Arc::clone(&stored),
            },
            &super::super::ProductionOAuthTokenRefresher,
        )
        .await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["sent"], true);
        assert!(sent.lock().unwrap().is_some());
        assert!(stored.lock().unwrap().is_none());
    }

    async fn seed_identity_row(
        pool: &sqlx::AnyPool,
        id: i64,
        user_id: i64,
        account_id: i64,
        name: &str,
        email: &str,
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
        .bind(email)
        .bind(None::<String>)
        .bind(false)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn send_as_test_state() -> (AppState, fm_session::Session, String, sqlx::AnyPool) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1201, "v1send", "correct-horse", None).await;
        let credential_key =
            fm_user::derive_credential_key("correct-horse", &[9_u8; fm_user::KDF_SALT_BYTES])
                .unwrap();
        let blob = fm_user::encrypt_account_secret("imap-secret", &credential_key).unwrap();
        seed_imap_account_with_password(&pool, 1201, 1201, &blob).await;
        sqlx::query(
            "UPDATE frickmail_mail_accounts
             SET smtp_host = ?, smtp_port = ?, smtp_secure = ?
             WHERE id = ?",
        )
        .bind("8.8.8.8")
        .bind(25_i64)
        .bind("none")
        .bind(1201_i64)
        .execute(&pool)
        .await
        .unwrap();
        let state = AppState::with_db_pool(test_api_config(), Some(pool.clone()));
        let session = authed_v1_session(1201, "v1send").await;
        let token = super::super::ensure_connection_token(&state, &session, Some(1201))
            .await
            .unwrap();
        (state, session, token, pool)
    }

    async fn send_with_identity(
        state: &AppState,
        session: &fm_session::Session,
        token: &str,
        identity_id: Option<i64>,
        sent: &std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    ) -> axum::response::Response {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-sm-token", token.parse().unwrap());
        super::send_with_sender_and_appender(
            state,
            session,
            Ok(axum::extract::Json(super::SendRequest {
                account_id: Some(1201),
                identity_id,
                to: "recipient@example.net".to_string(),
                cc: None,
                bcc: None,
                subject: Some("Identity send".to_string()),
                text: Some("Body text".to_string()),
                html: None,
                save_to_sent: false,
            })),
            &headers,
            &RecordingSmtpSender {
                message: std::sync::Arc::clone(sent),
            },
            &RecordingSentAppender {
                message: std::sync::Arc::new(std::sync::Mutex::new(None)),
            },
            &super::super::ProductionOAuthTokenRefresher,
        )
        .await
        .into_response()
    }

    #[tokio::test]
    async fn v1_send_uses_sender_identity_for_from() {
        let (state, session, token, pool) = send_as_test_state().await;
        seed_identity_row(&pool, 11, 1201, 1201, "Work Name", "work@example.com").await;
        let sent = std::sync::Arc::new(std::sync::Mutex::new(None));

        let response = send_with_identity(&state, &session, &token, Some(11), &sent).await;
        assert_eq!(response.status(), StatusCode::OK);
        let sent_text = String::from_utf8(sent.lock().unwrap().clone().unwrap()).unwrap();
        assert!(
            sent_text.contains("From: \"Work Name\" <work@example.com>"),
            "{sent_text}"
        );
    }

    #[tokio::test]
    async fn v1_send_rejects_unknown_and_foreign_identities() {
        let (state, session, token, pool) = send_as_test_state().await;
        seed_identity_row(&pool, 12, 1201, 1201, "Work Name", "work@example.com").await;
        seed_login_user(&pool, 1202, "v1other", "correct-horse", None).await;
        seed_imap_account_with_password(&pool, 1202, 1202, &[1_u8, 2, 3]).await;
        seed_identity_row(&pool, 13, 1202, 1202, "Other", "other@example.com").await;
        let sent = std::sync::Arc::new(std::sync::Mutex::new(None));

        // Unknown id and another user's identity both 404 with the same
        // code, revealing nothing about which case applied.
        for identity_id in [Some(999999_i64), Some(13)] {
            let response = send_with_identity(&state, &session, &token, identity_id, &sent).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body = read_json(response).await;
            assert_eq!(body["error"]["code"], "identity_not_found");
        }
        assert!(sent.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn v1_send_rejects_bad_requests_over_http() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1202, "v1senderr", "correct-horse", None).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1senderr", "correct-horse").await;

        // Missing recipients.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/send")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::from(
                        serde_json::json!({"account_id": 1202, "subject": "No recipients"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Malformed body.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/send")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::from("not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Tokenless send is rejected.
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/send")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .body(Body::from(
                        serde_json::json!({"to": "a@example.com"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    async fn contacts_test_state() -> (Router, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1301, "v1contacts", "correct-horse", None).await;
        fm_user::address_book::ensure_address_book_schema(&pool)
            .await
            .unwrap();
        for (index, name) in ["Ada", "Bob"].iter().enumerate() {
            fm_user::address_book::save_contact(
                &pool,
                1301,
                &fm_user::address_book::AddressBookContact {
                    id: 0,
                    uid: format!("manual:{index}"),
                    display: name.to_string(),
                    properties: Vec::new(),
                },
            )
            .await
            .unwrap();
        }
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1contacts", "correct-horse").await;
        (app, cookie)
    }

    #[tokio::test]
    async fn v1_contacts_lists_user_contacts() {
        let (app, cookie) = contacts_test_state().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/contacts?limit=10")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        let contacts = body["data"]["contacts"].as_array().unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0]["display"], "Ada");
        assert!(contacts[0].get("password_hash").is_none());
    }

    #[tokio::test]
    async fn v1_contacts_rejects_anonymous_callers() {
        let pool = login_db_pool().await;
        let app = login_app(pool);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/contacts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    async fn calendar_session(
        user_id: i64,
        username: &str,
        email: Option<&str>,
        credential_key: &[u8],
    ) -> fm_session::Session {
        use base64::Engine as _;
        let session = fm_session::Session::new(
            None,
            std::sync::Arc::new(fm_session::MemoryStore::default()),
            None,
        );
        session
            .insert(
                fm_session::USER_SESSION_KEY,
                fm_core::UserSession {
                    user_id,
                    username: username.to_string(),
                    email: email.map(ToOwned::to_owned),
                },
            )
            .await
            .unwrap();
        session
            .insert(
                fm_session::CREDENTIAL_KEY_SESSION_KEY,
                base64::engine::general_purpose::STANDARD.encode(credential_key),
            )
            .await
            .unwrap();
        session
    }

    async fn seed_gmail_oauth_account(
        pool: &sqlx::AnyPool,
        account_id: i64,
        user_id: i64,
        email: &str,
        credential_key: &[u8],
    ) {
        seed_mail_account(pool, account_id, user_id, "Gmail").await;
        sqlx::query(
            "UPDATE frickmail_mail_accounts
             SET email = ?, login = ?, type = 'gmail',
                 encrypted_oauth_refresh_token = ?
             WHERE id = ?",
        )
        .bind(email)
        .bind(email)
        .bind(fm_user::encrypt_account_secret("test-refresh-token", credential_key).unwrap())
        .bind(account_id)
        .execute(pool)
        .await
        .unwrap();
    }

    fn calendar_test_config() -> fm_core::FrickmailConfig {
        let mut config = test_api_config();
        config.oauth2.gmail.client_id = Some("cal-client".to_string());
        config
    }

    fn calendar_state(pool: sqlx::AnyPool) -> crate::AppState {
        crate::AppState::with_db_pool(calendar_test_config(), Some(pool))
    }

    fn calendar_ok_stub(
        json: serde_json::Value,
    ) -> impl Fn(
        super::super::calendar::CalendarHttpRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                Output = Result<
                    super::super::calendar::CalendarHttpResponse,
                    fm_core::FrickmailError,
                >,
            >,
        >,
    > {
        move |request: super::super::calendar::CalendarHttpRequest| {
            let json = json.clone();
            Box::pin(async move {
                if request.url.contains("accounts.google.com/o/oauth2/token") {
                    Ok(super::super::calendar::CalendarHttpResponse {
                        status: 200,
                        json: serde_json::json!({"access_token": "g-access"}),
                    })
                } else {
                    Ok(super::super::calendar::CalendarHttpResponse { status: 200, json })
                }
            })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                            Output = Result<
                                super::super::calendar::CalendarHttpResponse,
                                fm_core::FrickmailError,
                            >,
                        >,
                    >,
                >
        }
    }

    fn calendar_query(
        pairs: &[(&str, &str)],
    ) -> Result<
        axum::extract::Query<std::collections::HashMap<String, String>>,
        axum::extract::rejection::QueryRejection,
    > {
        Ok(axum::extract::Query(
            pairs
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        ))
    }

    #[tokio::test]
    async fn v1_calendars_rejects_anonymous_callers() {
        let app = login_app(login_db_pool().await);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/calendars")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "unauthenticated");
    }

    #[tokio::test]
    async fn v1_calendars_lists_provider_calendars() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1401, "v1cal", "correct-horse", None).await;
        let key = [21_u8; fm_user::CREDENTIAL_KEY_BYTES];
        seed_gmail_oauth_account(&pool, 1401, 1401, "v1cal@gmail.com", &key).await;
        let state = calendar_state(pool);
        let session = calendar_session(1401, "v1cal", Some("v1cal@gmail.com"), &key).await;

        let response = super::calendars_with_fetcher(
            &state,
            &session,
            calendar_query(&[("account_id", "1401")]),
            &calendar_ok_stub(serde_json::json!({"items": [
                {"id": "primary", "summary": "V1 Cal"},
                {"id": "work", "summary": "Work"},
            ]})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        let calendars = body["data"]["calendars"].as_array().unwrap();
        assert_eq!(calendars.len(), 2);
        assert_eq!(calendars[0]["name"], "V1 Cal");
        assert_eq!(body["data"]["provider"], "gmail");
    }

    #[tokio::test]
    async fn v1_calendars_rejects_non_oauth_accounts_without_provider_text() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1402, "v1calplain", "correct-horse", None).await;
        seed_mail_account(&pool, 1402, 1402, "Primary").await;
        let key = [22_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let state = calendar_state(pool);
        let session =
            calendar_session(1402, "v1calplain", Some("v1calplain@example.com"), &key).await;

        let response = super::calendars_with_fetcher(
            &state,
            &session,
            calendar_query(&[("account_id", "1402")]),
            &calendar_ok_stub(serde_json::json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_request");
        assert_eq!(body["error"]["message"], "Invalid calendar request");
    }

    #[tokio::test]
    async fn v1_calendar_events_lists_merged_events() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1403, "v1calev", "correct-horse", None).await;
        let key = [23_u8; fm_user::CREDENTIAL_KEY_BYTES];
        seed_gmail_oauth_account(&pool, 1403, 1403, "v1calev@gmail.com", &key).await;
        let state = calendar_state(pool);
        let session = calendar_session(1403, "v1calev", Some("v1calev@gmail.com"), &key).await;

        let response = super::calendar_events_with_fetcher(
            &state,
            &session,
            calendar_query(&[
                ("account_id", "1403"),
                ("calendar_ids", "primary, second"),
                ("start", "2026-09-01T00:00:00Z"),
                ("end", "2026-09-30T23:59:59Z"),
            ]),
            &calendar_ok_stub(serde_json::json!({"items": [
                {"id": "ev-1", "summary": "Standup",
                 "start": {"dateTime": "2026-09-02T09:00:00Z"},
                 "end": {"dateTime": "2026-09-02T09:30:00Z"}},
            ]})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        let events = body["data"]["events"].as_array().unwrap();
        // The stub answers both calendars identically; the merge keeps both.
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["title"], "Standup");
    }

    #[tokio::test]
    async fn v1_calendar_events_rejects_too_many_calendars() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1404, "v1calmany", "correct-horse", None).await;
        let key = [24_u8; fm_user::CREDENTIAL_KEY_BYTES];
        seed_gmail_oauth_account(&pool, 1404, 1404, "v1calmany@gmail.com", &key).await;
        let state = calendar_state(pool);
        let session = calendar_session(1404, "v1calmany", Some("v1calmany@gmail.com"), &key).await;
        let ids: Vec<String> = (0..60).map(|index| format!("cal-{index}")).collect();

        let response = super::calendar_events_with_fetcher(
            &state,
            &session,
            calendar_query(&[("account_id", "1404"), ("calendar_ids", &ids.join(","))]),
            &calendar_ok_stub(serde_json::json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_request");
    }

    #[tokio::test]
    async fn v1_calendar_save_validates_and_returns_new_id() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1405, "v1calsave", "correct-horse", None).await;
        let key = [25_u8; fm_user::CREDENTIAL_KEY_BYTES];
        seed_gmail_oauth_account(&pool, 1405, 1405, "v1calsave@gmail.com", &key).await;
        let state = calendar_state(pool);
        let session = calendar_session(1405, "v1calsave", Some("v1calsave@gmail.com"), &key).await;
        let token = super::super::ensure_connection_token(&state, &session, None)
            .await
            .unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-sm-token", token.parse().unwrap());

        // Missing title/start/end never reaches the provider.
        let response = super::calendar_save_event_with_fetcher(
            &state,
            &session,
            &headers,
            Ok(axum::extract::Json(super::CalendarSaveRequest {
                title: None,
                start: Some("2026-09-02T09:00:00Z".to_string()),
                end: Some("2026-09-02T10:00:00Z".to_string()),
                ..Default::default()
            })),
            &calendar_ok_stub(serde_json::json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = super::calendar_save_event_with_fetcher(
            &state,
            &session,
            &headers,
            Ok(axum::extract::Json(super::CalendarSaveRequest {
                account_id: Some(1405),
                title: Some("Planning".to_string()),
                start: Some("2026-09-02T09:00:00Z".to_string()),
                end: Some("2026-09-02T10:00:00Z".to_string()),
                ..Default::default()
            })),
            &calendar_ok_stub(serde_json::json!({"id": "new-ev-9"})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["ok"], true);
        assert_eq!(body["data"]["id"], "new-ev-9");
    }

    #[tokio::test]
    async fn v1_calendar_delete_removes_event_and_requires_token() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1406, "v1caldel", "correct-horse", None).await;
        let key = [26_u8; fm_user::CREDENTIAL_KEY_BYTES];
        seed_gmail_oauth_account(&pool, 1406, 1406, "v1caldel@gmail.com", &key).await;
        let state = calendar_state(pool);
        let session = calendar_session(1406, "v1caldel", Some("v1caldel@gmail.com"), &key).await;

        // Missing id is a 400 without provider contact.
        let token = super::super::ensure_connection_token(&state, &session, None)
            .await
            .unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-sm-token", token.parse().unwrap());
        let response = super::calendar_delete_event_with_fetcher(
            &state,
            &session,
            &headers,
            calendar_query(&[("account_id", "1406")]),
            &calendar_ok_stub(serde_json::json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // A provider 410 Gone still counts as deleted. The stub answers
        // the token refresh normally and reports Gone only for the
        // delete call itself.
        let gone = |request: super::super::calendar::CalendarHttpRequest| async move {
            if request.url.contains("accounts.google.com/o/oauth2/token") {
                Ok(super::super::calendar::CalendarHttpResponse {
                    status: 200,
                    json: serde_json::json!({"access_token": "g-access"}),
                })
            } else {
                Ok(super::super::calendar::CalendarHttpResponse {
                    status: 410,
                    json: serde_json::json!({}),
                })
            }
        };
        let response = super::calendar_delete_event_with_fetcher(
            &state,
            &session,
            &headers,
            calendar_query(&[("account_id", "1406"), ("id", "primary:ev-1")]),
            &gone,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["ok"], true);

        // Without the connection token the delete is forbidden before any
        // provider contact.
        let response = super::calendar_delete_event_with_fetcher(
            &state,
            &session,
            &axum::http::HeaderMap::new(),
            calendar_query(&[("account_id", "1406"), ("id", "primary:ev-1")]),
            &calendar_ok_stub(serde_json::json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_token");
    }

    #[tokio::test]
    async fn v1_calendar_save_rejects_missing_token_over_http() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1407, "v1caltok", "correct-horse", None).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1caltok", "correct-horse").await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/calendars/events")
                    .header("cookie", &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"title": "No token"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_token");
    }

    async fn create_message_index_table(pool: &sqlx::AnyPool) {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS frickmail_message_index (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                folder TEXT NOT NULL,
                imap_uid INTEGER NOT NULL,
                message_id TEXT,
                subject TEXT,
                from_addr TEXT,
                from_name TEXT,
                date_ts TEXT,
                snippet TEXT
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_search_index(pool: &sqlx::AnyPool) {
        create_message_index_table(pool).await;
        for (id, user_id, account_id, folder, imap_uid, subject) in [
            (1_i64, 1501_i64, 1501_i64, "INBOX", 31_i64, "Invoice"),
            (2, 1501, 1501, "Archive", 32, "Invoice reminder"),
            (3, 1502, 1502, "INBOX", 33, "Invoice from another user"),
        ] {
            sqlx::query(
                "INSERT INTO frickmail_message_index
                    (id, user_id, account_id, folder, imap_uid, message_id, subject,
                     from_addr, from_name, date_ts, snippet)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(user_id)
            .bind(account_id)
            .bind(folder)
            .bind(imap_uid)
            .bind(format!("search-{id}"))
            .bind(subject)
            .bind("billing@example.com")
            .bind("Billing")
            .bind("2026-06-01 10:00:00")
            .bind("First invoice")
            .execute(pool)
            .await
            .unwrap();
        }
    }

    async fn search_test_state() -> (Router, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1501, "v1search", "correct-horse", None).await;
        seed_login_user(&pool, 1502, "v1other", "correct-horse", None).await;
        seed_mail_account(&pool, 1501, 1501, "Primary").await;
        seed_mail_account(&pool, 1502, 1502, "Primary").await;
        seed_search_index(&pool).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1search", "correct-horse").await;
        (app, cookie)
    }

    #[tokio::test]
    async fn v1_search_rejects_anonymous_callers() {
        let app = login_app(login_db_pool().await);

        for uri in [
            "/api/frickmail/v1/search?q=invoice",
            "/api/frickmail/v1/unified-inbox",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn v1_search_requires_a_usable_query() {
        let (app, cookie) = search_test_state().await;

        for uri in [
            "/api/frickmail/v1/search",
            "/api/frickmail/v1/search?q=",
            "/api/frickmail/v1/search?q=x",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {uri}");
            let body = read_json(response).await;
            assert_eq!(body["error"]["code"], "invalid_request");
        }
    }

    #[tokio::test]
    async fn v1_search_returns_user_scoped_results_with_limit() {
        let (app, cookie) = search_test_state().await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/search?q=invoice")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["data"]["query"], "invoice");
        let results = body["data"]["results"].as_array().unwrap();
        // Both own folders match; the other user's message never leaks.
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| result["account_id"] == 1501));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/search?q=invoice&limit=1")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["results"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn v1_unified_inbox_returns_indexed_inbox_only() {
        let (app, cookie) = search_test_state().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/unified-inbox")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        let messages = body["data"]["messages"].as_array().unwrap();
        // Only INBOX rows of the caller's own password-backed account.
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["folder"], "INBOX");
        assert_eq!(messages[0]["subject"], "Invoice");
    }

    async fn seed_smime_cert_tables(pool: &sqlx::AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_smime_certs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                encrypted_key_pem BLOB,
                fingerprint TEXT NOT NULL,
                subject TEXT,
                not_before TEXT,
                not_after TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    fn test_smime_cert_material(
        email: &str,
    ) -> (String, openssl::pkey::PKey<openssl::pkey::Private>) {
        use openssl::{
            asn1::Asn1Time,
            bn::BigNum,
            hash::MessageDigest,
            nid::Nid,
            pkey::PKey,
            rsa::Rsa,
            x509::{extension::SubjectAlternativeName, X509NameBuilder, X509},
        };
        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, email).unwrap();
        name.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, email)
            .unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(43).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .email(email)
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = builder.build();
        let pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
        (pem, key)
    }

    fn test_smime_cert_pem(email: &str) -> String {
        test_smime_cert_material(email).0
    }

    fn test_smime_p12_b64(email: &str, password: &str) -> String {
        use base64::Engine as _;
        use openssl::{pkcs12::Pkcs12, x509::X509};
        let (pem, key) = test_smime_cert_material(email);
        let cert = X509::from_pem(pem.as_bytes()).unwrap();
        let der = Pkcs12::builder()
            .name(email)
            .pkey(&key)
            .cert(&cert)
            .build2(password)
            .unwrap()
            .to_der()
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    async fn smime_test_state() -> (Router, String, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1601, "v1smime", "correct-horse", None).await;
        seed_mail_account(&pool, 1601, 1601, "Primary").await;
        seed_smime_cert_tables(&pool).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1smime", "correct-horse").await;
        // Like the switch-account tests, the bootstrap connection token
        // stays valid after login.
        (app, cookie, token)
    }

    #[tokio::test]
    async fn v1_smime_rejects_anonymous_callers() {
        let app = login_app(login_db_pool().await);

        // Reads hit the session gate; writes hit the connection-token gate
        // first, exactly like v1 send.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/smime/certs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        for request in [
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/smime/certs")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/smime/p12")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/frickmail/v1/smime/certs?id=1")
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn v1_smime_import_validates_input() {
        let (app, cookie, token) = smime_test_state().await;
        let post = |uri: &str, body: serde_json::Value| {
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("cookie", &cookie)
                .header("x-sm-token", &token)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };

        // Missing account.
        let response = app
            .clone()
            .oneshot(post(
                "/api/frickmail/v1/smime/certs",
                serde_json::json!({"pem_b64": "eA=="}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Bad base64.
        let response = app
            .clone()
            .oneshot(post(
                "/api/frickmail/v1/smime/certs",
                serde_json::json!({"account_id": 1601, "pem_b64": "!!!"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Well-formed base64 but not a certificate.
        let response = app
            .clone()
            .oneshot(post(
                "/api/frickmail/v1/smime/certs",
                serde_json::json!({"account_id": 1601, "pem_b64": "aGVsbG8="}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_request");

        // Unknown account.
        let response = app
            .oneshot(post(
                "/api/frickmail/v1/smime/certs",
                serde_json::json!({"account_id": 9999, "pem_b64": "aGVsbG8="}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "account_not_found");
    }

    #[tokio::test]
    async fn v1_smime_import_lists_and_deletes_cert_without_key_material() {
        use base64::Engine as _;
        let (app, cookie, token) = smime_test_state().await;
        let pem_b64 =
            base64::engine::general_purpose::STANDARD.encode(test_smime_cert_pem("v1@example.com"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/smime/certs")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"account_id": 1601, "pem_b64": pem_b64}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["ok"], true);
        assert_eq!(body["data"]["email"], "v1@example.com");
        assert!(body["data"]["fingerprint"].as_str().unwrap().len() > 10);
        let id = body["data"]["id"].as_i64().unwrap();

        // Listing exposes metadata only — never key material.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/smime/certs")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        let certs = body["data"]["certs"].as_array().unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0]["id"], id);
        assert_eq!(certs[0]["has_key"], false);
        assert!(certs[0].get("encrypted_key_pem").is_none());
        assert!(certs[0].get("cert_pem").is_none());

        // Delete removes; a second delete 404s.
        for expected in [StatusCode::OK, StatusCode::NOT_FOUND] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::DELETE)
                        .uri(format!("/api/frickmail/v1/smime/certs?id={id}"))
                        .header("cookie", &cookie)
                        .header("x-sm-token", &token)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        let body = read_json(
            app.oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/smime/certs")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert!(body["data"]["certs"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn v1_smime_p12_import_stores_key_and_requires_token() {
        let (app, cookie, token) = smime_test_state().await;
        let p12 = test_smime_p12_b64("v1p12@example.com", "p12-secret");

        // Without the connection token the key-bearing write is forbidden.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/smime/p12")
                    .header("cookie", &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"account_id": 1601, "p12_b64": p12}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/smime/p12")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "account_id": 1601,
                            "p12_b64": p12,
                            "password": "p12-secret",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["ok"], true);
        assert_eq!(body["data"]["email"], "v1p12@example.com");

        let body = read_json(
            app.oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/smime/certs")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .await;
        let certs = body["data"]["certs"].as_array().unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0]["has_key"], true);
    }

    async fn account_test_state() -> (Router, String, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1701, "v1acctmgr", "correct-horse", None).await;
        // Account deletion cleans the message index, like the native hook.
        create_message_index_table(&pool).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1acctmgr", "correct-horse").await;
        // Like the switch-account tests, the bootstrap connection token
        // stays valid after login.
        (app, cookie, token)
    }

    fn account_post(
        cookie: &str,
        token: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("cookie", cookie)
            .header("x-sm-token", token)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn account_ids(app: &Router, cookie: &str) -> Vec<(i64, bool)> {
        let response = app
            .clone()
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
        body["data"]["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|account| {
                (
                    account["id"].as_i64().unwrap(),
                    account["is_primary"].as_bool().unwrap(),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn v1_account_writes_reject_anonymous_callers() {
        let app = login_app(login_db_pool().await);

        // Reads hit the session gate; writes hit the connection-token gate
        // first, exactly like v1 send.
        let response = app
            .clone()
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

        for request in [
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/accounts")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            Request::builder()
                .method(Method::PUT)
                .uri("/api/frickmail/v1/accounts/1")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/frickmail/v1/accounts/1")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/accounts/1/primary")
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn v1_accounts_add_validates_and_makes_first_primary() {
        let (app, cookie, token) = account_test_state().await;

        // Missing email is a 400.
        let response = app
            .clone()
            .oneshot(account_post(
                &cookie,
                &token,
                "/api/frickmail/v1/accounts",
                serde_json::json!({"label": "No address"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_request");

        let response = app
            .clone()
            .oneshot(account_post(
                &cookie,
                &token,
                "/api/frickmail/v1/accounts",
                serde_json::json!({
                    "label": "Primary",
                    "email": "primary@example.com",
                    "imap_host": "imap.example.com",
                    "password": "secret-horse",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        let id = body["data"]["id"].as_i64().unwrap();
        assert!(id > 0);

        // The first account is primary, and no secrets leak in listings.
        let listed = account_ids(&app, &cookie).await;
        assert_eq!(listed, vec![(id, true)]);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/accounts")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;
        let account = &body["data"]["accounts"][0];
        assert_eq!(account["email"], "primary@example.com");
        assert!(account.get("encrypted_password").is_none());
        assert!(account.get("password").is_none());
    }

    #[tokio::test]
    async fn v1_accounts_update_changes_fields_and_404s_unknown() {
        let (app, cookie, token) = account_test_state().await;
        let response = app
            .clone()
            .oneshot(account_post(
                &cookie,
                &token,
                "/api/frickmail/v1/accounts",
                serde_json::json!({
                    "email": "update@example.com",
                    "imap_host": "imap.example.com",
                    "smtp_host": "smtp.example.com",
                }),
            ))
            .await
            .unwrap();
        let id = read_json(response).await["data"]["id"].as_i64().unwrap();

        let put = |uri: String, body: serde_json::Value| {
            Request::builder()
                .method(Method::PUT)
                .uri(uri)
                .header("cookie", &cookie)
                .header("x-sm-token", &token)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let response = app
            .clone()
            .oneshot(put(
                "/api/frickmail/v1/accounts/999999".to_string(),
                serde_json::json!({"label": "Ghost"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .clone()
            .oneshot(put(
                format!("/api/frickmail/v1/accounts/{id}"),
                serde_json::json!({"label": "Renamed"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = account_ids(&app, &cookie).await;
        assert_eq!(listed.len(), 1);
    }

    #[tokio::test]
    async fn v1_accounts_delete_and_primary_need_ownership() {
        let (app, cookie, token) = account_test_state().await;
        let other_pool = login_db_pool().await;
        seed_login_user(&other_pool, 1702, "v1bystander", "correct-horse", None).await;
        seed_mail_account(&other_pool, 1702, 1702, "Foreign").await;

        let response = app
            .clone()
            .oneshot(account_post(
                &cookie,
                &token,
                "/api/frickmail/v1/accounts",
                serde_json::json!({"email": "first@example.com"}),
            ))
            .await
            .unwrap();
        let first = read_json(response).await["data"]["id"].as_i64().unwrap();
        let response = app
            .clone()
            .oneshot(account_post(
                &cookie,
                &token,
                "/api/frickmail/v1/accounts",
                serde_json::json!({"email": "second@example.com"}),
            ))
            .await
            .unwrap();
        let second = read_json(response).await["data"]["id"].as_i64().unwrap();

        // Unknown and foreign ids 404 on both mutating routes. (The
        // foreign account lives in another pool, so it reads as unknown
        // here — the user scoping is what matters.)
        for uri in [
            "/api/frickmail/v1/accounts/999999",
            "/api/frickmail/v1/accounts/999999/primary",
        ] {
            let (method, body) = if uri.ends_with("/primary") {
                (Method::POST, Body::empty())
            } else {
                (Method::DELETE, Body::empty())
            };
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("cookie", &cookie)
                        .header("x-sm-token", &token)
                        .header("content-type", "application/json")
                        .body(body)
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        // Promoting the second account flips the primary flag.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/frickmail/v1/accounts/{second}/primary"))
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut listed = account_ids(&app, &cookie).await;
        listed.sort();
        assert_eq!(listed, vec![(first, false), (second, true)]);

        // Deleting removes the account from the listing.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/api/frickmail/v1/accounts/{first}"))
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(account_ids(&app, &cookie).await, vec![(second, true)]);
    }

    async fn oauth_provider_ids(config: fm_core::FrickmailConfig) -> Vec<String> {
        let state = crate::AppState::new(config);
        let response = super::oauth_providers(axum::extract::State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        body["data"]["providers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|provider| provider["id"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn v1_oauth_providers_empty_without_configured_clients() {
        assert!(oauth_provider_ids(test_api_config()).await.is_empty());
    }

    #[tokio::test]
    async fn v1_oauth_providers_needs_id_and_secret_pairs() {
        let mut config = test_api_config();
        // Secret alone is not enough; neither is a blank id.
        config.oauth2.gmail.client_secret = Some("shh".to_string());
        config.oauth2.o365.client_id = Some("  ".to_string());
        config.oauth2.o365.client_secret = Some("shh".to_string());
        config.oidc.issuer = Some("https://sso.example.com".to_string());
        config.oidc.client_id = Some("id".to_string());
        assert!(oauth_provider_ids(config).await.is_empty());
    }

    #[tokio::test]
    async fn v1_oauth_providers_lists_configured_entries_without_secrets() {
        let mut config = test_api_config();
        config.oauth2.gmail.client_id = Some("gmail-id".to_string());
        config.oauth2.gmail.client_secret = Some("gmail-secret".to_string());
        config.oauth2.o365.client_id = Some("o365-id".to_string());
        config.oauth2.o365.client_secret = Some("o365-secret".to_string());
        config.oidc.issuer = Some("https://sso.example.com".to_string());
        config.oidc.client_id = Some("oidc-id".to_string());
        config.oidc.client_secret = Some("oidc-secret".to_string());
        config.oidc.provider_name = "Example SSO".to_string();
        let state = crate::AppState::new(config);
        let response = super::oauth_providers(axum::extract::State(state)).await;
        let body = read_json(response).await;
        let providers = body["data"]["providers"].as_array().unwrap();
        assert_eq!(providers.len(), 3);
        assert_eq!(providers[0]["id"], "gmail");
        assert_eq!(providers[0]["label"], "Google");
        assert_eq!(providers[0]["url"], "/?StartLoginGMail");
        assert_eq!(providers[1]["id"], "o365");
        assert_eq!(providers[2]["label"], "Example SSO");
        assert_eq!(providers[2]["url"], "/?StartLoginOIDC");
        let rendered = body.to_string();
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("gmail-id"));
    }

    #[tokio::test]
    async fn v1_oauth_providers_anonymous_over_http() {
        let app = login_app(login_db_pool().await);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/oauth/providers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Anonymous by design: the login screen needs it pre-auth.
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert!(body["data"]["providers"].as_array().unwrap().is_empty());
    }

    async fn identity_test_state() -> (Router, String, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1801, "v1ident", "correct-horse", None).await;
        seed_mail_account(&pool, 1801, 1801, "Primary").await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1ident", "correct-horse").await;
        // Like the switch-account tests, the bootstrap connection token
        // stays valid after login.
        (app, cookie, token)
    }

    async fn identity_ids(app: &Router, cookie: &str) -> Vec<(i64, bool)> {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/identities?account_id=1801")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        body["data"]["identities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|identity| {
                (
                    identity["id"].as_i64().unwrap(),
                    identity["is_default"].as_bool().unwrap(),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn v1_identities_reject_anonymous_callers() {
        let app = login_app(login_db_pool().await);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/identities?account_id=1801")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Writes hit the connection-token gate first, exactly like v1 send.
        for request in [
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/identities")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/frickmail/v1/identities/1")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/identities/1/default")
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn v1_identities_add_validates_input() {
        let (app, cookie, token) = identity_test_state().await;
        let post = |body: serde_json::Value| {
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/identities")
                .header("cookie", &cookie)
                .header("x-sm-token", &token)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };

        // Missing name/email is a 400.
        for body in [
            serde_json::json!({"account_id": 1801}),
            serde_json::json!({"account_id": 1801, "name": "No address"}),
            serde_json::json!({"account_id": 1801, "email": "a@example.com"}),
        ] {
            let response = app.clone().oneshot(post(body)).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        // Unknown account is a 404.
        let response = app
            .oneshot(post(serde_json::json!({
                "account_id": 999999,
                "name": "Ghost",
                "email": "ghost@example.com",
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "account_not_found");
    }

    #[tokio::test]
    async fn v1_identities_add_delete_and_default_round_trip() {
        let (app, cookie, token) = identity_test_state().await;
        let post = |uri: &str, body: serde_json::Value| {
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("cookie", &cookie)
                .header("x-sm-token", &token)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };

        let response = app
            .clone()
            .oneshot(post(
                "/api/frickmail/v1/identities",
                serde_json::json!({
                    "account_id": 1801,
                    "name": "Work",
                    "email": "work@example.com",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let first = read_json(response).await["data"]["id"].as_i64().unwrap();
        assert!(first > 0);

        let response = app
            .clone()
            .oneshot(post(
                "/api/frickmail/v1/identities",
                serde_json::json!({
                    "account_id": 1801,
                    "name": "Alias",
                    "email": "alias@example.com",
                    "is_default": true,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let second = read_json(response).await["data"]["id"].as_i64().unwrap();

        // The default flag lands on the second identity only.
        let mut listed = identity_ids(&app, &cookie).await;
        listed.sort();
        assert_eq!(listed, vec![(first, false), (second, true)]);

        // Unknown ids 404 on both mutating routes.
        for request in [
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/frickmail/v1/identities/999999")
                .header("cookie", &cookie)
                .header("x-sm-token", &token)
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/identities/999999/default")
                .header("cookie", &cookie)
                .header("x-sm-token", &token)
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        // Flipping the default back, then deleting, round-trips cleanly.
        let response = app
            .clone()
            .oneshot(post(
                &format!("/api/frickmail/v1/identities/{first}/default"),
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut listed = identity_ids(&app, &cookie).await;
        listed.sort();
        assert_eq!(listed, vec![(first, true), (second, false)]);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/api/frickmail/v1/identities/{second}"))
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(identity_ids(&app, &cookie).await, vec![(first, true)]);
    }

    async fn totp_test_state() -> (Router, String, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1901, "v1totp", "correct-horse", None).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1totp", "correct-horse").await;
        // Like the switch-account tests, the bootstrap connection token
        // stays valid after login.
        (app, cookie, token)
    }

    fn totp_post(cookie: &str, token: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("cookie", cookie)
            .header("x-sm-token", token)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn totp_status_of(app: &Router, cookie: &str) -> bool {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/security/totp")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        body["data"]["enabled"].as_bool().unwrap()
    }

    async fn totp_setup_secret(app: &Router, cookie: &str, token: &str) -> String {
        let response = app
            .clone()
            .oneshot(totp_post(
                cookie,
                token,
                "/api/frickmail/v1/security/totp/setup",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert!(body["data"]["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/"));
        assert!(body["data"]["qr_data_url"]
            .as_str()
            .unwrap()
            .starts_with("data:image/svg+xml;base64,"));
        body["data"]["secret"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn v1_totp_rejects_anonymous_callers() {
        let app = login_app(login_db_pool().await);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/security/totp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Writes hit the connection-token gate first, exactly like v1 send.
        for uri in [
            "/api/frickmail/v1/security/totp/setup",
            "/api/frickmail/v1/security/totp/confirm",
            "/api/frickmail/v1/security/totp/disable",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(uri)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn v1_totp_confirm_needs_pending_setup() {
        let (app, cookie, token) = totp_test_state().await;
        assert!(!totp_status_of(&app, &cookie).await);

        let response = app
            .oneshot(totp_post(
                &cookie,
                &token,
                "/api/frickmail/v1/security/totp/confirm",
                serde_json::json!({"code": "123456"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_request");
    }

    #[tokio::test]
    async fn v1_totp_enrolls_confirms_and_disables() {
        let (app, cookie, token) = totp_test_state().await;
        assert!(!totp_status_of(&app, &cookie).await);

        let secret = totp_setup_secret(&app, &cookie, &token).await;
        let live_code = || test_totp_code(&secret, test_totp_counter());
        // A code that cannot be the live one (last digit flipped).
        let wrong_code = || {
            let live = live_code();
            let flipped = if live.ends_with('0') { '1' } else { '0' };
            format!("{}{}", &live[..5], flipped)
        };

        // A wrong code never enrolls.
        let response = app
            .clone()
            .oneshot(totp_post(
                &cookie,
                &token,
                "/api/frickmail/v1/security/totp/confirm",
                serde_json::json!({"code": wrong_code()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!totp_status_of(&app, &cookie).await);

        // A live code enrolls and clears the pending secret.
        let response = app
            .clone()
            .oneshot(totp_post(
                &cookie,
                &token,
                "/api/frickmail/v1/security/totp/confirm",
                serde_json::json!({"code": live_code()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(totp_status_of(&app, &cookie).await);

        // Disabling needs a live code too.
        let response = app
            .clone()
            .oneshot(totp_post(
                &cookie,
                &token,
                "/api/frickmail/v1/security/totp/disable",
                serde_json::json!({"code": wrong_code()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(totp_status_of(&app, &cookie).await);

        let response = app
            .clone()
            .oneshot(totp_post(
                &cookie,
                &token,
                "/api/frickmail/v1/security/totp/disable",
                serde_json::json!({"code": live_code()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!totp_status_of(&app, &cookie).await);
    }

    fn password_app(pool: sqlx::AnyPool) -> Router {
        let mut config = test_api_config();
        config.change_password.enabled = true;
        Router::new()
            .nest("/api/frickmail/v1", super::routes())
            .layer(fm_session::session_layer(
                fm_session::AppSessionStore::Memory(fm_session::MemoryStore::default()),
            ))
            .with_state(AppState::with_db_pool(config, Some(pool)))
    }

    async fn password_test_state() -> (Router, String, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1951, "v1passwd", "correct-horse", None).await;
        let app = password_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1passwd", "correct-horse").await;
        // Like the switch-account tests, the bootstrap connection token
        // stays valid after login.
        (app, cookie, token)
    }

    fn password_post(cookie: &str, token: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/api/frickmail/v1/security/password")
            .header("cookie", cookie)
            .header("x-sm-token", token)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn v1_password_change_rejects_anonymous_callers() {
        let app = login_app(login_db_pool().await);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/security/password")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Token gate first, exactly like v1 send.
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn v1_password_change_needs_feature_flag() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1952, "v1passoff", "correct-horse", None).await;
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1passoff", "correct-horse").await;

        let response = app
            .oneshot(password_post(
                &cookie,
                &token,
                serde_json::json!({
                    "current_password": "correct-horse",
                    "new_password": "a-brand-new-strong-passphrase",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "unavailable");
    }

    #[tokio::test]
    async fn v1_password_change_validates_input() {
        let (app, cookie, token) = password_test_state().await;

        // Wrong current password.
        let response = app
            .clone()
            .oneshot(password_post(
                &cookie,
                &token,
                serde_json::json!({
                    "current_password": "wrong-horse",
                    "new_password": "a-brand-new-strong-passphrase",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_current_password");

        // Too short.
        let response = app
            .clone()
            .oneshot(password_post(
                &cookie,
                &token,
                serde_json::json!({
                    "current_password": "correct-horse",
                    "new_password": "short",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "password_too_short");

        // Long but weak.
        let response = app
            .oneshot(password_post(
                &cookie,
                &token,
                serde_json::json!({
                    "current_password": "correct-horse",
                    "new_password": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "password_too_weak");
    }

    #[tokio::test]
    async fn v1_password_change_rotates_session_and_rekeys_login() {
        let (app, cookie, token) = password_test_state().await;

        let response = app
            .clone()
            .oneshot(password_post(
                &cookie,
                &token,
                serde_json::json!({
                    "current_password": "correct-horse",
                    "new_password": "a-brand-new-strong-passphrase",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["changed"], true);

        // Old password rejected, new password accepted at login — on a
        // fresh session, since the change rotated the session id.
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let login = |password: &str| {
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/login")
                .header("content-type", "application/json")
                .header("x-sm-token", &token)
                .header("cookie", &cookie)
                .body(Body::from(
                    serde_json::json!({"username": "v1passwd", "password": password}).to_string(),
                ))
                .unwrap()
        };
        let response = app.clone().oneshot(login("correct-horse")).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .oneshot(login("a-brand-new-strong-passphrase"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn contacts_write_test_state() -> (Router, String, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 2001, "v1ctmgr", "correct-horse", None).await;
        fm_user::address_book::ensure_address_book_schema(&pool)
            .await
            .unwrap();
        let app = login_app(pool);
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1ctmgr", "correct-horse").await;
        // Like the switch-account tests, the bootstrap connection token
        // stays valid after login.
        (app, cookie, token)
    }

    fn contacts_post(
        cookie: &str,
        token: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("cookie", cookie)
            .header("x-sm-token", token)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn contact_ids(app: &Router, cookie: &str) -> Vec<i64> {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/contacts?limit=100")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        body["data"]["contacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|contact| contact["id"].as_i64().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn v1_contacts_writes_reject_anonymous_callers() {
        let app = login_app(login_db_pool().await);

        // Writes hit the connection-token gate first, exactly like v1 send.
        for request in [
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/contacts")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/api/frickmail/v1/contacts/deduplicate")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/frickmail/v1/contacts/1")
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn v1_contacts_add_validates_email() {
        let (app, cookie, token) = contacts_write_test_state().await;

        for body in [
            serde_json::json!({}),
            serde_json::json!({"name": "No address"}),
            serde_json::json!({"email": "not-an-address"}),
        ] {
            let response = app
                .clone()
                .oneshot(contacts_post(
                    &cookie,
                    &token,
                    "/api/frickmail/v1/contacts",
                    body,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = read_json(response).await;
            assert_eq!(body["error"]["code"], "invalid_request");
        }
    }

    #[tokio::test]
    async fn v1_contacts_add_delete_and_deduplicate_round_trip() {
        let (app, cookie, token) = contacts_write_test_state().await;

        let response = app
            .clone()
            .oneshot(contacts_post(
                &cookie,
                &token,
                "/api/frickmail/v1/contacts",
                serde_json::json!({"name": "Ada", "email": "ada@example.com"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["ok"], true);
        assert_eq!(body["data"]["email"], "ada@example.com");

        // Nothing to deduplicate yet.
        let response = app
            .clone()
            .oneshot(contacts_post(
                &cookie,
                &token,
                "/api/frickmail/v1/contacts/deduplicate",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["removed"], 0);

        let ids = contact_ids(&app, &cookie).await;
        assert_eq!(ids.len(), 1);

        // Unknown ids 404.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/frickmail/v1/contacts/999999")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "contact_not_found");

        // Deleting removes the contact from the listing.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/api/frickmail/v1/contacts/{}", ids[0]))
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(contact_ids(&app, &cookie).await.is_empty());
    }

    fn admin_test_config(token: Option<&str>) -> FrickmailConfig {
        let mut config = test_api_config();
        config.admin.token_hash = token.map(|token| fm_user::hash_admin_token(token).unwrap());
        config
    }

    fn admin_login_app(token: Option<&str>) -> Router {
        Router::new()
            .nest("/api/frickmail/v1", super::routes())
            .layer(fm_session::session_layer(
                fm_session::AppSessionStore::Memory(fm_session::MemoryStore::default()),
            ))
            .with_state(AppState::new(admin_test_config(token)))
    }

    async fn admin_bootstrapped(app: Router) -> (String, String) {
        bootstrap_csrf(app).await
    }

    #[tokio::test]
    async fn v1_admin_login_establishes_operator_sessions() {
        let app = admin_login_app(Some("opensesame"));
        let (cookie, token) = admin_bootstrapped(app.clone()).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/admin/login")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::from(
                        serde_json::json!({"token": "opensesame"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let cookie = session_cookie(&response);
        let body = read_json(response).await;
        assert_eq!(body["data"]["authenticated"], true);

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
        let body = read_json(response).await;
        assert_eq!(body["data"]["is_admin"], true);
    }

    #[tokio::test]
    async fn v1_admin_login_rejects_unknown_wrong_and_disabled_tokens() {
        // Wrong token.
        let app = admin_login_app(Some("opensesame"));
        let (cookie, token) = admin_bootstrapped(app.clone()).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/admin/login")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::from(
                        serde_json::json!({"token": "wrong"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_token");

        // Tokenless login is rejected.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/admin/login")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .body(Body::from(
                        serde_json::json!({"token": "opensesame"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Unconfigured operator authentication stays disabled.
        let app = admin_login_app(None);
        let (cookie, token) = admin_bootstrapped(app.clone()).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/admin/login")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::from(
                        serde_json::json!({"token": "anything"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "admin_disabled");
    }

    #[tokio::test]
    async fn v1_admin_logout_clears_only_the_operator_flag() {
        let app = admin_login_app(Some("opensesame"));
        let (cookie, token) = admin_bootstrapped(app.clone()).await;
        let login = Request::builder()
            .method(Method::POST)
            .uri("/api/frickmail/v1/admin/login")
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .header("x-sm-token", &token)
            .body(Body::from(
                serde_json::json!({"token": "opensesame"}).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(login).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = session_cookie(&response);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/admin/logout")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["logged_out"], true);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/session")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;
        // Anonymous again, and explicitly not an operator.
        assert_eq!(body["data"]["authenticated"], false);
        assert_eq!(body["data"]["is_admin"], false);
    }

    #[tokio::test]
    async fn v1_admin_login_rotates_the_session_id() {
        let app = admin_login_app(Some("opensesame"));
        let (cookie, token) = admin_bootstrapped(app.clone()).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/admin/login")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::from(
                        serde_json::json!({"token": "opensesame"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let rotated = session_cookie(&response);
        assert_ne!(rotated, cookie);
    }

    #[tokio::test]
    async fn v1_admin_logout_preserves_user_sessions() {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1401, "v1both", "correct-horse", None).await;
        let mut config = test_api_config();
        config.admin.token_hash = Some(fm_user::hash_admin_token("opensesame").unwrap());
        let app = Router::new()
            .nest("/api/frickmail/v1", super::routes())
            .layer(fm_session::session_layer(
                fm_session::AppSessionStore::Memory(fm_session::MemoryStore::default()),
            ))
            .with_state(AppState::with_db_pool(config, Some(pool)));
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1both", "correct-horse").await;

        let admin_login = Request::builder()
            .method(Method::POST)
            .uri("/api/frickmail/v1/admin/login")
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .header("x-sm-token", &token)
            .body(Body::from(
                serde_json::json!({"token": "opensesame"}).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(admin_login).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = session_cookie(&response);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/admin/logout")
                    .header("cookie", &cookie)
                    .header("x-sm-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/session")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;
        assert_eq!(body["data"]["authenticated"], true);
        assert_eq!(body["data"]["user"]["id"], 1401);
        assert_eq!(body["data"]["is_admin"], false);
    }

    async fn admin_domain_app() -> Router {
        let mut config = test_api_config();
        config.admin.token_hash = Some(fm_user::hash_admin_token("opensesame").unwrap());
        let pool = login_db_pool().await;
        Router::new()
            .nest("/api/frickmail/v1", super::routes())
            .layer(fm_session::session_layer(
                fm_session::AppSessionStore::Memory(fm_session::MemoryStore::default()),
            ))
            .with_state(AppState::with_db_pool(config, Some(pool)))
    }

    async fn admin_operator_cookie(app: Router, cookie: &str, token: &str) -> String {
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/frickmail/v1/admin/login")
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .header("x-sm-token", token)
                    .body(Body::from(
                        serde_json::json!({"token": "opensesame"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        session_cookie(&response)
    }

    fn admin_domain_request(
        method: Method,
        uri: &str,
        cookie: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("cookie", cookie);
        if let Some(token) = token {
            request = request
                .header("content-type", "application/json")
                .header("x-sm-token", token);
        }
        request
            .body(
                body.map(|value| Body::from(value.to_string()))
                    .unwrap_or_else(Body::empty),
            )
            .unwrap()
    }

    #[tokio::test]
    async fn v1_admin_domains_require_operator_sessions() {
        let app = admin_domain_app().await;
        let (cookie, token) = bootstrap_csrf(app.clone()).await;

        // Anonymous callers are rejected before any database or CSRF work.
        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/domains",
                &cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // A signed-in user without the operator flag is rejected too.
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1501, "v1plain", "correct-horse", None).await;
        let mut config = test_api_config();
        config.admin.token_hash = Some(fm_user::hash_admin_token("opensesame").unwrap());
        let user_app = Router::new()
            .nest("/api/frickmail/v1", super::routes())
            .layer(fm_session::session_layer(
                fm_session::AppSessionStore::Memory(fm_session::MemoryStore::default()),
            ))
            .with_state(AppState::with_db_pool(config, Some(pool)));
        let (user_cookie, user_token) = bootstrap_csrf(user_app.clone()).await;
        let user_cookie = login_as(
            user_app.clone(),
            &user_cookie,
            &user_token,
            "v1plain",
            "correct-horse",
        )
        .await;
        let response = user_app
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/domains",
                &user_cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Operator POSTs without CSRF are rejected even with a valid session.
        let cookie = admin_operator_cookie(app.clone(), &cookie, &token).await;
        let response = app
            .oneshot(admin_domain_request(
                Method::POST,
                "/api/frickmail/v1/admin/domains",
                &cookie,
                None,
                Some(serde_json::json!({"name": "example.com"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn v1_admin_domains_crud_roundtrip() {
        let app = admin_domain_app().await;
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = admin_operator_cookie(app.clone(), &cookie, &token).await;

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/domains",
                &cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(read_json(response).await["data"]["domains"], json!([]));

        let saved = serde_json::json!({
            "name": "Example.COM",
            "imap_host": "imap.example.com",
            "imap_port": 993,
            "imap_secure": "ssl",
            "smtp_host": "smtp.example.com",
            "smtp_port": 465,
            "smtp_secure": "SSL"
        });
        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::POST,
                "/api/frickmail/v1/admin/domains",
                &cookie,
                Some(&token),
                Some(saved),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["domain"]["name"], "example.com");
        assert_eq!(body["data"]["domain"]["imap_secure"], "SSL");

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/domains/example.com",
                &cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            read_json(response).await["data"]["domain"]["smtp_port"],
            465
        );

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/domains/missing.test",
                &cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::POST,
                "/api/frickmail/v1/admin/domains/aliases",
                &cookie,
                Some(&token),
                Some(serde_json::json!({"name": "example.com", "alias": "alias.test"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            read_json(response).await["data"]["domain"]["alias_of"],
            "example.com"
        );

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::POST,
                "/api/frickmail/v1/admin/domains/example.com/disable",
                &cookie,
                Some(&token),
                Some(serde_json::json!({"disabled": true})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            read_json(response).await["data"]["domain"]["disabled"],
            true
        );

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::DELETE,
                "/api/frickmail/v1/admin/domains/missing.test",
                &cookie,
                Some(&token),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::DELETE,
                "/api/frickmail/v1/admin/domains/example.com",
                &cookie,
                Some(&token),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(read_json(response).await["data"]["deleted"], true);

        let response = app
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/domains",
                &cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(read_json(response).await["data"]["domains"], json!([]));
    }

    #[tokio::test]
    async fn v1_admin_domains_reject_invalid_rows() {
        let app = admin_domain_app().await;
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = admin_operator_cookie(app.clone(), &cookie, &token).await;

        for body in [
            serde_json::json!({"name": "no-dot"}),
            serde_json::json!({"name": "example.com", "imap_port": 0}),
            serde_json::json!({"name": "example.com", "smtp_secure": "ROT13"}),
            serde_json::json!({"name": "example.com", "alias": "example.com"}),
        ] {
            let uri = if body.get("alias").is_some() {
                "/api/frickmail/v1/admin/domains/aliases"
            } else {
                "/api/frickmail/v1/admin/domains"
            };
            let response = app
                .clone()
                .oneshot(admin_domain_request(
                    Method::POST,
                    uri,
                    &cookie,
                    Some(&token),
                    Some(body),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        // Alias targets must exist.
        let response = app
            .oneshot(admin_domain_request(
                Method::POST,
                "/api/frickmail/v1/admin/domains/aliases",
                &cookie,
                Some(&token),
                Some(serde_json::json!({"name": "missing.test", "alias": "new.test"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    async fn admin_settings_operator() -> (Router, String, String) {
        let app = admin_domain_app().await;
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = admin_operator_cookie(app.clone(), &cookie, &token).await;
        (app, cookie, token)
    }

    #[tokio::test]
    async fn external_provisioning_api_requires_operator_and_csrf() {
        for bypass in ["none", "csrf_disabled", "php_bridge"] {
            let pool = login_db_pool().await;
            seed_login_user(&pool, 1501, "policy-user", "correct-horse", None).await;
            let mut config = test_api_config();
            config.admin.token_hash = Some(fm_user::hash_admin_token("opensesame").unwrap());
            if bypass == "csrf_disabled" {
                config.security.csrf_enabled = false;
            } else if bypass == "php_bridge" {
                config.php_bridge_url = Some("http://unused.invalid".to_string());
            }
            let app = Router::new()
                .nest("/api/frickmail/v1", super::routes())
                .layer(fm_session::session_layer(
                    fm_session::AppSessionStore::Memory(fm_session::MemoryStore::default()),
                ))
                .with_state(AppState::with_db_pool(config, Some(pool.clone())));
            let (anonymous_cookie, anonymous_token) = bootstrap_csrf(app.clone()).await;
            let (user_cookie, user_token) = bootstrap_csrf(app.clone()).await;
            let user_cookie = login_as(
                app.clone(),
                &user_cookie,
                &user_token,
                "policy-user",
                "correct-horse",
            )
            .await;

            for (cookie, token) in [
                (&anonymous_cookie, &anonymous_token),
                (&user_cookie, &user_token),
            ] {
                for (method, uri, body) in [
                    (Method::GET, "/api/frickmail/v1/admin/settings", None),
                    (
                        Method::PUT,
                        "/api/frickmail/v1/admin/settings",
                        Some(json!({"settings": {"external_auth.allow_provisioning": true}})),
                    ),
                    (
                        Method::DELETE,
                        "/api/frickmail/v1/admin/settings/external_auth.allow_provisioning",
                        None,
                    ),
                ] {
                    let response = app
                        .clone()
                        .oneshot(admin_domain_request(method, uri, cookie, Some(token), body))
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::FORBIDDEN, "{bypass}");
                    assert_eq!(
                        read_json(response).await["error"]["code"],
                        "admin_forbidden"
                    );
                }
            }

            let cookie =
                admin_operator_cookie(app.clone(), &anonymous_cookie, &anonymous_token).await;
            for token in [None, Some("wrong-token")] {
                for (method, uri, body) in [
                    (
                        Method::PUT,
                        "/api/frickmail/v1/admin/settings",
                        Some(json!({"settings": {"external_auth.allow_provisioning": true}})),
                    ),
                    (
                        Method::DELETE,
                        "/api/frickmail/v1/admin/settings/external_auth.allow_provisioning",
                        None,
                    ),
                ] {
                    let mut request = admin_domain_request(method, uri, &cookie, token, body);
                    request.headers_mut().insert(
                        "content-type",
                        axum::http::HeaderValue::from_static("application/json"),
                    );
                    let response = app.clone().oneshot(request).await.unwrap();
                    assert_eq!(response.status(), StatusCode::FORBIDDEN, "{bypass}");
                    assert_eq!(read_json(response).await["error"]["code"], "invalid_token");
                }
            }
            assert_eq!(
                fm_user::SqlxUserRepository::get_app_setting_value(
                    &pool,
                    "admin_override:external_auth.allow_provisioning",
                )
                .await
                .unwrap(),
                None
            );
        }
    }

    #[tokio::test]
    async fn external_provisioning_api_enable_disable_reset() {
        let (app, cookie, token) = admin_settings_operator().await;
        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::PUT,
                "/api/frickmail/v1/admin/settings",
                &cookie,
                Some(&token),
                Some(json!({"settings": {"open_signup": true}})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["settings"]["open_signup"]["value"], true);
        assert_eq!(
            body["data"]["settings"]["external_auth.allow_provisioning"],
            json!({"value": false, "source": "default"})
        );

        for enabled in [true, false, true] {
            let response = app
                .clone()
                .oneshot(admin_domain_request(
                    Method::PUT,
                    "/api/frickmail/v1/admin/settings",
                    &cookie,
                    Some(&token),
                    Some(json!({"settings": {"external_auth.allow_provisioning": enabled}})),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                read_json(response).await["data"]["settings"]["external_auth.allow_provisioning"],
                json!({"value": enabled, "source": "database"})
            );
            let response = app
                .clone()
                .oneshot(admin_domain_request(
                    Method::GET,
                    "/api/frickmail/v1/admin/settings",
                    &cookie,
                    None,
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                read_json(response).await["data"]["settings"]["external_auth.allow_provisioning"],
                json!({"value": enabled, "source": "database"})
            );
        }

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::DELETE,
                "/api/frickmail/v1/admin/settings/external_auth.allow_provisioning",
                &cookie,
                Some(&token),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(read_json(response).await["data"]["reset"], true);
        let response = app
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/settings",
                &cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["settings"]["open_signup"]["value"], true);
        assert_eq!(
            body["data"]["settings"]["external_auth.allow_provisioning"],
            json!({"value": false, "source": "default"})
        );
    }

    #[tokio::test]
    async fn external_provisioning_api_rejects_non_boolean_values() {
        let (app, cookie, token) = admin_settings_operator().await;
        for invalid in [
            json!("true"),
            json!("false"),
            json!("yes"),
            json!(1),
            json!(0),
            json!(null),
            json!([]),
            json!({}),
        ] {
            let response = app
                .clone()
                .oneshot(admin_domain_request(
                    Method::PUT,
                    "/api/frickmail/v1/admin/settings",
                    &cookie,
                    Some(&token),
                    Some(json!({"settings": {
                        "external_auth.allow_provisioning": invalid,
                        "open_signup": true
                    }})),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                read_json(response).await["error"]["code"],
                "invalid_request"
            );
            let response = app
                .clone()
                .oneshot(admin_domain_request(
                    Method::GET,
                    "/api/frickmail/v1/admin/settings",
                    &cookie,
                    None,
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = read_json(response).await;
            assert_eq!(body["data"]["settings"]["open_signup"]["value"], false);
            assert_eq!(
                body["data"]["settings"]["external_auth.allow_provisioning"],
                json!({"value": false, "source": "default"})
            );
        }
    }

    #[tokio::test]
    async fn v1_admin_settings_require_operator_sessions() {
        let app = admin_domain_app().await;
        let (cookie, token) = bootstrap_csrf(app.clone()).await;

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/settings",
                &cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Operator session without CSRF is still rejected on PUT.
        let cookie = admin_operator_cookie(app.clone(), &cookie, &token).await;
        let response = app
            .oneshot(admin_domain_request(
                Method::PUT,
                "/api/frickmail/v1/admin/settings",
                &cookie,
                None,
                Some(serde_json::json!({"settings": {"open_signup": true}})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn v1_admin_settings_roundtrip() {
        let (app, cookie, token) = admin_settings_operator().await;

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/settings",
                &cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["settings"]["open_signup"]["value"], false);
        assert_eq!(
            body["data"]["settings"]["open_signup"]["source"],
            "environment"
        );
        assert_eq!(
            body["data"]["settings"]["frickmail_user.allow_export"]["value"],
            true
        );
        assert_eq!(
            body["data"]["settings"]["frickmail_user.export_folder_max_messages"]["value"],
            5000
        );

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::PUT,
                "/api/frickmail/v1/admin/settings",
                &cookie,
                Some(&token),
                Some(serde_json::json!({"settings": {
                    "open_signup": true,
                    "frickmail_user.export_folder_max_messages": 500
                }})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["data"]["settings"]["open_signup"]["value"], true);
        assert_eq!(
            body["data"]["settings"]["open_signup"]["source"],
            "database"
        );
        assert_eq!(
            body["data"]["settings"]["frickmail_user.export_folder_max_messages"]["value"],
            500
        );
        // Untouched keys still report the environment.
        assert_eq!(
            body["data"]["settings"]["frickmail_user.allow_export"]["source"],
            "environment"
        );

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::DELETE,
                "/api/frickmail/v1/admin/settings/open_signup",
                &cookie,
                Some(&token),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(read_json(response).await["data"]["reset"], true);

        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/settings",
                &cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        let body = read_json(response).await;
        assert_eq!(body["data"]["settings"]["open_signup"]["value"], false);
        assert_eq!(
            body["data"]["settings"]["open_signup"]["source"],
            "environment"
        );

        // Resetting a key without an override is 404, not silent success.
        let response = app
            .oneshot(admin_domain_request(
                Method::DELETE,
                "/api/frickmail/v1/admin/settings/open_signup",
                &cookie,
                Some(&token),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn v1_admin_settings_reject_invalid_writes() {
        let (app, cookie, token) = admin_settings_operator().await;

        for (uri, body) in [
            (
                "/api/frickmail/v1/admin/settings",
                serde_json::json!({"settings": {"bogus.key": true}}),
            ),
            (
                "/api/frickmail/v1/admin/settings",
                serde_json::json!({"settings": {"open_signup": "yes"}}),
            ),
            (
                "/api/frickmail/v1/admin/settings",
                serde_json::json!({"settings": {"open_signup": 1}}),
            ),
            (
                "/api/frickmail/v1/admin/settings",
                serde_json::json!({"settings": {"frickmail_user.export_folder_max_messages": 0}}),
            ),
            (
                "/api/frickmail/v1/admin/settings",
                serde_json::json!({"settings": {"frickmail_user.export_folder_max_bytes": 1.5}}),
            ),
            (
                "/api/frickmail/v1/admin/settings",
                serde_json::json!({"settings": {}}),
            ),
        ] {
            let response = app
                .clone()
                .oneshot(admin_domain_request(
                    Method::PUT,
                    uri,
                    &cookie,
                    Some(&token),
                    Some(body),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        // A batch mixing a valid and an unknown key persists nothing.
        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::PUT,
                "/api/frickmail/v1/admin/settings",
                &cookie,
                Some(&token),
                Some(serde_json::json!({"settings": {"open_signup": true, "bogus.key": true}})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = app
            .clone()
            .oneshot(admin_domain_request(
                Method::GET,
                "/api/frickmail/v1/admin/settings",
                &cookie,
                None,
                None,
            ))
            .await
            .unwrap();
        let body = read_json(response).await;
        assert_eq!(
            body["data"]["settings"]["open_signup"]["source"],
            "environment"
        );

        // Resetting an unknown key is 400, not 404.
        let response = app
            .oneshot(admin_domain_request(
                Method::DELETE,
                "/api/frickmail/v1/admin/settings/bogus.key",
                &cookie,
                Some(&token),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    async fn avatar_user_cookie() -> (Router, String) {
        let pool = login_db_pool().await;
        seed_login_user(&pool, 1601, "v1avatar", "correct-horse", None).await;
        let app = Router::new()
            .nest("/api/frickmail/v1", super::routes())
            .layer(fm_session::session_layer(
                fm_session::AppSessionStore::Memory(fm_session::MemoryStore::default()),
            ))
            .with_state(AppState::with_db_pool(test_api_config(), Some(pool)));
        let (cookie, token) = bootstrap_csrf(app.clone()).await;
        let cookie = login_as(app.clone(), &cookie, &token, "v1avatar", "correct-horse").await;
        (app, cookie)
    }

    #[tokio::test]
    async fn v1_avatar_requires_user_sessions() {
        let (app, _) = avatar_user_cookie().await;
        let (anon_cookie, _) = bootstrap_csrf(app.clone()).await;

        // Anonymous callers are rejected even for harmless lookups.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/avatar?email=a%40github.com&bimi=1")
                    .header("cookie", &anon_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Operator-only sessions (no user) are rejected too.
        let op_app = admin_login_app(Some("opensesame"));
        let (op_cookie, op_token) = admin_bootstrapped(op_app.clone()).await;
        let op_cookie = {
            let response = op_app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/frickmail/v1/admin/login")
                        .header("content-type", "application/json")
                        .header("cookie", &op_cookie)
                        .header("x-sm-token", &op_token)
                        .body(Body::from(
                            serde_json::json!({"token": "opensesame"}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            session_cookie(&response)
        };
        let response = op_app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/avatar?email=a%40github.com&bimi=1")
                    .header("cookie", &op_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn v1_avatar_serves_bundled_icons_and_validates() {
        let (app, cookie) = avatar_user_cookie().await;

        for uri in [
            "/api/frickmail/v1/avatar",
            "/api/frickmail/v1/avatar?email=",
            "/api/frickmail/v1/avatar?email=not-an-email&bimi=1",
            "/api/frickmail/v1/avatar?email=a%40nodot&bimi=1",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }

        // No DKIM assertion and remotes off: miss, without network.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/avatar?email=boss%40github.com")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // DKIM-asserted sender on a bundled brand: PNG bytes with cache headers.
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/frickmail/v1/avatar?email=boss%40github.com&bimi=1")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("image/png")
        );
        assert!(
            response.headers().contains_key("cache-control"),
            "avatar responses carry a cache lifetime"
        );
        assert!(
            response.headers().contains_key("etag"),
            "avatar responses carry an etag"
        );
        let body = read_body(response).await;
        assert!(body.starts_with(b"\x89PNG\r\n\x1a\n"));
    }
}
