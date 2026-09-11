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
        .route("/accounts", get(accounts))
        .route("/identities", get(identities))
        .route("/switch-account", post(switch_account))
        .route("/messages", get(messages))
        .route("/preferences", get(get_preferences).put(set_preferences))
        .route("/rules", get(rules))
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
}
