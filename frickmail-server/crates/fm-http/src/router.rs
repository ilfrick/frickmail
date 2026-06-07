use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
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
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fm_core::{plugin::PluginRequest, ApiEnvelope, ErrorBody, FrickmailError, HealthResponse};
use fm_imap::{
    fetch_mailbox_status, fetch_message_body_preview, BodyPreviewPart, ImapConnectionConfig,
    MailboxStatus,
};
use fm_mime::parse_body;
use fm_plugin_compat::{
    bridge_unimplemented, is_compat_hook, normalize_plugin_action, ActionNameError,
};
use fm_smtp::{send_password_reset_email, PasswordResetEmail};
use fm_user::{
    decrypt_account_secret, derive_credential_key, verify_login_password, FrickmailMe, MailAccount,
    MailAccountConnectionSecret, NewMailAccount, NewMailIdentity, NewMailRule, NewMailTask,
    NewSmimeCert, PushSubscription, SqlxUserRepository, TaskFilter, UpdateMailAccount,
    UpdateMailTask, CREDENTIAL_KEY_BYTES,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use tower::ServiceBuilder;
use tower_http::{compression::CompressionLayer, services::ServeDir, trace::TraceLayer};
use tracing::warn;

use crate::AppState;

const INVALID_INPUT_ARGUMENT: u16 = 903;
const UNKNOWN_ERROR: u16 = 999;
const JSON_BODY_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const TOTP_PENDING_SESSION_KEY: &str = "frickmail_totp_pending_secret";
const MESSAGE_BODY_FETCH_DEADLINE: Duration = Duration::from_secs(20);
const CHECK_NEW_MAIL_ACCOUNT_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DiscoveredService {
    id: String,
    name: String,
    #[serde(rename = "type")]
    service_type: String,
    provider: String,
    url: String,
    note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    needs_oauth: Option<bool>,
}

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
        "FrickmailGetTotpStatus" => {
            Some(native_frickmail_get_totp_status(state, original_action, session).await)
        }
        "FrickmailEnableTotp" => {
            Some(native_frickmail_enable_totp(state, original_action, session).await)
        }
        "FrickmailConfirmTotp" => {
            Some(native_frickmail_confirm_totp(state, original_action, payload, session).await)
        }
        "FrickmailDisableTotp" => {
            Some(native_frickmail_disable_totp(state, original_action, payload, session).await)
        }
        "FrickmailRequestPasswordReset" => {
            Some(native_frickmail_request_password_reset(state, original_action, payload).await)
        }
        "FrickmailResetPassword" => {
            Some(native_frickmail_reset_password(state, original_action, payload).await)
        }
        "FrickmailRegister" => {
            Some(native_frickmail_register(state, original_action, payload).await)
        }
        "FrickmailLogin" => {
            Some(native_frickmail_login(state, original_action, payload, session).await)
        }
        "FrickmailDiscoverServices" => {
            Some(native_frickmail_discover_services(state, original_action, payload, session).await)
        }
        "FrickmailActivateService" => {
            Some(native_frickmail_activate_service(state, original_action, payload, session).await)
        }
        "FrickmailGetPrefs" => {
            Some(native_frickmail_get_prefs(state, original_action, session).await)
        }
        "FrickmailSetPrefs" => {
            Some(native_frickmail_set_prefs(state, original_action, payload, session).await)
        }
        "FrickmailListAccounts" => {
            Some(native_frickmail_list_accounts(state, original_action, session).await)
        }
        "FrickmailAddAccount" => {
            Some(native_frickmail_add_account(state, original_action, payload, session).await)
        }
        "FrickmailUpdateAccount" => {
            Some(native_frickmail_update_account(state, original_action, payload, session).await)
        }
        "FrickmailDeleteAccount" => {
            Some(native_frickmail_delete_account(state, original_action, payload, session).await)
        }
        "FrickmailSetPrimary" => {
            Some(native_frickmail_set_primary(state, original_action, payload, session).await)
        }
        "FrickmailSetAccountPassword" => Some(
            native_frickmail_set_account_password(state, original_action, payload, session).await,
        ),
        "FrickmailSaveOAuthToken" => {
            Some(native_frickmail_save_oauth_token(state, original_action, payload, session).await)
        }
        "FrickmailSearch" => {
            Some(native_frickmail_search(state, original_action, payload, session).await)
        }
        "FrickmailGetMessageBody" => {
            Some(native_frickmail_get_message_body(state, original_action, payload, session).await)
        }
        "FrickmailCheckNewMail" => {
            Some(native_frickmail_check_new_mail(state, original_action, payload, session).await)
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
        "FrickmailAddRule" => {
            Some(native_frickmail_add_rule(state, original_action, payload, session).await)
        }
        "FrickmailDeleteRule" => {
            Some(native_frickmail_delete_rule(state, original_action, payload, session).await)
        }
        "FrickmailToggleRule" => {
            Some(native_frickmail_toggle_rule(state, original_action, payload, session).await)
        }
        "FrickmailListTasks" => {
            Some(native_frickmail_list_tasks(state, original_action, payload, session).await)
        }
        "FrickmailAddTask" => {
            Some(native_frickmail_add_task(state, original_action, payload, session).await)
        }
        "FrickmailCompleteTask" => {
            Some(native_frickmail_complete_task(state, original_action, payload, session).await)
        }
        "FrickmailDeleteTask" => {
            Some(native_frickmail_delete_task(state, original_action, payload, session).await)
        }
        "FrickmailUpdateTask" => {
            Some(native_frickmail_update_task(state, original_action, payload, session).await)
        }
        "FrickmailPushSubscribe" => {
            Some(native_frickmail_push_subscribe(state, original_action, payload, session).await)
        }
        "FrickmailGetVapidKey" => {
            Some(native_frickmail_get_vapid_key(state, original_action, session).await)
        }
        "FrickmailPushUnsubscribe" => {
            Some(native_frickmail_push_unsubscribe(state, original_action, payload, session).await)
        }
        "FrickmailListOidcLinks" => {
            Some(native_frickmail_list_oidc_links(state, original_action, session).await)
        }
        "FrickmailUnlinkOidc" => {
            Some(native_frickmail_unlink_oidc(state, original_action, payload, session).await)
        }
        "FrickmailSmimeListCerts" => {
            Some(native_frickmail_smime_list_certs(state, original_action, session).await)
        }
        "FrickmailSmimeImportCert" => {
            Some(native_frickmail_smime_import_cert(state, original_action, payload, session).await)
        }
        "FrickmailSmimeDeleteCert" => {
            Some(native_frickmail_smime_delete_cert(state, original_action, payload, session).await)
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

async fn native_frickmail_get_totp_status(
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

    match SqlxUserRepository::totp_enabled(pool, user.user_id).await {
        Ok(enabled) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "enabled": enabled
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_enable_totp(
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

    match SqlxUserRepository::begin_totp_setup(pool, user.user_id).await {
        Ok(setup) => {
            if let Err(err) = session
                .insert(TOTP_PENDING_SESSION_KEY, setup.secret.clone())
                .await
            {
                return json_result_error(
                    original_action,
                    &format!("Frickmail session write failed: {err}"),
                );
            }
            json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": {
                        "ok": setup.ok,
                        "secret": setup.secret,
                        "otpauth_uri": setup.otpauth_uri,
                        "qr_data_url": setup.qr_data_url,
                        "message": setup.message
                    }
                }),
            )
        }
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_confirm_totp(
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

    let pending_secret = match session.get::<String>(TOTP_PENDING_SESSION_KEY).await {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            return json_result_error(
                original_action,
                "No pending TOTP setup. Call EnableTotp first.",
            )
        }
        Err(err) => {
            return json_result_error(
                original_action,
                &format!("Frickmail session read failed: {err}"),
            )
        }
    };

    match SqlxUserRepository::confirm_totp(
        pool,
        user.user_id,
        pending_secret,
        payload_string(payload, "code").unwrap_or_default(),
    )
    .await
    {
        Ok(result) => {
            if result.ok {
                if let Err(err) = session.remove::<String>(TOTP_PENDING_SESSION_KEY).await {
                    return json_result_error(
                        original_action,
                        &format!("Frickmail session cleanup failed: {err}"),
                    );
                }
            }
            json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": result
                }),
            )
        }
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_disable_totp(
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

    match SqlxUserRepository::disable_totp(
        pool,
        user.user_id,
        payload_string(payload, "code").unwrap_or_default(),
    )
    .await
    {
        Ok(result) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": result
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_request_password_reset(
    state: &AppState,
    original_action: &str,
    payload: &Value,
) -> Response {
    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    match SqlxUserRepository::request_password_reset(
        pool,
        payload_string(payload, "username").unwrap_or_default(),
        state.config().base_url.clone(),
    )
    .await
    {
        Ok(result) => {
            if let Some(delivery) = &result.delivery {
                let smtp_config = state.config().transactional_smtp.clone();
                let email = PasswordResetEmail {
                    to: delivery.to.clone(),
                    username: delivery.username.clone(),
                    reset_url: delivery.reset_url.clone(),
                };
                tokio::spawn(async move {
                    match tokio::task::spawn_blocking(move || {
                        send_password_reset_email(&smtp_config, &email)
                    })
                    .await
                    {
                        Ok(Ok(_sent)) => {}
                        Ok(Err(err)) => {
                            warn!(
                                error = %err,
                                "password-reset email delivery failed after generic response"
                            );
                        }
                        Err(err) => {
                            warn!(
                                error = %err,
                                "password-reset email worker failed after generic response"
                            );
                        }
                    }
                });
            }
            json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": result
                }),
            )
        }
        Err(err) => {
            warn!(
                error = %err,
                "password-reset request failed; returning generic server error"
            );
            json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": {
                        "ok": false,
                        "error": "Server error"
                    }
                }),
            )
        }
    }
}

async fn native_frickmail_reset_password(
    state: &AppState,
    original_action: &str,
    payload: &Value,
) -> Response {
    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    match SqlxUserRepository::reset_password(
        pool,
        payload_string(payload, "token").unwrap_or_default(),
        payload_string(payload, "password").unwrap_or_default(),
    )
    .await
    {
        Ok(result) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": result
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_register(
    state: &AppState,
    original_action: &str,
    payload: &Value,
) -> Response {
    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let email = payload_optional_string(payload, "email").and_then(|value| {
        let value = value.trim().to_string();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    });

    match SqlxUserRepository::register_user(
        pool,
        state.config().open_signup,
        payload_string(payload, "username").unwrap_or_default(),
        email,
        payload_string(payload, "password").unwrap_or_default(),
    )
    .await
    {
        Ok(result) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": result
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_login(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let username = payload_string(payload, "username").unwrap_or_default();
    let password = payload_string(payload, "password").unwrap_or_default();
    let user = match SqlxUserRepository::find_by_username(pool, &username).await {
        Ok(user) => user,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    let verified = match verify_login_password(&password, user.as_ref()) {
        Ok(verified) => verified,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    if !verified {
        return json_result_error(original_action, "Invalid username or password");
    }

    let user = user.expect("verified login requires a user");
    if user
        .totp_secret
        .as_deref()
        .is_some_and(|secret| !secret.is_empty() && secret != "0")
    {
        let secret = user.totp_secret.as_deref().unwrap_or_default();
        let totp_code = payload_string(payload, "totp_code")
            .unwrap_or_default()
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>();
        let totp_result = match SqlxUserRepository::verify_totp_login_code(
            pool, user.id, secret, totp_code,
        )
        .await
        {
            Ok(result) => result,
            Err(err) => return json_result_error(original_action, &err.public_message()),
        };
        if !totp_result.ok {
            return json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": {
                        "ok": false,
                        "requires_totp": true,
                        "error": totp_result.error.unwrap_or_else(|| "Invalid two-factor code".to_string())
                    }
                }),
            );
        }
    }

    let credential_key = match derive_credential_key(&password, &user.kdf_salt) {
        Ok(credential_key) => credential_key,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };

    if let Err(err) = session.cycle_id().await {
        return json_result_error(
            original_action,
            &format!("Frickmail session rotation failed: {err}"),
        );
    }
    if let Err(err) = session
        .insert(
            fm_session::USER_SESSION_KEY,
            fm_core::UserSession {
                user_id: user.id,
                username: user.username.clone(),
                email: user.email.clone(),
            },
        )
        .await
    {
        return json_result_error(
            original_action,
            &format!("Frickmail session write failed: {err}"),
        );
    }
    if let Err(err) = session
        .insert(
            fm_session::CREDENTIAL_KEY_SESSION_KEY,
            STANDARD.encode(credential_key),
        )
        .await
    {
        let _ = session
            .remove::<fm_core::UserSession>(fm_session::USER_SESSION_KEY)
            .await;
        return json_result_error(
            original_action,
            &format!("Frickmail session write failed: {err}"),
        );
    }

    match SqlxUserRepository::list_mail_accounts(pool, user.id).await {
        Ok(accounts) => {
            let primary = accounts.iter().find(|account| account.is_primary);
            if primary.is_none() {
                return json_value_envelope(
                    StatusCode::OK,
                    original_action,
                    json!({
                        "Result": {
                            "ok": true,
                            "no_primary": true,
                            "message": "Logged in. Add a mail account from the settings panel."
                        }
                    }),
                );
            }

            json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": {
                        "ok": false,
                        "bridge_pending": true,
                        "error": "Native primary-account bridge migration is pending."
                    }
                }),
            )
        }
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_discover_services(
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

    match SqlxUserRepository::get_mail_account(pool, user.user_id, payload_i64(payload, "id")).await
    {
        Ok(Some(account)) => {
            let services = discover_account_services(&account).await;
            json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": {
                        "ok": true,
                        "email": account.email,
                        "services": services
                    }
                }),
            )
        }
        Ok(None) => json_result_error(original_action, "Account not found"),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_activate_service(
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

    match SqlxUserRepository::activate_service(
        pool,
        user.user_id,
        payload_i64(payload, "account_id"),
        payload_string(payload, "service_type").unwrap_or_default(),
        payload_string(payload, "provider").unwrap_or_default(),
        payload_string(payload, "url").unwrap_or_default(),
    )
    .await
    {
        Ok(result) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": result
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
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

async fn native_frickmail_add_account(
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

    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };
    let account = NewMailAccount {
        label: payload_optional_string(payload, "label"),
        email: payload_string(payload, "email").unwrap_or_default(),
        account_type: payload_string(payload, "type")
            .or_else(|| payload_string(payload, "account_type"))
            .unwrap_or_else(|| "imap".to_string()),
        imap_host: payload_optional_string(payload, "imap_host"),
        imap_port: payload_optional_i64(payload, "imap_port"),
        imap_secure: payload_optional_string(payload, "imap_secure"),
        smtp_host: payload_optional_string(payload, "smtp_host"),
        smtp_port: payload_optional_i64(payload, "smtp_port"),
        smtp_secure: payload_optional_string(payload, "smtp_secure"),
        login: payload_optional_string(payload, "login"),
        password: payload_optional_string(payload, "password"),
        oauth_tenant: payload_optional_string(payload, "tenant")
            .or_else(|| payload_optional_string(payload, "oauth_tenant")),
        is_primary: payload_bool(payload, "is_primary"),
    };

    match SqlxUserRepository::add_mail_account(pool, user.user_id, account, &credential_key).await {
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

async fn native_frickmail_update_account(
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

    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };
    let account = UpdateMailAccount {
        id: payload_i64(payload, "id"),
        label: payload_optional_string(payload, "label"),
        imap_host: payload_optional_string(payload, "imap_host"),
        imap_port: payload_optional_i64(payload, "imap_port"),
        imap_secure: payload_optional_string(payload, "imap_secure"),
        smtp_host: payload_optional_string(payload, "smtp_host"),
        smtp_port: payload_optional_i64(payload, "smtp_port"),
        smtp_secure: payload_optional_string(payload, "smtp_secure"),
        login: payload_optional_string(payload, "login"),
        password: payload_optional_string(payload, "password"),
    };

    match SqlxUserRepository::update_mail_account(pool, user.user_id, account, &credential_key)
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

async fn native_frickmail_delete_account(
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

    match SqlxUserRepository::delete_mail_account(pool, user.user_id, payload_i64(payload, "id"))
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

async fn native_frickmail_set_primary(
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

    match SqlxUserRepository::set_primary_mail_account(
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

async fn native_frickmail_set_account_password(
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

    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };

    match SqlxUserRepository::set_mail_account_password(
        pool,
        user.user_id,
        payload_i64(payload, "id"),
        payload_string(payload, "password").unwrap_or_default(),
        &credential_key,
    )
    .await
    {
        Ok(true) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true
                }
            }),
        ),
        Ok(false) => json_result_error(original_action, "Account not found"),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_save_oauth_token(
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

    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };

    match SqlxUserRepository::save_oauth_refresh_token(
        pool,
        user.user_id,
        payload_string(payload, "type").unwrap_or_default(),
        payload_string(payload, "email").unwrap_or_default(),
        payload_string(payload, "refresh_token")
            .or_else(|| payload_string(payload, "token"))
            .unwrap_or_default(),
        &credential_key,
    )
    .await
    {
        Ok(true) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true
                }
            }),
        ),
        Ok(false) => json_result_error(original_action, "Account not found"),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_search(
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

    let query = payload_string(payload, "q").unwrap_or_default();
    let trimmed_query = query.trim().to_string();
    match SqlxUserRepository::search_messages(
        pool,
        user.user_id,
        trimmed_query.clone(),
        payload_search_limit(payload),
    )
    .await
    {
        Ok(results) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "query": trimmed_query,
                    "results": results
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_get_message_body(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_get_message_body_with_fetcher(
        state,
        original_action,
        payload,
        session,
        MESSAGE_BODY_FETCH_DEADLINE,
        |config, password, folder, uid| async move {
            fetch_message_body_preview(config, &password, &folder, uid).await
        },
    )
    .await
}

async fn native_frickmail_get_message_body_with_fetcher<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, u32) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Option<Vec<BodyPreviewPart>>>>,
{
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let account_id = payload_i64(payload, "account_id");
    let uid = payload_i64(payload, "uid");
    if account_id <= 0 {
        return json_result_error(original_action, "Account id required");
    }
    if uid <= 0 || uid > u32::MAX as i64 {
        return json_result_error(original_action, "uid required");
    }

    let account = match SqlxUserRepository::get_mail_account_connection_secret(
        pool,
        user.user_id,
        account_id,
    )
    .await
    {
        Ok(Some(account)) => account,
        Ok(None) => return json_result_error(original_action, "Account not found"),
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };

    let config = match imap_config_from_account_secret(&account) {
        Ok(config) => config,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    let password = match account_password(&account, &credential_key) {
        Ok(password) => password,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    let folder = payload_optional_string(payload, "folder").unwrap_or_else(|| "INBOX".to_string());

    let fetch = tokio::time::timeout(
        fetch_deadline,
        fetcher(config, password, folder, uid as u32),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Message body fetch timed out".to_string()));

    match fetch {
        Ok(Ok(Some(parts))) => message_body_parts_response(original_action, parts),
        Ok(Ok(None)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": false,
                    "error": "Message not found"
                }
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_check_new_mail(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_check_new_mail_with_fetcher(
        state,
        original_action,
        payload,
        session,
        CHECK_NEW_MAIL_ACCOUNT_DEADLINE,
        |config, password, folder| async move {
            fetch_mailbox_status(config, &password, &folder).await
        },
    )
    .await
}

async fn native_frickmail_check_new_mail_with_fetcher<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    F: Fn(ImapConnectionConfig, String, String) -> Fut + Clone,
    Fut: std::future::Future<Output = fm_core::Result<MailboxStatus>>,
{
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let last_uids = payload_last_uids(payload);
    let accounts = match SqlxUserRepository::list_mail_accounts(pool, user.user_id).await {
        Ok(accounts) => accounts,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };

    let mut results = Vec::new();
    for account in accounts {
        if account.account_type != "imap" {
            continue;
        }
        let secret = match SqlxUserRepository::get_mail_account_connection_secret(
            pool,
            user.user_id,
            account.id,
        )
        .await
        {
            Ok(Some(secret)) => secret,
            _ => continue,
        };
        let config = match imap_config_from_account_secret(&secret) {
            Ok(config) => config,
            Err(_) => continue,
        };
        let password = match account_password(&secret, &credential_key) {
            Ok(password) => password,
            Err(_) => continue,
        };

        let fetcher = fetcher.clone();
        let status = match tokio::time::timeout(
            fetch_deadline,
            fetcher(config, password, "INBOX".to_string()),
        )
        .await
        {
            Ok(Ok(status)) => status,
            _ => continue,
        };

        let uidnext = i64::from(status.uid_next.unwrap_or_default());
        let last_uidnext = last_uids
            .get(&account.id.to_string())
            .copied()
            .unwrap_or_default();
        let new_count = if last_uidnext > 0 && uidnext > last_uidnext {
            uidnext - last_uidnext
        } else {
            0
        };

        results.push(json!({
            "account_id": account.id,
            "account_email": account.email,
            "uidnext": uidnext,
            "messages": status.exists,
            "new_count": new_count
        }));
    }

    json_value_envelope(
        StatusCode::OK,
        original_action,
        json!({
            "Result": {
                "ok": true,
                "accounts": results
            }
        }),
    )
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

async fn native_frickmail_add_rule(
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

    let rule = NewMailRule {
        account_id: payload_i64(payload, "account_id"),
        name: payload_string(payload, "name").unwrap_or_default(),
        conditions: payload_array(payload, "conditions"),
        conditions_logic: payload_string(payload, "conditions_logic")
            .unwrap_or_else(|| "all".to_string()),
        actions: payload_array(payload, "actions"),
    };

    match SqlxUserRepository::add_mail_rule(pool, user.user_id, rule).await {
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

async fn native_frickmail_list_tasks(
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

    match SqlxUserRepository::list_tasks(pool, user.user_id, payload_task_filter(payload)).await {
        Ok(tasks) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "tasks": tasks
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_add_task(
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

    let task = NewMailTask {
        title: payload_string(payload, "title").unwrap_or_default(),
        notes: payload_optional_string(payload, "notes"),
        due_date: payload_optional_string(payload, "due_date"),
    };
    match SqlxUserRepository::add_task(pool, user.user_id, task).await {
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

async fn native_frickmail_complete_task(
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

    match SqlxUserRepository::complete_task(
        pool,
        user.user_id,
        payload_i64(payload, "id"),
        payload_bool(payload, "completed"),
    )
    .await
    {
        Ok(ok) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": ok
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_delete_task(
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

    match SqlxUserRepository::delete_task(pool, user.user_id, payload_i64(payload, "id")).await {
        Ok(ok) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": ok
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_update_task(
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

    let task = UpdateMailTask {
        id: payload_i64(payload, "id"),
        title: payload_string(payload, "title").unwrap_or_default(),
        notes: payload_optional_string(payload, "notes"),
        due_date: payload_optional_string(payload, "due_date"),
    };
    match SqlxUserRepository::update_task(pool, user.user_id, task).await {
        Ok(ok) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": ok
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_push_subscribe(
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

    let subscription = PushSubscription {
        endpoint: payload_string(payload, "endpoint").unwrap_or_default(),
        p256dh: payload_string(payload, "p256dh").unwrap_or_default(),
        auth_key: payload_string(payload, "auth").unwrap_or_default(),
    };

    match SqlxUserRepository::upsert_push_subscription(pool, user.user_id, subscription).await {
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

async fn native_frickmail_get_vapid_key(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
) -> Response {
    let Some(_user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "Not authenticated");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    match SqlxUserRepository::get_or_create_vapid_public_key(pool).await {
        Ok(public_key) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "public_key": public_key
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_push_unsubscribe(
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

    match SqlxUserRepository::delete_push_subscription(
        pool,
        user.user_id,
        payload_string(payload, "endpoint").unwrap_or_default(),
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

async fn native_frickmail_list_oidc_links(
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

    match SqlxUserRepository::list_oidc_links(
        pool,
        user.user_id,
        &state.config().oidc.provider_name,
    )
    .await
    {
        Ok(links) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "links": links
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_unlink_oidc(
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

    match SqlxUserRepository::unlink_oidc_identity(
        pool,
        user.user_id,
        payload_string(payload, "provider_hash").unwrap_or_default(),
    )
    .await
    {
        Ok(()) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "message": "OIDC identity unlinked."
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_smime_list_certs(
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

    match SqlxUserRepository::list_smime_certs(pool, user.user_id).await {
        Ok(certs) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "certs": certs
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_smime_import_cert(
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
    if account_id <= 0 {
        return json_result_error(original_action, "account_id required");
    }
    let pem_b64 = payload_string(payload, "pem_b64").unwrap_or_default();
    let pem_b64 = pem_b64.trim();
    if pem_b64.is_empty() {
        return json_result_error(original_action, "pem_b64 required");
    }
    let pem = match STANDARD.decode(pem_b64) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(value) => value,
            Err(_) => return json_result_error(original_action, "Invalid PEM certificate"),
        },
        Err(_) => return json_result_error(original_action, "Invalid base64 in pem_b64"),
    };

    match SqlxUserRepository::import_smime_cert(
        pool,
        user.user_id,
        NewSmimeCert { account_id, pem },
    )
    .await
    {
        Ok(result) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": result
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_smime_delete_cert(
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

    match SqlxUserRepository::delete_smime_cert(pool, user.user_id, payload_i64(payload, "id"))
        .await
    {
        Ok(true) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true
                }
            }),
        ),
        Ok(false) => json_result_error(original_action, "Certificate not found or already deleted"),
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

async fn load_session_credential_key(
    original_action: &str,
    session: &fm_session::Session,
) -> std::result::Result<Vec<u8>, Response> {
    let encoded_key = session
        .get::<String>(fm_session::CREDENTIAL_KEY_SESSION_KEY)
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

    let Some(encoded_key) = encoded_key else {
        return Err(json_result_error(original_action, "Not authenticated"));
    };
    let Ok(key) = STANDARD.decode(encoded_key.trim()) else {
        return Err(json_result_error(original_action, "Not authenticated"));
    };
    if key.len() != CREDENTIAL_KEY_BYTES {
        return Err(json_result_error(original_action, "Not authenticated"));
    }

    Ok(key)
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

async fn discover_account_services(account: &MailAccount) -> Vec<DiscoveredService> {
    let domain = account
        .email
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_ascii_lowercase())
        .unwrap_or_default();
    let account_type = account.account_type.as_str();

    let is_google = account_type == "gmail"
        || matches!(domain.as_str(), "gmail.com" | "googlemail.com")
        || domain.ends_with(".google.com");
    let is_microsoft = account_type == "o365"
        || matches!(
            domain.as_str(),
            "outlook.com" | "hotmail.com" | "live.com" | "msn.com"
        );

    if is_google {
        let has_oauth = account_type == "gmail";
        let note = if has_oauth {
            "Syncs via Google API using the linked OAuth token."
        } else {
            "Requires Google OAuth2 - app passwords are not supported by Google for contacts/calendar sync. Re-add this account via \"Sign in with Google\" to enable sync."
        };
        return vec![
            DiscoveredService {
                id: "google-contacts".to_string(),
                name: "Google Contacts".to_string(),
                service_type: "contacts".to_string(),
                provider: "google".to_string(),
                url: "https://www.googleapis.com/carddav/v1".to_string(),
                note: note.to_string(),
                needs_oauth: Some(!has_oauth),
            },
            DiscoveredService {
                id: "google-calendar".to_string(),
                name: "Google Calendar".to_string(),
                service_type: "calendar".to_string(),
                provider: "google".to_string(),
                url: "https://apidata.googleusercontent.com/caldav/v2".to_string(),
                note: note.to_string(),
                needs_oauth: Some(!has_oauth),
            },
        ];
    }

    if is_microsoft {
        let has_oauth = account_type == "o365";
        let note = if has_oauth {
            "Syncs via Microsoft Graph using the linked OAuth token."
        } else {
            "Requires Microsoft OAuth2 - re-add this account via \"Sign in with Microsoft\" to enable sync."
        };
        return vec![
            DiscoveredService {
                id: "o365-contacts".to_string(),
                name: "Microsoft Contacts".to_string(),
                service_type: "contacts".to_string(),
                provider: "o365".to_string(),
                url: "https://graph.microsoft.com/v1.0/me/contacts".to_string(),
                note: note.to_string(),
                needs_oauth: Some(!has_oauth),
            },
            DiscoveredService {
                id: "o365-calendar".to_string(),
                name: "Microsoft Calendar".to_string(),
                service_type: "calendar".to_string(),
                provider: "o365".to_string(),
                url: "https://outlook.office365.com/caldav/v1".to_string(),
                note: note.to_string(),
                needs_oauth: Some(!has_oauth),
            },
        ];
    }

    let mut services = Vec::new();
    if let Some(service) = probe_well_known_service(&domain, "carddav").await {
        services.push(service);
    }
    if let Some(service) = probe_well_known_service(&domain, "caldav").await {
        services.push(service);
    }
    services
}

async fn probe_well_known_service(domain: &str, proto: &str) -> Option<DiscoveredService> {
    let addrs = public_socket_addrs(domain, 443).await?;

    let url = format!("https://{domain}/.well-known/{proto}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(domain, &addrs)
        .build()
        .ok()?;
    let method = reqwest::Method::from_bytes(b"PROPFIND").ok()?;
    let response = client
        .request(method, &url)
        .header("Depth", "0")
        .header("Content-Type", "application/xml")
        .body("<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><prop><current-user-principal/></prop></propfind>")
        .send()
        .await
        .ok()?;

    if !matches!(response.status().as_u16(), 200 | 207 | 301 | 302) {
        return None;
    }

    let is_contacts = proto == "carddav";
    Some(DiscoveredService {
        id: format!("{proto}-{domain}"),
        name: if is_contacts {
            format!("Contacts ({domain})")
        } else {
            format!("Calendar ({domain})")
        },
        service_type: if is_contacts {
            "contacts".to_string()
        } else {
            "calendar".to_string()
        },
        provider: "dav".to_string(),
        url: url.clone(),
        note: format!(
            "{} service found at {url}",
            if is_contacts { "CardDAV" } else { "CalDAV" }
        ),
        needs_oauth: None,
    })
}

async fn public_socket_addrs(domain: &str, port: u16) -> Option<Vec<SocketAddr>> {
    if domain.is_empty() {
        return None;
    }
    let addrs = tokio::net::lookup_host((domain, port)).await.ok()?;
    let mut public_addrs = Vec::new();
    for addr in addrs {
        if is_reserved_ip(addr.ip()) {
            return None;
        }
        public_addrs.push(addr);
    }
    if public_addrs.is_empty() {
        None
    } else {
        Some(public_addrs)
    }
}

fn is_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return is_reserved_ip(IpAddr::V4(ipv4));
            }
            let segments = ip.segments();
            let nat64_well_known = segments[0] == 0x0064
                && segments[1] == 0xff9b
                && segments[2..6].iter().all(|segment| *segment == 0);
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || segments[..6].iter().all(|segment| *segment == 0)
                || nat64_well_known
                || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
                || (segments[0] == 0x0100
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0)
                || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || segments[0] == 0x2002
        }
    }
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

fn payload_optional_i64(payload: &Value, key: &str) -> Option<i64> {
    match payload.get(key) {
        Some(Value::Null) | None => None,
        Some(Value::Bool(false)) => None,
        Some(Value::Bool(true)) => Some(1),
        Some(Value::String(value)) if value.trim().is_empty() => None,
        Some(Value::String(value)) => {
            value
                .trim()
                .parse::<i64>()
                .ok()
                .and_then(|value| if value > 0 { Some(value) } else { None })
        }
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| {
                number
                    .as_u64()
                    .map(|value| value.min(i64::MAX as u64) as i64)
            })
            .or_else(|| number.as_f64().map(|value| value as i64))
            .and_then(|value| if value > 0 { Some(value) } else { None }),
        _ => None,
    }
}

fn payload_search_limit(payload: &Value) -> i64 {
    let Some(value) = payload.get("limit") else {
        return 50;
    };
    let raw = match value {
        Value::Null => 50,
        Value::Bool(false) => 50,
        Value::Number(number) if number.as_f64() == Some(0.0) => 50,
        Value::String(text) if text.is_empty() || text == "0" => 50,
        _ => payload_i64(payload, "limit"),
    };
    raw.clamp(1, 100)
}

fn payload_last_uids(payload: &Value) -> HashMap<String, i64> {
    fn parse_map(value: &Value) -> HashMap<String, i64> {
        let Some(object) = value.as_object() else {
            return HashMap::new();
        };

        object
            .iter()
            .filter_map(|(key, value)| {
                let uid = match value {
                    Value::Number(number) => number.as_i64(),
                    Value::String(text) => text.trim().parse::<i64>().ok(),
                    _ => None,
                }?;
                Some((key.clone(), uid.max(0)))
            })
            .collect()
    }

    match payload.get("last_uids") {
        Some(Value::Object(_)) => parse_map(&payload["last_uids"]),
        Some(Value::String(text)) => serde_json::from_str::<Value>(text)
            .map(|value| parse_map(&value))
            .unwrap_or_default(),
        _ => HashMap::new(),
    }
}

fn imap_config_from_account_secret(
    account: &MailAccountConnectionSecret,
) -> fm_core::Result<ImapConnectionConfig> {
    if account.account_type != "imap" {
        return Err(FrickmailError::BadRequest(
            "Not an IMAP account".to_string(),
        ));
    }

    let host = account
        .imap_host
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FrickmailError::BadRequest("IMAP host required".to_string()))?;
    let login = account
        .login
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| account.email.clone());

    ImapConnectionConfig::new(
        host,
        imap_port(account.imap_port)?,
        account.imap_secure.as_deref(),
        login,
    )
}

fn imap_port(port: Option<i64>) -> fm_core::Result<Option<u16>> {
    let Some(port) = port else {
        return Ok(None);
    };
    if port <= 0 {
        return Ok(None);
    }
    u16::try_from(port)
        .map(Some)
        .map_err(|_| FrickmailError::BadRequest("invalid IMAP port".to_string()))
}

fn account_password(
    account: &MailAccountConnectionSecret,
    credential_key: &[u8],
) -> fm_core::Result<String> {
    let Some(blob) = account.encrypted_password.as_deref() else {
        return Err(FrickmailError::BadRequest(
            "No credentials stored".to_string(),
        ));
    };
    decrypt_account_secret(blob, credential_key)?
        .ok_or_else(|| FrickmailError::BadRequest("No credentials stored".to_string()))
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

fn payload_array(payload: &Value, key: &str) -> Vec<Value> {
    match payload.get(key) {
        Some(Value::Array(values)) => values.clone(),
        Some(Value::Null) | None => Vec::new(),
        Some(value) => vec![value.clone()],
    }
}

fn payload_task_filter(payload: &Value) -> TaskFilter {
    match payload_string(payload, "filter").as_deref() {
        Some("pending") => TaskFilter::Pending,
        Some("completed") => TaskFilter::Completed,
        _ => TaskFilter::All,
    }
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

fn message_body_parts_response(action: &str, parts: Vec<BodyPreviewPart>) -> Response {
    let mut html = String::new();
    let mut plain = String::new();
    let mut subject = None;

    for part in parts {
        let Some(body) = parse_body(&part.raw) else {
            continue;
        };
        match part.kind {
            fm_imap::BodyPartKind::Html => {
                if html.is_empty() && !body.html.is_empty() {
                    html = body.html;
                }
            }
            fm_imap::BodyPartKind::Plain => {
                if plain.is_empty() && !body.plain.is_empty() {
                    plain = body.plain;
                }
            }
            fm_imap::BodyPartKind::RawMessage => {
                if html.is_empty() && !body.html.is_empty() {
                    html = body.html;
                }
                if plain.is_empty() && !body.plain.is_empty() {
                    plain = body.plain;
                }
            }
        }
        if subject.is_none() {
            subject = body.subject;
        }
    }

    if html.is_empty() && plain.is_empty() && subject.is_none() {
        return json_value_envelope(
            StatusCode::OK,
            action,
            json!({
                "Result": {
                    "ok": false,
                    "error": "Message body could not be parsed"
                }
            }),
        );
    }

    json_value_envelope(
        StatusCode::OK,
        action,
        json!({
            "Result": {
                "ok": true,
                "html": html,
                "plain": plain,
                "subject": subject
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use axum::{
        body::{to_bytes, Body},
        extract::{Request as AxumRequest, State},
        http::{Method, Request, StatusCode, Uri},
        response::IntoResponse,
        routing::any,
        Json, Router,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use data_encoding::BASE32_NOPAD;
    use fm_core::{FrickmailConfig, UserSession};
    use fm_imap::{BodyPartKind, BodyPreviewPart, MailboxStatus};
    use fm_session::{MemoryStore, Session, CREDENTIAL_KEY_SESSION_KEY, USER_SESSION_KEY};
    use hmac::{Hmac, Mac};
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        x509::{extension::SubjectAlternativeName, X509NameBuilder, X509},
    };
    use serde_json::{json, Value};
    use sha1::Sha1;
    use sqlx::{any::AnyPoolOptions, AnyPool, Row};
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
    async fn json_api_dispatches_native_totp_status_action() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("Action=PluginFrickmailGetTotpStatus"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
        assert_eq!(body["Action"], "PluginFrickmailGetTotpStatus");
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
    async fn native_frickmail_get_totp_status_matches_secret_presence() {
        let pool = user_db_pool().await;
        seed_user(&pool, 143, "totp", Some("totp@example.com")).await;
        set_totp_secret(&pool, 143, Some("SECRET")).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(143, "totp", None).await;

        let response =
            super::native_frickmail_get_totp_status(&state, "FrickmailGetTotpStatus", &session)
                .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["enabled"], true);

        set_totp_secret(&pool, 143, Some("")).await;
        let response =
            super::native_frickmail_get_totp_status(&state, "FrickmailGetTotpStatus", &session)
                .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["enabled"], false);

        set_totp_secret(&pool, 143, Some("0")).await;
        let response =
            super::native_frickmail_get_totp_status(&state, "FrickmailGetTotpStatus", &session)
                .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["enabled"], false);
    }

    #[tokio::test]
    async fn native_frickmail_totp_setup_and_disable_match_plugin_shape() {
        let pool = user_db_pool().await;
        seed_user(&pool, 1443, "totp-setup", Some("totp-setup@example.com")).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(1443, "totp-setup", None).await;

        let response =
            super::native_frickmail_enable_totp(&state, "FrickmailEnableTotp", &session).await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert!(body["Result"]["secret"].as_str().unwrap().len() >= 16);
        assert!(body["Result"]["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/Frickmail:"));
        assert!(body["Result"]["qr_data_url"]
            .as_str()
            .unwrap()
            .starts_with("data:image/svg+xml;base64,"));
        let pending = session
            .get::<String>(super::TOTP_PENDING_SESSION_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending, body["Result"]["secret"]);

        let response = super::native_frickmail_confirm_totp(
            &state,
            "FrickmailConfirmTotp",
            &json!({"code": "000000"}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Invalid code");

        set_totp_secret(&pool, 1443, Some("JBSWY3DPEHPK3PXP")).await;
        let response = super::native_frickmail_disable_totp(
            &state,
            "FrickmailDisableTotp",
            &json!({"code": "000000"}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(
            body["Result"]["error"],
            "A valid TOTP code is required to disable two-factor authentication."
        );
    }

    #[tokio::test]
    async fn json_api_dispatches_native_enable_totp_action() {
        let pool = user_db_pool().await;
        seed_user(&pool, 1444, "totp-route", Some("totp-route@example.com")).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(1444, "totp-route", None).await;

        let response = super::json_api_request(
            state,
            "/?/Json/".parse().unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/?/Json/")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("Action=PluginFrickmailEnableTotp"))
                .unwrap(),
            session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginFrickmailEnableTotp");
        assert_eq!(body["Result"]["ok"], true);
        assert!(body["Result"]["secret"].as_str().unwrap().len() >= 16);
    }

    #[tokio::test]
    async fn json_api_dispatches_native_request_password_reset_action() {
        let pool = user_db_pool().await;
        create_password_reset_table(&pool).await;
        seed_user(
            &pool,
            145,
            "request-reset",
            Some("reset-request@example.com"),
        )
        .await;
        let app = super::build_router(AppState::with_db_pool(
            test_config(None),
            Some(pool.clone()),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=PluginFrickmailRequestPasswordReset&username=request-reset",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "PluginFrickmailRequestPasswordReset");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(
            body["Result"]["message"],
            "If the username exists and has a recovery email, a reset link has been sent."
        );
        assert!(body["Result"].get("delivery").is_none());
        assert_eq!(active_password_reset_count(&pool, 145).await, 1);

        let response = super::native_frickmail_request_password_reset(
            &AppState::with_db_pool(test_config(None), Some(pool.clone())),
            "FrickmailRequestPasswordReset",
            &json!({"username": "missing"}),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(active_password_reset_count(&pool, 145).await, 1);
    }

    #[tokio::test]
    async fn json_api_dispatches_native_reset_password_action() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_password_reset_table(&pool).await;
        seed_user(&pool, 144, "reset-user", Some("reset@example.com")).await;
        seed_mail_account(&pool, 1200, 144, "Primary", true).await;
        insert_password_reset(
            &pool,
            700,
            144,
            &fm_user::password_reset_token_hash("reset-token"),
            "2999-01-01 00:00:00",
            None,
        )
        .await;
        let app = super::build_router(AppState::with_db_pool(
            test_config(None),
            Some(pool.clone()),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=PluginFrickmailResetPassword&token=reset-token&password=new-secret",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "PluginFrickmailResetPassword");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["username"], "reset-user");
        assert_eq!(
            body["Result"]["message"],
            "Password reset. Sign in with your new password. Linked mail-account credentials must be re-entered."
        );
        let user = SqlxUserRepository::find_by_id(&pool, 144)
            .await
            .unwrap()
            .unwrap();
        assert!(fm_user::verify_login_password("new-secret", Some(&user)).unwrap());
        assert!(password_reset_used_at(&pool, 700).await.is_some());

        let response = super::native_frickmail_reset_password(
            &AppState::with_db_pool(test_config(None), Some(pool)),
            "FrickmailResetPassword",
            &json!({"token": "reset-token", "password": "short"}),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Password must be at least 8 chars");
    }

    #[tokio::test]
    async fn json_api_dispatches_native_register_action() {
        let pool = user_db_pool().await;
        let mut config = test_config(None);
        config.open_signup = true;
        let app = super::build_router(AppState::with_db_pool(config, Some(pool.clone())));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=PluginFrickmailRegister&username=NewUser&email=new@example.com&password=correct-horse",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "PluginFrickmailRegister");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(
            body["Result"]["message"],
            "Account created. Sign in to add your mail accounts."
        );
        let user = SqlxUserRepository::find_by_username(&pool, "newuser")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.email.as_deref(), Some("new@example.com"));
        assert!(fm_user::verify_login_password("correct-horse", Some(&user)).unwrap());
    }

    #[tokio::test]
    async fn native_frickmail_register_matches_signup_gating() {
        let pool = user_db_pool().await;
        seed_user(&pool, 150, "existing", Some("existing@example.com")).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));

        let response = super::native_frickmail_register(
            &state,
            "FrickmailRegister",
            &json!({
                "username": "blocked",
                "password": "correct-horse",
            }),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(
            body["Result"]["error"],
            "Self-signup is disabled. Ask your admin or set FRICKMAIL_OPEN_SIGNUP=true."
        );

        let mut config = test_config(None);
        config.open_signup = true;
        let state = AppState::with_db_pool(config, Some(pool.clone()));
        let response = super::native_frickmail_register(
            &state,
            "FrickmailRegister",
            &json!({
                "username": " existing ",
                "password": "correct-horse",
            }),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Username already taken");
    }

    #[tokio::test]
    async fn native_frickmail_login_writes_user_and_credential_sessions() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        let salt = [8_u8; fm_user::KDF_SALT_BYTES];
        seed_login_user(
            &pool,
            1510,
            "login-user",
            Some("login-user@example.com"),
            "correct-horse",
            &salt,
            None,
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = test_session();

        let response = super::native_frickmail_login(
            &state,
            "FrickmailLogin",
            &json!({
                "username": " LOGIN-USER ",
                "password": "correct-horse"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["no_primary"], true);
        let user_session = session
            .get::<UserSession>(USER_SESSION_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user_session.user_id, 1510);
        assert_eq!(user_session.username, "login-user");
        let encoded_key = session
            .get::<String>(CREDENTIAL_KEY_SESSION_KEY)
            .await
            .unwrap()
            .unwrap();
        let stored_key = STANDARD.decode(encoded_key).unwrap();
        assert_eq!(
            stored_key,
            fm_user::derive_credential_key("correct-horse", &salt)
                .unwrap()
                .to_vec()
        );
    }

    #[tokio::test]
    async fn native_frickmail_login_does_not_bypass_totp() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_login_user(
            &pool,
            1511,
            "totp-login",
            None,
            "correct-horse",
            &[9_u8; fm_user::KDF_SALT_BYTES],
            Some("JBSWY3DPEHPK3PXP"),
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = test_session();

        let response = super::native_frickmail_login(
            &state,
            "FrickmailLogin",
            &json!({
                "username": "totp-login",
                "password": "correct-horse"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["requires_totp"], true);
        assert_eq!(body["Result"]["error"], "Two-factor code required");
        assert!(session
            .get::<String>(CREDENTIAL_KEY_SESSION_KEY)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn native_frickmail_login_accepts_totp_once_and_rejects_replay() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_totp_used_table(&pool).await;
        seed_login_user(
            &pool,
            1514,
            "totp-valid-login",
            None,
            "correct-horse",
            &[12_u8; fm_user::KDF_SALT_BYTES],
            Some("JBSWY3DPEHPK3PXP"),
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let code = test_totp_code("JBSWY3DPEHPK3PXP", current_test_totp_counter());
        let session = test_session();

        let response = super::native_frickmail_login(
            &state,
            "FrickmailLogin",
            &json!({
                "username": "totp-valid-login",
                "password": "correct-horse",
                "totp_code": code.clone()
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["no_primary"], true);
        assert!(session
            .get::<String>(CREDENTIAL_KEY_SESSION_KEY)
            .await
            .unwrap()
            .is_some());

        let replay_session = test_session();
        let response = super::native_frickmail_login(
            &state,
            "FrickmailLogin",
            &json!({
                "username": "totp-valid-login",
                "password": "correct-horse",
                "totp_code": code
            }),
            &replay_session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["requires_totp"], true);
        assert_eq!(body["Result"]["error"], "Two-factor code already used");
        assert!(replay_session
            .get::<String>(CREDENTIAL_KEY_SESSION_KEY)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn native_frickmail_login_marks_primary_accounts_as_bridge_pending() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_login_user(
            &pool,
            1513,
            "primary-login",
            Some("primary-login@example.com"),
            "correct-horse",
            &[11_u8; fm_user::KDF_SALT_BYTES],
            None,
        )
        .await;
        seed_mail_account(&pool, 15130, 1513, "Primary", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = test_session();

        let response = super::native_frickmail_login(
            &state,
            "FrickmailLogin",
            &json!({
                "username": "primary-login",
                "password": "correct-horse"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["bridge_pending"], true);
        assert!(body["Result"].get("no_primary").is_none());
        assert!(session
            .get::<String>(CREDENTIAL_KEY_SESSION_KEY)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn json_api_dispatches_native_login_action() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_login_user(
            &pool,
            1512,
            "route-login",
            None,
            "correct-horse",
            &[10_u8; fm_user::KDF_SALT_BYTES],
            None,
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = test_session();

        let response = super::json_api_request(
            state,
            "/?/Json/".parse().unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/?/Json/")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "Action=PluginFrickmailLogin&username=route-login&password=correct-horse",
                ))
                .unwrap(),
            session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginFrickmailLogin");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["no_primary"], true);
    }

    #[tokio::test]
    async fn native_frickmail_discover_services_matches_provider_shape() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 151, "discover", Some("discover@example.com")).await;
        seed_user(
            &pool,
            152,
            "other-discover",
            Some("other-discover@example.com"),
        )
        .await;
        seed_mail_account(&pool, 1320, 151, "Google", true).await;
        seed_mail_account(&pool, 1321, 152, "Other", true).await;
        set_mail_account_email_and_type(&pool, 1320, "person@gmail.com", "imap").await;
        set_mail_account_email_and_type(&pool, 1321, "person@hotmail.com", "imap").await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(151, "discover", None).await;

        let response = super::native_frickmail_discover_services(
            &state,
            "FrickmailDiscoverServices",
            &json!({"id": 1320}),
            &session,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["email"], "person@gmail.com");
        let services = body["Result"]["services"].as_array().unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0]["id"], "google-contacts");
        assert_eq!(services[0]["type"], "contacts");
        assert_eq!(services[0]["provider"], "google");
        assert_eq!(services[0]["needs_oauth"], true);
        assert_eq!(services[1]["id"], "google-calendar");
        assert_eq!(services[1]["type"], "calendar");

        let response = super::native_frickmail_discover_services(
            &state,
            "FrickmailDiscoverServices",
            &json!({"id": 1321}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Account not found");
    }

    #[tokio::test]
    async fn json_api_dispatches_native_discover_services_action() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        let app = super::build_router(AppState::with_db_pool(test_config(None), Some(pool)));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("Action=PluginFrickmailDiscoverServices&id=1"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "PluginFrickmailDiscoverServices");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
    }

    #[tokio::test]
    async fn native_frickmail_activate_service_matches_provider_shape() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 153, "activate", Some("activate@example.com")).await;
        seed_user(&pool, 154, "other-activate", Some("other@example.com")).await;
        seed_mail_account(&pool, 1330, 153, "Work", true).await;
        seed_mail_account(&pool, 1331, 154, "Other", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(153, "activate", None).await;

        let response = super::native_frickmail_activate_service(
            &state,
            "FrickmailActivateService",
            &json!({
                "account_id": 1330,
                "service_type": "contacts",
                "provider": "google",
                "url": "https://ignored.example/contacts"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(
            body["Result"]["message"],
            "Contacts sync triggered. Open Settings -> Contacts Sync to run a full sync."
        );
        assert_eq!(mail_account_settings(&pool, 1330).await, json!({}));

        let response = super::native_frickmail_activate_service(
            &state,
            "FrickmailActivateService",
            &json!({
                "account_id": 1330,
                "service_type": "contacts",
                "provider": "dav",
                "url": "https://dav.example/.well-known/carddav"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(
            mail_account_settings(&pool, 1330).await,
            json!({"carddav_url": "https://dav.example/.well-known/carddav"})
        );

        let response = super::native_frickmail_activate_service(
            &state,
            "FrickmailActivateService",
            &json!({
                "account_id": 1331,
                "service_type": "calendar",
                "provider": "dav",
                "url": "https://dav.example/.well-known/caldav"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Account not found");
    }

    #[tokio::test]
    async fn json_api_dispatches_native_activate_service_action() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        let app = super::build_router(AppState::with_db_pool(test_config(None), Some(pool)));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=PluginFrickmailActivateService&account_id=1&service_type=contacts&provider=dav&url=https%3A%2F%2Fdav.example",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "PluginFrickmailActivateService");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
    }

    #[test]
    fn service_discovery_rejects_reserved_ips() {
        assert!(super::is_reserved_ip("127.0.0.1".parse().unwrap()));
        assert!(super::is_reserved_ip("10.0.0.1".parse().unwrap()));
        assert!(super::is_reserved_ip("100.64.0.1".parse().unwrap()));
        assert!(super::is_reserved_ip("198.18.0.1".parse().unwrap()));
        assert!(super::is_reserved_ip("192.0.2.1".parse().unwrap()));
        assert!(super::is_reserved_ip("240.0.0.1".parse().unwrap()));
        assert!(super::is_reserved_ip("::1".parse().unwrap()));
        assert!(super::is_reserved_ip("fc00::1".parse().unwrap()));
        assert!(super::is_reserved_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(super::is_reserved_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(super::is_reserved_ip("::127.0.0.1".parse().unwrap()));
        assert!(super::is_reserved_ip("64:ff9b::0a00:0001".parse().unwrap()));
        assert!(super::is_reserved_ip(
            "64:ff9b:1::0a00:0001".parse().unwrap()
        ));
        assert!(super::is_reserved_ip("100::1".parse().unwrap()));
        assert!(super::is_reserved_ip("2001:20::1".parse().unwrap()));
        assert!(super::is_reserved_ip("2002:0808:0808::1".parse().unwrap()));
        assert!(super::is_reserved_ip("2001::1".parse().unwrap()));
        assert!(super::is_reserved_ip("2001:db8::1".parse().unwrap()));
        assert!(!super::is_reserved_ip("8.8.8.8".parse().unwrap()));
        assert!(!super::is_reserved_ip("::ffff:8.8.8.8".parse().unwrap()));
        assert!(!super::is_reserved_ip(
            "2606:4700:4700::1111".parse().unwrap()
        ));
        assert!(!super::is_reserved_ip(
            "2001:4860:4860::8888".parse().unwrap()
        ));
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
    async fn native_frickmail_account_mutations_encrypt_with_session_key() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(
            &pool,
            155,
            "account-write",
            Some("account-write@example.com"),
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let key = [7_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let session = credential_session(
            155,
            "account-write",
            Some("account-write@example.com"),
            &key,
        )
        .await;

        let response = super::native_frickmail_add_account(
            &state,
            "FrickmailAddAccount",
            &json!({
                "type": "imap",
                "label": "",
                "email": "user@example.com",
                "login": "user@example.com",
                "password": "secret-pass",
                "imap_host": "8.8.8.8",
                "imap_port": 0,
                "smtp_host": "8.8.4.4",
                "smtp_port": "0",
                "is_primary": true
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        let account_id = body["Result"]["id"].as_i64().unwrap();
        assert_eq!(body["Result"]["ok"], true);

        let accounts = SqlxUserRepository::list_mail_accounts(&pool, 155)
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, account_id);
        assert_eq!(accounts[0].label, "user@example.com");
        assert_eq!(accounts[0].imap_port, Some(993));
        assert!(accounts[0].is_primary);
        let initial_password_blob = account_encrypted_password(&pool, account_id).await.unwrap();
        assert_eq!(
            fm_user::decrypt_account_secret(&initial_password_blob, &key)
                .unwrap()
                .as_deref(),
            Some("secret-pass")
        );

        let response = super::native_frickmail_update_account(
            &state,
            "FrickmailUpdateAccount",
            &json!({
                "id": account_id,
                "label": " Updated ",
                "login": "updated-login",
                "password": "",
                "imap_host": "1.1.1.1",
                "imap_port": "143",
                "imap_secure": "STARTTLS",
                "smtp_host": "8.8.8.8",
                "smtp_port": 587,
                "smtp_secure": "STARTTLS"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        let account = SqlxUserRepository::get_mail_account(&pool, 155, account_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(account.label, "Updated");
        assert_eq!(account.login.as_deref(), Some("updated-login"));
        assert_eq!(account.imap_host.as_deref(), Some("1.1.1.1"));
        assert_eq!(account.imap_port, Some(143));
        assert_eq!(account.smtp_port, Some(587));
        assert_eq!(
            account_encrypted_password(&pool, account_id).await.unwrap(),
            initial_password_blob
        );

        let response = super::native_frickmail_update_account(
            &state,
            "FrickmailUpdateAccount",
            &json!({
                "id": account_id,
                "imap_port": "0",
                "smtp_port": false
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        let account = SqlxUserRepository::get_mail_account(&pool, 155, account_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(account.imap_port, Some(143));
        assert_eq!(account.smtp_port, Some(587));

        let response = super::native_frickmail_set_account_password(
            &state,
            "FrickmailSetAccountPassword",
            &json!({
                "id": account_id,
                "password": "new-secret"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        let new_password_blob = account_encrypted_password(&pool, account_id).await.unwrap();
        assert_ne!(new_password_blob, initial_password_blob);
        assert_eq!(
            fm_user::decrypt_account_secret(&new_password_blob, &key)
                .unwrap()
                .as_deref(),
            Some("new-secret")
        );

        let response = super::native_frickmail_save_oauth_token(
            &state,
            "FrickmailSaveOAuthToken",
            &json!({
                "type": "o365",
                "email": "USER@example.com",
                "refresh_token": "refresh-token"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(account_type(&pool, account_id).await, "o365");
        let token_blob = account_oauth_refresh_token(&pool, account_id)
            .await
            .unwrap();
        assert_eq!(
            fm_user::decrypt_account_secret(&token_blob, &key)
                .unwrap()
                .as_deref(),
            Some("refresh-token")
        );
    }

    #[tokio::test]
    async fn native_frickmail_account_mutations_require_credential_key() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 156, "account-missing-key", None).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(156, "account-missing-key", None).await;

        let response = super::native_frickmail_add_account(
            &state,
            "FrickmailAddAccount",
            &json!({
                "type": "imap",
                "email": "blocked@example.com",
                "imap_host": "8.8.8.8",
                "smtp_host": "8.8.4.4"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
        assert_eq!(mail_account_count(&pool, 156).await, 0);
    }

    #[tokio::test]
    async fn json_api_dispatches_native_add_account_action() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        let app = super::build_router(AppState::with_db_pool(test_config(None), Some(pool)));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=PluginFrickmailAddAccount&type=imap&email=user%40example.com",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "PluginFrickmailAddAccount");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
    }

    #[tokio::test]
    async fn native_frickmail_delete_account_cleans_user_scoped_message_index() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_message_index_table(&pool).await;
        seed_user(&pool, 145, "accounts", Some("accounts@example.com")).await;
        seed_user(&pool, 146, "other", Some("other@example.com")).await;
        seed_mail_account(&pool, 1300, 145, "Primary", true).await;
        seed_mail_account(&pool, 1301, 146, "Other", true).await;
        seed_message_index(&pool, 145, 1300, "INBOX", 1).await;
        seed_message_index(&pool, 146, 1301, "INBOX", 2).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(145, "accounts", None).await;

        let response = super::native_frickmail_delete_account(
            &state,
            "FrickmailDeleteAccount",
            &json!({"id": 1301}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(mail_account_count(&pool, 146).await, 1);
        assert_eq!(message_index_count(&pool, 146, 1301).await, 1);

        let response = super::native_frickmail_delete_account(
            &state,
            "FrickmailDeleteAccount",
            &json!({"id": 1300}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(mail_account_count(&pool, 145).await, 0);
        assert_eq!(message_index_count(&pool, 145, 1300).await, 0);
    }

    #[tokio::test]
    async fn native_frickmail_set_primary_matches_account_scope() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 147, "accounts", Some("accounts@example.com")).await;
        seed_user(&pool, 148, "other", Some("other@example.com")).await;
        seed_mail_account(&pool, 1302, 147, "Primary", true).await;
        seed_mail_account(&pool, 1303, 147, "Secondary", false).await;
        seed_mail_account(&pool, 1304, 148, "Other", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(147, "accounts", None).await;

        let response = super::native_frickmail_set_primary(
            &state,
            "FrickmailSetPrimary",
            &json!({"id": 1303}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        let accounts = SqlxUserRepository::list_mail_accounts(&pool, 147)
            .await
            .unwrap();
        assert_eq!(accounts[0].id, 1303);
        assert!(accounts[0].is_primary);

        let response = super::native_frickmail_set_primary(
            &state,
            "FrickmailSetPrimary",
            &json!({"id": 1304}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        let accounts = SqlxUserRepository::list_mail_accounts(&pool, 147)
            .await
            .unwrap();
        assert!(accounts.iter().all(|account| !account.is_primary));
        let other_accounts = SqlxUserRepository::list_mail_accounts(&pool, 148)
            .await
            .unwrap();
        assert!(other_accounts[0].is_primary);
    }

    #[tokio::test]
    async fn native_frickmail_search_matches_plugin_shape() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_message_index_table(&pool).await;
        seed_user(&pool, 149, "search", Some("search@example.com")).await;
        seed_user(&pool, 150, "other-search", Some("other-search@example.com")).await;
        seed_mail_account(&pool, 1310, 149, "Work", true).await;
        seed_mail_account(&pool, 1311, 150, "Other", true).await;
        seed_search_message(
            &pool,
            SearchMessageSeed {
                id: 1,
                user_id: 149,
                account_id: 1310,
                folder: "INBOX",
                imap_uid: 31,
                message_id: Some("search-1"),
                subject: Some("Invoice"),
                from_addr: Some("billing@example.com"),
                from_name: Some("Billing"),
                date_ts: Some("2026-06-01 10:00:00"),
                snippet: Some("First invoice"),
            },
        )
        .await;
        seed_search_message(
            &pool,
            SearchMessageSeed {
                id: 2,
                user_id: 149,
                account_id: 1310,
                folder: "Archive",
                imap_uid: 32,
                message_id: Some("search-2"),
                subject: Some("Invoice reminder"),
                from_addr: Some("boss@example.com"),
                from_name: Some("Boss"),
                date_ts: Some("2026-06-02 10:00:00"),
                snippet: Some("Second invoice"),
            },
        )
        .await;
        seed_search_message(
            &pool,
            SearchMessageSeed {
                id: 3,
                user_id: 150,
                account_id: 1311,
                folder: "INBOX",
                imap_uid: 33,
                message_id: Some("search-3"),
                subject: Some("Invoice from other user"),
                from_addr: Some("other@example.com"),
                from_name: Some("Other"),
                date_ts: Some("2026-06-03 10:00:00"),
                snippet: Some("Must not leak"),
            },
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(149, "search", None).await;

        let response = super::native_frickmail_search(
            &state,
            "FrickmailSearch",
            &json!({"q": " invoice ", "limit": 1}),
            &session,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FrickmailSearch");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["query"], "invoice");
        let results = body["Result"]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["id"], 2);
        assert_eq!(results[0]["account_id"], 1310);
        assert_eq!(results[0]["folder"], "Archive");
        assert_eq!(results[0]["imap_uid"], 32);
        assert_eq!(results[0]["message_id"], "search-2");
        assert_eq!(results[0]["subject"], "Invoice reminder");
        assert_eq!(results[0]["from_addr"], "boss@example.com");
        assert_eq!(results[0]["from_name"], "Boss");
        assert_eq!(results[0]["date_ts"], "2026-06-02 10:00:00");
        assert_eq!(results[0]["snippet"], "Second invoice");
        assert_eq!(results[0]["account_email"], "work@example.com");

        let response =
            super::native_frickmail_search(&state, "FrickmailSearch", &json!({"q": "i"}), &session)
                .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Query too short");
    }

    #[tokio::test]
    async fn json_api_dispatches_native_search_action() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_message_index_table(&pool).await;
        let app = super::build_router(AppState::with_db_pool(test_config(None), Some(pool)));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("Action=PluginFrickmailSearch&q=invoice"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "PluginFrickmailSearch");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
    }

    #[tokio::test]
    async fn json_api_get_message_body_requires_authentication() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_message_index_table(&pool).await;
        let app = super::build_router(AppState::with_db_pool(test_config(None), Some(pool)));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=PluginFrickmailGetMessageBody&account_id=1320&uid=41",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "PluginFrickmailGetMessageBody");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
    }

    #[tokio::test]
    async fn native_frickmail_get_message_body_validates_account_before_imap() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1322, "viewer", Some("viewer@example.com")).await;
        seed_mail_account(&pool, 1320, 1322, "Work", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = credential_session(
            1322,
            "viewer",
            Some("viewer@example.com"),
            &[7_u8; fm_user::CREDENTIAL_KEY_BYTES],
        )
        .await;

        let response = super::native_frickmail_get_message_body(
            &state,
            "FrickmailGetMessageBody",
            &json!({"account_id": 9999, "uid": 41}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Account not found");

        set_mail_account_email_and_type(&pool, 1320, "person@gmail.com", "gmail").await;
        let response = super::native_frickmail_get_message_body(
            &state,
            "FrickmailGetMessageBody",
            &json!({"account_id": 1320, "uid": 41}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not an IMAP account");

        set_mail_account_email_and_type(&pool, 1320, "work@example.com", "imap").await;
        let response = super::native_frickmail_get_message_body(
            &state,
            "FrickmailGetMessageBody",
            &json!({"account_id": 1320, "uid": 41}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "No credentials stored");
    }

    #[tokio::test]
    async fn native_frickmail_get_message_body_returns_mocked_imap_body() {
        let key = [9_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1323, 1325, &key).await;

        let response = super::native_frickmail_get_message_body_with_fetcher(
            &state,
            "FrickmailGetMessageBody",
            &json!({"account_id": 1325, "uid": 41, "folder": "Sent Items"}),
            &session,
            Duration::from_secs(1),
            |config, password, folder, uid| async move {
                assert_eq!(config.host, "imap.example.com");
                assert_eq!(config.port, 993);
                assert_eq!(password, "imap-secret");
                assert_eq!(folder, "Sent Items");
                assert_eq!(uid, 41);
                Ok(Some(vec![
                    BodyPreviewPart {
                        kind: BodyPartKind::Html,
                        raw: concat!(
                            "Content-Type: text/html; charset=utf-8\r\n",
                            "\r\n",
                            "<p onclick=\"bad()\">HTML body.</p><script>bad()</script>"
                        )
                        .as_bytes()
                        .to_vec(),
                    },
                    BodyPreviewPart {
                        kind: BodyPartKind::Plain,
                        raw: b"Content-Type: text/plain; charset=utf-8\r\n\r\nPlain body.".to_vec(),
                    },
                ]))
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FrickmailGetMessageBody");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["html"], "<p>HTML body.</p>");
        assert_eq!(body["Result"]["plain"], "Plain body.");
        assert!(body["Result"]["subject"].is_null());
    }

    #[tokio::test]
    async fn native_frickmail_get_message_body_reports_missing_message() {
        let key = [10_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1326, 1327, &key).await;

        let response = super::native_frickmail_get_message_body_with_fetcher(
            &state,
            "FrickmailGetMessageBody",
            &json!({"account_id": 1327, "uid": 42}),
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _uid| async move { Ok(None) },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Message not found");
    }

    #[tokio::test]
    async fn native_frickmail_get_message_body_reports_unparseable_body() {
        let key = [11_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1328, 1329, &key).await;

        let response = super::native_frickmail_get_message_body_with_fetcher(
            &state,
            "FrickmailGetMessageBody",
            &json!({"account_id": 1329, "uid": 43}),
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _uid| async move {
                Ok(Some(vec![BodyPreviewPart {
                    kind: BodyPartKind::RawMessage,
                    raw: b"\0".to_vec(),
                }]))
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Message body could not be parsed");
    }

    #[tokio::test]
    async fn native_frickmail_get_message_body_enforces_fetch_deadline() {
        let key = [12_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1332, 1333, &key).await;

        let response = super::native_frickmail_get_message_body_with_fetcher(
            &state,
            "FrickmailGetMessageBody",
            &json!({"account_id": 1333, "uid": 44}),
            &session,
            Duration::from_millis(1),
            |_config, _password, _folder, _uid| async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(Some(Vec::new()))
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Message body fetch timed out");
    }

    #[test]
    fn last_uid_payload_parses_object_and_json_string() {
        assert_eq!(
            super::payload_last_uids(&json!({"last_uids": {"7": 42, "8": "43", "9": -1}})),
            HashMap::from([
                ("7".to_string(), 42),
                ("8".to_string(), 43),
                ("9".to_string(), 0)
            ])
        );
        assert_eq!(
            super::payload_last_uids(&json!({"last_uids": "{\"7\":44,\"8\":\"45\"}"})),
            HashMap::from([("7".to_string(), 44), ("8".to_string(), 45)])
        );
        assert!(super::payload_last_uids(&json!({})).is_empty());
    }

    #[tokio::test]
    async fn native_frickmail_check_new_mail_requires_authentication() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));

        let response = super::native_frickmail_check_new_mail(
            &state,
            "FrickmailCheckNewMail",
            &json!({"last_uids": {}}),
            &test_session(),
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
    }

    #[tokio::test]
    async fn native_frickmail_check_new_mail_reports_uidnext_deltas() {
        let key = [13_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1334, "poller", Some("poller@example.com")).await;
        seed_mail_account(&pool, 1335, 1334, "Work", true).await;
        seed_mail_account(&pool, 1336, 1334, "Broken", false).await;
        seed_mail_account(&pool, 1337, 1334, "Google", false).await;
        set_mail_account_email_and_type(&pool, 1337, "google@example.com", "gmail").await;
        assert!(SqlxUserRepository::set_mail_account_password(
            &pool,
            1334,
            1335,
            "imap-secret".to_string(),
            &key,
        )
        .await
        .unwrap());
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = credential_session(1334, "poller", Some("poller@example.com"), &key).await;
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let calls_for_fetch = Arc::clone(&calls);

        let response = super::native_frickmail_check_new_mail_with_fetcher(
            &state,
            "FrickmailCheckNewMail",
            &json!({"last_uids": {"1335": 12, "1336": 99}}),
            &session,
            Duration::from_secs(1),
            move |config, password, folder| {
                let calls_for_fetch = Arc::clone(&calls_for_fetch);
                async move {
                    assert_eq!(password, "imap-secret");
                    assert_eq!(folder, "INBOX");
                    calls_for_fetch.lock().unwrap().push(config.login);
                    Ok(MailboxStatus {
                        uid_next: Some(15),
                        exists: 7,
                    })
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        let accounts = body["Result"]["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["account_id"], 1335);
        assert_eq!(accounts[0]["account_email"], "work@example.com");
        assert_eq!(accounts[0]["uidnext"], 15);
        assert_eq!(accounts[0]["messages"], 7);
        assert_eq!(accounts[0]["new_count"], 3);
        assert_eq!(*calls.lock().unwrap(), vec!["work@example.com".to_string()]);
    }

    #[test]
    fn search_limit_parsing_matches_php_defaults_and_clamps() {
        assert_eq!(super::payload_search_limit(&json!({})), 50);
        assert_eq!(super::payload_search_limit(&json!({"limit": null})), 50);
        assert_eq!(super::payload_search_limit(&json!({"limit": false})), 50);
        assert_eq!(super::payload_search_limit(&json!({"limit": 0})), 50);
        assert_eq!(super::payload_search_limit(&json!({"limit": 0.0})), 50);
        assert_eq!(super::payload_search_limit(&json!({"limit": ""})), 50);
        assert_eq!(super::payload_search_limit(&json!({"limit": "0"})), 50);
        assert_eq!(super::payload_search_limit(&json!({"limit": " 0 "})), 1);
        assert_eq!(super::payload_search_limit(&json!({"limit": -5})), 1);
        assert_eq!(super::payload_search_limit(&json!({"limit": 250})), 100);
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

        let response = super::native_frickmail_add_rule(
            &state,
            "FrickmailAddRule",
            &json!({
                "account_id": 330,
                "name": "Archive alerts",
                "conditions": [
                    {"field": "subject", "op": "contains", "value": "alert"}
                ],
                "conditions_logic": "any",
                "actions": [
                    {"type": "move", "params": {"folder": "Alerts"}}
                ]
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert!(body["Result"]["id"].as_i64().unwrap() > 0);

        let response = super::native_frickmail_list_rules(
            &state,
            "FrickmailListRules",
            &json!({"account_id": 330}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["rules"].as_array().unwrap().len(), 1);
        assert_eq!(body["Result"]["rules"][0]["name"], "Archive alerts");
        assert_eq!(body["Result"]["rules"][0]["conditions_logic"], "any");
        assert_eq!(
            body["Result"]["rules"][0]["conditions"][0]["field"],
            "subject"
        );
        assert_eq!(
            body["Result"]["rules"][0]["actions"][0]["params"]["folder"],
            "Alerts"
        );
    }

    #[tokio::test]
    async fn native_frickmail_task_crud_matches_plugin_shape() {
        let pool = user_db_pool().await;
        create_task_tables(&pool).await;
        seed_user(&pool, 49, "tasks", Some("tasks@example.com")).await;
        seed_task(&pool, 530, 49, "Soon", Some("2026-06-01"), false).await;
        seed_task(&pool, 531, 49, "Done", None, true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(49, "tasks", None).await;

        let response = super::native_frickmail_list_tasks(
            &state,
            "FrickmailListTasks",
            &json!({"filter": ""}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["tasks"].as_array().unwrap().len(), 2);
        assert_eq!(body["Result"]["tasks"][0]["id"], 530);
        assert_eq!(body["Result"]["tasks"][0]["completed"], false);

        let response = super::native_frickmail_add_task(
            &state,
            "FrickmailAddTask",
            &json!({"title": "  Call accountant  ", "notes": "", "due_date": "2026-06-05"}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        let id = body["Result"]["id"].as_i64().unwrap();
        assert!(id > 0);

        let response = super::native_frickmail_complete_task(
            &state,
            "FrickmailCompleteTask",
            &json!({"id": id, "completed": "1"}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);

        let response = super::native_frickmail_update_task(
            &state,
            "FrickmailUpdateTask",
            &json!({"id": id, "title": " Updated task ", "notes": "notes", "due_date": ""}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);

        let response = super::native_frickmail_list_tasks(
            &state,
            "FrickmailListTasks",
            &json!({"filter": "completed"}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        let tasks = body["Result"]["tasks"].as_array().unwrap();
        let updated = tasks.iter().find(|task| task["id"] == id).unwrap();
        assert_eq!(updated["title"], "Updated task");
        assert_eq!(updated["notes"], "notes");
        assert_eq!(updated["due_date"], Value::Null);

        let response = super::native_frickmail_delete_task(
            &state,
            "FrickmailDeleteTask",
            &json!({"id": id}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);

        let response = super::native_frickmail_delete_task(
            &state,
            "FrickmailDeleteTask",
            &json!({"id": id}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
    }

    #[tokio::test]
    async fn native_frickmail_push_subscription_mutations_match_plugin_shape() {
        let pool = user_db_pool().await;
        create_push_subscription_tables(&pool).await;
        seed_user(&pool, 50, "push", Some("push@example.com")).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(50, "push", None).await;

        let response = super::native_frickmail_push_subscribe(
            &state,
            "FrickmailPushSubscribe",
            &json!({
                "endpoint": "https://push.example/sub",
                "p256dh": "key-1",
                "auth": "auth-1"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);

        let response = super::native_frickmail_push_subscribe(
            &state,
            "FrickmailPushSubscribe",
            &json!({
                "endpoint": "https://push.example/sub",
                "p256dh": "key-2",
                "auth": "auth-2"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(push_subscription_count(&pool, 50).await, 1);
        assert_eq!(
            push_subscription_auth(&pool, 50, "https://push.example/sub")
                .await
                .as_deref(),
            Some("auth-2")
        );

        let response = super::native_frickmail_push_unsubscribe(
            &state,
            "FrickmailPushUnsubscribe",
            &json!({"endpoint": "https://push.example/sub"}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(push_subscription_count(&pool, 50).await, 0);

        let response = super::native_frickmail_push_subscribe(
            &state,
            "FrickmailPushSubscribe",
            &json!({"endpoint": "", "p256dh": "key", "auth": "auth"}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Missing subscription fields");
    }

    #[tokio::test]
    async fn native_frickmail_get_vapid_key_matches_plugin_shape() {
        let pool = user_db_pool().await;
        create_app_settings_table(&pool).await;
        seed_user(&pool, 501, "vapid", Some("vapid@example.com")).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(501, "vapid", None).await;

        let response =
            super::native_frickmail_get_vapid_key(&state, "FrickmailGetVapidKey", &session).await;
        let body = read_json(response).await;
        let public_key = body["Result"]["public_key"].as_str().unwrap().to_string();
        assert_eq!(body["Result"]["ok"], true);
        assert!(!public_key.is_empty());
        assert!(app_setting(&pool, "vapid_keys").await.is_some());

        let response =
            super::native_frickmail_get_vapid_key(&state, "FrickmailGetVapidKey", &session).await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["public_key"], public_key);
    }

    #[tokio::test]
    async fn json_api_dispatches_native_get_vapid_key_action() {
        let pool = user_db_pool().await;
        create_app_settings_table(&pool).await;
        seed_user(&pool, 502, "vapid-route", Some("vapid-route@example.com")).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(502, "vapid-route", None).await;

        let response = super::json_api_request(
            state,
            "/?/Json/".parse().unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/?/Json/")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("Action=PluginFrickmailGetVapidKey"))
                .unwrap(),
            session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginFrickmailGetVapidKey");
        assert_eq!(body["Result"]["ok"], true);
        assert!(!body["Result"]["public_key"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn native_frickmail_oidc_link_list_and_unlink_match_plugin_shape() {
        let pool = user_db_pool().await;
        create_oidc_identity_tables(&pool).await;
        seed_user(&pool, 51, "oidc", Some("oidc@example.com")).await;
        set_oidc_escrow_key(&pool, 51, Some(vec![4, 5, 6])).await;
        seed_oidc_identity(&pool, 51, "provider-a", "subject-a", "2026-06-02 10:00:00").await;
        seed_oidc_identity(&pool, 51, "provider-b", "subject-b", "2026-06-01 10:00:00").await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(51, "oidc", None).await;

        let response =
            super::native_frickmail_list_oidc_links(&state, "FrickmailListOidcLinks", &session)
                .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["links"].as_array().unwrap().len(), 2);
        assert_eq!(body["Result"]["links"][0]["provider_hash"], "provider-a");
        assert_eq!(body["Result"]["links"][0]["provider_name"], "SSO");

        let response = super::native_frickmail_unlink_oidc(
            &state,
            "FrickmailUnlinkOidc",
            &json!({"provider_hash": "provider-a"}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["message"], "OIDC identity unlinked.");
        assert_eq!(oidc_identity_count(&pool, 51).await, 1);
        assert!(SqlxUserRepository::find_by_id(&pool, 51)
            .await
            .unwrap()
            .unwrap()
            .oidc_escrow_key
            .is_some());

        let response = super::native_frickmail_unlink_oidc(
            &state,
            "FrickmailUnlinkOidc",
            &json!({"provider_hash": "provider-b"}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(oidc_identity_count(&pool, 51).await, 0);
        assert!(SqlxUserRepository::find_by_id(&pool, 51)
            .await
            .unwrap()
            .unwrap()
            .oidc_escrow_key
            .is_none());

        let response = super::native_frickmail_unlink_oidc(
            &state,
            "FrickmailUnlinkOidc",
            &json!({"provider_hash": ""}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "provider_hash required");
    }

    #[tokio::test]
    async fn native_frickmail_smime_list_and_delete_match_plugin_shape() {
        let pool = user_db_pool().await;
        create_smime_cert_tables(&pool).await;
        seed_user(&pool, 61, "smime", Some("smime@example.com")).await;
        seed_user(&pool, 62, "other", Some("other@example.com")).await;
        seed_smime_cert(
            &pool,
            201,
            61,
            401,
            "signer@example.com",
            "fp-new",
            Some("CN=Signer"),
            Some(vec![1, 2, 3]),
            "2026-06-02 10:00:00",
        )
        .await;
        seed_smime_cert(
            &pool,
            202,
            61,
            402,
            "public@example.com",
            "fp-old",
            None,
            None,
            "2026-06-01 10:00:00",
        )
        .await;
        seed_smime_cert(
            &pool,
            204,
            61,
            404,
            "empty-key@example.com",
            "fp-empty",
            Some("CN=Empty"),
            Some(Vec::new()),
            "2026-05-31 10:00:00",
        )
        .await;
        seed_smime_cert(
            &pool,
            203,
            62,
            403,
            "other@example.com",
            "fp-other",
            Some("CN=Other"),
            Some(vec![9]),
            "2026-06-03 10:00:00",
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(61, "smime", None).await;

        let response =
            super::native_frickmail_smime_list_certs(&state, "FrickmailSmimeListCerts", &session)
                .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["certs"].as_array().unwrap().len(), 3);
        assert_eq!(body["Result"]["certs"][0]["id"], 201);
        assert_eq!(body["Result"]["certs"][0]["account_id"], 401);
        assert_eq!(body["Result"]["certs"][0]["email"], "signer@example.com");
        assert_eq!(body["Result"]["certs"][0]["fingerprint"], "fp-new");
        assert_eq!(body["Result"]["certs"][0]["subject"], "CN=Signer");
        assert_eq!(body["Result"]["certs"][0]["has_key"], true);
        assert_eq!(body["Result"]["certs"][0]["cert_pem"], Value::Null);
        assert_eq!(body["Result"]["certs"][0]["encrypted_key_pem"], Value::Null);
        assert_eq!(body["Result"]["certs"][1]["id"], 202);
        assert_eq!(body["Result"]["certs"][1]["subject"], "");
        assert_eq!(body["Result"]["certs"][1]["has_key"], false);
        assert_eq!(body["Result"]["certs"][2]["id"], 204);
        assert_eq!(body["Result"]["certs"][2]["has_key"], false);

        let response = super::native_frickmail_smime_delete_cert(
            &state,
            "FrickmailSmimeDeleteCert",
            &json!({"id": 203}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(
            body["Result"]["error"],
            "Certificate not found or already deleted"
        );
        assert_eq!(smime_cert_count(&pool, 62).await, 1);

        let response = super::native_frickmail_smime_delete_cert(
            &state,
            "FrickmailSmimeDeleteCert",
            &json!({"id": 202}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(smime_cert_count(&pool, 61).await, 2);
    }

    #[tokio::test]
    async fn native_frickmail_smime_import_cert_matches_plugin_shape() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_smime_cert_tables(&pool).await;
        seed_user(&pool, 63, "smime-import", Some("smime-import@example.com")).await;
        seed_user(&pool, 64, "smime-other", Some("smime-other@example.com")).await;
        seed_mail_account(&pool, 405, 63, "Work", true).await;
        seed_mail_account(&pool, 406, 64, "Other", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session = authenticated_session(63, "smime-import", None).await;
        let pem = test_smime_cert_pem("signer@example.com");

        let response = super::native_frickmail_smime_import_cert(
            &state,
            "FrickmailSmimeImportCert",
            &json!({
                "account_id": 405,
                "pem_b64": STANDARD.encode(pem.as_bytes())
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        let id = body["Result"]["id"].as_i64().unwrap();
        assert_eq!(body["Action"], "FrickmailSmimeImportCert");
        assert_eq!(body["Result"]["ok"], true);
        assert!(id > 0);
        assert_eq!(body["Result"]["email"], "signer@example.com");
        assert_eq!(
            body["Result"]["fingerprint"]
                .as_str()
                .unwrap()
                .matches(':')
                .count(),
            19
        );
        assert!(body["Result"]["not_after"].as_str().is_some());

        let response =
            super::native_frickmail_smime_list_certs(&state, "FrickmailSmimeListCerts", &session)
                .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["certs"].as_array().unwrap().len(), 1);
        assert_eq!(body["Result"]["certs"][0]["id"], id);
        assert_eq!(body["Result"]["certs"][0]["account_id"], 405);
        assert_eq!(body["Result"]["certs"][0]["email"], "signer@example.com");
        assert_eq!(body["Result"]["certs"][0]["has_key"], false);
        assert_eq!(body["Result"]["certs"][0]["cert_pem"], Value::Null);
        assert_eq!(body["Result"]["certs"][0]["encrypted_key_pem"], Value::Null);

        let response = super::native_frickmail_smime_import_cert(
            &state,
            "FrickmailSmimeImportCert",
            &json!({
                "account_id": 406,
                "pem_b64": STANDARD.encode(test_smime_cert_pem("other@example.com"))
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Account not found");
        assert_eq!(smime_cert_count(&pool, 64).await, 0);

        let response = super::native_frickmail_smime_import_cert(
            &state,
            "FrickmailSmimeImportCert",
            &json!({
                "account_id": 405,
                "pem_b64": "not-valid-base64"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Invalid base64 in pem_b64");
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
            open_signup: false,
            oidc: Default::default(),
            mail: Default::default(),
            transactional_smtp: Default::default(),
        }
    }

    fn test_session() -> Session {
        Session::new(None, Arc::new(MemoryStore::default()), None)
    }

    fn current_test_totp_counter() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() / 30)
            .unwrap_or_default()
    }

    fn test_totp_code(secret: &str, counter: u64) -> String {
        let key = BASE32_NOPAD
            .decode(secret.trim().to_ascii_uppercase().as_bytes())
            .unwrap();
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

    async fn credential_session(
        user_id: i64,
        username: &str,
        email: Option<&str>,
        credential_key: &[u8],
    ) -> Session {
        let session = authenticated_session(user_id, username, email).await;
        session
            .insert(CREDENTIAL_KEY_SESSION_KEY, STANDARD.encode(credential_key))
            .await
            .unwrap();
        session
    }

    async fn message_body_test_state(
        user_id: i64,
        account_id: i64,
        credential_key: &[u8],
    ) -> (AppState, Session) {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(
            &pool,
            user_id,
            &format!("viewer{user_id}"),
            Some(&format!("viewer{user_id}@example.com")),
        )
        .await;
        seed_mail_account(&pool, account_id, user_id, "Work", true).await;
        assert!(SqlxUserRepository::set_mail_account_password(
            &pool,
            user_id,
            account_id,
            "imap-secret".to_string(),
            credential_key,
        )
        .await
        .unwrap());
        let session = credential_session(
            user_id,
            &format!("viewer{user_id}"),
            Some(&format!("viewer{user_id}@example.com")),
            credential_key,
        )
        .await;
        (
            AppState::with_db_pool(test_config(None), Some(pool)),
            session,
        )
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
                settings TEXT NOT NULL DEFAULT '{}',
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

    async fn create_message_index_table(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_message_index (
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

    async fn create_password_reset_table(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_password_resets (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_totp_used_table(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_totp_used (
                user_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                \"window\" INTEGER NOT NULL,
                used_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, code, \"window\")
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_task_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_tasks (
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
    }

    async fn create_push_subscription_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_push_subscriptions (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                endpoint TEXT NOT NULL,
                p256dh TEXT NOT NULL,
                auth_key TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, endpoint)
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_app_settings_table(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_app_settings (
                setting_key VARCHAR(191) PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_oidc_identity_tables(pool: &AnyPool) {
        sqlx::query(
            "CREATE TABLE frickmail_oidc_identities (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                provider_hash TEXT NOT NULL,
                subject TEXT NOT NULL,
                linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(provider_hash, subject)
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn create_smime_cert_tables(pool: &AnyPool) {
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

    async fn seed_login_user(
        pool: &AnyPool,
        id: i64,
        username: &str,
        email: Option<&str>,
        password: &str,
        kdf_salt: &[u8],
        totp_secret: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_users
                (id, username, email, password_hash, kdf_salt, settings, totp_secret, oidc_escrow_key, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(username)
        .bind(email.map(ToOwned::to_owned))
        .bind(fm_user::hash_login_password(password).unwrap())
        .bind(kdf_salt.to_vec())
        .bind(json!({}).to_string())
        .bind(totp_secret.map(ToOwned::to_owned))
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

    async fn set_mail_account_email_and_type(
        pool: &AnyPool,
        account_id: i64,
        email: &str,
        account_type: &str,
    ) {
        sqlx::query(
            "UPDATE frickmail_mail_accounts
             SET email = ?, type = ?, login = ?
             WHERE id = ?",
        )
        .bind(email)
        .bind(account_type)
        .bind(email)
        .bind(account_id)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn mail_account_settings(pool: &AnyPool, account_id: i64) -> Value {
        let settings: String =
            sqlx::query("SELECT settings FROM frickmail_mail_accounts WHERE id = ?")
                .bind(account_id)
                .fetch_one(pool)
                .await
                .and_then(|row| row.try_get("settings"))
                .unwrap();
        serde_json::from_str(&settings).unwrap()
    }

    async fn account_encrypted_password(pool: &AnyPool, account_id: i64) -> Option<Vec<u8>> {
        sqlx::query("SELECT encrypted_password FROM frickmail_mail_accounts WHERE id = ?")
            .bind(account_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("encrypted_password"))
            .unwrap()
    }

    async fn account_oauth_refresh_token(pool: &AnyPool, account_id: i64) -> Option<Vec<u8>> {
        sqlx::query(
            "SELECT encrypted_oauth_refresh_token FROM frickmail_mail_accounts WHERE id = ?",
        )
        .bind(account_id)
        .fetch_one(pool)
        .await
        .and_then(|row| row.try_get("encrypted_oauth_refresh_token"))
        .unwrap()
    }

    async fn account_type(pool: &AnyPool, account_id: i64) -> String {
        sqlx::query("SELECT type FROM frickmail_mail_accounts WHERE id = ?")
            .bind(account_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("type"))
            .unwrap()
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

    async fn seed_message_index(
        pool: &AnyPool,
        user_id: i64,
        account_id: i64,
        folder: &str,
        imap_uid: i64,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_message_index
                (user_id, account_id, folder, imap_uid, subject)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(account_id)
        .bind(folder)
        .bind(imap_uid)
        .bind("Indexed message")
        .execute(pool)
        .await
        .unwrap();
    }

    struct SearchMessageSeed<'a> {
        id: i64,
        user_id: i64,
        account_id: i64,
        folder: &'a str,
        imap_uid: i64,
        message_id: Option<&'a str>,
        subject: Option<&'a str>,
        from_addr: Option<&'a str>,
        from_name: Option<&'a str>,
        date_ts: Option<&'a str>,
        snippet: Option<&'a str>,
    }

    async fn seed_search_message(pool: &AnyPool, message: SearchMessageSeed<'_>) {
        sqlx::query(
            "INSERT INTO frickmail_message_index
                (id, user_id, account_id, folder, imap_uid, message_id, subject,
                 from_addr, from_name, date_ts, snippet)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(message.id)
        .bind(message.user_id)
        .bind(message.account_id)
        .bind(message.folder)
        .bind(message.imap_uid)
        .bind(message.message_id)
        .bind(message.subject)
        .bind(message.from_addr)
        .bind(message.from_name)
        .bind(message.date_ts)
        .bind(message.snippet)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_password_reset(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        token_hash: &str,
        expires_at: &str,
        used_at: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_password_resets
                (id, user_id, token_hash, expires_at, used_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .bind(used_at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn password_reset_used_at(pool: &AnyPool, reset_id: i64) -> Option<String> {
        sqlx::query("SELECT used_at FROM frickmail_password_resets WHERE id = ?")
            .bind(reset_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("used_at"))
            .unwrap()
    }

    async fn active_password_reset_count(pool: &AnyPool, user_id: i64) -> i64 {
        sqlx::query(
            "SELECT COUNT(*) AS count FROM frickmail_password_resets
             WHERE user_id = ? AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .and_then(|row| row.try_get("count"))
        .unwrap()
    }

    async fn mail_account_count(pool: &AnyPool, user_id: i64) -> i64 {
        sqlx::query("SELECT COUNT(*) AS count FROM frickmail_mail_accounts WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("count"))
            .unwrap()
    }

    async fn message_index_count(pool: &AnyPool, user_id: i64, account_id: i64) -> i64 {
        sqlx::query(
            "SELECT COUNT(*) AS count FROM frickmail_message_index
             WHERE user_id = ? AND account_id = ?",
        )
        .bind(user_id)
        .bind(account_id)
        .fetch_one(pool)
        .await
        .and_then(|row| row.try_get("count"))
        .unwrap()
    }

    async fn set_totp_secret(pool: &AnyPool, user_id: i64, secret: Option<&str>) {
        sqlx::query("UPDATE frickmail_users SET totp_secret = ? WHERE id = ?")
            .bind(secret)
            .bind(user_id)
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

    async fn seed_task(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        title: &str,
        due_date: Option<&str>,
        completed: bool,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_tasks
                (id, user_id, title, notes, due_date, completed, completed_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(id)
        .bind(user_id)
        .bind(title)
        .bind(None::<String>)
        .bind(due_date)
        .bind(completed)
        .bind(if completed {
            Some("2026-06-01 10:00:00")
        } else {
            None
        })
        .execute(pool)
        .await
        .unwrap();
    }

    async fn push_subscription_count(pool: &AnyPool, user_id: i64) -> i64 {
        sqlx::query("SELECT COUNT(*) AS count FROM frickmail_push_subscriptions WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("count"))
            .unwrap()
    }

    async fn push_subscription_auth(
        pool: &AnyPool,
        user_id: i64,
        endpoint: &str,
    ) -> Option<String> {
        sqlx::query(
            "SELECT auth_key FROM frickmail_push_subscriptions WHERE user_id = ? AND endpoint = ?",
        )
        .bind(user_id)
        .bind(endpoint)
        .fetch_optional(pool)
        .await
        .unwrap()
        .map(|row| row.try_get("auth_key").unwrap())
    }

    async fn app_setting(pool: &AnyPool, key: &str) -> Option<String> {
        sqlx::query("SELECT setting_value FROM frickmail_app_settings WHERE setting_key = ?")
            .bind(key)
            .fetch_optional(pool)
            .await
            .unwrap()
            .map(|row| row.try_get("setting_value").unwrap())
    }

    async fn set_oidc_escrow_key(pool: &AnyPool, user_id: i64, value: Option<Vec<u8>>) {
        sqlx::query("UPDATE frickmail_users SET oidc_escrow_key = ? WHERE id = ?")
            .bind(value)
            .bind(user_id)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn seed_oidc_identity(
        pool: &AnyPool,
        user_id: i64,
        provider_hash: &str,
        subject: &str,
        linked_at: &str,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_oidc_identities
                (user_id, provider_hash, subject, linked_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(provider_hash)
        .bind(subject)
        .bind(linked_at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn oidc_identity_count(pool: &AnyPool, user_id: i64) -> i64 {
        sqlx::query("SELECT COUNT(*) AS count FROM frickmail_oidc_identities WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("count"))
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    async fn seed_smime_cert(
        pool: &AnyPool,
        id: i64,
        user_id: i64,
        account_id: i64,
        email: &str,
        fingerprint: &str,
        subject: Option<&str>,
        encrypted_key_pem: Option<Vec<u8>>,
        created_at: &str,
    ) {
        sqlx::query(
            "INSERT INTO frickmail_smime_certs
                (id, user_id, account_id, email, cert_pem, encrypted_key_pem,
                 fingerprint, subject, not_before, not_after, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(user_id)
        .bind(account_id)
        .bind(email)
        .bind("-----BEGIN CERTIFICATE-----\nredacted\n-----END CERTIFICATE-----")
        .bind(encrypted_key_pem)
        .bind(fingerprint)
        .bind(subject)
        .bind(Some("2026-01-01 00:00:00"))
        .bind(Some("2027-01-01 00:00:00"))
        .bind(created_at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn smime_cert_count(pool: &AnyPool, user_id: i64) -> i64 {
        sqlx::query("SELECT COUNT(*) AS count FROM frickmail_smime_certs WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get("count"))
            .unwrap()
    }

    fn test_smime_cert_pem(email: &str) -> String {
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
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();
        let san = SubjectAlternativeName::new()
            .email(email)
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();

        String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
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
