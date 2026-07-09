use std::{
    collections::HashMap,
    env,
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
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::Local;
use fm_core::{plugin::PluginRequest, ApiEnvelope, ErrorBody, FrickmailError, HealthResponse};
use fm_imap::{
    append_raw_message, append_raw_message_without_flags, apply_imap_rules, copy_messages,
    delete_messages, fetch_legacy_folder_information, fetch_legacy_message_list,
    fetch_mailbox_status, fetch_message_body_preview, fetch_raw_folder_messages, fetch_raw_message,
    legacy_message_hash, legacy_message_list_cache_key, legacy_message_list_params_hash,
    move_messages, store_message_flag, store_message_keyword, store_seen_to_all, validate_eml,
    BodyPreviewPart, ImapConnectionConfig, ImapLoginProbe, ImapMessageFlag, ImapMoveLearning,
    ImapMoveOptions, LegacyFolderInformation, LegacyMessageList, LegacyMessageListRequest,
    MailboxStatus, RawFolderFetchLimits, RuleAction, RuleCondition, RuleConditionField,
    RuleConditionOp, RuleConditionsLogic, RuleExecutionPlan, RuleExecutionReport,
};
use fm_mime::parse_body;
use fm_plugin_compat::{
    bridge_unimplemented, is_compat_hook, normalize_plugin_action, ActionNameError,
};
use fm_smtp::{send_password_reset_email, PasswordResetEmail};
use fm_user::{
    decrypt_account_secret, derive_credential_key, verify_login_password, FrickmailMe, MailAccount,
    MailAccountConnectionSecret, NewMailAccount, NewMailIdentity, NewMailRule, NewMailTask,
    NewSmimeCert, NewSmimeP12, PushSubscription, SqlxUserRepository, TaskFilter, UpdateMailAccount,
    UpdateMailTask, VapidKeyBundle, CREDENTIAL_KEY_BYTES,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
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
const LONG_POLL_NEW_MAIL_DEADLINE: Duration = Duration::from_secs(25);
const LONG_POLL_NEW_MAIL_INTERVAL: Duration = Duration::from_secs(5);
const ACCOUNT_SWITCH_VALIDATE_DEADLINE: Duration = Duration::from_secs(20);
const APPLY_RULES_DEADLINE: Duration = Duration::from_secs(60);
const EXPORT_MESSAGE_DEADLINE: Duration = Duration::from_secs(30);
const EXPORT_FOLDER_DEADLINE: Duration = Duration::from_secs(120);
const IMPORT_EML_DEADLINE: Duration = Duration::from_secs(30);
const FOLDER_APPEND_DEADLINE: Duration = Duration::from_secs(30);
const MESSAGE_LIST_DEADLINE: Duration = Duration::from_secs(30);
const MESSAGE_MUTATION_DEADLINE: Duration = Duration::from_secs(30);
const FOLDER_INFORMATION_DEADLINE: Duration = Duration::from_secs(15);
const WEB_PUSH_DELIVERY_DEADLINE: Duration = Duration::from_secs(10);
const GRAPH_FETCH_DEADLINE: Duration = Duration::from_secs(20);
const SMIME_VERIFY_DEADLINE: Duration = Duration::from_secs(10);
const SMIME_VERIFY_MAX_BYTES: usize = 2 * 1024 * 1024;
const SMIME_VERIFY_MAX_BASE64_CHARS: usize = SMIME_VERIFY_MAX_BYTES.div_ceil(3) * 4;
const MICROSOFT_GRAPH_ROOT: &str = "https://graph.microsoft.com";
const MICROSOFT_GRAPH_SCOPES: &str = "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send offline_access";
const MICROSOFT_ACCOUNT_SWITCH_SCOPES: &str = "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read";
const GMAIL_ACCOUNT_SWITCH_SCOPES: &str = "https://mail.google.com/";

#[derive(Debug, Clone, Copy)]
struct LongPollNewMailTiming {
    fetch_deadline: Duration,
    poll_deadline: Duration,
    poll_interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyMessageListRawKeyRequest {
    request: LegacyMessageListRequest,
    cache_hash: String,
    account_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyMessageListRawCacheState {
    request_hash_validator: String,
    account_hash: String,
    current_cache_key: String,
    verify_existing_cache: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyMessageRawKeyRequest {
    folder: String,
    uid: u32,
    use_threads: bool,
    account_hash: String,
}

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

#[derive(Clone, PartialEq, Eq)]
struct GraphOAuthConfig {
    client_id: String,
    client_secret: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
struct OAuthRefreshConfig {
    token_url: String,
    client_id: String,
    client_secret: Option<String>,
    scope: &'static str,
}

#[derive(Clone, PartialEq, Eq)]
enum MailAccountBridgeValidation {
    Imap {
        config: ImapConnectionConfig,
        password: String,
    },
    OAuth {
        account_type: String,
        refresh_token: String,
        tenant: Option<String>,
    },
}

struct MailAccountBridgeRequest<'a> {
    pool: &'a sqlx::AnyPool,
    user_id: i64,
    account_id: i64,
    credential_key: &'a [u8],
    session: &'a fm_session::Session,
    original_action: &'a str,
    reauth_response: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct GraphAccountRequest {
    tenant: String,
    client_id: String,
    client_secret: Option<String>,
    refresh_token: String,
}

#[derive(Clone, PartialEq, Eq)]
struct GraphListMessagesRequest {
    tenant: String,
    client_id: String,
    client_secret: Option<String>,
    refresh_token: String,
    folder: String,
    top: i64,
}

#[derive(Clone, PartialEq, Eq)]
struct GraphSearchMessagesRequest {
    tenant: String,
    client_id: String,
    client_secret: Option<String>,
    refresh_token: String,
    query: String,
    top: i64,
}

#[derive(Clone, PartialEq, Eq)]
struct GraphDeltaMessagesRequest {
    auth: GraphAccountRequest,
    folder_id: String,
    delta_token: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
struct GraphGetMessageRequest {
    auth: GraphAccountRequest,
    message_id: String,
}

#[derive(Clone, PartialEq, Eq)]
struct GraphMarkReadRequest {
    auth: GraphAccountRequest,
    message_id: String,
    is_read: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct GraphMoveMessageRequest {
    auth: GraphAccountRequest,
    message_id: String,
    target_folder_id: String,
}

#[derive(Clone, PartialEq, Eq)]
struct GraphDeleteMessageRequest {
    auth: GraphAccountRequest,
    message_id: String,
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
            let request = attach_legacy_json_raw_key(request, &uri);
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

    if action == "FolderAppend" {
        return native_legacy_folder_append_multipart(
            &state,
            &request.action,
            &headers,
            &body,
            &session,
        )
        .await;
    }

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
        "FrickmailBridgeSession" => {
            Some(native_frickmail_bridge_session(state, original_action, session).await)
        }
        "FrickmailSwitchAccount" => {
            Some(native_frickmail_switch_account(state, original_action, payload, session).await)
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
        "FrickmailUnifiedInbox" => {
            Some(native_frickmail_unified_inbox(state, original_action, payload, session).await)
        }
        "FrickmailGetMessageBody" => {
            Some(native_frickmail_get_message_body(state, original_action, payload, session).await)
        }
        "FrickmailGraphListMessages" => Some(
            native_frickmail_graph_list_messages(state, original_action, payload, session).await,
        ),
        "FrickmailGraphSearch" => {
            Some(native_frickmail_graph_search(state, original_action, payload, session).await)
        }
        "FrickmailGraphDelta" => {
            Some(native_frickmail_graph_delta(state, original_action, payload, session).await)
        }
        "FrickmailGraphGetMessage" => {
            Some(native_frickmail_graph_get_message(state, original_action, payload, session).await)
        }
        "FrickmailGraphMarkRead" => {
            Some(native_frickmail_graph_mark_read(state, original_action, payload, session).await)
        }
        "FrickmailGraphMove" => {
            Some(native_frickmail_graph_move(state, original_action, payload, session).await)
        }
        "FrickmailGraphDelete" => {
            Some(native_frickmail_graph_delete(state, original_action, payload, session).await)
        }
        "FrickmailCheckNewMail" => {
            Some(native_frickmail_check_new_mail(state, original_action, payload, session).await)
        }
        "FrickmailLongPollNewMail" => Some(
            native_frickmail_long_poll_new_mail(state, original_action, payload, session).await,
        ),
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
        "FrickmailApplyRules" => {
            Some(native_frickmail_apply_rules(state, original_action, payload, session).await)
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
        "FrickmailExportMessage" => {
            if state.config().frickmail_user.allow_export {
                Some(
                    native_frickmail_export_message(state, original_action, payload, session).await,
                )
            } else {
                None
            }
        }
        "FrickmailExportFolder" => {
            if state.config().frickmail_user.allow_export {
                Some(native_frickmail_export_folder(state, original_action, payload, session).await)
            } else {
                None
            }
        }
        "FrickmailImportEml" => {
            if state.config().frickmail_user.allow_export {
                Some(native_frickmail_import_eml(state, original_action, payload, session).await)
            } else {
                None
            }
        }
        "FrickmailListOidcLinks" => {
            Some(native_frickmail_list_oidc_links(state, original_action, session).await)
        }
        "FrickmailUnlinkOidc" => {
            Some(native_frickmail_unlink_oidc(state, original_action, payload, session).await)
        }
        "FrickmailSmimeListCerts" => {
            native_smime_action(state, || {
                Box::pin(native_frickmail_smime_list_certs(
                    state,
                    original_action,
                    session,
                ))
            })
            .await
        }
        "FrickmailSmimeImportP12" => {
            native_smime_action(state, || {
                Box::pin(native_frickmail_smime_import_p12(
                    state,
                    original_action,
                    payload,
                    session,
                ))
            })
            .await
        }
        "FrickmailSmimeImportCert" => {
            native_smime_action(state, || {
                Box::pin(native_frickmail_smime_import_cert(
                    state,
                    original_action,
                    payload,
                    session,
                ))
            })
            .await
        }
        "FrickmailSmimeDeleteCert" => {
            native_smime_action(state, || {
                Box::pin(native_frickmail_smime_delete_cert(
                    state,
                    original_action,
                    payload,
                    session,
                ))
            })
            .await
        }
        "FrickmailSmimeSign" => {
            native_smime_action(state, || {
                Box::pin(native_frickmail_smime_sign(
                    state,
                    original_action,
                    payload,
                    session,
                ))
            })
            .await
        }
        "FrickmailSmimeVerify" => {
            native_smime_action(state, || {
                Box::pin(native_frickmail_smime_verify(original_action, payload))
            })
            .await
        }
        "Message" if legacy_message_payload_is_native_candidate(payload) => {
            Some(native_legacy_message(state, original_action, payload, session).await)
        }
        "FolderInformation" => {
            Some(native_legacy_folder_information(state, original_action, payload, session).await)
        }
        "FolderInformationMultiply" => Some(
            native_legacy_folder_information_multiply(state, original_action, payload, session)
                .await,
        ),
        "MessageSetSeen" => Some(
            native_legacy_message_store_flag(
                state,
                original_action,
                payload,
                session,
                ImapMessageFlag::Seen,
            )
            .await,
        ),
        "MessageSetSeenToAll" => Some(
            native_legacy_message_set_seen_to_all(state, original_action, payload, session).await,
        ),
        "MessageSetFlagged" => Some(
            native_legacy_message_store_flag(
                state,
                original_action,
                payload,
                session,
                ImapMessageFlag::Flagged,
            )
            .await,
        ),
        "MessageSetDeleted" => Some(
            native_legacy_message_store_flag(
                state,
                original_action,
                payload,
                session,
                ImapMessageFlag::Deleted,
            )
            .await,
        ),
        "MessageSetKeyword" => Some(
            native_legacy_message_store_keyword(state, original_action, payload, session).await,
        ),
        "MessageCopy" => {
            Some(native_legacy_message_copy(state, original_action, payload, session).await)
        }
        "MessageMove" => {
            Some(native_legacy_message_move(state, original_action, payload, session).await)
        }
        "MessageDelete" => {
            Some(native_legacy_message_delete(state, original_action, payload, session).await)
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
    native_frickmail_login_with_validator(
        state,
        original_action,
        payload,
        session,
        validate_mail_account_bridge_live,
    )
    .await
}

async fn native_frickmail_login_with_validator<V, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    validator: V,
) -> Response
where
    V: FnOnce(MailAccountBridgeValidation) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
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
            if let Some(account) = accounts.first() {
                return prepare_mail_account_bridge_with_validator(
                    MailAccountBridgeRequest {
                        pool,
                        user_id: user.id,
                        account_id: account.id,
                        credential_key: &credential_key,
                        session,
                        original_action,
                        reauth_response: true,
                    },
                    validator,
                )
                .await;
            }

            json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": {
                        "ok": true,
                        "no_primary": true,
                        "message": "Logged in. Add a mail account from the settings panel."
                    }
                }),
            )
        }
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_bridge_session(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_bridge_session_with_validator(
        state,
        original_action,
        session,
        validate_mail_account_bridge_live,
    )
    .await
}

async fn native_frickmail_bridge_session_with_validator<V, Fut>(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
    validator: V,
) -> Response
where
    V: FnOnce(MailAccountBridgeValidation) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return response,
    }) else {
        return json_result_error(original_action, "No active Frickmail session");
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };

    let accounts = match SqlxUserRepository::list_mail_accounts(pool, user.user_id).await {
        Ok(accounts) => accounts,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    let Some(account) = accounts.first() else {
        return json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "no_primary": true
                }
            }),
        );
    };

    prepare_mail_account_bridge_with_validator(
        MailAccountBridgeRequest {
            pool,
            user_id: user.user_id,
            account_id: account.id,
            credential_key: &credential_key,
            session,
            original_action,
            reauth_response: true,
        },
        validator,
    )
    .await
}

async fn native_frickmail_switch_account(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_switch_account_with_validator(
        state,
        original_action,
        payload,
        session,
        validate_mail_account_bridge_live,
    )
    .await
}

async fn native_frickmail_switch_account_with_validator<V, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    validator: V,
) -> Response
where
    V: FnOnce(MailAccountBridgeValidation) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
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

    prepare_mail_account_bridge_with_validator(
        MailAccountBridgeRequest {
            pool,
            user_id: user.user_id,
            account_id: payload_i64(payload, "id"),
            credential_key: &credential_key,
            session,
            original_action,
            reauth_response: false,
        },
        validator,
    )
    .await
}

async fn prepare_mail_account_bridge_with_validator<V, Fut>(
    request: MailAccountBridgeRequest<'_>,
    validator: V,
) -> Response
where
    V: FnOnce(MailAccountBridgeValidation) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
    let account = match SqlxUserRepository::get_mail_account_connection_secret(
        request.pool,
        request.user_id,
        request.account_id,
    )
    .await
    {
        Ok(Some(account)) => account,
        Ok(None) => return json_result_error(request.original_action, "Account not found"),
        Err(err) => return json_result_error(request.original_action, &err.public_message()),
    };

    let validation = match mail_account_bridge_validation(&account, request.credential_key) {
        Ok(validation) => validation,
        Err(err) => {
            if request.reauth_response {
                return reauth_required_response(
                    request.original_action,
                    &account,
                    &err.public_message(),
                );
            }
            return json_result_error(request.original_action, &err.public_message());
        }
    };
    if let Err(err) = validator(validation).await {
        if request.reauth_response {
            return reauth_required_response(
                request.original_action,
                &account,
                &err.public_message(),
            );
        }
        return json_result_error(request.original_action, &err.public_message());
    }

    if let Err(response) =
        store_selected_mail_account(request.session, request.original_action, account.id).await
    {
        return response;
    }

    mailbox_switch_success_response(request.original_action, &account)
}

async fn store_selected_mail_account(
    session: &fm_session::Session,
    original_action: &str,
    account_id: i64,
) -> Result<(), Response> {
    session
        .insert(
            fm_session::SELECTED_ACCOUNT_SESSION_KEY,
            fm_core::SelectedMailAccountSession { account_id },
        )
        .await
        .map_err(|err| {
            json_result_error(
                original_action,
                &format!("Frickmail session write failed: {err}"),
            )
        })
}

fn mail_account_bridge_validation(
    account: &MailAccountConnectionSecret,
    credential_key: &[u8],
) -> fm_core::Result<MailAccountBridgeValidation> {
    match account.account_type.as_str() {
        "imap" => {
            let config = imap_config_from_account_secret(account)?;
            let password = account_password(account, credential_key)?;
            Ok(MailAccountBridgeValidation::Imap { config, password })
        }
        "gmail" | "o365" => {
            let Some(blob) = account.encrypted_oauth_refresh_token.as_deref() else {
                return Err(FrickmailError::BadRequest(
                    "Missing OAuth refresh token — re-authorize this account.".to_string(),
                ));
            };
            let token = decrypt_account_secret(blob, credential_key)?;
            if token.as_deref().unwrap_or_default().trim().is_empty() {
                return Err(FrickmailError::BadRequest(
                    "Missing OAuth refresh token — re-authorize this account.".to_string(),
                ));
            }
            Ok(MailAccountBridgeValidation::OAuth {
                account_type: account.account_type.clone(),
                refresh_token: token.unwrap_or_default(),
                tenant: account.oauth_tenant.clone(),
            })
        }
        _ => Err(FrickmailError::BadRequest("Invalid type".to_string())),
    }
}

async fn validate_mail_account_bridge_live(
    validation: MailAccountBridgeValidation,
) -> fm_core::Result<()> {
    match validation {
        MailAccountBridgeValidation::Imap { config, password } => {
            let probe = ImapLoginProbe {
                host: config.host,
                port: config.port,
                security: config.security,
                login: config.login,
            };
            tokio::time::timeout(
                ACCOUNT_SWITCH_VALIDATE_DEADLINE,
                fm_imap::probe_login(probe, &password),
            )
            .await
            .map_err(|_| FrickmailError::Upstream("IMAP login timed out".to_string()))??;
            Ok(())
        }
        MailAccountBridgeValidation::OAuth {
            account_type,
            refresh_token,
            tenant,
        } => validate_oauth_refresh_token(&account_type, &refresh_token, tenant.as_deref()).await,
    }
}

async fn validate_oauth_refresh_token(
    account_type: &str,
    refresh_token: &str,
    tenant: Option<&str>,
) -> fm_core::Result<()> {
    let config = oauth_refresh_config_from_env(account_type, tenant)?;
    let client = reqwest::Client::builder()
        .timeout(ACCOUNT_SWITCH_VALIDATE_DEADLINE)
        .build()
        .map_err(|err| FrickmailError::Upstream(format!("OAuth client setup failed: {err}")))?;
    let _ = oauth_access_token_for(
        &client,
        &config.token_url,
        &config.client_id,
        config.client_secret.as_deref(),
        refresh_token,
        config.scope,
    )
    .await?;
    Ok(())
}

fn oauth_refresh_config_from_env(
    account_type: &str,
    tenant: Option<&str>,
) -> fm_core::Result<OAuthRefreshConfig> {
    match account_type {
        "gmail" => {
            let client_id = trimmed_env("FRICKMAIL_GMAIL_CLIENT_ID").ok_or_else(|| {
                FrickmailError::BadRequest("Gmail OAuth client is not configured".to_string())
            })?;
            Ok(OAuthRefreshConfig {
                token_url: "https://accounts.google.com/o/oauth2/token".to_string(),
                client_id,
                client_secret: trimmed_env("FRICKMAIL_GMAIL_CLIENT_SECRET"),
                scope: GMAIL_ACCOUNT_SWITCH_SCOPES,
            })
        }
        "o365" => {
            let oauth = graph_oauth_config_from_env()?;
            let tenant = graph_tenant(tenant.unwrap_or("common"))?;
            Ok(OAuthRefreshConfig {
                token_url: format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
                client_id: oauth.client_id,
                client_secret: oauth.client_secret,
                scope: MICROSOFT_ACCOUNT_SWITCH_SCOPES,
            })
        }
        _ => Err(FrickmailError::BadRequest("Invalid type".to_string())),
    }
}

fn trimmed_env(name: &str) -> Option<String> {
    env::var(name).ok().and_then(|value| {
        let value = value.trim().to_string();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

fn mailbox_switch_success_response(
    action: &str,
    account: &MailAccountConnectionSecret,
) -> Response {
    json_value_envelope(
        StatusCode::OK,
        action,
        json!({
            "Result": {
                "ok": true,
                "account_id": account.id,
                "email": account.email.as_str()
            }
        }),
    )
}

fn reauth_required_response(
    action: &str,
    account: &MailAccountConnectionSecret,
    message: &str,
) -> Response {
    json_value_envelope(
        StatusCode::OK,
        action,
        json!({
            "Result": {
                "ok": true,
                "reauth_required": true,
                "reauth_account_id": account.id,
                "reauth_account_email": account.email.as_str(),
                "reauth_account_type": account.account_type.as_str(),
                "message": reauth_message(message)
            }
        }),
    )
}

fn reauth_message(message: &str) -> String {
    if message.contains("please re-authorise") || message.contains("please re-authorize") {
        message.to_string()
    } else {
        format!("{message} — please re-authorise this account.")
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

async fn native_frickmail_graph_list_messages(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_graph_list_messages_with_fetcher(
        state,
        original_action,
        payload,
        session,
        graph_oauth_config_from_env,
        GRAPH_FETCH_DEADLINE,
        |request| async move { graph_list_messages_via_reqwest(request).await },
    )
    .await
}

async fn native_frickmail_graph_list_messages_with_fetcher<C, F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    oauth_config: C,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    C: FnOnce() -> fm_core::Result<GraphOAuthConfig>,
    F: FnOnce(GraphListMessagesRequest) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Value>>,
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
    if account_id <= 0 {
        return json_result_error(original_action, "account_id required");
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

    let (refresh_token, tenant) = match graph_account_oauth(&account, &credential_key) {
        Ok(oauth) => oauth,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    let oauth = match oauth_config() {
        Ok(oauth) => oauth,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    let request = GraphListMessagesRequest {
        tenant,
        client_id: oauth.client_id,
        client_secret: oauth.client_secret,
        refresh_token,
        folder: payload_optional_string(payload, "folder").unwrap_or_else(|| "inbox".to_string()),
        top: payload_graph_top(payload),
    };

    let fetch = tokio::time::timeout(fetch_deadline, fetcher(request))
        .await
        .map_err(|_| FrickmailError::Upstream("Microsoft Graph request timed out".to_string()));

    match fetch {
        Ok(Ok(data)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "data": data
                }
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_graph_search(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_graph_search_with_fetcher(
        state,
        original_action,
        payload,
        session,
        graph_oauth_config_from_env,
        GRAPH_FETCH_DEADLINE,
        |request| async move { graph_search_messages_via_reqwest(request).await },
    )
    .await
}

async fn native_frickmail_graph_search_with_fetcher<C, F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    oauth_config: C,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    C: FnOnce() -> fm_core::Result<GraphOAuthConfig>,
    F: FnOnce(GraphSearchMessagesRequest) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Value>>,
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
    if account_id <= 0 {
        return json_result_error(original_action, "account_id required");
    }
    let query = payload_string(payload, "q").unwrap_or_default();
    let query = query.trim().to_string();
    if query.is_empty() {
        return json_result_error(original_action, "Search query is required");
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

    let (refresh_token, tenant) = match graph_account_oauth(&account, &credential_key) {
        Ok(oauth) => oauth,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    let oauth = match oauth_config() {
        Ok(oauth) => oauth,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    let request = GraphSearchMessagesRequest {
        tenant,
        client_id: oauth.client_id,
        client_secret: oauth.client_secret,
        refresh_token,
        query: query.clone(),
        top: payload_graph_top(payload),
    };

    let fetch = tokio::time::timeout(fetch_deadline, fetcher(request))
        .await
        .map_err(|_| FrickmailError::Upstream("Microsoft Graph request timed out".to_string()));

    match fetch {
        Ok(Ok(data)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "query": query,
                    "data": data
                }
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn graph_account_request_from_payload<C>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    oauth_config: C,
) -> Result<GraphAccountRequest, Response>
where
    C: FnOnce() -> fm_core::Result<GraphOAuthConfig>,
{
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return Err(response),
    }) else {
        return Err(json_result_error(original_action, "Not authenticated"));
    };

    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return Err(response),
    };

    let Some(pool) = state.db_pool() else {
        return Err(json_result_error(
            original_action,
            "Frickmail database is not configured",
        ));
    };

    if let Some(response) = graph_account_id_error(original_action, payload) {
        return Err(response);
    }
    let account_id = payload_i64(payload, "account_id");

    let account = match SqlxUserRepository::get_mail_account_connection_secret(
        pool,
        user.user_id,
        account_id,
    )
    .await
    {
        Ok(Some(account)) => account,
        Ok(None) => return Err(json_result_error(original_action, "Account not found")),
        Err(err) => return Err(json_result_error(original_action, &err.public_message())),
    };

    let (refresh_token, tenant) = match graph_account_oauth(&account, &credential_key) {
        Ok(oauth) => oauth,
        Err(err) => return Err(json_result_error(original_action, &err.public_message())),
    };
    let oauth = match oauth_config() {
        Ok(oauth) => oauth,
        Err(err) => return Err(json_result_error(original_action, &err.public_message())),
    };

    Ok(GraphAccountRequest {
        tenant,
        client_id: oauth.client_id,
        client_secret: oauth.client_secret,
        refresh_token,
    })
}

fn graph_account_id_error(original_action: &str, payload: &Value) -> Option<Response> {
    (payload_i64(payload, "account_id") <= 0)
        .then(|| json_result_error(original_action, "account_id required"))
}

async fn graph_authentication_error(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
) -> Option<Response> {
    match load_session_user(state, original_action, session).await {
        Ok(Some(_)) => None,
        Ok(None) => Some(json_result_error(original_action, "Not authenticated")),
        Err(response) => Some(response),
    }
}

async fn native_frickmail_graph_delta(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_graph_delta_with_fetcher(
        state,
        original_action,
        payload,
        session,
        graph_oauth_config_from_env,
        GRAPH_FETCH_DEADLINE,
        |request| async move { graph_delta_messages_via_reqwest(request).await },
    )
    .await
}

async fn native_frickmail_graph_delta_with_fetcher<C, F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    oauth_config: C,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    C: FnOnce() -> fm_core::Result<GraphOAuthConfig>,
    F: FnOnce(GraphDeltaMessagesRequest) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Value>>,
{
    if let Some(response) = graph_authentication_error(state, original_action, session).await {
        return response;
    }
    if let Some(response) = graph_account_id_error(original_action, payload) {
        return response;
    }
    let folder_id =
        payload_optional_string(payload, "folder_id").unwrap_or_else(|| "inbox".to_string());
    let delta_token = payload_optional_string(payload, "delta_token");
    if let Err(err) = validate_graph_delta_token(delta_token.as_deref()) {
        return json_result_error(original_action, &err.public_message());
    }

    let auth = match graph_account_request_from_payload(
        state,
        original_action,
        payload,
        session,
        oauth_config,
    )
    .await
    {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let request = GraphDeltaMessagesRequest {
        auth,
        folder_id,
        delta_token,
    };

    let fetch = tokio::time::timeout(fetch_deadline, fetcher(request))
        .await
        .map_err(|_| FrickmailError::Upstream("Microsoft Graph request timed out".to_string()));

    match fetch {
        Ok(Ok(data)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "data": data
                }
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_graph_get_message(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_graph_get_message_with_fetcher(
        state,
        original_action,
        payload,
        session,
        graph_oauth_config_from_env,
        GRAPH_FETCH_DEADLINE,
        |request| async move { graph_get_message_via_reqwest(request).await },
    )
    .await
}

async fn native_frickmail_graph_get_message_with_fetcher<C, F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    oauth_config: C,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    C: FnOnce() -> fm_core::Result<GraphOAuthConfig>,
    F: FnOnce(GraphGetMessageRequest) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Value>>,
{
    if let Some(response) = graph_authentication_error(state, original_action, session).await {
        return response;
    }
    if let Some(response) = graph_account_id_error(original_action, payload) {
        return response;
    }
    let message_id = payload_string(payload, "message_id").unwrap_or_default();
    if message_id.is_empty() {
        return json_result_error(original_action, "message_id required");
    }

    let auth = match graph_account_request_from_payload(
        state,
        original_action,
        payload,
        session,
        oauth_config,
    )
    .await
    {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let request = GraphGetMessageRequest { auth, message_id };

    let fetch = tokio::time::timeout(fetch_deadline, fetcher(request))
        .await
        .map_err(|_| FrickmailError::Upstream("Microsoft Graph request timed out".to_string()));

    match fetch {
        Ok(Ok(message)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "message": message
                }
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_graph_mark_read(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_graph_mark_read_with_fetcher(
        state,
        original_action,
        payload,
        session,
        graph_oauth_config_from_env,
        GRAPH_FETCH_DEADLINE,
        |request| async move { graph_mark_read_via_reqwest(request).await },
    )
    .await
}

async fn native_frickmail_graph_mark_read_with_fetcher<C, F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    oauth_config: C,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    C: FnOnce() -> fm_core::Result<GraphOAuthConfig>,
    F: FnOnce(GraphMarkReadRequest) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Value>>,
{
    if let Some(response) = graph_authentication_error(state, original_action, session).await {
        return response;
    }
    if let Some(response) = graph_account_id_error(original_action, payload) {
        return response;
    }
    let message_id = payload_string(payload, "message_id").unwrap_or_default();
    if message_id.is_empty() {
        return json_result_error(original_action, "message_id required");
    }
    let is_read = match payload_json_bool(payload, "is_read") {
        Ok(is_read) => is_read,
        Err(message) => return json_result_error(original_action, &message),
    };

    let auth = match graph_account_request_from_payload(
        state,
        original_action,
        payload,
        session,
        oauth_config,
    )
    .await
    {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let request = GraphMarkReadRequest {
        auth,
        message_id,
        is_read,
    };

    let fetch = tokio::time::timeout(fetch_deadline, fetcher(request))
        .await
        .map_err(|_| FrickmailError::Upstream("Microsoft Graph request timed out".to_string()));

    match fetch {
        Ok(Ok(_)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true
                }
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_graph_move(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_graph_move_with_fetcher(
        state,
        original_action,
        payload,
        session,
        graph_oauth_config_from_env,
        GRAPH_FETCH_DEADLINE,
        |request| async move { graph_move_message_via_reqwest(request).await },
    )
    .await
}

async fn native_frickmail_graph_move_with_fetcher<C, F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    oauth_config: C,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    C: FnOnce() -> fm_core::Result<GraphOAuthConfig>,
    F: FnOnce(GraphMoveMessageRequest) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Value>>,
{
    if let Some(response) = graph_authentication_error(state, original_action, session).await {
        return response;
    }
    if let Some(response) = graph_account_id_error(original_action, payload) {
        return response;
    }
    let message_id = payload_string(payload, "message_id").unwrap_or_default();
    if message_id.is_empty() {
        return json_result_error(original_action, "message_id required");
    }
    let target_folder_id = payload_string(payload, "target_folder_id").unwrap_or_default();
    if target_folder_id.is_empty() {
        return json_result_error(original_action, "target_folder_id required");
    }

    let auth = match graph_account_request_from_payload(
        state,
        original_action,
        payload,
        session,
        oauth_config,
    )
    .await
    {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let request = GraphMoveMessageRequest {
        auth,
        message_id,
        target_folder_id,
    };

    let fetch = tokio::time::timeout(fetch_deadline, fetcher(request))
        .await
        .map_err(|_| FrickmailError::Upstream("Microsoft Graph request timed out".to_string()));

    match fetch {
        Ok(Ok(message)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "message": message
                }
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_graph_delete(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_graph_delete_with_fetcher(
        state,
        original_action,
        payload,
        session,
        graph_oauth_config_from_env,
        GRAPH_FETCH_DEADLINE,
        |request| async move { graph_delete_message_via_reqwest(request).await },
    )
    .await
}

async fn native_frickmail_graph_delete_with_fetcher<C, F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    oauth_config: C,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    C: FnOnce() -> fm_core::Result<GraphOAuthConfig>,
    F: FnOnce(GraphDeleteMessageRequest) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Value>>,
{
    if let Some(response) = graph_authentication_error(state, original_action, session).await {
        return response;
    }
    if let Some(response) = graph_account_id_error(original_action, payload) {
        return response;
    }
    let message_id = payload_string(payload, "message_id").unwrap_or_default();
    if message_id.is_empty() {
        return json_result_error(original_action, "message_id required");
    }

    let auth = match graph_account_request_from_payload(
        state,
        original_action,
        payload,
        session,
        oauth_config,
    )
    .await
    {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let request = GraphDeleteMessageRequest { auth, message_id };

    let fetch = tokio::time::timeout(fetch_deadline, fetcher(request))
        .await
        .map_err(|_| FrickmailError::Upstream("Microsoft Graph request timed out".to_string()));

    match fetch {
        Ok(Ok(_)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true
                }
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
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

async fn native_frickmail_unified_inbox(
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

    match SqlxUserRepository::unified_inbox_messages(
        pool,
        user.user_id,
        payload_search_limit(payload),
    )
    .await
    {
        Ok(messages) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "messages": messages,
                    "errors": []
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

    let account_id = match resolve_message_body_account_id(payload, session, original_action).await
    {
        Ok(account_id) => account_id,
        Err(response) => return response,
    };
    let uid = payload_i64(payload, "uid");
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

async fn resolve_message_body_account_id(
    payload: &Value,
    session: &fm_session::Session,
    original_action: &str,
) -> Result<i64, Response> {
    let account_id = payload_i64(payload, "account_id");
    if account_id > 0 {
        return Ok(account_id);
    }

    let selected = session
        .get::<fm_core::SelectedMailAccountSession>(fm_session::SELECTED_ACCOUNT_SESSION_KEY)
        .await
        .map_err(|err| {
            json_result_error(
                original_action,
                &format!("Frickmail session read failed: {err}"),
            )
        })?;

    let Some(selected) = selected else {
        return Err(json_result_error(original_action, "Account id required"));
    };
    if selected.account_id <= 0 {
        return Err(json_result_error(original_action, "Account id required"));
    }

    Ok(selected.account_id)
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
    let accounts = match check_new_mail_accounts_with_fetcher(
        pool,
        user.user_id,
        &credential_key,
        &last_uids,
        fetch_deadline,
        fetcher,
    )
    .await
    {
        Ok(accounts) => accounts,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };

    new_mail_accounts_response(original_action, accounts, false)
}

async fn native_frickmail_long_poll_new_mail(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_long_poll_new_mail_with_fetcher(
        state,
        original_action,
        payload,
        session,
        LongPollNewMailTiming {
            fetch_deadline: CHECK_NEW_MAIL_ACCOUNT_DEADLINE,
            poll_deadline: LONG_POLL_NEW_MAIL_DEADLINE,
            poll_interval: LONG_POLL_NEW_MAIL_INTERVAL,
        },
        |config, password, folder| async move {
            fetch_mailbox_status(config, &password, &folder).await
        },
    )
    .await
}

async fn native_frickmail_long_poll_new_mail_with_fetcher<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    timing: LongPollNewMailTiming,
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

    let started = tokio::time::Instant::now();
    let mut last_uids = payload_last_uids(payload);

    loop {
        let accounts = match check_new_mail_accounts_with_fetcher(
            pool,
            user.user_id,
            &credential_key,
            &last_uids,
            timing.fetch_deadline,
            fetcher.clone(),
        )
        .await
        {
            Ok(accounts) => accounts,
            Err(err) => return json_result_error(original_action, &err.public_message()),
        };

        for account in &accounts {
            let Some(account_id) = account.get("account_id").and_then(Value::as_i64) else {
                continue;
            };
            let uidnext = account
                .get("uidnext")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            if uidnext > 0 {
                last_uids.insert(account_id.to_string(), uidnext);
            }
        }

        if accounts.iter().any(new_mail_account_has_delta) {
            spawn_web_push_to_user(pool.clone(), user.user_id, accounts.clone());
            return new_mail_accounts_response(original_action, accounts, false);
        }

        if started.elapsed() >= timing.poll_deadline {
            return new_mail_accounts_response(original_action, accounts, true);
        }

        let remaining = timing
            .poll_deadline
            .checked_sub(started.elapsed())
            .unwrap_or_default();
        let sleep_for = timing.poll_interval.min(remaining);
        if sleep_for.is_zero() {
            return new_mail_accounts_response(original_action, accounts, true);
        }
        tokio::time::sleep(sleep_for).await;
    }
}

async fn check_new_mail_accounts_with_fetcher<F, Fut>(
    pool: &sqlx::AnyPool,
    user_id: i64,
    credential_key: &[u8],
    last_uids: &HashMap<String, i64>,
    fetch_deadline: Duration,
    fetcher: F,
) -> fm_core::Result<Vec<Value>>
where
    F: Fn(ImapConnectionConfig, String, String) -> Fut + Clone,
    Fut: std::future::Future<Output = fm_core::Result<MailboxStatus>>,
{
    let accounts = SqlxUserRepository::list_mail_accounts(pool, user_id).await?;
    let mut results = Vec::new();
    for account in accounts {
        if account.account_type != "imap" {
            continue;
        }
        let secret =
            match SqlxUserRepository::get_mail_account_connection_secret(pool, user_id, account.id)
                .await
            {
                Ok(Some(secret)) => secret,
                _ => continue,
            };
        let config = match imap_config_from_account_secret(&secret) {
            Ok(config) => config,
            Err(_) => continue,
        };
        let password = match account_password(&secret, credential_key) {
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

    Ok(results)
}

fn new_mail_accounts_response(action: &str, accounts: Vec<Value>, timeout: bool) -> Response {
    let mut result = json!({
        "ok": true,
        "accounts": accounts
    });
    if timeout {
        result["timeout"] = Value::Bool(true);
    }

    json_value_envelope(
        StatusCode::OK,
        action,
        json!({
            "Result": result
        }),
    )
}

fn new_mail_account_has_delta(account: &Value) -> bool {
    account
        .get("new_count")
        .and_then(Value::as_i64)
        .unwrap_or_default()
        > 0
}

fn spawn_web_push_to_user(pool: sqlx::AnyPool, user_id: i64, accounts: Vec<Value>) {
    tokio::spawn(async move {
        send_web_push_to_user(&pool, user_id, &accounts).await;
    });
}

async fn send_web_push_to_user(pool: &sqlx::AnyPool, user_id: i64, accounts: &[Value]) {
    let subscriptions = match SqlxUserRepository::list_push_subscriptions(pool, user_id).await {
        Ok(subscriptions) if !subscriptions.is_empty() => subscriptions,
        _ => return,
    };
    let bundle = match SqlxUserRepository::get_or_create_vapid_key_bundle(pool).await {
        Ok(bundle) => bundle,
        Err(_) => return,
    };
    let subject = "mailto:Frickmail";
    let payload = new_mail_push_payload(accounts);

    for subscription in subscriptions {
        let _ = tokio::time::timeout(
            WEB_PUSH_DELIVERY_DEADLINE,
            send_validated_web_push_subscription(&subscription, &bundle, subject, &payload),
        )
        .await;
    }
}

fn new_mail_push_payload(accounts: &[Value]) -> Value {
    let mut total = 0_i64;
    let mut body = String::new();
    for account in accounts {
        let new_count = account
            .get("new_count")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        if new_count <= 0 {
            continue;
        }
        total += new_count;
        if body.is_empty() {
            body = account
                .get("account_email")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
        }
    }

    json!({
        "title": if total == 1 {
            "1 new message".to_string()
        } else {
            format!("{total} new messages")
        },
        "body": body,
        "tag": "fm-newmail",
        "url": "/"
    })
}

async fn send_validated_web_push_subscription(
    subscription: &PushSubscription,
    bundle: &VapidKeyBundle,
    subject: &str,
    payload: &Value,
) -> fm_core::Result<bool> {
    let client = validated_web_push_client(&subscription.endpoint).await?;
    send_web_push_subscription(&client, subscription, bundle, subject, payload).await
}

async fn validated_web_push_client(endpoint: &str) -> fm_core::Result<reqwest::Client> {
    let endpoint = url::Url::parse(endpoint.trim())
        .map_err(|err| FrickmailError::BadRequest(format!("invalid push endpoint: {err}")))?;
    if endpoint.scheme() != "https" {
        return Err(FrickmailError::BadRequest(
            "push endpoint must use https".to_string(),
        ));
    }
    let host = endpoint
        .host_str()
        .ok_or_else(|| FrickmailError::BadRequest("invalid push endpoint host".to_string()))?;
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| FrickmailError::BadRequest("invalid push endpoint port".to_string()))?;
    let addrs = public_socket_addrs(host, port).await.ok_or_else(|| {
        FrickmailError::BadRequest("push endpoint must resolve to public addresses".to_string())
    })?;

    reqwest::Client::builder()
        .timeout(WEB_PUSH_DELIVERY_DEADLINE)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addrs)
        .build()
        .map_err(|err| FrickmailError::Upstream(format!("Web Push client setup failed: {err}")))
}

async fn send_web_push_subscription(
    client: &reqwest::Client,
    subscription: &PushSubscription,
    bundle: &VapidKeyBundle,
    subject: &str,
    payload: &Value,
) -> fm_core::Result<bool> {
    if subscription.endpoint.trim().is_empty() {
        return Ok(false);
    }
    let auth_header = vapid_auth_header(&subscription.endpoint, subject, bundle)?;
    let body = payload.to_string();
    let response = client
        .post(subscription.endpoint.trim())
        .header("Authorization", auth_header)
        .header("TTL", "86400")
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|err| FrickmailError::Upstream(format!("Web Push request failed: {err}")))?;

    Ok(response.status().is_success())
}

fn vapid_auth_header(
    endpoint: &str,
    subject: &str,
    bundle: &VapidKeyBundle,
) -> fm_core::Result<String> {
    let endpoint = url::Url::parse(endpoint)
        .map_err(|err| FrickmailError::BadRequest(format!("invalid push endpoint: {err}")))?;
    let host = endpoint
        .host_str()
        .ok_or_else(|| FrickmailError::BadRequest("invalid push endpoint host".to_string()))?;
    let audience = format!("{}://{}", endpoint.scheme(), host);
    let jwt_header = URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"ES256"}"#);
    let jwt_payload = URL_SAFE_NO_PAD.encode(
        json!({
            "aud": audience,
            "exp": current_epoch() + 43_200,
            "sub": subject
        })
        .to_string(),
    );
    let sig_input = format!("{jwt_header}.{jwt_payload}");
    let signing_key = SigningKey::from_pkcs8_pem(&bundle.private_pem).map_err(|err| {
        FrickmailError::Upstream(format!("stored VAPID private key is invalid: {err}"))
    })?;
    let signature: Signature = signing_key.sign(sig_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!(
        "vapid t={sig_input}.{signature_b64},k={}",
        bundle.public_b64u
    ))
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

async fn native_frickmail_apply_rules(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_apply_rules_with_executor(
        state,
        original_action,
        payload,
        session,
        APPLY_RULES_DEADLINE,
        |config, password, rules| async move { apply_imap_rules(config, &password, &rules).await },
    )
    .await
}

async fn native_frickmail_apply_rules_with_executor<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    apply_deadline: Duration,
    executor: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, Vec<RuleExecutionPlan>) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<RuleExecutionReport>>,
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

    if account.account_type != "imap" {
        return json_result_error(original_action, "Rules only supported for IMAP accounts");
    }
    let config = match imap_config_from_account_secret(&account) {
        Ok(config) => config,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    let password = match account_password(&account, &credential_key) {
        Ok(password) => password,
        Err(_) => return json_result_error(original_action, "Missing IMAP password"),
    };

    let rules = match SqlxUserRepository::list_mail_rules(pool, user.user_id, account_id).await {
        Ok(rules) => rules,
        Err(err) => return json_result_error(original_action, &err.public_message()),
    };
    if rules.is_empty() {
        return apply_rules_response(original_action, Vec::new());
    }

    let plans = rules
        .iter()
        .filter(|rule| rule.enabled)
        .filter_map(mail_rule_execution_plan)
        .collect::<Vec<_>>();
    if plans.is_empty() {
        return apply_rules_response(original_action, Vec::new());
    }

    let report = tokio::time::timeout(apply_deadline, executor(config, password, plans))
        .await
        .map_err(|_| FrickmailError::Upstream("Rule application timed out".to_string()));

    match report {
        Ok(Ok(report)) => {
            for rule_id in &report.executed_rule_ids {
                if let Err(err) =
                    SqlxUserRepository::update_mail_rule_last_run(pool, user.user_id, *rule_id)
                        .await
                {
                    return json_result_error(original_action, &err.public_message());
                }
            }
            apply_rules_response(original_action, report.applied)
        }
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

fn apply_rules_response(
    original_action: &str,
    applied: Vec<fm_imap::RuleExecutionResult>,
) -> Response {
    json_value_envelope(
        StatusCode::OK,
        original_action,
        json!({
            "Result": {
                "ok": true,
                "applied": applied
            }
        }),
    )
}

fn mail_rule_execution_plan(rule: &fm_user::MailRule) -> Option<RuleExecutionPlan> {
    let conditions = mail_rule_conditions(&rule.conditions)?;
    let actions_array = rule.actions.as_array()?;
    if actions_array.is_empty() {
        return None;
    }
    let action_type = actions_array
        .first()
        .and_then(|action| action.get("type"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let actions = actions_array
        .iter()
        .map(mail_rule_action)
        .collect::<Vec<_>>();

    Some(RuleExecutionPlan {
        rule_id: rule.id,
        rule_name: rule.name.clone(),
        conditions,
        conditions_logic: match rule.conditions_logic.as_str() {
            "any" => RuleConditionsLogic::Any,
            _ => RuleConditionsLogic::All,
        },
        actions,
        action_type,
    })
}

fn mail_rule_conditions(value: &Value) -> Option<Vec<RuleCondition>> {
    let mut conditions = Vec::new();
    for condition in value.as_array()? {
        let field = match condition.get("field").and_then(Value::as_str).unwrap_or("") {
            "from" => RuleConditionField::From,
            "subject" => RuleConditionField::Subject,
            "to" => RuleConditionField::To,
            _ => return None,
        };
        let value = condition
            .get("value")
            .map(value_to_php_string)
            .unwrap_or_default();
        if value.is_empty() {
            continue;
        }
        let op = match condition
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("contains")
        {
            "not_contains" => RuleConditionOp::NotContains,
            "equals" => RuleConditionOp::Equals,
            _ => RuleConditionOp::Contains,
        };
        conditions.push(RuleCondition { field, op, value });
    }

    if conditions.is_empty() {
        None
    } else {
        Some(conditions)
    }
}

fn mail_rule_action(action: &Value) -> RuleAction {
    match action.get("type").and_then(Value::as_str).unwrap_or("") {
        "move" => {
            let folder = action
                .get("params")
                .and_then(|params| params.get("folder"))
                .map(value_to_php_string)
                .unwrap_or_default();
            if folder.is_empty() {
                RuleAction::Noop
            } else {
                RuleAction::Move { folder }
            }
        }
        "read" => RuleAction::Read,
        "flag" => RuleAction::Flag,
        "delete" => RuleAction::Delete,
        _ => RuleAction::Noop,
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

async fn native_frickmail_export_message(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_export_message_with_fetcher(
        state,
        original_action,
        payload,
        session,
        EXPORT_MESSAGE_DEADLINE,
        |config, password, folder, uid| async move {
            fetch_raw_message(config, &password, &folder, uid).await
        },
    )
    .await
}

async fn native_frickmail_export_message_with_fetcher<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    export_deadline: Duration,
    fetcher: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, u32) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Option<Vec<u8>>>>,
{
    let (user, credential_key) = match imap_action_auth(state, original_action, session).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    if payload_i64(payload, "account_id") <= 0 {
        return json_result_error(original_action, "account_id required");
    }
    let folder = match required_payload_string(payload, "folder", "folder required") {
        Ok(folder) => folder,
        Err(message) => return json_result_error(original_action, message),
    };
    let uid = payload_i64(payload, "uid");
    if uid <= 0 || uid > u32::MAX as i64 {
        return json_result_error(original_action, "uid required");
    }

    let (config, password) = match imap_action_connection_for_user(
        state,
        original_action,
        payload,
        user.user_id,
        &credential_key,
    )
    .await
    {
        Ok(connection) => connection,
        Err(response) => return response,
    };

    let raw = tokio::time::timeout(
        export_deadline,
        fetcher(config, password, folder, uid as u32),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Message export timed out".to_string()));

    match raw {
        Ok(Ok(Some(raw))) if !raw.is_empty() => {
            let subject = payload_optional_string(payload, "subject")
                .unwrap_or_else(|| "message".to_string());
            json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": {
                        "ok": true,
                        "filename": format!("{}.eml", plugin_safe_filename(&subject, "message", true)),
                        "content_b64": STANDARD.encode(raw)
                    }
                }),
            )
        }
        Ok(Ok(Some(_))) => json_result_error(original_action, "Empty message body"),
        Ok(Ok(None)) => {
            json_result_error(original_action, &format!("Message not found (UID {uid})"))
        }
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_export_folder(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let limits = export_folder_limits(state.config());
    native_frickmail_export_folder_with_fetcher(
        state,
        original_action,
        payload,
        session,
        EXPORT_FOLDER_DEADLINE,
        limits,
        move |config, password, folder| async move {
            fetch_raw_folder_messages(config, &password, &folder, limits).await
        },
    )
    .await
}

async fn native_frickmail_export_folder_with_fetcher<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    export_deadline: Duration,
    limits: RawFolderFetchLimits,
    fetcher: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<Vec<Vec<u8>>>>,
{
    let (user, credential_key) = match imap_action_auth(state, original_action, session).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    if payload_i64(payload, "account_id") <= 0 {
        return json_result_error(original_action, "account_id required");
    }
    let folder = match required_payload_string(payload, "folder", "folder required") {
        Ok(folder) => folder,
        Err(message) => return json_result_error(original_action, message),
    };

    let (config, password) = match imap_action_connection_for_user(
        state,
        original_action,
        payload,
        user.user_id,
        &credential_key,
    )
    .await
    {
        Ok(connection) => connection,
        Err(response) => return response,
    };

    let messages = tokio::time::timeout(export_deadline, fetcher(config, password, folder.clone()))
        .await
        .map_err(|_| FrickmailError::Upstream("Folder export timed out".to_string()));

    match messages {
        Ok(Ok(messages)) => {
            let mbox = match plugin_mbox(messages, limits) {
                Ok(mbox) => mbox,
                Err(err) => return json_result_error(original_action, &err.public_message()),
            };
            json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": {
                        "ok": true,
                        "filename": format!("{}.mbox", plugin_safe_filename(&folder, "folder", false)),
                        "content_b64": STANDARD.encode(mbox)
                    }
                }),
            )
        }
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_import_eml(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_frickmail_import_eml_with_appender(
        state,
        original_action,
        payload,
        session,
        IMPORT_EML_DEADLINE,
        |config, password, folder, raw| async move {
            append_raw_message(config, &password, &folder, &raw).await
        },
    )
    .await
}

async fn native_frickmail_import_eml_with_appender<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    import_deadline: Duration,
    appender: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
    let (user, credential_key) = match imap_action_auth(state, original_action, session).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    if payload_i64(payload, "account_id") <= 0 {
        return json_result_error(original_action, "account_id required");
    }
    let folder = payload_optional_string(payload, "folder").unwrap_or_else(|| "INBOX".to_string());
    let Some(eml_b64) = payload_optional_string(payload, "eml_b64") else {
        return json_result_error(original_action, "eml_b64 required");
    };
    let raw = match STANDARD.decode(eml_b64.as_bytes()) {
        Ok(raw) => raw,
        Err(_) => return json_result_error(original_action, "Invalid base64 in eml_b64"),
    };
    if let Err(err) = validate_eml(&raw) {
        return json_result_error(original_action, &err.public_message());
    }

    let (config, password) = match imap_action_connection_for_user(
        state,
        original_action,
        payload,
        user.user_id,
        &credential_key,
    )
    .await
    {
        Ok(connection) => connection,
        Err(response) => return response,
    };

    let result = tokio::time::timeout(import_deadline, appender(config, password, folder, raw))
        .await
        .map_err(|_| FrickmailError::Upstream("EML import timed out".to_string()));

    match result {
        Ok(Ok(())) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true
                }
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_legacy_folder_append_multipart(
    state: &AppState,
    original_action: &str,
    headers: &HeaderMap,
    body: &[u8],
    session: &fm_session::Session,
) -> Response {
    native_legacy_folder_append_multipart_with_appender(
        state,
        original_action,
        headers,
        body,
        session,
        FOLDER_APPEND_DEADLINE,
        |config, password, folder, raw| async move {
            append_raw_message_without_flags(config, &password, &folder, &raw).await
        },
    )
    .await
}

async fn native_legacy_folder_append_multipart_with_appender<F, Fut>(
    state: &AppState,
    original_action: &str,
    headers: &HeaderMap,
    body: &[u8],
    session: &fm_session::Session,
    append_deadline: Duration,
    appender: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
    let (user, credential_key) =
        match legacy_folder_append_auth(state, original_action, session).await {
            Ok(auth) => auth,
            Err(response) => return response,
        };

    if !state.config().frickmail_user.allow_message_append {
        return legacy_folder_append_error(original_action, "Permission denied");
    }

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let upload = match folder_append_upload(content_type, body) {
        FolderAppendUploadResult::Upload(upload) => upload,
        FolderAppendUploadResult::MissingFile => {
            return legacy_folder_append_error(original_action, "No file");
        }
        FolderAppendUploadResult::MissingFolder => {
            return legacy_folder_append_error(original_action, "");
        }
    };

    let payload = json!({
        "folder": upload.folder.clone()
    });
    let (config, password) = match legacy_folder_append_connection_for_selected_or_payload(
        state,
        original_action,
        &payload,
        session,
        user.user_id,
        &credential_key,
    )
    .await
    {
        Ok(connection) => connection,
        Err(response) => return response,
    };

    let result = tokio::time::timeout(
        append_deadline,
        appender(config, password, upload.folder, upload.raw),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Folder append timed out".to_string()));

    legacy_folder_append_response(original_action, result)
}

async fn legacy_folder_append_auth(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
) -> Result<(fm_core::UserSession, Vec<u8>), Response> {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return Err(response),
    }) else {
        return Err(legacy_folder_append_error(
            original_action,
            "Not authenticated",
        ));
    };

    let encoded_key = session
        .get::<String>(fm_session::CREDENTIAL_KEY_SESSION_KEY)
        .await
        .map_err(|err| {
            legacy_folder_append_error(
                original_action,
                format!("Frickmail session read failed: {err}"),
            )
        })?;
    let Some(encoded_key) = encoded_key else {
        return Err(legacy_folder_append_error(
            original_action,
            "Not authenticated",
        ));
    };
    let Ok(key) = STANDARD.decode(encoded_key.trim()) else {
        return Err(legacy_folder_append_error(
            original_action,
            "Not authenticated",
        ));
    };
    if key.len() != CREDENTIAL_KEY_BYTES {
        return Err(legacy_folder_append_error(
            original_action,
            "Not authenticated",
        ));
    }

    Ok((user, key))
}

async fn legacy_folder_append_connection_for_selected_or_payload(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    user_id: i64,
    credential_key: &[u8],
) -> Result<(ImapConnectionConfig, String), Response> {
    let Some(pool) = state.db_pool() else {
        return Err(legacy_folder_append_error(
            original_action,
            "Frickmail database is not configured",
        ));
    };

    let account_id = legacy_folder_append_account_id(payload, session, original_action).await?;
    let account =
        match SqlxUserRepository::get_mail_account_connection_secret(pool, user_id, account_id)
            .await
        {
            Ok(Some(account)) => account,
            Ok(None) => {
                return Err(legacy_folder_append_error(
                    original_action,
                    "Account not found",
                ))
            }
            Err(err) => {
                return Err(legacy_folder_append_error(
                    original_action,
                    err.public_message(),
                ))
            }
        };
    let config = match imap_config_from_account_secret(&account) {
        Ok(config) => config,
        Err(err) => {
            return Err(legacy_folder_append_error(
                original_action,
                err.public_message(),
            ))
        }
    };
    let password = match account_password(&account, credential_key) {
        Ok(password) => password,
        Err(_) => {
            return Err(legacy_folder_append_error(
                original_action,
                "Missing IMAP password",
            ))
        }
    };

    Ok((config, password))
}

async fn legacy_folder_append_account_id(
    payload: &Value,
    session: &fm_session::Session,
    original_action: &str,
) -> Result<i64, Response> {
    let account_id = payload_i64(payload, "account_id");
    if account_id > 0 {
        return Ok(account_id);
    }

    let selected = session
        .get::<fm_core::SelectedMailAccountSession>(fm_session::SELECTED_ACCOUNT_SESSION_KEY)
        .await
        .map_err(|err| {
            legacy_folder_append_error(
                original_action,
                format!("Frickmail session read failed: {err}"),
            )
        })?;

    let Some(selected) = selected else {
        return Err(legacy_folder_append_error(
            original_action,
            "Account id required",
        ));
    };
    if selected.account_id <= 0 {
        return Err(legacy_folder_append_error(
            original_action,
            "Account id required",
        ));
    }

    Ok(selected.account_id)
}

async fn native_legacy_message(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_legacy_message_with_fetcher(
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

async fn native_legacy_message_with_fetcher<F, Fut>(
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
    let (config, password) =
        match legacy_imap_connection_context(state, original_action, payload, session).await {
            Ok(connection) => connection,
            Err(response) => return response,
        };
    let message_request = match legacy_message_request_from_payload(payload) {
        Ok(request) => request,
        Err(message) => return json_result_error(original_action, message),
    };

    let result = tokio::time::timeout(
        fetch_deadline,
        fetcher(
            config,
            password,
            message_request.folder.clone(),
            message_request.uid,
        ),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Message fetch timed out".to_string()));

    match result {
        Ok(Ok(Some(parts))) => legacy_message_body_response(
            original_action,
            &message_request.folder,
            message_request.uid,
            parts,
        ),
        Ok(Ok(None)) => json_result_error(original_action, "Message not found"),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

fn legacy_message_payload_is_native_candidate(payload: &Value) -> bool {
    (payload.get("folder").is_some() && payload.get("uid").is_some())
        || legacy_message_raw_key_request_from_payload(payload)
            .ok()
            .flatten()
            .is_some()
}

fn legacy_message_request_from_payload(
    payload: &Value,
) -> Result<LegacyMessageRawKeyRequest, &'static str> {
    if let Some(raw_key_request) = legacy_message_raw_key_request_from_payload(payload)? {
        return Ok(raw_key_request);
    }

    let folder = required_payload_string(payload, "folder", "folder required")?;
    let uid = payload_i64(payload, "uid");
    if uid <= 0 || uid > u32::MAX as i64 {
        return Err("uid required");
    }

    Ok(LegacyMessageRawKeyRequest {
        folder,
        uid: uid as u32,
        use_threads: payload_bool(payload, "useThreads"),
        account_hash: payload_string(payload, "accountHash").unwrap_or_default(),
    })
}

fn legacy_message_raw_key_request_from_payload(
    payload: &Value,
) -> Result<Option<LegacyMessageRawKeyRequest>, &'static str> {
    let Some(raw_key) = payload_optional_string(payload, "RawKey") else {
        return Ok(None);
    };
    let Some(raw_payload) = legacy_raw_key_json(&raw_key) else {
        return Ok(None);
    };
    let Some(values) = raw_payload.as_array() else {
        return Ok(None);
    };
    if values.len() < 2 {
        return Ok(None);
    }

    let folder = value_to_php_string(&values[0]);
    if folder.is_empty() {
        return Err("folder required");
    }
    let uid = value_to_php_i64(&values[1]);
    if uid <= 0 || uid > u32::MAX as i64 {
        return Err("uid required");
    }

    Ok(Some(LegacyMessageRawKeyRequest {
        folder,
        uid: uid as u32,
        use_threads: values.get(2).map(legacy_php_truthy).unwrap_or(false),
        account_hash: values.get(3).map(value_to_php_string).unwrap_or_default(),
    }))
}

#[allow(dead_code)]
async fn native_legacy_message_list(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_legacy_message_list_with_fetcher(
        state,
        original_action,
        payload,
        session,
        MESSAGE_LIST_DEADLINE,
        |config, password, request| async move {
            fetch_legacy_message_list(config, &password, request).await
        },
    )
    .await
}

#[allow(dead_code)]
async fn native_legacy_message_list_with_fetcher<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, LegacyMessageListRequest) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<LegacyMessageList>>,
{
    let (user, credential_key) = match imap_action_auth(state, original_action, session).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let hide_deleted = match legacy_message_list_hide_deleted_setting(
        state,
        original_action,
        user.user_id,
    )
    .await
    {
        Ok(hide_deleted) => hide_deleted,
        Err(response) => return response,
    };
    let (config, password) = match imap_action_connection_for_selected_or_payload(
        state,
        original_action,
        payload,
        session,
        user.user_id,
        &credential_key,
    )
    .await
    {
        Ok(connection) => connection,
        Err(response) => return response,
    };
    let (mut request, raw_cache_hash) =
        match legacy_message_list_raw_key_request_from_payload(payload) {
            Ok(Some(raw_key_request)) => {
                let LegacyMessageListRawKeyRequest {
                    request,
                    cache_hash,
                    account_hash: _account_hash,
                } = raw_key_request;
                (request, Some(cache_hash))
            }
            Ok(None) => match legacy_message_list_request_from_payload(payload) {
                Ok(request) => (request, None),
                Err(message) => return json_result_error(original_action, message),
            },
            Err(message) => return json_result_error(original_action, message),
        };
    request.hide_deleted = hide_deleted;

    let result = tokio::time::timeout(fetch_deadline, fetcher(config, password, request.clone()))
        .await
        .map_err(|_| FrickmailError::Upstream("Message list fetch timed out".to_string()));

    match result {
        Ok(Ok(list)) => {
            let _raw_cache_state = raw_cache_hash.as_deref().and_then(|cache_hash| {
                legacy_message_list_raw_cache_state(cache_hash, &request, &list.folder.etag)
            });
            json_value_envelope(
                StatusCode::OK,
                original_action,
                json!({
                    "Result": legacy_message_list_json(&list)
                }),
            )
        }
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

#[allow(dead_code)]
fn legacy_message_list_request_from_payload(
    payload: &Value,
) -> Result<LegacyMessageListRequest, &'static str> {
    legacy_message_list_request_from_payload_with_limit_default(payload, 10)
}

fn legacy_message_list_raw_key_request_from_payload_values(
    payload: &Value,
) -> Result<LegacyMessageListRequest, &'static str> {
    legacy_message_list_request_from_payload_with_limit_default(payload, 0)
}

fn legacy_message_list_request_from_payload_with_limit_default(
    payload: &Value,
    missing_limit: u32,
) -> Result<LegacyMessageListRequest, &'static str> {
    let mailbox = required_payload_string(payload, "folder", "folder required")?;
    let offset = payload_clamped_u32(payload, "offset");
    let limit = legacy_message_list_payload_limit(payload, missing_limit);
    let prev_uid_next = Some(legacy_message_list_payload_uid_next(payload));
    let use_threads = payload_bool(payload, "useThreads");
    let thread_uid = if use_threads {
        payload_optional_u32(payload, "threadUid").unwrap_or_default()
    } else {
        0
    };
    let thread_algorithm = if use_threads {
        payload_string(payload, "threadAlgorithm").unwrap_or_default()
    } else {
        String::new()
    };

    Ok(LegacyMessageListRequest {
        mailbox,
        offset,
        limit,
        search: payload_string(payload, "search").unwrap_or_default(),
        sort: payload_string(payload, "sort").unwrap_or_default(),
        prev_uid_next,
        hide_deleted: true,
        use_threads,
        thread_uid,
        thread_algorithm,
    })
}

fn legacy_message_list_payload_limit(payload: &Value, missing_limit: u32) -> u32 {
    if payload.get("limit").is_some() {
        payload_clamped_u32(payload, "limit")
    } else {
        missing_limit
    }
}

fn legacy_message_list_payload_uid_next(payload: &Value) -> u32 {
    payload_optional_u32(payload, "uidNext").unwrap_or_default()
}

#[allow(dead_code)]
fn legacy_message_list_raw_key_from_uri(uri: &Uri) -> Option<String> {
    legacy_action_raw_key_from_uri(uri, "MessageList")
}

fn legacy_action_raw_key_from_uri(uri: &Uri, action: &str) -> Option<String> {
    let query = uri.query()?;
    if !is_legacy_json_request(uri) {
        return None;
    }
    let tail = query.split_once("/0/")?.1.trim_start_matches('/');
    let mut parts = tail.split('/');
    if parts.next()? != action {
        return None;
    }

    while let Some(part) = parts.next() {
        if part == "&q[]=" {
            return parts
                .next()
                .filter(|value| !value.is_empty())
                .map(ToString::to_string);
        }
    }

    None
}

fn legacy_message_list_raw_key_request_from_payload(
    payload: &Value,
) -> Result<Option<LegacyMessageListRawKeyRequest>, &'static str> {
    let Some(raw_key) = payload_optional_string(payload, "RawKey") else {
        return Ok(None);
    };
    let Some(raw_payload) = legacy_raw_key_json(&raw_key) else {
        return Ok(None);
    };
    let Some(values) = raw_payload.as_object() else {
        return Ok(None);
    };
    if values.len() <= 6 {
        return Ok(None);
    }

    let cache_hash = payload_string(&raw_payload, "hash").unwrap_or_default();
    let account_hash = legacy_message_list_raw_key_account_hash(&raw_payload, &cache_hash);

    Ok(Some(LegacyMessageListRawKeyRequest {
        cache_hash,
        account_hash,
        request: legacy_message_list_raw_key_request_from_payload_values(&raw_payload)?,
    }))
}

fn legacy_raw_key_json(raw_key: &str) -> Option<Value> {
    if raw_key.is_empty() {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(raw_key)
        .or_else(|_| URL_SAFE.decode(raw_key))
        .ok()?;
    serde_json::from_slice::<Value>(&decoded).ok()
}

fn legacy_message_list_raw_cache_state(
    request_cache_hash: &str,
    request: &LegacyMessageListRequest,
    current_folder_etag: &str,
) -> Option<LegacyMessageListRawCacheState> {
    if request_cache_hash.is_empty() || current_folder_etag.is_empty() {
        return None;
    }

    let request_hash_validator = legacy_message_list_request_hash_validator(request_cache_hash)?;
    let account_hash =
        legacy_message_list_cache_hash_account(request_cache_hash).unwrap_or_default();
    let params_hash = legacy_message_list_params_hash(request, false, true);
    let current_cache_key = legacy_message_list_cache_key(&params_hash, current_folder_etag);

    Some(LegacyMessageListRawCacheState {
        verify_existing_cache: request_hash_validator == current_folder_etag,
        request_hash_validator,
        account_hash,
        current_cache_key,
    })
}

fn legacy_message_list_request_hash_validator(request_cache_hash: &str) -> Option<String> {
    request_cache_hash
        .split('-')
        .nth(1)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn legacy_message_list_raw_key_account_hash(
    raw_payload: &Value,
    request_cache_hash: &str,
) -> String {
    payload_string(raw_payload, "accountHash")
        .or_else(|| legacy_message_list_cache_hash_account(request_cache_hash))
        .unwrap_or_default()
}

fn legacy_message_list_cache_hash_account(request_cache_hash: &str) -> Option<String> {
    request_cache_hash
        .rsplit_once('-')
        .map(|(_, account_hash)| account_hash)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

async fn legacy_message_list_hide_deleted_setting(
    state: &AppState,
    original_action: &str,
    user_id: i64,
) -> Result<bool, Response> {
    let Some(pool) = state.db_pool() else {
        return Ok(true);
    };

    match SqlxUserRepository::find_by_id(pool, user_id).await {
        Ok(Some(user)) => Ok(legacy_message_list_hide_deleted_from_settings(
            &user.settings,
        )),
        Ok(None) => Err(json_result_error(original_action, "Not authenticated")),
        Err(err) => Err(json_result_error(original_action, &err.public_message())),
    }
}

fn legacy_message_list_hide_deleted_from_settings(settings: &Value) -> bool {
    settings
        .get("HideDeleted")
        .or_else(|| settings.get("hideDeleted"))
        .map(legacy_php_truthy)
        .unwrap_or(true)
}

fn legacy_php_truthy(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Null => false,
        Value::Number(number) => number
            .as_i64()
            .map(|value| value != 0)
            .or_else(|| number.as_u64().map(|value| value != 0))
            .or_else(|| number.as_f64().map(|value| value != 0.0))
            .unwrap_or(false),
        Value::String(value) => !value.is_empty() && value != "0",
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
    }
}

async fn native_legacy_folder_information(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let fetch_new_messages = state.config().mail.fetch_new_messages;
    native_legacy_folder_information_with_fetcher(
        state,
        original_action,
        payload,
        session,
        FOLDER_INFORMATION_DEADLINE,
        |config, password, folder, prev_uid_next, flag_uids| async move {
            fetch_legacy_folder_information(
                config,
                &password,
                &folder,
                prev_uid_next,
                flag_uids,
                fetch_new_messages,
            )
            .await
        },
    )
    .await
}

async fn native_legacy_folder_information_with_fetcher<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, Option<u32>, Option<Vec<u32>>) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<LegacyFolderInformation>>,
{
    let (config, password) =
        match legacy_imap_connection_context(state, original_action, payload, session).await {
            Ok(connection) => connection,
            Err(response) => return response,
        };
    let folder = match required_payload_string(payload, "folder", "folder required") {
        Ok(folder) => folder,
        Err(message) => return json_result_error(original_action, message),
    };
    let prev_uid_next = payload_optional_i64(payload, "uidNext").map(|value| value as u32);
    let flag_uids = payload_uid_list_optional(payload, "flagsUids");

    let result = tokio::time::timeout(
        fetch_deadline,
        fetcher(config, password, folder, prev_uid_next, flag_uids),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Folder information fetch timed out".to_string()));

    match result {
        Ok(Ok(info)) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": legacy_folder_information_json(&info)
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_legacy_folder_information_multiply(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    let fetch_new_messages = state.config().mail.fetch_new_messages;
    native_legacy_folder_information_multiply_with_fetcher(
        state,
        original_action,
        payload,
        session,
        FOLDER_INFORMATION_DEADLINE,
        |config, password, folder| async move {
            fetch_legacy_folder_information(
                config,
                &password,
                &folder,
                None,
                None,
                fetch_new_messages,
            )
            .await
        },
    )
    .await
}

async fn native_legacy_folder_information_multiply_with_fetcher<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    fetch_deadline: Duration,
    fetcher: F,
) -> Response
where
    F: Fn(ImapConnectionConfig, String, String) -> Fut + Clone,
    Fut: std::future::Future<Output = fm_core::Result<LegacyFolderInformation>>,
{
    let (config, password) =
        match legacy_imap_connection_context(state, original_action, payload, session).await {
            Ok(connection) => connection,
            Err(response) => return response,
        };
    let folders = payload_array(payload, "folders")
        .into_iter()
        .filter_map(|value| match value {
            Value::String(folder) if !folder.trim().is_empty() => Some(folder),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut results = Vec::new();
    for folder in folders {
        let fetch = fetcher.clone();
        let result = tokio::time::timeout(
            fetch_deadline,
            fetch(config.clone(), password.clone(), folder),
        )
        .await
        .map_err(|_| FrickmailError::Upstream("Folder information fetch timed out".to_string()));
        if let Ok(Ok(info)) = result {
            results.push(legacy_folder_information_json(&info));
        }
    }

    json_value_envelope(
        StatusCode::OK,
        original_action,
        json!({
            "Result": results
        }),
    )
}

async fn native_legacy_message_store_flag(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    flag: ImapMessageFlag,
) -> Response {
    native_legacy_message_store_flag_with_storer(
        state,
        original_action,
        payload,
        session,
        flag,
        MESSAGE_MUTATION_DEADLINE,
        |config, password, folder, uid_set, flag, set| async move {
            store_message_flag(config, &password, &folder, &uid_set, flag, set).await
        },
    )
    .await
}

async fn native_legacy_message_store_flag_with_storer<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    flag: ImapMessageFlag,
    mutation_deadline: Duration,
    storer: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, String, ImapMessageFlag, bool) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
    let (config, password, folder, uid_set) =
        match legacy_message_mutation_context(state, original_action, payload, session).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let set = payload_i64(payload, "setAction") != 0;

    let result = tokio::time::timeout(
        mutation_deadline,
        storer(config, password, folder, uid_set, flag, set),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Message flag update timed out".to_string()));

    legacy_message_bool_response(original_action, result)
}

async fn native_legacy_message_store_keyword(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_legacy_message_store_keyword_with_storer(
        state,
        original_action,
        payload,
        session,
        MESSAGE_MUTATION_DEADLINE,
        |config, password, folder, uid_set, keyword, set| async move {
            store_message_keyword(config, &password, &folder, &uid_set, &keyword, set).await
        },
    )
    .await
}

async fn native_legacy_message_store_keyword_with_storer<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    mutation_deadline: Duration,
    storer: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, String, String, bool) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
    let (config, password, folder, uid_set) =
        match legacy_message_mutation_context(state, original_action, payload, session).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let keyword = payload_string(payload, "keyword").unwrap_or_default();
    let set = payload_i64(payload, "setAction") != 0;

    let result = tokio::time::timeout(
        mutation_deadline,
        storer(config, password, folder, uid_set, keyword, set),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Message keyword update timed out".to_string()));

    legacy_message_bool_response(original_action, result)
}

async fn native_legacy_message_set_seen_to_all(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_legacy_message_set_seen_to_all_with_storer(
        state,
        original_action,
        payload,
        session,
        MESSAGE_MUTATION_DEADLINE,
        |config, password, folder, thread_uids, set| async move {
            store_seen_to_all(config, &password, &folder, thread_uids.as_deref(), set).await
        },
    )
    .await
}

async fn native_legacy_message_set_seen_to_all_with_storer<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    mutation_deadline: Duration,
    storer: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, Option<String>, bool) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
    let (config, password) =
        match legacy_imap_connection_context(state, original_action, payload, session).await {
            Ok(connection) => connection,
            Err(response) => return response,
        };
    let folder = match required_payload_string(payload, "folder", "folder required") {
        Ok(folder) => folder,
        Err(message) => return json_result_error(original_action, message),
    };
    let thread_uids = payload_optional_string(payload, "threadUids")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let set = payload_i64(payload, "setAction") != 0;

    let result = tokio::time::timeout(
        mutation_deadline,
        storer(config, password, folder, thread_uids, set),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Message flag update timed out".to_string()));

    legacy_message_bool_response(original_action, result)
}

async fn native_legacy_message_copy(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_legacy_message_copy_with_copier(
        state,
        original_action,
        payload,
        session,
        MESSAGE_MUTATION_DEADLINE,
        |config, password, from_folder, to_folder, uid_set| async move {
            copy_messages(config, &password, &from_folder, &to_folder, &uid_set).await
        },
    )
    .await
}

async fn native_legacy_message_copy_with_copier<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    mutation_deadline: Duration,
    copier: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, String, String) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
    let (config, password, from_folder, uid_set) =
        match legacy_message_mutation_context_with_folder_key(
            state,
            original_action,
            payload,
            session,
            "fromFolder",
        )
        .await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    let to_folder = match required_payload_string(payload, "toFolder", "toFolder required") {
        Ok(folder) => folder,
        Err(message) => return json_result_error(original_action, message),
    };

    let result = tokio::time::timeout(
        mutation_deadline,
        copier(config, password, from_folder, to_folder.clone(), uid_set),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Message copy timed out".to_string()));

    legacy_message_folder_response(original_action, &to_folder, result)
}

async fn native_legacy_message_move(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_legacy_message_move_with_mover(
        state,
        original_action,
        payload,
        session,
        MESSAGE_MUTATION_DEADLINE,
        |config, password, from_folder, to_folder, uid_set, options| async move {
            move_messages(
                config,
                &password,
                &from_folder,
                &to_folder,
                &uid_set,
                options,
            )
            .await
        },
    )
    .await
}

async fn native_legacy_message_move_with_mover<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    mutation_deadline: Duration,
    mover: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, String, String, ImapMoveOptions) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
    let (config, password, from_folder, uid_set) =
        match legacy_message_mutation_context_with_folder_key(
            state,
            original_action,
            payload,
            session,
            "fromFolder",
        )
        .await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    let to_folder = match required_payload_string(payload, "toFolder", "toFolder required") {
        Ok(folder) => folder,
        Err(message) => return json_result_error(original_action, message),
    };
    let options = legacy_message_move_options(payload);

    let result = tokio::time::timeout(
        mutation_deadline,
        mover(
            config,
            password,
            from_folder.clone(),
            to_folder,
            uid_set,
            options,
        ),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Message move timed out".to_string()));

    legacy_message_folder_response(original_action, &from_folder, result)
}

async fn native_legacy_message_delete(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Response {
    native_legacy_message_delete_with_deleter(
        state,
        original_action,
        payload,
        session,
        MESSAGE_MUTATION_DEADLINE,
        |config, password, folder, uid_set| async move {
            delete_messages(config, &password, &folder, &uid_set).await
        },
    )
    .await
}

async fn native_legacy_message_delete_with_deleter<F, Fut>(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    mutation_deadline: Duration,
    deleter: F,
) -> Response
where
    F: FnOnce(ImapConnectionConfig, String, String, String) -> Fut,
    Fut: std::future::Future<Output = fm_core::Result<()>>,
{
    let (config, password, folder, uid_set) =
        match legacy_message_mutation_context(state, original_action, payload, session).await {
            Ok(context) => context,
            Err(response) => return response,
        };

    let result = tokio::time::timeout(
        mutation_deadline,
        deleter(config, password, folder.clone(), uid_set),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("Message delete timed out".to_string()));

    legacy_message_folder_response(original_action, &folder, result)
}

async fn legacy_message_mutation_context(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Result<(ImapConnectionConfig, String, String, String), Response> {
    legacy_message_mutation_context_with_folder_key(
        state,
        original_action,
        payload,
        session,
        "folder",
    )
    .await
}

async fn legacy_message_mutation_context_with_folder_key(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    folder_key: &str,
) -> Result<(ImapConnectionConfig, String, String, String), Response> {
    let (user, credential_key) = imap_action_auth(state, original_action, session).await?;
    let folder = match required_payload_string(payload, folder_key, "folder required") {
        Ok(folder) => folder,
        Err(message) => return Err(json_result_error(original_action, message)),
    };
    let uid_set = match required_payload_string(payload, "uids", "uids required") {
        Ok(uid_set) => uid_set,
        Err(message) => return Err(json_result_error(original_action, message)),
    };
    let (config, password) = imap_action_connection_for_selected_or_payload(
        state,
        original_action,
        payload,
        session,
        user.user_id,
        &credential_key,
    )
    .await?;

    Ok((config, password, folder, uid_set))
}

fn legacy_message_move_options(payload: &Value) -> ImapMoveOptions {
    let learning = payload_optional_string(payload, "learning").and_then(|value| {
        match value.trim().to_ascii_uppercase().as_str() {
            "SPAM" => Some(ImapMoveLearning::Spam),
            "HAM" => Some(ImapMoveLearning::Ham),
            _ => None,
        }
    });

    ImapMoveOptions {
        mark_as_read: payload_i64(payload, "markAsRead") != 0,
        learning,
    }
}

fn legacy_message_bool_response(
    original_action: &str,
    result: Result<fm_core::Result<()>, FrickmailError>,
) -> Response {
    match result {
        Ok(Ok(())) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": true
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

fn legacy_folder_append_response(
    original_action: &str,
    result: Result<fm_core::Result<()>, FrickmailError>,
) -> Response {
    match result {
        Ok(Ok(())) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": true
            }),
        ),
        Ok(Err(err)) | Err(err) => json_value_envelope(
            StatusCode::OK,
            original_action,
            compat_error(UNKNOWN_ERROR, err.public_message()),
        ),
    }
}

fn legacy_folder_append_error(original_action: &str, message: impl Into<String>) -> Response {
    json_value_envelope(
        StatusCode::OK,
        original_action,
        compat_error(UNKNOWN_ERROR, message),
    )
}

fn legacy_message_folder_response(
    original_action: &str,
    folder: &str,
    result: Result<fm_core::Result<()>, FrickmailError>,
) -> Response {
    match result {
        Ok(Ok(())) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": [folder, ""]
            }),
        ),
        Ok(Err(err)) | Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn legacy_imap_connection_context(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
) -> Result<(ImapConnectionConfig, String), Response> {
    let (user, credential_key) = imap_action_auth(state, original_action, session).await?;
    imap_action_connection_for_selected_or_payload(
        state,
        original_action,
        payload,
        session,
        user.user_id,
        &credential_key,
    )
    .await
}

fn legacy_folder_information_json(info: &LegacyFolderInformation) -> Value {
    let mut value = json!({
        "id": Value::Null,
        "name": info.name,
        "uidNext": info.uid_next,
        "uidValidity": info.uid_validity,
        "newMessages": info.new_messages.iter().map(legacy_new_message_json).collect::<Vec<_>>(),
    });
    if let Some(total_emails) = info.total_emails {
        value["totalEmails"] = json!(total_emails);
        value["unreadEmails"] = json!(info.unread_emails);
    }
    if let Some(highest_modseq) = info.highest_modseq {
        value["highestModSeq"] = json!(highest_modseq);
    }
    if let Some(append_limit) = info.append_limit {
        value["appendLimit"] = json!(append_limit);
    }
    if let Some(size) = info.size {
        value["size"] = json!(size);
    }
    if !info.etag.is_empty() {
        value["etag"] = json!(info.etag);
    }
    if !info.permanent_flags.is_empty() {
        value["permanentFlags"] = json!(info.permanent_flags);
    }
    if let Some(messages_flags) = &info.messages_flags {
        value["messagesFlags"] = json!(messages_flags
            .iter()
            .map(|message| json!({
                "uid": message.uid,
                "flags": message.flags,
            }))
            .collect::<Vec<_>>());
    }
    value
}

fn legacy_new_message_json(message: &fm_imap::LegacyNewMessage) -> Value {
    json!({
        "folder": message.folder,
        "uid": message.uid,
        "subject": message.subject,
        "from": legacy_email_collection(&message.from),
    })
}

fn legacy_nullable_string(value: Option<&str>) -> Value {
    value
        .filter(|value| !value.is_empty() && *value != "0")
        .map(|value| json!(value))
        .unwrap_or(Value::Null)
}

#[allow(dead_code)]
fn legacy_message_list_json(list: &fm_imap::LegacyMessageList) -> Value {
    let mut folder = legacy_folder_information_json(&list.folder);
    if let Some(folder) = folder.as_object_mut() {
        folder.remove("messagesFlags");
        folder.remove("newMessages");
    }

    json!({
        "@Object": "Collection/MessageCollection",
        "@Collection": list.messages.iter().map(legacy_message_summary_json).collect::<Vec<_>>(),
        "totalEmails": list.total_emails,
        "totalThreads": list.total_threads,
        "threadUid": list.thread_uid,
        "newMessages": list.folder.new_messages.iter().map(legacy_new_message_json).collect::<Vec<_>>(),
        "offset": list.offset,
        "limit": list.limit,
        "search": list.search,
        "sort": list.sort,
        "limited": list.limited,
        "folder": folder,
    })
}

#[allow(dead_code)]
fn legacy_message_summary_json(message: &fm_imap::LegacyMessageSummary) -> Value {
    let mut value = json!({
        "@Object": "Object/Message",
        "folder": message.folder,
        "uid": message.uid,
        "hash": message.hash,
        "subject": message.subject,
        "encrypted": message.encrypted,
        "messageId": message.message_id,
        "spamScore": message.spam_score,
        "spamResult": message.spam_result,
        "isSpam": message.is_spam,
        "dateTimestamp": message.date_timestamp,
        "dateTimestampSource": message.date_timestamp_source,
        "from": legacy_email_collection(&message.from),
        "replyTo": legacy_email_collection(&message.reply_to),
        "to": legacy_email_collection(&message.to),
        "cc": legacy_email_collection(&message.cc),
        "bcc": legacy_email_collection(&message.bcc),
        "sender": legacy_email_collection(&message.sender),
        "deliveredTo": legacy_email_collection(&message.delivered_to),
        "readReceipt": message.read_receipt,
        "attachments": message.attachments,
        "spf": [],
        "dkim": [],
        "dmarc": [],
        "flags": message.flags,
        "inReplyTo": message.in_reply_to,
        "id": Value::Null,
        "size": message.size,
        "preview": legacy_nullable_string(message.preview.as_deref()),
        "headers": [],
    });

    if !message.references.is_empty() {
        value["references"] = json!(message.references);
    }

    value
}

#[allow(clippy::too_many_arguments)]
fn legacy_message_json(
    folder: &str,
    uid: u32,
    hash: &str,
    subject: &str,
    html: &str,
    plain: &str,
    message_id: &str,
    in_reply_to: &str,
    references: &str,
    from: Option<&[String]>,
    reply_to: Option<&[String]>,
    to: Option<&[String]>,
    cc: Option<&[String]>,
    bcc: Option<&[String]>,
    sender: Option<&[String]>,
    delivered_to: Option<&[String]>,
    size: u32,
    flags: &[String],
    preview: Option<&str>,
) -> Value {
    let mut value = json!({
        "@Object": "Object/Message",
        "folder": folder,
        "uid": uid,
        "hash": hash,
        "subject": subject,
        "encrypted": false,
        "messageId": message_id,
        "spamScore": 0,
        "spamResult": "",
        "isSpam": false,
        "dateTimestamp": 0,
        "dateTimestampSource": "internal",
        "from": legacy_optional_email_collection(from),
        "replyTo": legacy_optional_email_collection(reply_to),
        "to": legacy_optional_email_collection(to),
        "cc": legacy_optional_email_collection(cc),
        "bcc": legacy_optional_email_collection(bcc),
        "sender": legacy_optional_email_collection(sender),
        "deliveredTo": legacy_optional_email_collection(delivered_to),
        "readReceipt": "",
        "attachments": Value::Null,
        "spf": [],
        "dkim": [],
        "dmarc": [],
        "flags": flags,
        "inReplyTo": in_reply_to,
        "id": Value::Null,
        "size": size,
        "preview": legacy_nullable_string(preview),
        "headers": Value::Null,
    });

    if !references.is_empty() {
        value["references"] = json!(references);
    }
    if !html.is_empty() || !plain.is_empty() {
        value["html"] = json!(html);
        value["plain"] = json!(plain);
    }

    value
}

fn legacy_message_body_response(
    action: &str,
    folder: &str,
    uid: u32,
    parts: Vec<BodyPreviewPart>,
) -> Response {
    let mut html = String::new();
    let mut plain = String::new();
    let mut subject = String::new();
    let mut message_id = String::new();
    let mut in_reply_to = String::new();
    let mut references = String::new();
    let mut from = None;
    let mut reply_to = None;
    let mut to = None;
    let mut cc = None;
    let mut bcc = None;
    let mut sender = None;
    let mut delivered_to = None;

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
                if message_id.is_empty() {
                    message_id = body.message_id.clone();
                }
                if in_reply_to.is_empty() {
                    in_reply_to = body.in_reply_to.clone();
                }
                if references.is_empty() {
                    references = body.references.clone();
                }
                if from.is_none() {
                    from = Some(body.from.clone());
                }
                if reply_to.is_none() {
                    reply_to = Some(body.reply_to.clone());
                }
                if to.is_none() {
                    to = Some(body.to.clone());
                }
                if cc.is_none() {
                    cc = Some(body.cc.clone());
                }
                if bcc.is_none() {
                    bcc = Some(body.bcc.clone());
                }
                if sender.is_none() {
                    sender = Some(body.sender.clone());
                }
                if delivered_to.is_none() {
                    delivered_to = Some(body.delivered_to.clone());
                }
                if html.is_empty() && !body.html.is_empty() {
                    html = body.html;
                }
                if plain.is_empty() && !body.plain.is_empty() {
                    plain = body.plain;
                }
            }
        }
        if subject.is_empty() {
            subject = body.subject.unwrap_or_default();
        }
    }

    if html.is_empty()
        && plain.is_empty()
        && subject.is_empty()
        && message_id.is_empty()
        && in_reply_to.is_empty()
        && references.is_empty()
        && from.is_none()
        && reply_to.is_none()
        && to.is_none()
        && cc.is_none()
        && bcc.is_none()
        && sender.is_none()
        && delivered_to.is_none()
    {
        return json_result_error(action, "Message body could not be parsed");
    }

    let hash = legacy_message_hash(folder, uid);
    json_value_envelope(
        StatusCode::OK,
        action,
        json!({
            "Result": legacy_message_json(
                folder,
                uid,
                &hash,
                &subject,
                &html,
                &plain,
                &message_id,
                &in_reply_to,
                &references,
                from.as_deref(),
                reply_to.as_deref(),
                to.as_deref(),
                cc.as_deref(),
                bcc.as_deref(),
                sender.as_deref(),
                delivered_to.as_deref(),
                0,
                &[],
                None,
            )
        }),
    )
}

const LEGACY_EMAIL_COLLECTION_JSON_LIMIT: usize = 100;

fn legacy_optional_email_collection(addresses: Option<&[String]>) -> Value {
    addresses
        .map(|addresses| json!(legacy_email_collection_from_strings(addresses)))
        .unwrap_or(Value::Null)
}

fn legacy_email_collection_from_strings(addresses: &[String]) -> Vec<Value> {
    addresses
        .iter()
        .filter_map(|item| legacy_email_json(item.trim()))
        .take(LEGACY_EMAIL_COLLECTION_JSON_LIMIT)
        .collect()
}

fn legacy_email_collection(raw: &str) -> Vec<Value> {
    raw.split(',')
        .filter_map(|item| legacy_email_json(item.trim()))
        .take(LEGACY_EMAIL_COLLECTION_JSON_LIMIT)
        .collect()
}

fn legacy_email_json(raw: &str) -> Option<Value> {
    if raw.is_empty() {
        return None;
    }
    let (name, email) = if let (Some(start), Some(end)) = (raw.find('<'), raw.rfind('>')) {
        let name = raw[..start].trim().trim_matches('"').to_string();
        let email = raw[start + 1..end].trim().to_string();
        (name, email)
    } else if raw.contains('@') {
        (String::new(), raw.trim().trim_matches('"').to_string())
    } else {
        (raw.trim().trim_matches('"').to_string(), String::new())
    };
    if name.is_empty() && email.is_empty() {
        return None;
    }
    Some(json!({
        "@Object": "Object/Email",
        "name": name,
        "email": email,
        "dkimStatus": "none"
    }))
}

async fn imap_action_auth(
    state: &AppState,
    original_action: &str,
    session: &fm_session::Session,
) -> Result<(fm_core::UserSession, Vec<u8>), Response> {
    let Some(user) = (match load_session_user(state, original_action, session).await {
        Ok(user) => user,
        Err(response) => return Err(response),
    }) else {
        return Err(json_result_error(original_action, "Not authenticated"));
    };
    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return Err(response),
    };
    Ok((user, credential_key))
}

async fn imap_action_connection_for_user(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    user_id: i64,
    credential_key: &[u8],
) -> Result<(ImapConnectionConfig, String), Response> {
    let Some(pool) = state.db_pool() else {
        return Err(json_result_error(
            original_action,
            "Frickmail database is not configured",
        ));
    };

    let account_id = payload_i64(payload, "account_id");
    if account_id <= 0 {
        return Err(json_result_error(original_action, "account_id required"));
    }
    let account =
        match SqlxUserRepository::get_mail_account_connection_secret(pool, user_id, account_id)
            .await
        {
            Ok(Some(account)) => account,
            Ok(None) => return Err(json_result_error(original_action, "Account not found")),
            Err(err) => return Err(json_result_error(original_action, &err.public_message())),
        };
    let config = match imap_config_from_account_secret(&account) {
        Ok(config) => config,
        Err(err) => return Err(json_result_error(original_action, &err.public_message())),
    };
    let password = match account_password(&account, credential_key) {
        Ok(password) => password,
        Err(_) => return Err(json_result_error(original_action, "Missing IMAP password")),
    };

    Ok((config, password))
}

async fn imap_action_connection_for_selected_or_payload(
    state: &AppState,
    original_action: &str,
    payload: &Value,
    session: &fm_session::Session,
    user_id: i64,
    credential_key: &[u8],
) -> Result<(ImapConnectionConfig, String), Response> {
    let Some(pool) = state.db_pool() else {
        return Err(json_result_error(
            original_action,
            "Frickmail database is not configured",
        ));
    };

    let account_id = resolve_message_body_account_id(payload, session, original_action).await?;
    let account =
        match SqlxUserRepository::get_mail_account_connection_secret(pool, user_id, account_id)
            .await
        {
            Ok(Some(account)) => account,
            Ok(None) => return Err(json_result_error(original_action, "Account not found")),
            Err(err) => return Err(json_result_error(original_action, &err.public_message())),
        };
    let config = match imap_config_from_account_secret(&account) {
        Ok(config) => config,
        Err(err) => return Err(json_result_error(original_action, &err.public_message())),
    };
    let password = match account_password(&account, credential_key) {
        Ok(password) => password,
        Err(_) => return Err(json_result_error(original_action, "Missing IMAP password")),
    };

    Ok((config, password))
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

async fn native_frickmail_smime_import_p12(
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
    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let account_id = payload_i64(payload, "account_id");
    if account_id <= 0 {
        return json_result_error(original_action, "account_id required");
    }
    let p12_b64 = payload_string(payload, "p12_b64").unwrap_or_default();
    let p12_b64 = p12_b64.trim();
    if p12_b64.is_empty() {
        return json_result_error(original_action, "p12_b64 required");
    }
    let p12_der = match STANDARD.decode(p12_b64) {
        Ok(bytes) => bytes,
        Err(_) => return json_result_error(original_action, "Invalid base64 in p12_b64"),
    };
    let password = payload_string(payload, "password").unwrap_or_default();

    match SqlxUserRepository::import_smime_p12(
        pool,
        user.user_id,
        NewSmimeP12 {
            account_id,
            p12_der,
            password,
        },
        &credential_key,
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

async fn native_frickmail_smime_sign(
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
    let credential_key = match load_session_credential_key(original_action, session).await {
        Ok(credential_key) => credential_key,
        Err(response) => return response,
    };

    let Some(pool) = state.db_pool() else {
        return json_result_error(original_action, "Frickmail database is not configured");
    };

    let email = payload_string(payload, "email").unwrap_or_default();
    let email = email.trim().to_string();
    if email.is_empty() {
        return json_result_error(original_action, "email required");
    }
    let body = payload_string(payload, "body").unwrap_or_default();

    match SqlxUserRepository::sign_smime_message(pool, user.user_id, &email, &body, &credential_key)
        .await
    {
        Ok(signed) => json_value_envelope(
            StatusCode::OK,
            original_action,
            json!({
                "Result": {
                    "ok": true,
                    "signed_b64": STANDARD.encode(signed)
                }
            }),
        ),
        Err(err) => json_result_error(original_action, &err.public_message()),
    }
}

async fn native_frickmail_smime_verify(original_action: &str, payload: &Value) -> Response {
    let message_b64 = payload_string(payload, "message_b64").unwrap_or_default();
    let message_b64 = message_b64.trim();
    if message_b64.is_empty() {
        return json_result_error(original_action, "message_b64 required");
    }
    if message_b64.len() > SMIME_VERIFY_MAX_BASE64_CHARS {
        return json_result_error(original_action, "message_b64 too large");
    }
    let message = match STANDARD.decode(message_b64) {
        Ok(bytes) => bytes,
        Err(_) => return json_result_error(original_action, "Invalid base64 in message_b64"),
    };
    if message.len() > SMIME_VERIFY_MAX_BYTES {
        return json_result_error(original_action, "message_b64 too large");
    }
    let verify =
        tokio::task::spawn_blocking(move || SqlxUserRepository::verify_smime_message(&message));
    let result = match tokio::time::timeout(SMIME_VERIFY_DEADLINE, verify).await {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => {
            return json_result_error(
                original_action,
                &format!("S/MIME verification task failed: {err}"),
            );
        }
        Err(_) => return json_result_error(original_action, "S/MIME verification timed out"),
    };
    json_value_envelope(
        StatusCode::OK,
        original_action,
        json!({
            "Result": result
        }),
    )
}

async fn native_smime_action<F, Fut>(state: &AppState, f: F) -> Option<Response>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    if state.config().frickmail_user.smime_enabled {
        Some(f().await)
    } else {
        None
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

fn attach_legacy_json_raw_key(mut request: PluginRequest, uri: &Uri) -> PluginRequest {
    let raw_key = match request.action.as_str() {
        "MessageList" => legacy_action_raw_key_from_uri(uri, "MessageList"),
        "Message" => legacy_action_raw_key_from_uri(uri, "Message"),
        _ => None,
    };
    if let Some(raw_key) = raw_key {
        request.payload = merge_payload(request.payload, json!({ "RawKey": raw_key }));
    }
    request
}

fn content_type_contains(content_type: &str, needle: &str) -> bool {
    content_type
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

struct MultipartPart {
    headers: String,
    value: Vec<u8>,
}

struct FolderAppendUpload {
    folder: String,
    raw: Vec<u8>,
}

enum FolderAppendUploadResult {
    Upload(FolderAppendUpload),
    MissingFile,
    MissingFolder,
}

fn folder_append_upload(content_type: &str, body: &[u8]) -> FolderAppendUploadResult {
    let Some(parts) = multipart_parts(content_type, body) else {
        return FolderAppendUploadResult::MissingFile;
    };
    let mut folder = None;
    let mut raw = None;

    for part in parts {
        match multipart_field_name(&part.headers) {
            Some("folder") => {
                folder = Some(String::from_utf8_lossy(&part.value).trim().to_string());
            }
            Some("appendFile") if !part.value.is_empty() => {
                raw = Some(part.value);
            }
            _ => {}
        }
    }

    let Some(raw) = raw else {
        return FolderAppendUploadResult::MissingFile;
    };
    let Some(folder) = folder.filter(|folder| !folder.is_empty()) else {
        return FolderAppendUploadResult::MissingFolder;
    };
    FolderAppendUploadResult::Upload(FolderAppendUpload { folder, raw })
}

fn multipart_parts(content_type: &str, body: &[u8]) -> Option<Vec<MultipartPart>> {
    let boundary = multipart_boundary(content_type)?;
    let delimiter = format!("--{boundary}").into_bytes();
    let first = find_multipart_delimiter(body, &delimiter, 0)?;
    let mut cursor = multipart_delimiter_after(body, first, &delimiter)?;
    let mut parts = Vec::new();

    while let MultipartCursor::PartStart(start) = cursor {
        let next = find_multipart_delimiter(body, &delimiter, start)?;
        let part = trim_multipart_part_end(&body[start..next]);
        if let Some((headers, value)) = split_multipart_part_bytes(part) {
            parts.push(MultipartPart { headers, value });
        }
        cursor = multipart_delimiter_after(body, next, &delimiter)?;
    }

    Some(parts)
}

enum MultipartCursor {
    PartStart(usize),
    End,
}

fn find_multipart_delimiter(body: &[u8], delimiter: &[u8], start: usize) -> Option<usize> {
    let mut search_start = start;
    while search_start <= body.len() {
        let offset = find_bytes(&body[search_start..], delimiter)?;
        let index = search_start + offset;
        if multipart_delimiter_after(body, index, delimiter).is_some() {
            return Some(index);
        }
        search_start = index + 1;
    }
    None
}

fn multipart_delimiter_after(
    body: &[u8],
    index: usize,
    delimiter: &[u8],
) -> Option<MultipartCursor> {
    if index > 0 && body.get(index - 1) != Some(&b'\n') {
        return None;
    }
    if !body.get(index..)?.starts_with(delimiter) {
        return None;
    }

    let after = index + delimiter.len();
    let remaining = &body[after..];
    if let Some(tail) = remaining.strip_prefix(b"--") {
        if tail.is_empty() || tail.starts_with(b"\r\n") || tail.starts_with(b"\n") {
            return Some(MultipartCursor::End);
        }
        return None;
    }
    if remaining.starts_with(b"\r\n") {
        return Some(MultipartCursor::PartStart(after + 2));
    }
    if remaining.starts_with(b"\n") {
        return Some(MultipartCursor::PartStart(after + 1));
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|value| value == needle)
}

fn trim_multipart_part_end(mut value: &[u8]) -> &[u8] {
    if value.ends_with(b"\r\n") {
        value = &value[..value.len() - 2];
    } else if value.ends_with(b"\n") {
        value = &value[..value.len() - 1];
    }
    value
}

fn split_multipart_part_bytes(part: &[u8]) -> Option<(String, Vec<u8>)> {
    if let Some(index) = find_bytes(part, b"\r\n\r\n") {
        return Some((
            String::from_utf8_lossy(&part[..index]).to_string(),
            part[index + 4..].to_vec(),
        ));
    }
    let index = find_bytes(part, b"\n\n")?;
    Some((
        String::from_utf8_lossy(&part[..index]).to_string(),
        part[index + 2..].to_vec(),
    ))
}

fn multipart_action(content_type: &str, body: &[u8]) -> Option<String> {
    for part in multipart_parts(content_type, body)? {
        if multipart_field_name(&part.headers)
            .is_some_and(|name| name.eq_ignore_ascii_case("Action") || name == "_action")
        {
            let action = String::from_utf8_lossy(&part.value).trim().to_string();
            if !action.is_empty() {
                return Some(action);
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

fn graph_oauth_config_from_env() -> fm_core::Result<GraphOAuthConfig> {
    let client_id = env::var("FRICKMAIL_O365_CLIENT_ID").unwrap_or_default();
    if client_id.trim().is_empty() {
        return Err(FrickmailError::BadRequest(
            "Microsoft Graph OAuth client is not configured".to_string(),
        ));
    }

    Ok(GraphOAuthConfig {
        client_id: client_id.trim().to_string(),
        client_secret: env::var("FRICKMAIL_O365_CLIENT_SECRET")
            .ok()
            .and_then(|secret| {
                let secret = secret.trim().to_string();
                if secret.is_empty() {
                    None
                } else {
                    Some(secret)
                }
            }),
    })
}

fn graph_account_oauth(
    account: &MailAccountConnectionSecret,
    credential_key: &[u8],
) -> fm_core::Result<(String, String)> {
    if account.account_type != "o365" {
        return Err(FrickmailError::BadRequest(
            "Account is not an Office 365 account (type must be o365)".to_string(),
        ));
    }

    let Some(blob) = account.encrypted_oauth_refresh_token.as_deref() else {
        return Err(FrickmailError::BadRequest(
            "Missing OAuth refresh token — re-authorize this account.".to_string(),
        ));
    };
    let refresh_token = decrypt_account_secret(blob, credential_key)?
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            FrickmailError::BadRequest(
                "Missing OAuth refresh token — re-authorize this account.".to_string(),
            )
        })?;
    let tenant = graph_tenant(
        account
            .oauth_tenant
            .as_deref()
            .filter(|tenant| !tenant.trim().is_empty())
            .unwrap_or("common"),
    )?;

    Ok((refresh_token, tenant))
}

fn graph_tenant(tenant: &str) -> fm_core::Result<String> {
    let tenant = tenant.trim();
    if tenant.is_empty()
        || tenant.contains('/')
        || tenant.contains('\\')
        || tenant.contains('?')
        || tenant.contains('#')
    {
        return Err(FrickmailError::BadRequest(
            "Invalid Microsoft OAuth tenant".to_string(),
        ));
    }
    Ok(tenant.to_string())
}

async fn graph_list_messages_via_reqwest(
    request: GraphListMessagesRequest,
) -> fm_core::Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(GRAPH_FETCH_DEADLINE)
        .build()
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft Graph client setup failed: {err}"))
        })?;
    let access_token = graph_access_token_for(
        &client,
        &request.tenant,
        &request.client_id,
        request.client_secret.as_deref(),
        &request.refresh_token,
    )
    .await?;
    let url = graph_list_messages_url(&request.folder, request.top)?;
    let response = client
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft Graph request failed: {err}"))
        })?;

    graph_json_response(response, "Microsoft Graph request").await
}

async fn graph_search_messages_via_reqwest(
    request: GraphSearchMessagesRequest,
) -> fm_core::Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(GRAPH_FETCH_DEADLINE)
        .build()
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft Graph client setup failed: {err}"))
        })?;
    let access_token = graph_access_token_for(
        &client,
        &request.tenant,
        &request.client_id,
        request.client_secret.as_deref(),
        &request.refresh_token,
    )
    .await?;
    let url = graph_search_messages_url(&request.query, request.top)?;
    let response = client
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft Graph request failed: {err}"))
        })?;

    graph_json_response(response, "Microsoft Graph request").await
}

async fn graph_delta_messages_via_reqwest(
    request: GraphDeltaMessagesRequest,
) -> fm_core::Result<Value> {
    let url = graph_delta_messages_url(&request.folder_id, request.delta_token.as_deref())?;
    let (client, access_token) = graph_client_with_access_token(&request.auth).await?;
    let response = client
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft Graph request failed: {err}"))
        })?;

    graph_json_response(response, "Microsoft Graph request").await
}

async fn graph_get_message_via_reqwest(request: GraphGetMessageRequest) -> fm_core::Result<Value> {
    let (client, access_token) = graph_client_with_access_token(&request.auth).await?;
    let url = graph_message_url(&request.message_id, true)?;
    let response = client
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft Graph request failed: {err}"))
        })?;

    graph_json_response(response, "Microsoft Graph request").await
}

async fn graph_mark_read_via_reqwest(request: GraphMarkReadRequest) -> fm_core::Result<Value> {
    let (client, access_token) = graph_client_with_access_token(&request.auth).await?;
    let url = graph_message_url(&request.message_id, false)?;
    let response = client
        .patch(url)
        .bearer_auth(access_token)
        .json(&json!({ "isRead": request.is_read }))
        .send()
        .await
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft Graph request failed: {err}"))
        })?;

    graph_json_response(response, "Microsoft Graph request").await
}

async fn graph_move_message_via_reqwest(
    request: GraphMoveMessageRequest,
) -> fm_core::Result<Value> {
    let (client, access_token) = graph_client_with_access_token(&request.auth).await?;
    let url = graph_move_message_url(&request.message_id)?;
    let response = client
        .post(url)
        .bearer_auth(access_token)
        .json(&json!({ "destinationId": request.target_folder_id }))
        .send()
        .await
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft Graph request failed: {err}"))
        })?;

    graph_json_response(response, "Microsoft Graph request").await
}

async fn graph_delete_message_via_reqwest(
    request: GraphDeleteMessageRequest,
) -> fm_core::Result<Value> {
    let (client, access_token) = graph_client_with_access_token(&request.auth).await?;
    let url = graph_message_url(&request.message_id, false)?;
    let response = client
        .delete(url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft Graph request failed: {err}"))
        })?;

    graph_json_response(response, "Microsoft Graph request").await
}

async fn graph_client_with_access_token(
    auth: &GraphAccountRequest,
) -> fm_core::Result<(reqwest::Client, String)> {
    let client = reqwest::Client::builder()
        .timeout(GRAPH_FETCH_DEADLINE)
        .build()
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft Graph client setup failed: {err}"))
        })?;
    let access_token = graph_access_token_for(
        &client,
        &auth.tenant,
        &auth.client_id,
        auth.client_secret.as_deref(),
        &auth.refresh_token,
    )
    .await?;

    Ok((client, access_token))
}

async fn graph_access_token_for(
    client: &reqwest::Client,
    tenant: &str,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> fm_core::Result<String> {
    let token_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let response = client
        .post(token_url)
        .form(&graph_token_form_fields(
            client_id,
            client_secret,
            refresh_token,
        ))
        .send()
        .await
        .map_err(|err| {
            FrickmailError::Upstream(format!("Microsoft token request failed: {err}"))
        })?;
    let body = graph_json_response(response, "Microsoft token request").await?;

    body.get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            FrickmailError::Upstream(
                "Microsoft token response did not include access_token".to_string(),
            )
        })
}

async fn oauth_access_token_for(
    client: &reqwest::Client,
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
    scope: &str,
) -> fm_core::Result<String> {
    let response = client
        .post(token_url)
        .form(&oauth_token_form_fields(
            client_id,
            client_secret,
            refresh_token,
            scope,
        ))
        .send()
        .await
        .map_err(|err| FrickmailError::Upstream(format!("OAuth token request failed: {err}")))?;
    let body = graph_json_response(response, "OAuth token request").await?;

    body.get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            FrickmailError::Upstream(
                "OAuth token response did not include access_token".to_string(),
            )
        })
}

fn oauth_token_form_fields(
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
    scope: &str,
) -> Vec<(&'static str, String)> {
    let mut form = vec![
        ("client_id", client_id.to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("grant_type", "refresh_token".to_string()),
        ("scope", scope.to_string()),
    ];
    if let Some(client_secret) = client_secret {
        form.push(("client_secret", client_secret.to_string()));
    }
    form
}

fn graph_token_form_fields(
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> Vec<(&'static str, String)> {
    let mut form = vec![
        ("client_id", client_id.to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("grant_type", "refresh_token".to_string()),
        ("scope", MICROSOFT_GRAPH_SCOPES.to_string()),
    ];
    if let Some(client_secret) = client_secret {
        form.push(("client_secret", client_secret.to_string()));
    }
    form
}

fn graph_list_messages_url(folder: &str, top: i64) -> fm_core::Result<url::Url> {
    let mut url = url::Url::parse(MICROSOFT_GRAPH_ROOT)
        .map_err(|err| FrickmailError::Upstream(format!("Invalid Microsoft Graph URL: {err}")))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| FrickmailError::Upstream("Invalid Microsoft Graph URL".to_string()))?;
        segments
            .push("v1.0")
            .push("me")
            .push("mailFolders")
            .push(folder)
            .push("messages");
    }
    url.query_pairs_mut()
        .append_pair("$top", &top.to_string())
        .append_pair(
            "$select",
            "id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments",
        )
        .append_pair("$orderby", "receivedDateTime desc");
    Ok(url)
}

fn graph_search_messages_url(query: &str, top: i64) -> fm_core::Result<url::Url> {
    let mut url = url::Url::parse(MICROSOFT_GRAPH_ROOT)
        .map_err(|err| FrickmailError::Upstream(format!("Invalid Microsoft Graph URL: {err}")))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| FrickmailError::Upstream("Invalid Microsoft Graph URL".to_string()))?;
        segments.push("v1.0").push("me").push("messages");
    }
    let escaped_query = format!("\"{}\"", query.replace('"', "\\\""));
    url.query_pairs_mut()
        .append_pair("$search", &escaped_query)
        .append_pair("$top", &top.to_string())
        .append_pair(
            "$select",
            "id,subject,from,receivedDateTime,isRead,bodyPreview,parentFolderId",
        );
    Ok(url)
}

fn graph_delta_messages_url(
    folder_id: &str,
    delta_token: Option<&str>,
) -> fm_core::Result<url::Url> {
    validate_graph_delta_token(delta_token)?;
    if let Some(delta_token) = delta_token.filter(|token| token.contains("://")) {
        return assert_graph_followup_url(delta_token, "Invalid Graph delta URL");
    }

    let mut url = url::Url::parse(MICROSOFT_GRAPH_ROOT)
        .map_err(|err| FrickmailError::Upstream(format!("Invalid Microsoft Graph URL: {err}")))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| FrickmailError::Upstream("Invalid Microsoft Graph URL".to_string()))?;
        segments
            .push("v1.0")
            .push("me")
            .push("mailFolders")
            .push(folder_id)
            .push("messages")
            .push("delta");
    }
    match delta_token {
        Some(delta_token) => {
            url.query_pairs_mut()
                .append_pair("$deltatoken", delta_token);
        }
        None => {
            url.query_pairs_mut().append_pair(
                "$select",
                "id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments",
            );
        }
    }
    Ok(url)
}

fn validate_graph_delta_token(delta_token: Option<&str>) -> fm_core::Result<()> {
    if let Some(delta_token) = delta_token {
        if delta_token.contains("://") {
            assert_graph_followup_url(delta_token, "Invalid Graph delta URL")?;
        }
    }
    Ok(())
}

fn graph_message_url(message_id: &str, include_select: bool) -> fm_core::Result<url::Url> {
    let mut url = url::Url::parse(MICROSOFT_GRAPH_ROOT)
        .map_err(|err| FrickmailError::Upstream(format!("Invalid Microsoft Graph URL: {err}")))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| FrickmailError::Upstream("Invalid Microsoft Graph URL".to_string()))?;
        segments
            .push("v1.0")
            .push("me")
            .push("messages")
            .push(message_id);
    }
    if include_select {
        url.query_pairs_mut().append_pair(
            "$select",
            "id,subject,from,toRecipients,ccRecipients,receivedDateTime,body,isRead,hasAttachments",
        );
    }
    Ok(url)
}

fn graph_move_message_url(message_id: &str) -> fm_core::Result<url::Url> {
    let mut url = graph_message_url(message_id, false)?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| FrickmailError::Upstream("Invalid Microsoft Graph URL".to_string()))?;
        segments.push("move");
    }
    Ok(url)
}

fn assert_graph_followup_url(raw_url: &str, error: &str) -> fm_core::Result<url::Url> {
    let url =
        url::Url::parse(raw_url).map_err(|_| FrickmailError::BadRequest(error.to_string()))?;
    let port = url.port_or_known_default();
    if url.scheme() != "https"
        || url.host_str() != Some("graph.microsoft.com")
        || (port != Some(443))
        || !url.path().starts_with("/v1.0/")
        || !url.path().ends_with("/messages/delta")
        || !graph_followup_query_is_delta_token(&url)
    {
        return Err(FrickmailError::BadRequest(error.to_string()));
    }
    Ok(url)
}

fn graph_followup_query_is_delta_token(url: &url::Url) -> bool {
    let mut has_delta_cursor = false;
    for (key, _) in url.query_pairs() {
        match key.as_ref() {
            "$deltatoken" | "$skiptoken" => has_delta_cursor = true,
            _ => return false,
        }
    }
    has_delta_cursor
}

async fn graph_json_response(response: reqwest::Response, context: &str) -> fm_core::Result<Value> {
    let status = response.status();
    let text = response.text().await.map_err(|err| {
        FrickmailError::Upstream(format!("{context} response read failed: {err}"))
    })?;
    if !status.is_success() {
        return Err(FrickmailError::Upstream(format!(
            "{context} failed ({}): {}",
            status.as_u16(),
            graph_error_summary(&text)
        )));
    }
    if text.trim().is_empty() {
        return Ok(json!({}));
    }

    serde_json::from_str(&text)
        .map_err(|err| FrickmailError::Upstream(format!("{context} returned invalid JSON: {err}")))
}

fn graph_error_summary(text: &str) -> String {
    let Ok(body) = serde_json::from_str::<Value>(text) else {
        return "upstream returned a non-JSON error".to_string();
    };
    let error = body
        .get("error")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("upstream_error");
    let description = body
        .get("error_description")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("error")
                .and_then(|value| value.get("message"))
                .and_then(Value::as_str)
        })
        .map(|value| redact_graph_error_secrets(&value.replace(['\r', '\n'], " ")))
        .unwrap_or_else(|| "request rejected".to_string());
    format!(
        "{error}: {}",
        truncate_graph_error_description(&description)
    )
}

fn redact_graph_error_secrets(text: &str) -> String {
    text.split_whitespace()
        .map(|part| {
            let key = part
                .split_once('=')
                .or_else(|| part.split_once(':'))
                .map(|(key, _)| key.trim_matches(['"', '\'', ',', ';']).to_ascii_lowercase());
            match key.as_deref() {
                Some("client_secret" | "refresh_token" | "access_token" | "id_token") => part
                    .replace(
                        part.split_once(['=', ':'])
                            .map(|(_, value)| value)
                            .unwrap_or_default(),
                        "[redacted]",
                    ),
                _ => part.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate_graph_error_description(text: &str) -> String {
    const LIMIT: usize = 240;
    if text.len() <= LIMIT {
        return text.to_string();
    }

    let mut end = LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
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

fn payload_clamped_u32(payload: &Value, key: &str) -> u32 {
    let value = payload_i64(payload, key);
    if value <= 0 {
        return 0;
    }
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn payload_optional_u32(payload: &Value, key: &str) -> Option<u32> {
    payload_optional_i64(payload, key).and_then(|value| u32::try_from(value).ok())
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

fn payload_graph_top(payload: &Value) -> i64 {
    let Some(value) = payload.get("top") else {
        return 50;
    };
    let raw = match value {
        Value::Null => 50,
        Value::Bool(false) => 50,
        Value::Number(number) if number.as_f64() == Some(0.0) => 50,
        Value::String(text) if text.is_empty() || text == "0" => 50,
        _ => payload_i64(payload, "top"),
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
    let password = decrypt_account_secret(blob, credential_key)?
        .ok_or_else(|| FrickmailError::BadRequest("No credentials stored".to_string()))?;
    if password.trim().is_empty() {
        return Err(FrickmailError::BadRequest(
            "No credentials stored".to_string(),
        ));
    }
    Ok(password)
}

fn payload_string(payload: &Value, key: &str) -> Option<String> {
    match payload.get(key) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        Some(Value::Bool(value)) => Some(if *value { "1" } else { "" }.to_string()),
        _ => None,
    }
}

fn required_payload_string(
    payload: &Value,
    key: &str,
    message: &'static str,
) -> Result<String, &'static str> {
    payload_optional_string(payload, key).ok_or(message)
}

fn value_to_php_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(true) => "1".to_string(),
        Value::Bool(false) => String::new(),
        Value::Number(number) => number.to_string(),
        Value::String(value) => value.clone(),
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn value_to_php_i64(value: &Value) -> i64 {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| {
                number
                    .as_u64()
                    .map(|value| value.min(i64::MAX as u64) as i64)
            })
            .or_else(|| number.as_f64().map(|value| value as i64))
            .unwrap_or_default(),
        Value::Bool(value) => i64::from(*value),
        Value::String(value) => value.trim().parse::<i64>().unwrap_or_default(),
        _ => 0,
    }
}

fn plugin_safe_filename(value: &str, fallback: &str, trim_edges: bool) -> String {
    let mut filename = String::new();
    let mut in_invalid_run = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ' ') {
            filename.push(ch);
            in_invalid_run = false;
        } else if !in_invalid_run {
            filename.push('_');
            in_invalid_run = true;
        } else {
            in_invalid_run = true;
        }
    }
    if trim_edges {
        filename = filename.trim_matches([' ', '_']).to_string();
    }
    if filename.is_empty() {
        filename = fallback.to_string();
    }
    filename.chars().take(80).collect()
}

fn export_folder_limits(config: &fm_core::FrickmailConfig) -> RawFolderFetchLimits {
    RawFolderFetchLimits {
        max_messages: config.frickmail_user.export_folder_max_messages,
        max_bytes: config.frickmail_user.export_folder_max_bytes,
    }
}

fn plugin_mbox(messages: Vec<Vec<u8>>, limits: RawFolderFetchLimits) -> fm_core::Result<Vec<u8>> {
    let separator_date = Local::now().format("%a %b %d %H:%M:%S %Y").to_string();
    plugin_mbox_with_date(messages, limits, &separator_date)
}

fn plugin_mbox_with_date(
    messages: Vec<Vec<u8>>,
    limits: RawFolderFetchLimits,
    separator_date: &str,
) -> fm_core::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut total_raw_bytes = 0_usize;
    for (index, raw) in messages.into_iter().enumerate() {
        if index >= limits.max_messages {
            return Err(FrickmailError::BadRequest(
                "Folder export exceeds configured message limit".to_string(),
            ));
        }
        total_raw_bytes = total_raw_bytes
            .checked_add(raw.len())
            .filter(|bytes| *bytes <= limits.max_bytes)
            .ok_or_else(|| {
                FrickmailError::BadRequest(
                    "Folder export exceeds configured size limit".to_string(),
                )
            })?;
        out.extend_from_slice(format!("From nobody {separator_date}\r\n").as_bytes());
        out.extend_from_slice(&mbox_escape_from_lines(&raw));
        out.extend_from_slice(b"\r\n");
    }
    Ok(out)
}

fn mbox_escape_from_lines(raw: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(raw.len());
    if raw.starts_with(b"From ") {
        escaped.push(b'>');
    }
    for index in 0..raw.len() {
        escaped.push(raw[index]);
        if raw[index] == b'\n' && raw[index + 1..].starts_with(b"From ") {
            escaped.push(b'>');
        }
    }
    escaped
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

fn payload_uid_list_optional(payload: &Value, key: &str) -> Option<Vec<u32>> {
    payload.get(key).map(|_| {
        payload_array(payload, key)
            .into_iter()
            .filter_map(|value| match value {
                Value::Number(number) => number
                    .as_u64()
                    .or_else(|| number.as_i64().and_then(|value| u64::try_from(value).ok()))
                    .and_then(|value| u32::try_from(value).ok()),
                Value::String(value) => value.trim().parse::<u32>().ok(),
                _ => None,
            })
            .filter(|uid| *uid > 0)
            .collect()
    })
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

fn payload_json_bool(payload: &Value, key: &str) -> Result<bool, String> {
    match payload.get(key) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(Value::Number(number)) => {
            if let Some(value) = number.as_i64() {
                Ok(value != 0)
            } else if let Some(value) = number.as_u64() {
                Ok(value != 0)
            } else {
                Ok(number.as_f64().unwrap_or_default() != 0.0)
            }
        }
        Some(Value::String(value)) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "on" | "yes" => Ok(true),
            "" | "0" | "false" | "off" | "no" => Ok(false),
            _ => Err(format!("{key} must be boolean")),
        },
        _ => Err(format!("{key} must be boolean")),
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
        http::{HeaderMap, Method, Request, StatusCode, Uri},
        response::IntoResponse,
        routing::any,
        Json, Router,
    };
    use base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine as _,
    };
    use data_encoding::BASE32_NOPAD;
    use fm_core::{FrickmailConfig, FrickmailError, SelectedMailAccountSession, UserSession};
    use fm_imap::{
        BodyPartKind, BodyPreviewPart, ImapConnectionConfig, ImapMessageFlag, ImapMoveLearning,
        ImapMoveOptions, LegacyAttachmentSummary, LegacyFolderInformation, LegacyMessageFlags,
        LegacyMessageList, LegacyMessageListRequest, LegacyMessageSummary, LegacyNewMessage,
        MailboxStatus, RawFolderFetchLimits, RuleAction, RuleConditionField, RuleConditionOp,
        RuleConditionsLogic, RuleExecutionPlan, RuleExecutionReport, RuleExecutionResult,
    };
    use fm_session::{
        MemoryStore, Session, CREDENTIAL_KEY_SESSION_KEY, SELECTED_ACCOUNT_SESSION_KEY,
        USER_SESSION_KEY,
    };
    use fm_user::PushSubscription;
    use hmac::{Hmac, Mac};
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        nid::Nid,
        pkcs12::Pkcs12,
        pkey::{PKey, Private},
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
        authorization: Option<String>,
        ttl: Option<String>,
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
    async fn json_api_dispatches_native_graph_list_messages_action() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=PluginFrickmailGraphListMessages&account_id=7",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginFrickmailGraphListMessages");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
    }

    #[tokio::test]
    async fn json_api_dispatches_native_graph_search_action() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=PluginFrickmailGraphSearch&account_id=7&q=report",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginFrickmailGraphSearch");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
    }

    #[tokio::test]
    async fn json_api_dispatches_remaining_native_graph_actions() {
        for action in [
            "PluginFrickmailGraphDelta",
            "PluginFrickmailGraphGetMessage",
            "PluginFrickmailGraphMarkRead",
            "PluginFrickmailGraphMove",
            "PluginFrickmailGraphDelete",
        ] {
            let response = app()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(format!(
                            "Action={action}&account_id=7&message_id=msg-1&is_read=false&target_folder_id=deleteditems"
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            let body = read_json(response).await;
            assert_eq!(body["Action"], action);
            assert_eq!(body["Result"]["ok"], false);
            assert_eq!(body["Result"]["error"], "Not authenticated");
        }
    }

    #[tokio::test]
    async fn json_api_dispatches_native_apply_rules_action() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("Action=PluginFrickmailApplyRules&account_id=7"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginFrickmailApplyRules");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
    }

    #[tokio::test]
    async fn json_api_dispatches_native_import_export_actions() {
        let eml_b64 = STANDARD.encode(b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nbody");
        for body in [
            "Action=PluginFrickmailExportMessage&account_id=7&folder=INBOX&uid=1".to_string(),
            "Action=PluginFrickmailExportFolder&account_id=7&folder=INBOX".to_string(),
            format!("Action=PluginFrickmailImportEml&account_id=7&eml_b64={eml_b64}"),
        ] {
            let response = app()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            let body = read_json(response).await;
            assert_eq!(body["Result"]["ok"], false);
            assert_eq!(body["Result"]["error"], "Not authenticated");
        }
    }

    #[tokio::test]
    async fn json_api_respects_disabled_import_export_feature_gate() {
        let mut config = test_config(None);
        config.frickmail_user.allow_export = false;
        let app = super::build_router(AppState::new(config));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=PluginFrickmailExportMessage&account_id=7&folder=INBOX&uid=1",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginFrickmailExportMessage");
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 501);
        assert_eq!(
            body["message"],
            "Frickmail compatibility hook 'FrickmailExportMessage' is not migrated yet"
        );
    }

    #[tokio::test]
    async fn json_api_keeps_unmigrated_actions_as_compatibility_fallback() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("Action=PluginJsonAdminRestoreData"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginJsonAdminRestoreData");
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 501);
        assert_eq!(
            body["message"],
            "Frickmail compatibility hook 'JsonAdminRestoreData' is not migrated yet"
        );
    }

    #[tokio::test]
    async fn native_frickmail_graph_list_messages_fetches_o365_messages() {
        let key = [31_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1700, "graph-user", Some("graph@example.com")).await;
        seed_mail_account(&pool, 1701, 1700, "Graph", true).await;
        set_mail_account_oauth_token(
            &pool,
            1701,
            "graph@example.com",
            "refresh-token",
            Some("organizations"),
            &key,
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = credential_session(1700, "graph-user", Some("graph@example.com"), &key).await;
        let captured: Arc<Mutex<Option<super::GraphListMessagesRequest>>> =
            Arc::new(Mutex::new(None));

        let response = super::native_frickmail_graph_list_messages_with_fetcher(
            &state,
            "FrickmailGraphListMessages",
            &json!({
                "account_id": 1701,
                "folder": "Inbox/Sub Folder",
                "top": "0"
            }),
            &session,
            || {
                Ok(super::GraphOAuthConfig {
                    client_id: "client-id".to_string(),
                    client_secret: Some("client-secret".to_string()),
                })
            },
            Duration::from_secs(1),
            {
                let captured = captured.clone();
                move |request| async move {
                    *captured.lock().unwrap() = Some(request);
                    Ok(json!({
                        "value": [
                            {
                                "id": "message-1",
                                "subject": "Native Graph",
                                "isRead": false
                            }
                        ],
                        "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"
                    }))
                }
            },
        )
        .await;
        let body = read_json(response).await;
        let request = captured.lock().unwrap().clone().unwrap();

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(
            body["Result"]["data"]["value"][0]["subject"],
            "Native Graph"
        );
        assert_eq!(request.tenant, "organizations");
        assert_eq!(request.client_id, "client-id");
        assert_eq!(request.client_secret.as_deref(), Some("client-secret"));
        assert_eq!(request.refresh_token, "refresh-token");
        assert_eq!(request.folder, "Inbox/Sub Folder");
        assert_eq!(request.top, 50);
    }

    #[tokio::test]
    async fn native_frickmail_graph_list_messages_scopes_account_and_requires_o365_token() {
        let key = [32_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1702, "graph-owner", Some("owner@example.com")).await;
        seed_user(&pool, 1703, "graph-other", Some("other@example.com")).await;
        seed_mail_account(&pool, 1704, 1702, "Local", true).await;
        seed_mail_account(&pool, 1705, 1703, "Other", true).await;
        set_mail_account_oauth_token(
            &pool,
            1705,
            "other@example.com",
            "other-refresh-token",
            None,
            &key,
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session =
            credential_session(1702, "graph-owner", Some("owner@example.com"), &key).await;
        let oauth = super::GraphOAuthConfig {
            client_id: "client-id".to_string(),
            client_secret: Some("client-secret".to_string()),
        };

        let response = super::native_frickmail_graph_list_messages_with_fetcher(
            &state,
            "FrickmailGraphListMessages",
            &json!({"account_id": 1705}),
            &session,
            {
                let oauth = oauth.clone();
                move || Ok(oauth)
            },
            Duration::from_secs(1),
            |_| async { Err(FrickmailError::Upstream("should not fetch".to_string())) },
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Account not found");

        let response = super::native_frickmail_graph_list_messages_with_fetcher(
            &state,
            "FrickmailGraphListMessages",
            &json!({"account_id": 1704}),
            &session,
            {
                let oauth = oauth.clone();
                move || Ok(oauth)
            },
            Duration::from_secs(1),
            |_| async { Err(FrickmailError::Upstream("should not fetch".to_string())) },
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(
            body["Result"]["error"],
            "Account is not an Office 365 account (type must be o365)"
        );

        set_mail_account_email_and_type(&pool, 1704, "owner@example.com", "o365").await;
        let response = super::native_frickmail_graph_list_messages_with_fetcher(
            &state,
            "FrickmailGraphListMessages",
            &json!({"account_id": 1704}),
            &session,
            move || Ok(oauth),
            Duration::from_secs(1),
            |_| async { Err(FrickmailError::Upstream("should not fetch".to_string())) },
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(
            body["Result"]["error"],
            "Missing OAuth refresh token — re-authorize this account."
        );
    }

    #[tokio::test]
    async fn native_frickmail_graph_search_fetches_o365_results() {
        let key = [33_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1706, "graph-search", Some("search@example.com")).await;
        seed_mail_account(&pool, 1707, 1706, "Graph Search", true).await;
        set_mail_account_oauth_token(
            &pool,
            1707,
            "search@example.com",
            "refresh-token",
            None,
            &key,
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1706, "graph-search", Some("search@example.com"), &key).await;
        let captured: Arc<Mutex<Option<super::GraphSearchMessagesRequest>>> =
            Arc::new(Mutex::new(None));

        let response = super::native_frickmail_graph_search_with_fetcher(
            &state,
            "FrickmailGraphSearch",
            &json!({
                "account_id": 1707,
                "q": " quarterly report ",
                "top": "2"
            }),
            &session,
            || {
                Ok(super::GraphOAuthConfig {
                    client_id: "client-id".to_string(),
                    client_secret: None,
                })
            },
            Duration::from_secs(1),
            {
                let captured = captured.clone();
                move |request| async move {
                    *captured.lock().unwrap() = Some(request);
                    Ok(json!({
                        "value": [
                            {
                                "id": "message-2",
                                "subject": "Quarterly report",
                                "bodyPreview": "Preview"
                            }
                        ]
                    }))
                }
            },
        )
        .await;
        let body = read_json(response).await;
        let request = captured.lock().unwrap().clone().unwrap();

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["query"], "quarterly report");
        assert_eq!(body["Result"]["data"]["value"][0]["bodyPreview"], "Preview");
        assert_eq!(request.tenant, "common");
        assert_eq!(request.client_id, "client-id");
        assert_eq!(request.client_secret, None);
        assert_eq!(request.refresh_token, "refresh-token");
        assert_eq!(request.query, "quarterly report");
        assert_eq!(request.top, 2);
    }

    #[tokio::test]
    async fn native_frickmail_graph_search_requires_query_before_fetch() {
        let key = [34_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1708, "graph-search-empty", Some("empty@example.com")).await;
        seed_mail_account(&pool, 1709, 1708, "Graph Empty", true).await;
        set_mail_account_oauth_token(
            &pool,
            1709,
            "empty@example.com",
            "refresh-token",
            None,
            &key,
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1708, "graph-search-empty", Some("empty@example.com"), &key).await;

        let response = super::native_frickmail_graph_search_with_fetcher(
            &state,
            "FrickmailGraphSearch",
            &json!({"account_id": 1709, "q": "   "}),
            &session,
            || {
                Ok(super::GraphOAuthConfig {
                    client_id: "client-id".to_string(),
                    client_secret: None,
                })
            },
            Duration::from_secs(1),
            |_| async { Err(FrickmailError::Upstream("should not fetch".to_string())) },
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Search query is required");
    }

    #[tokio::test]
    async fn native_frickmail_remaining_graph_actions_match_plugin_shapes() {
        let key = [35_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1710, "graph-rest", Some("rest@example.com")).await;
        seed_mail_account(&pool, 1711, 1710, "Graph Rest", true).await;
        set_mail_account_oauth_token(
            &pool,
            1711,
            "rest@example.com",
            "refresh-token",
            Some("organizations"),
            &key,
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = credential_session(1710, "graph-rest", Some("rest@example.com"), &key).await;
        let oauth = super::GraphOAuthConfig {
            client_id: "client-id".to_string(),
            client_secret: Some("client-secret".to_string()),
        };

        let captured_delta: Arc<Mutex<Option<super::GraphDeltaMessagesRequest>>> =
            Arc::new(Mutex::new(None));
        let response = super::native_frickmail_graph_delta_with_fetcher(
            &state,
            "FrickmailGraphDelta",
            &json!({
                "account_id": 1711,
                "folder_id": "archive",
                "delta_token": "delta-token"
            }),
            &session,
            {
                let oauth = oauth.clone();
                move || Ok(oauth)
            },
            Duration::from_secs(1),
            {
                let captured_delta = captured_delta.clone();
                move |request| async move {
                    *captured_delta.lock().unwrap() = Some(request);
                    Ok(json!({
                        "value": [{"id": "delta-message"}],
                        "@odata.deltaLink": "https://graph.microsoft.com/v1.0/me/messages/delta?$deltatoken=next"
                    }))
                }
            },
        )
        .await;
        let body = read_json(response).await;
        let request = captured_delta.lock().unwrap().clone().unwrap();
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["data"]["value"][0]["id"], "delta-message");
        assert_eq!(request.auth.tenant, "organizations");
        assert_eq!(request.auth.client_id, "client-id");
        assert_eq!(request.auth.client_secret.as_deref(), Some("client-secret"));
        assert_eq!(request.auth.refresh_token, "refresh-token");
        assert_eq!(request.folder_id, "archive");
        assert_eq!(request.delta_token.as_deref(), Some("delta-token"));

        let captured_get: Arc<Mutex<Option<super::GraphGetMessageRequest>>> =
            Arc::new(Mutex::new(None));
        let response = super::native_frickmail_graph_get_message_with_fetcher(
            &state,
            "FrickmailGraphGetMessage",
            &json!({"account_id": 1711, "message_id": "message-1"}),
            &session,
            {
                let oauth = oauth.clone();
                move || Ok(oauth)
            },
            Duration::from_secs(1),
            {
                let captured_get = captured_get.clone();
                move |request| async move {
                    *captured_get.lock().unwrap() = Some(request);
                    Ok(json!({
                        "id": "message-1",
                        "body": {"content": "<p>Hello</p>"}
                    }))
                }
            },
        )
        .await;
        let body = read_json(response).await;
        let request = captured_get.lock().unwrap().clone().unwrap();
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["message"]["body"]["content"], "<p>Hello</p>");
        assert_eq!(request.message_id, "message-1");

        let captured_mark_read: Arc<Mutex<Option<super::GraphMarkReadRequest>>> =
            Arc::new(Mutex::new(None));
        let response = super::native_frickmail_graph_mark_read_with_fetcher(
            &state,
            "FrickmailGraphMarkRead",
            &json!({"account_id": 1711, "message_id": "message-1", "is_read": "false"}),
            &session,
            {
                let oauth = oauth.clone();
                move || Ok(oauth)
            },
            Duration::from_secs(1),
            {
                let captured_mark_read = captured_mark_read.clone();
                move |request| async move {
                    *captured_mark_read.lock().unwrap() = Some(request);
                    Ok(json!({}))
                }
            },
        )
        .await;
        let body = read_json(response).await;
        let request = captured_mark_read.lock().unwrap().clone().unwrap();
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(request.message_id, "message-1");
        assert!(!request.is_read);

        let captured_move: Arc<Mutex<Option<super::GraphMoveMessageRequest>>> =
            Arc::new(Mutex::new(None));
        let response = super::native_frickmail_graph_move_with_fetcher(
            &state,
            "FrickmailGraphMove",
            &json!({
                "account_id": 1711,
                "message_id": "message-1",
                "target_folder_id": "deleteditems"
            }),
            &session,
            {
                let oauth = oauth.clone();
                move || Ok(oauth)
            },
            Duration::from_secs(1),
            {
                let captured_move = captured_move.clone();
                move |request| async move {
                    *captured_move.lock().unwrap() = Some(request);
                    Ok(json!({"id": "message-1-moved"}))
                }
            },
        )
        .await;
        let body = read_json(response).await;
        let request = captured_move.lock().unwrap().clone().unwrap();
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["message"]["id"], "message-1-moved");
        assert_eq!(request.target_folder_id, "deleteditems");

        let captured_delete: Arc<Mutex<Option<super::GraphDeleteMessageRequest>>> =
            Arc::new(Mutex::new(None));
        let response = super::native_frickmail_graph_delete_with_fetcher(
            &state,
            "FrickmailGraphDelete",
            &json!({"account_id": 1711, "message_id": "message-1"}),
            &session,
            move || Ok(oauth),
            Duration::from_secs(1),
            {
                let captured_delete = captured_delete.clone();
                move |request| async move {
                    *captured_delete.lock().unwrap() = Some(request);
                    Ok(json!({}))
                }
            },
        )
        .await;
        let body = read_json(response).await;
        let request = captured_delete.lock().unwrap().clone().unwrap();
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(request.message_id, "message-1");
    }

    #[tokio::test]
    async fn native_frickmail_graph_delta_rejects_bad_followup_before_secret_lookup() {
        let key = [36_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let state = AppState::with_db_pool(test_config(None), None);
        let session =
            credential_session(1712, "graph-delta-bad", Some("delta@example.com"), &key).await;

        let response = super::native_frickmail_graph_delta_with_fetcher(
            &state,
            "FrickmailGraphDelta",
            &json!({
                "account_id": 1711,
                "delta_token": "https://graph.microsoft.com/v1.0/me/messages"
            }),
            &session,
            || {
                Err(FrickmailError::Upstream(
                    "should not load oauth config".to_string(),
                ))
            },
            Duration::from_secs(1),
            |_| async { Err(FrickmailError::Upstream("should not fetch".to_string())) },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Invalid Graph delta URL");
    }

    #[test]
    fn graph_search_messages_url_matches_legacy_query_shape() {
        let url = super::graph_search_messages_url("report \"q\"", 12).unwrap();
        let pairs = url.query_pairs().collect::<HashMap<_, _>>();

        assert_eq!(url.path(), "/v1.0/me/messages");
        assert_eq!(
            pairs.get("$search").map(|value| value.as_ref()),
            Some("\"report \\\"q\\\"\"")
        );
        assert_eq!(pairs.get("$top").map(|value| value.as_ref()), Some("12"));
        assert_eq!(
            pairs.get("$select").map(|value| value.as_ref()),
            Some("id,subject,from,receivedDateTime,isRead,bodyPreview,parentFolderId")
        );
    }

    #[test]
    fn graph_remaining_urls_match_legacy_shapes_and_reject_bad_delta_links() {
        let initial_delta = super::graph_delta_messages_url("inbox", None).unwrap();
        let initial_pairs = initial_delta.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(
            initial_delta.path(),
            "/v1.0/me/mailFolders/inbox/messages/delta"
        );
        assert_eq!(
            initial_pairs.get("$select").map(|value| value.as_ref()),
            Some("id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments")
        );

        let token_delta = super::graph_delta_messages_url("inbox", Some("opaque-token")).unwrap();
        let token_pairs = token_delta.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(
            token_pairs.get("$deltatoken").map(|value| value.as_ref()),
            Some("opaque-token")
        );

        let followup = "https://graph.microsoft.com/v1.0/me/messages/delta?$deltatoken=next";
        assert_eq!(
            super::graph_delta_messages_url("inbox", Some(followup))
                .unwrap()
                .as_str(),
            followup
        );
        for bad in [
            "http://graph.microsoft.com/v1.0/me/messages/delta",
            "https://evil.example/v1.0/me/messages/delta",
            "https://graph.microsoft.com/v1.0/me/messages",
            "https://graph.microsoft.com/v1.0/me/messages/delta?$select=id",
            "https://graph.microsoft.com/v2.0/me/messages/delta",
            "https://graph.microsoft.com:444/v1.0/me/messages/delta",
        ] {
            assert!(super::graph_delta_messages_url("inbox", Some(bad)).is_err());
        }

        let message = super::graph_message_url("message/id", true).unwrap();
        let message_pairs = message.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(message.path(), "/v1.0/me/messages/message%2Fid");
        assert_eq!(
            message_pairs.get("$select").map(|value| value.as_ref()),
            Some("id,subject,from,toRecipients,ccRecipients,receivedDateTime,body,isRead,hasAttachments")
        );

        let move_url = super::graph_move_message_url("message-1").unwrap();
        assert_eq!(move_url.path(), "/v1.0/me/messages/message-1/move");
    }

    #[test]
    fn graph_bool_json_param_matches_php_boolean_rules() {
        assert_eq!(
            super::payload_json_bool(&json!({"is_read": true}), "is_read"),
            Ok(true)
        );
        assert_eq!(
            super::payload_json_bool(&json!({"is_read": 1}), "is_read"),
            Ok(true)
        );
        assert_eq!(
            super::payload_json_bool(&json!({"is_read": "yes"}), "is_read"),
            Ok(true)
        );
        assert_eq!(
            super::payload_json_bool(&json!({"is_read": false}), "is_read"),
            Ok(false)
        );
        assert_eq!(
            super::payload_json_bool(&json!({"is_read": 0}), "is_read"),
            Ok(false)
        );
        assert_eq!(
            super::payload_json_bool(&json!({"is_read": "false"}), "is_read"),
            Ok(false)
        );
        assert_eq!(
            super::payload_json_bool(&json!({"is_read": "off"}), "is_read"),
            Ok(false)
        );
        assert!(super::payload_json_bool(&json!({"is_read": "definitely"}), "is_read").is_err());
        assert!(super::payload_json_bool(&json!({}), "is_read").is_err());
    }

    #[test]
    fn graph_error_summary_does_not_echo_raw_upstream_body() {
        let summary = super::graph_error_summary(
            r#"{"error":"invalid_grant","error_description":"line1\nline2 refresh_token=secret"}"#,
        );
        assert_eq!(
            summary,
            "invalid_grant: line1 line2 refresh_token=[redacted]"
        );
        assert_eq!(
            super::graph_error_summary("client_secret=secret"),
            "upstream returned a non-JSON error"
        );
    }

    #[test]
    fn graph_token_form_supports_public_clients_and_mail_scopes() {
        let form = super::graph_token_form_fields("client-id", None, "refresh-token");

        assert!(form
            .iter()
            .any(|(key, value)| *key == "client_id" && value == "client-id"));
        assert!(form
            .iter()
            .any(|(key, value)| *key == "refresh_token" && value == "refresh-token"));
        assert!(form
            .iter()
            .any(|(key, value)| *key == "grant_type" && value == "refresh_token"));
        assert!(form
            .iter()
            .any(|(key, value)| *key == "scope" && value.contains("Mail.ReadWrite")));
        assert!(!form.iter().any(|(key, _)| *key == "client_secret"));

        assert!(
            super::graph_token_form_fields("client-id", Some("secret"), "refresh-token")
                .iter()
                .any(|(key, value)| *key == "client_secret" && value == "secret")
        );
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

    #[test]
    fn legacy_get_plugin_request_includes_raw_key_payload() {
        let uri: Uri = "/?/Json/&q[]=/0/MessageList/&q[]=/encoded-key"
            .parse()
            .unwrap();
        let query = super::query_map(&uri);
        let request = super::plugin_request_from_http(
            &query,
            &HeaderMap::new(),
            &[],
            super::legacy_json_action(&uri),
        )
        .unwrap();
        let request = super::attach_legacy_json_raw_key(request, &uri);

        assert_eq!(request.action, "MessageList");
        assert_eq!(request.payload["RawKey"], "encoded-key");

        let uri: Uri = "/?/Json/&q[]=/0/Message/&q[]=/message-key".parse().unwrap();
        let query = super::query_map(&uri);
        let request = super::plugin_request_from_http(
            &query,
            &HeaderMap::new(),
            &[],
            super::legacy_json_action(&uri),
        )
        .unwrap();
        let request = super::attach_legacy_json_raw_key(request, &uri);

        assert_eq!(request.action, "Message");
        assert_eq!(request.payload["RawKey"], "message-key");
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
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
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

        let replay =
            SqlxUserRepository::verify_totp_login_code(&pool, 1514, "JBSWY3DPEHPK3PXP", code)
                .await
                .unwrap();
        assert_eq!(replay.ok, false);
        assert_eq!(
            replay.error.as_deref(),
            Some("Two-factor code already used")
        );
    }

    #[tokio::test]
    async fn native_frickmail_login_selects_primary_account_after_validation() {
        let salt = [11_u8; fm_user::KDF_SALT_BYTES];
        let credential_key = fm_user::derive_credential_key("correct-horse", &salt).unwrap();
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_login_user(
            &pool,
            1513,
            "primary-login",
            Some("primary-login@example.com"),
            "correct-horse",
            &salt,
            None,
        )
        .await;
        seed_mail_account(&pool, 15130, 1513, "Primary", true).await;
        assert!(SqlxUserRepository::set_mail_account_password(
            &pool,
            1513,
            15130,
            "imap-secret".to_string(),
            &credential_key,
        )
        .await
        .unwrap());
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = test_session();

        let response = super::native_frickmail_login_with_validator(
            &state,
            "FrickmailLogin",
            &json!({
                "username": "primary-login",
                "password": "correct-horse"
            }),
            &session,
            accept_mail_account_bridge_validation,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["email"], "primary@example.com");
        assert_eq!(body["Result"]["account_id"], 15130);
        assert!(body["Result"].get("bridge_pending").is_none());
        assert!(body["Result"].get("no_primary").is_none());
        assert!(session
            .get::<String>(CREDENTIAL_KEY_SESSION_KEY)
            .await
            .unwrap()
            .is_some());
        let selected = session
            .get::<SelectedMailAccountSession>(SELECTED_ACCOUNT_SESSION_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.account_id, 15130);
    }

    #[tokio::test]
    async fn native_frickmail_bridge_session_selects_primary_account() {
        let key = [21_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1600, "bridge-primary", Some("bridge@example.com")).await;
        seed_mail_account(&pool, 1601, 1600, "Oldest", false).await;
        seed_mail_account(&pool, 1602, 1600, "Primary", true).await;
        assert!(SqlxUserRepository::set_mail_account_password(
            &pool,
            1600,
            1602,
            "imap-secret".to_string(),
            &key,
        )
        .await
        .unwrap());
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1600, "bridge-primary", Some("bridge@example.com"), &key).await;

        let response = super::native_frickmail_bridge_session_with_validator(
            &state,
            "FrickmailBridgeSession",
            &session,
            accept_mail_account_bridge_validation,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["email"], "primary@example.com");
        assert_eq!(body["Result"]["account_id"], 1602);
        assert!(body["Result"].get("bridge_pending").is_none());
        let selected = session
            .get::<SelectedMailAccountSession>(SELECTED_ACCOUNT_SESSION_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.account_id, 1602);
    }

    #[tokio::test]
    async fn native_frickmail_bridge_session_falls_back_to_oldest_account() {
        let key = [22_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1603, "bridge-oldest", Some("oldest@example.com")).await;
        seed_mail_account(&pool, 1604, 1603, "Oldest", false).await;
        seed_mail_account(&pool, 1605, 1603, "Newest", false).await;
        assert!(SqlxUserRepository::set_mail_account_password(
            &pool,
            1603,
            1604,
            "imap-secret".to_string(),
            &key,
        )
        .await
        .unwrap());
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1603, "bridge-oldest", Some("oldest@example.com"), &key).await;

        let response = super::native_frickmail_bridge_session_with_validator(
            &state,
            "FrickmailBridgeSession",
            &session,
            accept_mail_account_bridge_validation,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["email"], "oldest@example.com");
        assert_eq!(body["Result"]["account_id"], 1604);
        assert!(body["Result"].get("bridge_pending").is_none());
    }

    #[tokio::test]
    async fn native_frickmail_bridge_session_reports_no_primary_without_accounts() {
        let key = [23_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1606, "bridge-empty", Some("empty@example.com")).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1606, "bridge-empty", Some("empty@example.com"), &key).await;

        let response =
            super::native_frickmail_bridge_session(&state, "FrickmailBridgeSession", &session)
                .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["no_primary"], true);
    }

    #[tokio::test]
    async fn native_frickmail_bridge_session_requires_reauth_for_missing_credentials() {
        let key = [24_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1607, "bridge-reauth", Some("reauth@example.com")).await;
        seed_mail_account(&pool, 1608, 1607, "Primary", true).await;
        clear_mail_account_password(&pool, 1608).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1607, "bridge-reauth", Some("reauth@example.com"), &key).await;

        let response =
            super::native_frickmail_bridge_session(&state, "FrickmailBridgeSession", &session)
                .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["reauth_required"], true);
        assert_eq!(body["Result"]["reauth_account_id"], 1608);
        assert_eq!(
            body["Result"]["reauth_account_email"],
            "primary@example.com"
        );
        assert_eq!(body["Result"]["reauth_account_type"], "imap");
        assert!(body["Result"]["message"]
            .as_str()
            .unwrap()
            .contains("please re-authorise"));
    }

    #[tokio::test]
    async fn native_frickmail_bridge_session_requires_reauth_for_empty_credentials() {
        let key = [27_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(
            &pool,
            1616,
            "bridge-empty-password",
            Some("empty-password@example.com"),
        )
        .await;
        seed_mail_account(&pool, 1617, 1616, "Primary", true).await;
        set_mail_account_password_blob(
            &pool,
            1617,
            Some(fm_user::encrypt_account_secret("", &key).unwrap()),
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = credential_session(
            1616,
            "bridge-empty-password",
            Some("empty-password@example.com"),
            &key,
        )
        .await;

        let response =
            super::native_frickmail_bridge_session(&state, "FrickmailBridgeSession", &session)
                .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["reauth_required"], true);
        assert_eq!(
            body["Result"]["message"],
            "No credentials stored — please re-authorise this account."
        );
    }

    #[tokio::test]
    async fn native_frickmail_switch_account_scopes_user_and_selects_validated_account() {
        let key = [25_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1609, "switch-user", Some("switch@example.com")).await;
        seed_user(&pool, 1610, "other-switch", Some("other@example.com")).await;
        seed_mail_account(&pool, 1611, 1609, "Work", true).await;
        seed_mail_account(&pool, 1612, 1610, "Other", true).await;
        seed_mail_account(&pool, 1613, 1609, "Missing", false).await;
        clear_mail_account_password(&pool, 1613).await;
        assert!(SqlxUserRepository::set_mail_account_password(
            &pool,
            1609,
            1611,
            "imap-secret".to_string(),
            &key,
        )
        .await
        .unwrap());
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1609, "switch-user", Some("switch@example.com"), &key).await;

        let response = super::native_frickmail_switch_account(
            &state,
            "FrickmailSwitchAccount",
            &json!({"id": 1612}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Account not found");

        let response = super::native_frickmail_switch_account(
            &state,
            "FrickmailSwitchAccount",
            &json!({"id": 1613}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "No credentials stored");

        let response = super::native_frickmail_switch_account_with_validator(
            &state,
            "FrickmailSwitchAccount",
            &json!({"id": "1611"}),
            &session,
            accept_mail_account_bridge_validation,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["email"], "work@example.com");
        assert_eq!(body["Result"]["account_id"], 1611);
        assert!(body["Result"].get("bridge_pending").is_none());
        let selected = session
            .get::<SelectedMailAccountSession>(SELECTED_ACCOUNT_SESSION_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.account_id, 1611);
    }

    #[tokio::test]
    async fn native_frickmail_switch_account_does_not_select_when_live_validation_fails() {
        let key = [37_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1618, "switch-invalid", Some("invalid@example.com")).await;
        seed_mail_account(&pool, 1619, 1618, "Invalid", true).await;
        assert!(SqlxUserRepository::set_mail_account_password(
            &pool,
            1618,
            1619,
            "wrong-but-present".to_string(),
            &key,
        )
        .await
        .unwrap());
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1618, "switch-invalid", Some("invalid@example.com"), &key).await;

        let response = super::native_frickmail_switch_account_with_validator(
            &state,
            "FrickmailSwitchAccount",
            &json!({"id": 1619}),
            &session,
            reject_mail_account_bridge_validation,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "IMAP authentication failed");
        assert!(session
            .get::<SelectedMailAccountSession>(SELECTED_ACCOUNT_SESSION_KEY)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn native_frickmail_switch_account_does_not_select_oauth_when_refresh_validation_fails() {
        let key = [38_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1623, "switch-oauth", Some("oauth@example.com")).await;
        seed_mail_account(&pool, 1624, 1623, "OAuth", true).await;
        set_mail_account_oauth_token(
            &pool,
            1624,
            "oauth@example.com",
            "revoked-refresh-token",
            Some("common"),
            &key,
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1623, "switch-oauth", Some("oauth@example.com"), &key).await;

        let response = super::native_frickmail_switch_account_with_validator(
            &state,
            "FrickmailSwitchAccount",
            &json!({"id": 1624}),
            &session,
            reject_oauth_bridge_validation,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "OAuth refresh failed");
        assert!(session
            .get::<SelectedMailAccountSession>(SELECTED_ACCOUNT_SESSION_KEY)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn json_api_dispatches_native_bridge_and_switch_error_paths() {
        let key = [26_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1614, "route-bridge", Some("route@example.com")).await;
        seed_mail_account(&pool, 1615, 1614, "Primary", true).await;
        clear_mail_account_password(&pool, 1615).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1614, "route-bridge", Some("route@example.com"), &key).await;

        let response = super::json_api_request(
            state.clone(),
            "/?/Json/".parse().unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/?/Json/")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("Action=PluginFrickmailBridgeSession"))
                .unwrap(),
            session.clone(),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginFrickmailBridgeSession");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["reauth_required"], true);
        assert_eq!(body["Result"]["reauth_account_id"], 1615);

        let response = super::json_api_request(
            state,
            "/?/Json/".parse().unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/?/Json/")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("Action=PluginFrickmailSwitchAccount&id=1615"))
                .unwrap(),
            session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginFrickmailSwitchAccount");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "No credentials stored");
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
    async fn native_frickmail_unified_inbox_returns_indexed_inbox_shape() {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_message_index_table(&pool).await;
        seed_user(&pool, 151, "unified", Some("unified@example.com")).await;
        seed_user(
            &pool,
            152,
            "other-unified",
            Some("other-unified@example.com"),
        )
        .await;
        seed_mail_account(&pool, 1312, 151, "Work", true).await;
        seed_mail_account(&pool, 1313, 151, "Personal", false).await;
        seed_mail_account(&pool, 1314, 152, "Other", true).await;
        seed_mail_account(&pool, 1315, 151, "OAuthOnly", false).await;
        seed_mail_account(&pool, 1316, 151, "NoPassword", false).await;
        sqlx::query("UPDATE frickmail_mail_accounts SET type = 'gmail' WHERE id = ?")
            .bind(1315_i64)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE frickmail_mail_accounts SET encrypted_password = NULL WHERE id = ?")
            .bind(1316_i64)
            .execute(&pool)
            .await
            .unwrap();
        seed_search_message(
            &pool,
            SearchMessageSeed {
                id: 4,
                user_id: 151,
                account_id: 1312,
                folder: "INBOX",
                imap_uid: 41,
                message_id: Some("unified-1"),
                subject: Some("Old inbox"),
                from_addr: Some("billing@example.com"),
                from_name: Some("Billing"),
                date_ts: Some("2026-06-01 10:00:00"),
                snippet: Some("Old body"),
            },
        )
        .await;
        seed_search_message(
            &pool,
            SearchMessageSeed {
                id: 5,
                user_id: 151,
                account_id: 1313,
                folder: "INBOX",
                imap_uid: 42,
                message_id: Some("unified-2"),
                subject: Some("New inbox"),
                from_addr: Some("friend@example.com"),
                from_name: None,
                date_ts: Some("2026-06-02 10:00:00"),
                snippet: Some("New body"),
            },
        )
        .await;
        seed_search_message(
            &pool,
            SearchMessageSeed {
                id: 6,
                user_id: 151,
                account_id: 1312,
                folder: "Archive",
                imap_uid: 43,
                message_id: Some("unified-3"),
                subject: Some("Archived"),
                from_addr: Some("archive@example.com"),
                from_name: Some("Archive"),
                date_ts: Some("2026-06-03 10:00:00"),
                snippet: Some("Must not appear"),
            },
        )
        .await;
        seed_search_message(
            &pool,
            SearchMessageSeed {
                id: 7,
                user_id: 152,
                account_id: 1314,
                folder: "INBOX",
                imap_uid: 44,
                message_id: Some("unified-4"),
                subject: Some("Other user"),
                from_addr: Some("other@example.com"),
                from_name: Some("Other"),
                date_ts: Some("2026-06-04 10:00:00"),
                snippet: Some("Must not leak"),
            },
        )
        .await;
        seed_search_message(
            &pool,
            SearchMessageSeed {
                id: 8,
                user_id: 151,
                account_id: 1315,
                folder: "INBOX",
                imap_uid: 45,
                message_id: Some("unified-5"),
                subject: Some("OAuth-only account"),
                from_addr: Some("oauth@example.com"),
                from_name: Some("OAuth"),
                date_ts: Some("2026-06-05 10:00:00"),
                snippet: Some("Non-IMAP account should not appear"),
            },
        )
        .await;
        seed_search_message(
            &pool,
            SearchMessageSeed {
                id: 9,
                user_id: 151,
                account_id: 1316,
                folder: "INBOX",
                imap_uid: 46,
                message_id: Some("unified-6"),
                subject: Some("Passwordless account"),
                from_addr: Some("nopass@example.com"),
                from_name: Some("NoPassword"),
                date_ts: Some("2026-06-06 10:00:00"),
                snippet: Some("Credential-cleared account should not appear"),
            },
        )
        .await;
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session = authenticated_session(151, "unified", None).await;

        let response = super::native_frickmail_unified_inbox(
            &state,
            "PluginFrickmailUnifiedInbox",
            &json!({"limit": 1}),
            &session,
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "PluginFrickmailUnifiedInbox");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["errors"].as_array().unwrap().len(), 0);
        let messages = body["Result"]["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["account_id"], 1313);
        assert_eq!(messages[0]["account_email"], "personal@example.com");
        assert_eq!(messages[0]["uid"], 42);
        assert_eq!(messages[0]["subject"], "New inbox");
        assert_eq!(messages[0]["from"], "friend@example.com");
        assert_eq!(messages[0]["date_ts"], 1_780_394_400);
        assert_eq!(messages[0]["is_seen"], true);
        assert_eq!(messages[0]["flags"].as_array().unwrap().len(), 0);
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
    async fn json_api_dispatches_native_legacy_message_mutation_auth_path() {
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
                        "Action=MessageSetSeen&folder=INBOX&uids=41&setAction=1",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "MessageSetSeen");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Not authenticated");
    }

    #[tokio::test]
    async fn json_api_recognizes_unmigrated_legacy_mailbox_actions() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/?/Json/&q[]=/0/MessageList/&q[]=/payload")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "MessageList");
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 501);
        assert_eq!(
            body["message"],
            "Frickmail compatibility hook 'MessageList' is not migrated yet"
        );
    }

    #[tokio::test]
    async fn json_api_dispatches_folder_information_with_uidnext_to_native_auth_path() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=FolderInformation&folder=INBOX&uidNext=50",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FolderInformation");
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
            &json!({"uid": 41}),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Account id required");

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
    async fn native_frickmail_get_message_body_uses_selected_account_when_account_id_missing() {
        let key = [28_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1620, "selected-viewer", Some("selected@example.com")).await;
        seed_mail_account(&pool, 1621, 1620, "Primary", true).await;
        seed_mail_account(&pool, 1622, 1620, "Selected", false).await;
        assert!(SqlxUserRepository::set_mail_account_password(
            &pool,
            1620,
            1622,
            "selected-secret".to_string(),
            &key,
        )
        .await
        .unwrap());
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1620, "selected-viewer", Some("selected@example.com"), &key).await;

        let switch_response = super::native_frickmail_switch_account_with_validator(
            &state,
            "FrickmailSwitchAccount",
            &json!({"id": 1622}),
            &session,
            accept_mail_account_bridge_validation,
        )
        .await;
        let switch_body = read_json(switch_response).await;
        assert_eq!(switch_body["Result"]["ok"], true);
        assert_eq!(switch_body["Result"]["account_id"], 1622);
        assert!(switch_body["Result"].get("bridge_pending").is_none());
        let selected = session
            .get::<SelectedMailAccountSession>(SELECTED_ACCOUNT_SESSION_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.account_id, 1622);

        let response = super::native_frickmail_get_message_body_with_fetcher(
            &state,
            "FrickmailGetMessageBody",
            &json!({"uid": 77}),
            &session,
            Duration::from_secs(1),
            |config, password, folder, uid| async move {
                assert_eq!(config.login, "selected@example.com");
                assert_eq!(password, "selected-secret");
                assert_eq!(folder, "INBOX");
                assert_eq!(uid, 77);
                Ok(Some(vec![BodyPreviewPart {
                    kind: BodyPartKind::Plain,
                    raw: b"Content-Type: text/plain; charset=utf-8\r\n\r\nSelected body.".to_vec(),
                }]))
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["plain"], "Selected body.");
    }

    #[tokio::test]
    async fn native_frickmail_get_message_body_revalidates_selected_account_scope() {
        let key = [29_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user(&pool, 1630, "scoped-viewer", Some("scoped@example.com")).await;
        seed_user(&pool, 1631, "other-viewer", Some("other@example.com")).await;
        seed_mail_account(&pool, 1632, 1631, "Other", true).await;
        assert!(SqlxUserRepository::set_mail_account_password(
            &pool,
            1631,
            1632,
            "other-secret".to_string(),
            &key,
        )
        .await
        .unwrap());
        let state = AppState::with_db_pool(test_config(None), Some(pool));
        let session =
            credential_session(1630, "scoped-viewer", Some("scoped@example.com"), &key).await;
        session
            .insert(
                SELECTED_ACCOUNT_SESSION_KEY,
                SelectedMailAccountSession { account_id: 1632 },
            )
            .await
            .unwrap();

        let response = super::native_frickmail_get_message_body_with_fetcher(
            &state,
            "FrickmailGetMessageBody",
            &json!({"uid": 77}),
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _uid| async move {
                panic!("fetcher should not run for another user's selected account")
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Account not found");
    }

    #[tokio::test]
    async fn native_legacy_message_returns_legacy_message_shape() {
        let key = [46_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1812, 1813, &key).await;

        let response = super::native_legacy_message_with_fetcher(
            &state,
            "Message",
            &json!({"account_id": 1813, "folder": "INBOX", "uid": 51}),
            &session,
            Duration::from_secs(1),
            |_config, _password, folder, uid| async move {
                assert_eq!(folder, "INBOX");
                assert_eq!(uid, 51);
                Ok(Some(vec![BodyPreviewPart {
                    kind: BodyPartKind::RawMessage,
                    raw: b"From: \"Sender, Example\" <sender@example.com>\r\nReply-To: reply@example.com\r\nTo: Recipient <recipient@example.com>\r\nCc: cc@example.com\r\nBcc: hidden@example.com\r\nSender: Actual <actual@example.com>\r\nDelivered-To: delivered@example.com\r\nMessage-ID: <message@example.com>\r\nIn-Reply-To: <parent@example.com>\r\nReferences: <root@example.com>\r\n <parent@example.com>\r\nSubject: Legacy body\r\n\r\nHello legacy".to_vec(),
                }]))
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "Message");
        assert_eq!(body["Result"]["@Object"], "Object/Message");
        assert_eq!(body["Result"]["folder"], "INBOX");
        assert_eq!(body["Result"]["uid"], 51);
        assert_eq!(body["Result"]["id"], Value::Null);
        assert_eq!(body["Result"]["subject"], "Legacy body");
        assert_eq!(body["Result"]["messageId"], "<message@example.com>");
        assert_eq!(body["Result"]["inReplyTo"], "<parent@example.com>");
        assert_eq!(
            body["Result"]["references"],
            "<root@example.com> <parent@example.com>"
        );
        assert_eq!(body["Result"]["preview"], Value::Null);
        assert_eq!(body["Result"]["from"][0]["name"], "Sender, Example");
        assert_eq!(body["Result"]["from"][0]["email"], "sender@example.com");
        assert_eq!(body["Result"]["replyTo"][0]["email"], "reply@example.com");
        assert_eq!(body["Result"]["to"][0]["name"], "Recipient");
        assert_eq!(body["Result"]["to"][0]["email"], "recipient@example.com");
        assert_eq!(body["Result"]["cc"][0]["email"], "cc@example.com");
        assert_eq!(body["Result"]["bcc"][0]["email"], "hidden@example.com");
        assert_eq!(body["Result"]["sender"][0]["name"], "Actual");
        assert_eq!(body["Result"]["sender"][0]["email"], "actual@example.com");
        assert_eq!(
            body["Result"]["deliveredTo"][0]["email"],
            "delivered@example.com"
        );
        assert_eq!(body["Result"]["attachments"], Value::Null);
        assert_eq!(body["Result"]["headers"], Value::Null);
        assert_eq!(body["Result"]["dateTimestamp"], 0);
        assert_eq!(body["Result"]["dateTimestampSource"], "internal");
        assert!(body["Result"].get("date").is_none());
        assert!(body["Result"].get("html").is_some());
        assert_eq!(body["Result"]["plain"], "Hello legacy");
        assert!(body["Result"].get("threads").is_none());
        assert!(body["Result"].get("threadUnseen").is_none());
    }

    #[tokio::test]
    async fn native_legacy_message_accepts_header_only_raw_message() {
        let key = [50_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1918, 1919, &key).await;

        let response = super::native_legacy_message_with_fetcher(
            &state,
            "Message",
            &json!({"account_id": 1919, "folder": "INBOX", "uid": 55}),
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _uid| async move {
                Ok(Some(vec![BodyPreviewPart {
                    kind: BodyPartKind::RawMessage,
                    raw: b"From: sender@example.com\r\n\
Message-ID: <message@example.com>\r\n\
In-Reply-To: <parent@example.com>\r\n\
References: <root@example.com>\r\n <parent@example.com>\r\n\r\n"
                        .to_vec(),
                }]))
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "Message");
        assert_eq!(body["Result"]["messageId"], "<message@example.com>");
        assert_eq!(body["Result"]["inReplyTo"], "<parent@example.com>");
        assert_eq!(
            body["Result"]["references"],
            "<root@example.com> <parent@example.com>"
        );
        assert_eq!(body["Result"]["from"][0]["email"], "sender@example.com");
        assert!(body["Result"].get("html").is_none());
        assert!(body["Result"].get("plain").is_none());
    }

    #[tokio::test]
    async fn native_legacy_message_keeps_part_only_email_collections_unavailable() {
        let key = [49_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1818, 1819, &key).await;

        let response = super::native_legacy_message_with_fetcher(
            &state,
            "Message",
            &json!({"account_id": 1819, "folder": "INBOX", "uid": 53}),
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _uid| async move {
                Ok(Some(vec![BodyPreviewPart {
                    kind: BodyPartKind::Plain,
                    raw: b"Content-Type: text/plain; charset=utf-8\r\n\r\nPart-only body".to_vec(),
                }]))
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "Message");
        assert_eq!(body["Result"]["plain"], "Part-only body");
        assert_eq!(body["Result"]["messageId"], "");
        assert_eq!(body["Result"]["inReplyTo"], "");
        assert!(body["Result"].get("references").is_none());
        assert_eq!(body["Result"]["from"], Value::Null);
        assert_eq!(body["Result"]["replyTo"], Value::Null);
        assert_eq!(body["Result"]["to"], Value::Null);
        assert_eq!(body["Result"]["cc"], Value::Null);
        assert_eq!(body["Result"]["bcc"], Value::Null);
        assert_eq!(body["Result"]["sender"], Value::Null);
        assert_eq!(body["Result"]["deliveredTo"], Value::Null);
    }

    #[tokio::test]
    async fn native_legacy_message_omits_empty_body_fields_like_php() {
        let key = [47_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1814, 1815, &key).await;

        let response = super::native_legacy_message_with_fetcher(
            &state,
            "Message",
            &json!({"account_id": 1815, "folder": "INBOX", "uid": 52}),
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _uid| async move {
                Ok(Some(vec![BodyPreviewPart {
                    kind: BodyPartKind::RawMessage,
                    raw: b"Subject: Metadata only\r\n\r\n".to_vec(),
                }]))
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "Message");
        assert_eq!(body["Result"]["@Object"], "Object/Message");
        assert_eq!(body["Result"]["id"], Value::Null);
        assert_eq!(body["Result"]["subject"], "Metadata only");
        assert_eq!(body["Result"]["preview"], Value::Null);
        assert!(body["Result"].get("date").is_none());
        assert!(body["Result"].get("html").is_none());
        assert!(body["Result"].get("plain").is_none());
        assert!(body["Result"].get("references").is_none());
        assert!(body["Result"].get("threads").is_none());
        assert!(body["Result"].get("threadUnseen").is_none());
    }

    #[test]
    fn legacy_message_json_keeps_nonempty_optional_body_fields() {
        let from = vec!["Sender <sender@example.com>".to_string()];
        let reply_to = vec!["reply@example.com".to_string()];
        let to = vec!["Recipient <recipient@example.com>".to_string()];
        let cc = vec!["cc@example.com".to_string()];
        let bcc = vec!["hidden@example.com".to_string()];
        let sender = vec!["Actual <actual@example.com>".to_string()];
        let delivered_to = vec!["delivered@example.com".to_string()];
        let message = super::legacy_message_json(
            "INBOX",
            54,
            "hash",
            "Optional fields",
            "<p>Hello</p>",
            "",
            "",
            "",
            "<root@example>",
            Some(from.as_slice()),
            Some(reply_to.as_slice()),
            Some(to.as_slice()),
            Some(cc.as_slice()),
            Some(bcc.as_slice()),
            Some(sender.as_slice()),
            Some(delivered_to.as_slice()),
            0,
            &[],
            None,
        );

        assert_eq!(message["references"], "<root@example>");
        assert_eq!(message["html"], "<p>Hello</p>");
        assert_eq!(message["plain"], "");
        assert_eq!(message["preview"], Value::Null);
        assert_eq!(message["from"][0]["name"], "Sender");
        assert_eq!(message["from"][0]["email"], "sender@example.com");
        assert_eq!(message["replyTo"][0]["email"], "reply@example.com");
        assert_eq!(message["to"][0]["name"], "Recipient");
        assert_eq!(message["to"][0]["email"], "recipient@example.com");
        assert_eq!(message["cc"][0]["email"], "cc@example.com");
        assert_eq!(message["bcc"][0]["email"], "hidden@example.com");
        assert_eq!(message["sender"][0]["name"], "Actual");
        assert_eq!(message["sender"][0]["email"], "actual@example.com");
        assert_eq!(message["deliveredTo"][0]["email"], "delivered@example.com");
        assert_eq!(message["attachments"], Value::Null);
        assert_eq!(message["headers"], Value::Null);
        assert_eq!(message["dateTimestamp"], 0);
        assert_eq!(message["dateTimestampSource"], "internal");
        assert!(message.get("date").is_none());
        assert!(message.get("threads").is_none());
        assert!(message.get("threadUnseen").is_none());
    }

    #[tokio::test]
    async fn native_legacy_message_decodes_legacy_raw_key_get_shape() {
        let key = [49_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1816, 1817, &key).await;
        let raw_key = URL_SAFE_NO_PAD.encode(json!(["INBOX", "52", 1, "account"]).to_string());
        let captured = Arc::new(Mutex::new(None));
        let captured_for_fetch = Arc::clone(&captured);

        let response = super::native_legacy_message_with_fetcher(
            &state,
            "Message",
            &json!({"account_id": 1817, "RawKey": raw_key}),
            &session,
            Duration::from_secs(1),
            move |_config, _password, folder, uid| {
                let captured = Arc::clone(&captured_for_fetch);
                async move {
                    *captured.lock().unwrap() = Some((folder, uid));
                    Ok(Some(vec![BodyPreviewPart {
                        kind: BodyPartKind::RawMessage,
                        raw: b"Subject: RawKey body\r\n\r\nHello from raw key".to_vec(),
                    }]))
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "Message");
        assert_eq!(body["Result"]["folder"], "INBOX");
        assert_eq!(body["Result"]["uid"], 52);
        assert_eq!(body["Result"]["subject"], "RawKey body");
        assert_eq!(body["Result"]["plain"], "Hello from raw key");
        assert_eq!(
            captured.lock().unwrap().clone().unwrap(),
            ("INBOX".to_string(), 52)
        );

        let parsed = super::legacy_message_request_from_payload(&json!({
            "RawKey": URL_SAFE_NO_PAD.encode(json!(["Archive", 53, 0, "account-2"]).to_string())
        }))
        .unwrap();
        assert_eq!(parsed.folder, "Archive");
        assert_eq!(parsed.uid, 53);
        assert!(!parsed.use_threads);
        assert_eq!(parsed.account_hash, "account-2");
    }

    #[tokio::test]
    async fn native_legacy_message_list_builds_request_and_returns_collection_shape() {
        let key = [50_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1820, 1821, &key).await;
        let captured = Arc::new(Mutex::new(None));
        let captured_for_fetch = Arc::clone(&captured);

        let response = super::native_legacy_message_list_with_fetcher(
            &state,
            "MessageList",
            &json!({
                "account_id": 1821,
                "folder": "INBOX",
                "offset": "10",
                "limit": "50",
                "search": "from:alice",
                "sort": "REVERSE DATE",
                "uidNext": "52",
                "useThreads": "1",
                "threadUid": "77",
                "threadAlgorithm": "REFERENCES"
            }),
            &session,
            Duration::from_secs(1),
            move |config, password, request| {
                let captured = Arc::clone(&captured_for_fetch);
                async move {
                    *captured.lock().unwrap() = Some((config, password, request.clone()));
                    Ok(LegacyMessageList {
                        folder: legacy_test_folder_information(),
                        total_emails: 12,
                        total_threads: Some(6),
                        offset: request.offset,
                        limit: request.limit,
                        search: request.search,
                        sort: request.sort,
                        limited: false,
                        thread_uid: request.thread_uid,
                        messages: vec![legacy_test_message_summary()],
                    })
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "MessageList");
        assert_eq!(body["Result"]["@Object"], "Collection/MessageCollection");
        assert_eq!(body["Result"]["@Collection"][0]["uid"], 44);
        assert_eq!(body["Result"]["offset"], 10);
        assert_eq!(body["Result"]["limit"], 50);
        assert_eq!(body["Result"]["search"], "from:alice");
        assert_eq!(body["Result"]["sort"], "REVERSE DATE");
        assert_eq!(body["Result"]["totalThreads"], 6);
        assert_eq!(body["Result"]["threadUid"], 77);

        let (config, password, request) = captured.lock().unwrap().clone().unwrap();
        assert_eq!(config.host, "imap.example.com");
        assert_eq!(config.port, 993);
        assert_eq!(password, "imap-secret");
        assert_eq!(request.mailbox, "INBOX");
        assert_eq!(request.offset, 10);
        assert_eq!(request.limit, 50);
        assert_eq!(request.search, "from:alice");
        assert_eq!(request.sort, "REVERSE DATE");
        assert_eq!(request.prev_uid_next, Some(52));
        assert!(request.hide_deleted);
        assert!(request.use_threads);
        assert_eq!(request.thread_uid, 77);
        assert_eq!(request.thread_algorithm, "REFERENCES");
    }

    #[tokio::test]
    async fn native_legacy_message_list_uses_hide_deleted_setting() {
        let key = [51_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) =
            message_body_test_state_with_settings(1826, 1827, &key, json!({"HideDeleted": false}))
                .await;
        let captured = Arc::new(Mutex::new(None));
        let captured_for_fetch = Arc::clone(&captured);

        let response = super::native_legacy_message_list_with_fetcher(
            &state,
            "MessageList",
            &json!({
                "account_id": 1827,
                "folder": "INBOX"
            }),
            &session,
            Duration::from_secs(1),
            move |_config, _password, request| {
                let captured = Arc::clone(&captured_for_fetch);
                async move {
                    *captured.lock().unwrap() = Some(request.clone());
                    Ok(LegacyMessageList {
                        folder: legacy_test_folder_information(),
                        total_emails: 1,
                        total_threads: None,
                        offset: request.offset,
                        limit: request.limit,
                        search: request.search,
                        sort: request.sort,
                        limited: false,
                        thread_uid: request.thread_uid,
                        messages: Vec::new(),
                    })
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "MessageList");
        assert_eq!(body["Result"]["@Object"], "Collection/MessageCollection");
        assert_eq!(body["Result"]["totalThreads"], Value::Null);
        assert!(!captured.lock().unwrap().clone().unwrap().hide_deleted);
    }

    #[test]
    fn legacy_message_list_request_matches_post_defaults_and_thread_flag() {
        let request = super::legacy_message_list_request_from_payload(&json!({
            "folder": "INBOX",
            "threadUid": 77,
            "useThreads": "0"
        }))
        .unwrap();

        assert_eq!(
            request,
            LegacyMessageListRequest {
                mailbox: "INBOX".to_string(),
                offset: 0,
                limit: 10,
                search: String::new(),
                sort: String::new(),
                prev_uid_next: Some(0),
                hide_deleted: true,
                use_threads: false,
                thread_uid: 0,
                thread_algorithm: String::new(),
            }
        );

        let threaded = super::legacy_message_list_request_from_payload(&json!({
            "folder": "INBOX",
            "offset": 5,
            "limit": 25,
            "search": "subject:test",
            "sort": "DATE",
            "uidNext": "42",
            "threadUid": "77",
            "threadAlgorithm": "ORDEREDSUBJECT",
            "useThreads": true
        }))
        .unwrap();

        assert_eq!(threaded.offset, 5);
        assert_eq!(threaded.limit, 25);
        assert_eq!(threaded.search, "subject:test");
        assert_eq!(threaded.sort, "DATE");
        assert_eq!(threaded.prev_uid_next, Some(42));
        assert!(threaded.use_threads);
        assert_eq!(threaded.thread_uid, 77);
        assert_eq!(threaded.thread_algorithm, "ORDEREDSUBJECT");

        let negative = super::legacy_message_list_request_from_payload(&json!({
            "folder": "INBOX",
            "offset": -1,
            "limit": -1
        }))
        .unwrap();

        assert_eq!(negative.offset, 0);
        assert_eq!(negative.limit, 0);
        assert_eq!(negative.prev_uid_next, Some(0));

        let malformed_uid_next = super::legacy_message_list_request_from_payload(&json!({
            "folder": "INBOX",
            "uidNext": "abc"
        }))
        .unwrap();

        assert_eq!(malformed_uid_next.prev_uid_next, Some(0));

        let zero_limit = super::legacy_message_list_request_from_payload(&json!({
            "folder": "INBOX",
            "limit": 0
        }))
        .unwrap();

        assert_eq!(zero_limit.limit, 0);

        let missing_limit = super::legacy_message_list_request_from_payload(&json!({
            "folder": "INBOX",
            "offset": 1
        }))
        .unwrap();

        assert_eq!(missing_limit.limit, 10);

        let saturated = super::legacy_message_list_request_from_payload(&json!({
            "folder": "INBOX",
            "offset": 999999999999_i64,
            "limit": 999999999999_i64
        }))
        .unwrap();

        assert_eq!(saturated.offset, u32::MAX);
        assert_eq!(saturated.limit, u32::MAX);
    }

    #[test]
    fn legacy_message_list_raw_key_request_matches_get_branch() {
        let raw_payload = json!({
            "folder": "INBOX",
            "offset": "15",
            "limit": "25",
            "search": "from:bob",
            "sort": "REVERSE DATE",
            "uidNext": "123",
            "useThreads": 1,
            "threadUid": "77",
            "threadAlgorithm": "REFERENCES",
            "hash": "folder-etag-account",
            "accountHash": "account"
        });
        let raw_key = URL_SAFE_NO_PAD.encode(raw_payload.to_string());
        let decoded = super::legacy_message_list_raw_key_request_from_payload(&json!({
            "RawKey": raw_key
        }))
        .unwrap()
        .unwrap();

        assert_eq!(decoded.cache_hash, "folder-etag-account");
        assert_eq!(decoded.account_hash, "account");
        assert_eq!(decoded.request.mailbox, "INBOX");
        assert_eq!(decoded.request.offset, 15);
        assert_eq!(decoded.request.limit, 25);
        assert_eq!(decoded.request.search, "from:bob");
        assert_eq!(decoded.request.sort, "REVERSE DATE");
        assert_eq!(decoded.request.prev_uid_next, Some(123));
        assert!(decoded.request.use_threads);
        assert_eq!(decoded.request.thread_uid, 77);
        assert_eq!(decoded.request.thread_algorithm, "REFERENCES");

        let raw_missing_limit = URL_SAFE_NO_PAD.encode(
            json!({
                "folder": "INBOX",
                "offset": 15,
                "uidNext": 0,
                "search": "",
                "sort": "",
                "useThreads": 0,
                "hash": "folder-etag-account"
            })
            .to_string(),
        );
        let decoded_missing_limit =
            super::legacy_message_list_raw_key_request_from_payload(&json!({
                "RawKey": raw_missing_limit
            }))
            .unwrap()
            .unwrap();

        assert_eq!(decoded_missing_limit.account_hash, "account");
        assert_eq!(decoded_missing_limit.request.limit, 0);
        assert_eq!(decoded_missing_limit.request.prev_uid_next, Some(0));
    }

    #[test]
    fn legacy_message_list_raw_cache_state_matches_mailso_key_rules() {
        let request = LegacyMessageListRequest {
            mailbox: "INBOX".to_string(),
            offset: 15,
            limit: 25,
            search: "from:bob".to_string(),
            sort: "REVERSE DATE".to_string(),
            prev_uid_next: Some(123),
            hide_deleted: true,
            use_threads: true,
            thread_uid: 77,
            thread_algorithm: "REFERENCES".to_string(),
        };

        let state =
            super::legacy_message_list_raw_cache_state("previous-etag-account", &request, "etag")
                .unwrap();

        assert_eq!(state.request_hash_validator, "etag");
        assert_eq!(state.account_hash, "account");
        assert!(state.verify_existing_cache);
        assert_eq!(
            state.current_cache_key,
            "8ae7bf17ace2089e3708d4eda1bb88ff-etag"
        );
        assert_eq!(
            {
                let mut visible_deleted = request.clone();
                visible_deleted.hide_deleted = false;
                super::legacy_message_list_raw_cache_state(
                    "previous-etag-account",
                    &visible_deleted,
                    "etag",
                )
                .unwrap()
                .current_cache_key
            },
            "d7e2e978346bca7156523bceddb5b45d-etag"
        );

        let frontend_shape =
            super::legacy_message_list_raw_cache_state("etag-account", &request, "etag").unwrap();
        assert_eq!(frontend_shape.request_hash_validator, "account");
        assert_eq!(frontend_shape.account_hash, "account");
        assert!(!frontend_shape.verify_existing_cache);

        let stale = super::legacy_message_list_raw_cache_state(
            "previous-oldetag-account",
            &request,
            "etag",
        )
        .unwrap();
        assert!(!stale.verify_existing_cache);
        assert_eq!(stale.account_hash, "account");
        assert_eq!(
            stale.current_cache_key,
            "8ae7bf17ace2089e3708d4eda1bb88ff-etag"
        );

        assert_eq!(
            super::legacy_message_list_raw_cache_state("notenoughparts", &request, "etag"),
            None
        );
    }

    #[test]
    fn legacy_message_list_hide_deleted_setting_matches_php_default() {
        assert!(super::legacy_message_list_hide_deleted_from_settings(
            &json!({})
        ));
        assert!(super::legacy_message_list_hide_deleted_from_settings(
            &json!({"HideDeleted": 1})
        ));
        assert!(!super::legacy_message_list_hide_deleted_from_settings(
            &json!({"HideDeleted": "0"})
        ));
        assert!(!super::legacy_message_list_hide_deleted_from_settings(
            &json!({"hideDeleted": false})
        ));
    }

    #[test]
    fn legacy_folder_information_json_omits_php_optional_fields() {
        let value = super::legacy_folder_information_json(&LegacyFolderInformation {
            name: "Archive".to_string(),
            uid_next: Some(9),
            uid_validity: Some(4),
            total_emails: None,
            unread_emails: None,
            highest_modseq: None,
            append_limit: None,
            size: None,
            permanent_flags: Vec::new(),
            etag: String::new(),
            messages_flags: None,
            new_messages: Vec::new(),
        });
        let object = value.as_object().unwrap();

        assert_eq!(value["id"], Value::Null);
        assert_eq!(value["name"], "Archive");
        assert_eq!(value["uidNext"], 9);
        assert_eq!(value["uidValidity"], 4);
        assert!(object.contains_key("newMessages"));
        assert!(!object.contains_key("totalEmails"));
        assert!(!object.contains_key("unreadEmails"));
        assert!(!object.contains_key("highestModSeq"));
        assert!(!object.contains_key("appendLimit"));
        assert!(!object.contains_key("size"));
        assert!(!object.contains_key("etag"));
        assert!(!object.contains_key("permanentFlags"));
        assert!(!object.contains_key("messagesFlags"));

        let counts_with_unknown_unread =
            super::legacy_folder_information_json(&LegacyFolderInformation {
                name: "Archive".to_string(),
                uid_next: Some(9),
                uid_validity: Some(4),
                total_emails: Some(7),
                unread_emails: None,
                highest_modseq: None,
                append_limit: Some(10_485_760),
                size: Some(123_456),
                permanent_flags: Vec::new(),
                etag: String::new(),
                messages_flags: None,
                new_messages: Vec::new(),
            });

        assert_eq!(counts_with_unknown_unread["totalEmails"], 7);
        assert_eq!(counts_with_unknown_unread["unreadEmails"], Value::Null);
        assert_eq!(counts_with_unknown_unread["appendLimit"], 10_485_760);
        assert_eq!(counts_with_unknown_unread["size"], 123_456);

        let populated = super::legacy_folder_information_json(&legacy_test_folder_information());
        let populated = populated.as_object().unwrap();
        assert!(populated.contains_key("totalEmails"));
        assert!(populated.contains_key("unreadEmails"));
        assert!(populated.contains_key("highestModSeq"));
        assert!(populated.contains_key("etag"));
        assert!(populated.contains_key("permanentFlags"));
        assert!(populated.contains_key("messagesFlags"));
    }

    #[test]
    fn legacy_message_list_raw_key_request_falls_back_like_legacy_decode() {
        assert_eq!(
            super::legacy_message_list_raw_key_request_from_payload(&json!({
                "RawKey": "not-valid-base64"
            }))
            .unwrap(),
            None
        );

        let short_payload = URL_SAFE_NO_PAD.encode(
            json!({
                "folder": "INBOX",
                "offset": 0,
                "limit": 10
            })
            .to_string(),
        );
        assert_eq!(
            super::legacy_message_list_raw_key_request_from_payload(&json!({
                "RawKey": short_payload
            }))
            .unwrap(),
            None
        );

        let missing_folder = URL_SAFE_NO_PAD.encode(
            json!({
                "offset": 0,
                "limit": 10,
                "search": "",
                "sort": "",
                "uidNext": 0,
                "useThreads": 0,
                "hash": "etag-account"
            })
            .to_string(),
        );
        assert_eq!(
            super::legacy_message_list_raw_key_request_from_payload(&json!({
                "RawKey": missing_folder
            })),
            Err("folder required")
        );
    }

    #[test]
    fn legacy_message_list_raw_key_from_uri_matches_get_route_shape() {
        let uri: Uri = "/?/Json/&q[]=/0/MessageList/&q[]=/encoded-key"
            .parse()
            .unwrap();
        assert_eq!(
            super::legacy_message_list_raw_key_from_uri(&uri).as_deref(),
            Some("encoded-key")
        );
        assert_eq!(
            super::legacy_action_raw_key_from_uri(&uri, "MessageList").as_deref(),
            Some("encoded-key")
        );

        let message: Uri = "/?/Json/&q[]=/0/Message/&q[]=/message-key".parse().unwrap();
        assert_eq!(
            super::legacy_action_raw_key_from_uri(&message, "Message").as_deref(),
            Some("message-key")
        );
        assert_eq!(super::legacy_message_list_raw_key_from_uri(&message), None);
    }

    #[test]
    fn legacy_message_list_json_matches_mailso_collection_shape() {
        let list = LegacyMessageList {
            folder: legacy_test_folder_information(),
            total_emails: 12,
            total_threads: Some(5),
            offset: 10,
            limit: 50,
            search: "from:alice".to_string(),
            sort: "REVERSE DATE".to_string(),
            limited: true,
            thread_uid: 0,
            messages: vec![legacy_test_message_summary()],
        };

        let value = super::legacy_message_list_json(&list);
        let folder = value["folder"].as_object().unwrap();
        let message = &value["@Collection"][0];
        let attachment = &message["attachments"][0];

        assert_eq!(value["@Object"], "Collection/MessageCollection");
        assert_eq!(value["totalEmails"], 12);
        assert_eq!(value["totalThreads"], 5);
        assert_eq!(value["threadUid"], 0);
        assert_eq!(value["newMessages"][0]["uid"], 51);
        assert_eq!(value["offset"], 10);
        assert_eq!(value["limit"], 50);
        assert_eq!(value["search"], "from:alice");
        assert_eq!(value["sort"], "REVERSE DATE");
        assert_eq!(value["limited"], true);
        assert_eq!(folder["name"], "INBOX");
        assert!(!folder.contains_key("newMessages"));
        assert!(!folder.contains_key("messagesFlags"));

        assert_eq!(message["@Object"], "Object/Message");
        assert_eq!(message["folder"], "INBOX");
        assert_eq!(message["uid"], 44);
        assert_eq!(message["id"], Value::Null);
        assert_eq!(message["subject"], "Staged summary");
        assert_eq!(message["encrypted"], true);
        assert_eq!(message["messageId"], "<message@example.com>");
        assert_eq!(message["spamScore"], 100);
        assert_eq!(message["spamResult"], "7.13 / 9.00");
        assert_eq!(message["isSpam"], true);
        assert_eq!(message["dateTimestamp"], 1_057_049_557);
        assert_eq!(message["dateTimestampSource"], "header");
        assert_eq!(message["from"][0]["email"], "alice@example.com");
        assert_eq!(message["replyTo"][0]["email"], "reply@example.com");
        assert_eq!(message["to"][0]["email"], "bob@example.com");
        assert_eq!(message["cc"][0]["email"], "carol@example.com");
        assert_eq!(message["bcc"][0]["email"], "hidden@example.com");
        assert_eq!(message["sender"][0]["email"], "sender@example.com");
        assert_eq!(message["deliveredTo"][0]["email"], "delivered@example.com");
        assert_eq!(message["readReceipt"], "Receipt <receipt@example.com>");
        assert_eq!(message["flags"][0], "\\seen");
        assert_eq!(message["inReplyTo"], "<previous@example.com>");
        assert_eq!(message["references"], "<one@example> <two@example>");
        assert_eq!(message["size"], 4096);
        assert_eq!(message["preview"], "Preview text");

        assert_eq!(attachment["@Object"], "Object/Attachment");
        assert_eq!(attachment["mimeIndex"], "2");
        assert_eq!(attachment["mimeType"], "application/pdf");
        assert_eq!(attachment["fileName"], "report.pdf");
        assert_eq!(attachment["estimatedSize"], 768);
        assert_eq!(attachment["cId"], "<part@example.com>");
        assert_eq!(attachment["contentLocation"], "cid:report");
        assert_eq!(attachment["isInline"], true);
    }

    #[test]
    fn legacy_email_collection_caps_serialized_entries_like_mailso() {
        let mut addresses = vec![String::new()];
        addresses.extend((0..105).map(|index| format!("User {index} <user{index}@example.com>")));
        let value = super::legacy_email_collection(&addresses.join(","));

        assert_eq!(value.len(), super::LEGACY_EMAIL_COLLECTION_JSON_LIMIT);
        assert_eq!(value[0]["email"], "user0@example.com");
        assert_eq!(value[99]["email"], "user99@example.com");
    }

    #[test]
    fn legacy_nullable_string_matches_mailso_preview_falsey_rule() {
        assert_eq!(super::legacy_nullable_string(None), Value::Null);
        assert_eq!(super::legacy_nullable_string(Some("")), Value::Null);
        assert_eq!(super::legacy_nullable_string(Some("0")), Value::Null);
        assert_eq!(super::legacy_nullable_string(Some("Preview")), "Preview");
    }

    #[test]
    fn legacy_optional_email_collection_separates_unavailable_from_empty() {
        let empty = Vec::new();
        assert_eq!(super::legacy_optional_email_collection(None), Value::Null);
        assert_eq!(
            super::legacy_optional_email_collection(Some(empty.as_slice())),
            json!([])
        );
    }

    #[test]
    fn legacy_message_summary_json_omits_empty_references_like_mailso() {
        let mut message = legacy_test_message_summary();
        message.references.clear();

        let value = super::legacy_message_summary_json(&message);

        assert!(!value.as_object().unwrap().contains_key("references"));
    }

    #[tokio::test]
    async fn native_legacy_folder_information_returns_status_shape() {
        let key = [47_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1814, 1815, &key).await;
        let captured = Arc::new(Mutex::new(None));
        let captured_for_fetch = Arc::clone(&captured);

        let response = super::native_legacy_folder_information_with_fetcher(
            &state,
            "FolderInformation",
            &json!({
                "account_id": 1815,
                "folder": "INBOX",
                "uidNext": 50,
                "flagsUids": [41, "42", 0, "bad"]
            }),
            &session,
            Duration::from_secs(1),
            move |config, password, folder, prev_uid_next, flag_uids| {
                let captured = Arc::clone(&captured_for_fetch);
                async move {
                    *captured.lock().unwrap() =
                        Some((config, password, folder, prev_uid_next, flag_uids));
                    Ok(LegacyFolderInformation {
                        name: "INBOX".to_string(),
                        uid_next: Some(52),
                        uid_validity: Some(10),
                        total_emails: Some(8),
                        unread_emails: Some(3),
                        highest_modseq: Some(99),
                        append_limit: None,
                        size: None,
                        permanent_flags: vec!["\\seen".to_string()],
                        etag: "etag-2".to_string(),
                        messages_flags: Some(vec![LegacyMessageFlags {
                            uid: 41,
                            flags: vec!["\\seen".to_string()],
                        }]),
                        new_messages: vec![LegacyNewMessage {
                            folder: "INBOX".to_string(),
                            uid: 50,
                            subject: "Fresh mail".to_string(),
                            from: "Alice <alice@example.com>".to_string(),
                        }],
                    })
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FolderInformation");
        assert_eq!(body["Result"]["name"], "INBOX");
        assert_eq!(body["Result"]["uidNext"], 52);
        assert_eq!(body["Result"]["totalEmails"], 8);
        assert_eq!(body["Result"]["unreadEmails"], 3);
        assert_eq!(body["Result"]["highestModSeq"], 99);
        assert_eq!(body["Result"]["messagesFlags"][0]["uid"], 41);
        assert_eq!(body["Result"]["messagesFlags"][0]["flags"][0], "\\seen");
        assert_eq!(body["Result"]["newMessages"][0]["uid"], 50);
        assert_eq!(body["Result"]["newMessages"][0]["subject"], "Fresh mail");
        assert_eq!(
            body["Result"]["newMessages"][0]["from"][0]["email"],
            "alice@example.com"
        );

        let (_config, password, folder, prev_uid_next, flag_uids) =
            captured.lock().unwrap().clone().unwrap();
        assert_eq!(password, "imap-secret");
        assert_eq!(folder, "INBOX");
        assert_eq!(prev_uid_next, Some(50));
        assert_eq!(flag_uids, Some(vec![41, 42]));
    }

    #[tokio::test]
    async fn native_legacy_message_set_seen_uses_selected_account() {
        let key = [41_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1801, 1802, &key).await;
        session
            .insert(
                SELECTED_ACCOUNT_SESSION_KEY,
                SelectedMailAccountSession { account_id: 1802 },
            )
            .await
            .unwrap();
        let captured = Arc::new(Mutex::new(None));
        let captured_for_store = Arc::clone(&captured);

        let response = super::native_legacy_message_store_flag_with_storer(
            &state,
            "MessageSetSeen",
            &json!({"folder": "INBOX", "uids": "41,42", "setAction": "1"}),
            &session,
            ImapMessageFlag::Seen,
            Duration::from_secs(1),
            move |config, password, folder, uid_set, flag, set| {
                let captured = Arc::clone(&captured_for_store);
                async move {
                    *captured.lock().unwrap() =
                        Some((config, password, folder, uid_set, flag, set));
                    Ok(())
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "MessageSetSeen");
        assert_eq!(body["Result"], true);
        let (config, password, folder, uid_set, flag, set) =
            captured.lock().unwrap().clone().unwrap();
        assert_eq!(config.host, "imap.example.com");
        assert_eq!(config.port, 993);
        assert_eq!(password, "imap-secret");
        assert_eq!(folder, "INBOX");
        assert_eq!(uid_set, "41,42");
        assert_eq!(flag, ImapMessageFlag::Seen);
        assert!(set);
    }

    #[tokio::test]
    async fn native_legacy_message_set_keyword_uses_selected_account() {
        let key = [49_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1818, 1819, &key).await;
        session
            .insert(
                SELECTED_ACCOUNT_SESSION_KEY,
                SelectedMailAccountSession { account_id: 1819 },
            )
            .await
            .unwrap();
        let captured = Arc::new(Mutex::new(None));
        let captured_for_store = Arc::clone(&captured);

        let response = super::native_legacy_message_store_keyword_with_storer(
            &state,
            "MessageSetKeyword",
            &json!({"folder": "INBOX", "uids": "41:42", "keyword": "$label1", "setAction": "0"}),
            &session,
            Duration::from_secs(1),
            move |config, password, folder, uid_set, keyword, set| {
                let captured = Arc::clone(&captured_for_store);
                async move {
                    *captured.lock().unwrap() =
                        Some((config, password, folder, uid_set, keyword, set));
                    Ok(())
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "MessageSetKeyword");
        assert_eq!(body["Result"], true);
        let (config, password, folder, uid_set, keyword, set) =
            captured.lock().unwrap().clone().unwrap();
        assert_eq!(config.host, "imap.example.com");
        assert_eq!(config.port, 993);
        assert_eq!(password, "imap-secret");
        assert_eq!(folder, "INBOX");
        assert_eq!(uid_set, "41:42");
        assert_eq!(keyword, "$label1");
        assert!(!set);
    }

    #[tokio::test]
    async fn native_legacy_message_set_seen_to_all_uses_selected_account() {
        let key = [48_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1816, 1817, &key).await;
        session
            .insert(
                SELECTED_ACCOUNT_SESSION_KEY,
                SelectedMailAccountSession { account_id: 1817 },
            )
            .await
            .unwrap();
        let captured = Arc::new(Mutex::new(None));
        let captured_for_store = Arc::clone(&captured);

        let response = super::native_legacy_message_set_seen_to_all_with_storer(
            &state,
            "MessageSetSeenToAll",
            &json!({"folder": "INBOX", "threadUids": "41,42", "setAction": "1"}),
            &session,
            Duration::from_secs(1),
            move |config, password, folder, thread_uids, set| {
                let captured = Arc::clone(&captured_for_store);
                async move {
                    *captured.lock().unwrap() = Some((config, password, folder, thread_uids, set));
                    Ok(())
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "MessageSetSeenToAll");
        assert_eq!(body["Result"], true);
        let (config, password, folder, thread_uids, set) =
            captured.lock().unwrap().clone().unwrap();
        assert_eq!(config.host, "imap.example.com");
        assert_eq!(config.port, 993);
        assert_eq!(password, "imap-secret");
        assert_eq!(folder, "INBOX");
        assert_eq!(thread_uids.as_deref(), Some("41,42"));
        assert!(set);
    }

    #[tokio::test]
    async fn native_legacy_message_copy_returns_legacy_target_folder_tuple() {
        let key = [44_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1807, 1808, &key).await;
        session
            .insert(
                SELECTED_ACCOUNT_SESSION_KEY,
                SelectedMailAccountSession { account_id: 1808 },
            )
            .await
            .unwrap();
        let captured = Arc::new(Mutex::new(None));
        let captured_for_copy = Arc::clone(&captured);

        let response = super::native_legacy_message_copy_with_copier(
            &state,
            "MessageCopy",
            &json!({"fromFolder": "INBOX", "toFolder": "Archive", "uids": "45"}),
            &session,
            Duration::from_secs(1),
            move |config, password, from_folder, to_folder, uid_set| {
                let captured = Arc::clone(&captured_for_copy);
                async move {
                    *captured.lock().unwrap() =
                        Some((config, password, from_folder, to_folder, uid_set));
                    Ok(())
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "MessageCopy");
        assert_eq!(body["Result"][0], "Archive");
        assert_eq!(body["Result"][1], "");
        let (config, password, from_folder, to_folder, uid_set) =
            captured.lock().unwrap().clone().unwrap();
        assert_eq!(config.host, "imap.example.com");
        assert_eq!(password, "imap-secret");
        assert_eq!(from_folder, "INBOX");
        assert_eq!(to_folder, "Archive");
        assert_eq!(uid_set, "45");
    }

    #[tokio::test]
    async fn native_legacy_message_move_returns_legacy_folder_tuple_and_options() {
        let key = [42_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1803, 1804, &key).await;
        session
            .insert(
                SELECTED_ACCOUNT_SESSION_KEY,
                SelectedMailAccountSession { account_id: 1804 },
            )
            .await
            .unwrap();
        let captured = Arc::new(Mutex::new(None));
        let captured_for_move = Arc::clone(&captured);

        let response = super::native_legacy_message_move_with_mover(
            &state,
            "MessageMove",
            &json!({
                "fromFolder": "INBOX",
                "toFolder": "Archive",
                "uids": "44",
                "markAsRead": "1",
                "learning": "SPAM"
            }),
            &session,
            Duration::from_secs(1),
            move |config, password, from_folder, to_folder, uid_set, options| {
                let captured = Arc::clone(&captured_for_move);
                async move {
                    *captured.lock().unwrap() =
                        Some((config, password, from_folder, to_folder, uid_set, options));
                    Ok(())
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "MessageMove");
        assert_eq!(body["Result"][0], "INBOX");
        assert_eq!(body["Result"][1], "");
        let (config, password, from_folder, to_folder, uid_set, options) =
            captured.lock().unwrap().clone().unwrap();
        assert_eq!(config.host, "imap.example.com");
        assert_eq!(password, "imap-secret");
        assert_eq!(from_folder, "INBOX");
        assert_eq!(to_folder, "Archive");
        assert_eq!(uid_set, "44");
        assert_eq!(
            options,
            ImapMoveOptions {
                mark_as_read: true,
                learning: Some(ImapMoveLearning::Spam)
            }
        );
    }

    #[tokio::test]
    async fn native_legacy_message_delete_requires_selected_or_payload_account() {
        let key = [43_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1805, 1806, &key).await;

        let response = super::native_legacy_message_delete_with_deleter(
            &state,
            "MessageDelete",
            &json!({"folder": "INBOX", "uids": "44"}),
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _uid_set| async {
                Err(FrickmailError::Upstream("should not delete".to_string()))
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "MessageDelete");
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Account id required");
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

    #[tokio::test]
    async fn native_frickmail_export_message_returns_safe_eml_payload() {
        let key = [30_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1640, 1641, &key).await;
        let captured: Arc<Mutex<Option<(String, String, String, u32)>>> =
            Arc::new(Mutex::new(None));
        let captured_for_fetch = Arc::clone(&captured);

        let response = super::native_frickmail_export_message_with_fetcher(
            &state,
            "FrickmailExportMessage",
            &json!({
                "account_id": 1641,
                "folder": "Sent Items",
                "uid": 77,
                "subject": "__Hello?/World__"
            }),
            &session,
            Duration::from_secs(1),
            move |config, password, folder, uid| {
                let captured_for_fetch = Arc::clone(&captured_for_fetch);
                async move {
                    *captured_for_fetch.lock().unwrap() =
                        Some((config.login, password, folder, uid));
                    Ok(Some(
                        b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nExported body".to_vec(),
                    ))
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["filename"], "Hello_World.eml");
        let raw = STANDARD
            .decode(body["Result"]["content_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            raw,
            b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nExported body"
        );
        assert_eq!(
            *captured.lock().unwrap(),
            Some((
                "work@example.com".to_string(),
                "imap-secret".to_string(),
                "Sent Items".to_string(),
                77,
            ))
        );
    }

    #[tokio::test]
    async fn native_frickmail_export_folder_returns_mbox_payload() {
        let key = [31_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1642, 1643, &key).await;
        let captured: Arc<Mutex<Option<(String, String, String)>>> = Arc::new(Mutex::new(None));
        let captured_for_fetch = Arc::clone(&captured);

        let response = super::native_frickmail_export_folder_with_fetcher(
            &state,
            "FrickmailExportFolder",
            &json!({"account_id": 1643, "folder": "Archive?/2026"}),
            &session,
            Duration::from_secs(1),
            RawFolderFetchLimits {
                max_messages: 10,
                max_bytes: 1024,
            },
            move |config, password, folder| {
                let captured_for_fetch = Arc::clone(&captured_for_fetch);
                async move {
                    *captured_for_fetch.lock().unwrap() = Some((config.login, password, folder));
                    Ok(vec![
                        b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\nFrom escaped\r\nBody".to_vec(),
                        b"From sender@example.com\r\n\r\nBody".to_vec(),
                    ])
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["filename"], "Archive_2026.mbox");
        let mbox = STANDARD
            .decode(body["Result"]["content_b64"].as_str().unwrap())
            .unwrap();
        let mbox = String::from_utf8(mbox).unwrap();
        assert!(mbox.contains("From nobody "));
        assert!(mbox.contains("\r\n>From escaped\r\n"));
        assert!(mbox.contains("\r\n>From sender@example.com"));
        assert_eq!(
            *captured.lock().unwrap(),
            Some((
                "work@example.com".to_string(),
                "imap-secret".to_string(),
                "Archive?/2026".to_string(),
            ))
        );
    }

    #[tokio::test]
    async fn native_frickmail_export_folder_enforces_configured_limits() {
        let key = [33_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1646, 1647, &key).await;

        let response = super::native_frickmail_export_folder_with_fetcher(
            &state,
            "FrickmailExportFolder",
            &json!({"account_id": 1647, "folder": "Archive"}),
            &session,
            Duration::from_secs(1),
            RawFolderFetchLimits {
                max_messages: 1,
                max_bytes: 1024,
            },
            |_config, _password, _folder| async move {
                Ok(vec![
                    b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nOne".to_vec(),
                    b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nTwo".to_vec(),
                ])
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(
            body["Result"]["error"],
            "Folder export exceeds configured message limit"
        );
    }

    #[tokio::test]
    async fn native_frickmail_import_eml_appends_decoded_message() {
        let key = [32_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1644, 1645, &key).await;
        let raw = b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nImported body";
        let captured: Arc<Mutex<Option<(String, String, String, Vec<u8>)>>> =
            Arc::new(Mutex::new(None));
        let captured_for_append = Arc::clone(&captured);

        let response = super::native_frickmail_import_eml_with_appender(
            &state,
            "FrickmailImportEml",
            &json!({
                "account_id": 1645,
                "folder": "Uploads",
                "eml_b64": STANDARD.encode(raw)
            }),
            &session,
            Duration::from_secs(1),
            move |config, password, folder, raw| {
                let captured_for_append = Arc::clone(&captured_for_append);
                async move {
                    *captured_for_append.lock().unwrap() =
                        Some((config.login, password, folder, raw));
                    Ok(())
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(
            *captured.lock().unwrap(),
            Some((
                "work@example.com".to_string(),
                "imap-secret".to_string(),
                "Uploads".to_string(),
                raw.to_vec(),
            ))
        );
    }

    #[test]
    fn folder_append_upload_extracts_folder_and_file_bytes() {
        let raw = b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nAppended body";
        match super::folder_append_upload(
            "multipart/form-data; boundary=frickmail",
            &folder_append_multipart_body("Archive", raw),
        ) {
            super::FolderAppendUploadResult::Upload(upload) => {
                assert_eq!(upload.folder, "Archive");
                assert_eq!(upload.raw, raw);
            }
            _ => panic!("expected folder append upload"),
        }
    }

    #[test]
    fn folder_append_upload_preserves_embedded_boundary_token() {
        let raw = b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nBody mentions --frickmail inline";
        match super::folder_append_upload(
            "multipart/form-data; boundary=frickmail",
            &folder_append_multipart_body("Archive", raw),
        ) {
            super::FolderAppendUploadResult::Upload(upload) => {
                assert_eq!(upload.folder, "Archive");
                assert_eq!(upload.raw, raw);
            }
            _ => panic!("expected folder append upload"),
        }
    }

    #[tokio::test]
    async fn json_api_dispatches_folder_append_multipart_to_native_auth_path() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "multipart/form-data; boundary=frickmail")
                    .body(Body::from(folder_append_multipart_body_with_action(
                        "FolderAppend",
                        "INBOX",
                        b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nBody",
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FolderAppend");
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 999);
        assert_eq!(body["message"], "Not authenticated");
    }

    #[tokio::test]
    async fn native_legacy_folder_append_respects_feature_gate() {
        let key = [50_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let state = AppState::new(test_config(None));
        let session =
            credential_session(1820, "append-user", Some("append@example.com"), &key).await;

        let response = super::native_legacy_folder_append_multipart_with_appender(
            &state,
            "FolderAppend",
            &folder_append_headers(),
            &folder_append_multipart_body(
                "INBOX",
                b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nBody",
            ),
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _raw| async move {
                panic!("appender should not run when FolderAppend is disabled")
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FolderAppend");
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 999);
        assert_eq!(body["message"], "Permission denied");
    }

    #[tokio::test]
    async fn native_legacy_folder_append_reports_missing_file() {
        let key = [52_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let state = AppState::new(test_config_with_message_append(true));
        let session =
            credential_session(1823, "append-user", Some("append@example.com"), &key).await;

        let response = super::native_legacy_folder_append_multipart_with_appender(
            &state,
            "FolderAppend",
            &folder_append_headers(),
            b"--frickmail\r\nContent-Disposition: form-data; name=\"folder\"\r\n\r\nINBOX\r\n--frickmail--\r\n",
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _raw| async move {
                panic!("appender should not run without appendFile")
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FolderAppend");
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 999);
        assert_eq!(body["message"], "No file");
    }

    #[tokio::test]
    async fn native_legacy_folder_append_reports_append_failure_as_legacy_false() {
        let key = [53_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state_with_config(
            1824,
            1825,
            &key,
            test_config_with_message_append(true),
        )
        .await;
        session
            .insert(
                SELECTED_ACCOUNT_SESSION_KEY,
                SelectedMailAccountSession { account_id: 1825 },
            )
            .await
            .unwrap();

        let response = super::native_legacy_folder_append_multipart_with_appender(
            &state,
            "FolderAppend",
            &folder_append_headers(),
            &folder_append_multipart_body(
                "INBOX",
                b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nBody",
            ),
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _raw| async move {
                Err(FrickmailError::Upstream("append rejected".to_string()))
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FolderAppend");
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 999);
        assert_eq!(body["message"], "append rejected");
    }

    #[tokio::test]
    async fn native_legacy_folder_append_appends_uploaded_message() {
        let key = [51_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state_with_config(
            1821,
            1822,
            &key,
            test_config_with_message_append(true),
        )
        .await;
        session
            .insert(
                SELECTED_ACCOUNT_SESSION_KEY,
                SelectedMailAccountSession { account_id: 1822 },
            )
            .await
            .unwrap();
        let raw = b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nAppended body";
        let captured: Arc<Mutex<Option<(String, String, String, Vec<u8>)>>> =
            Arc::new(Mutex::new(None));
        let captured_for_append = Arc::clone(&captured);

        let response = super::native_legacy_folder_append_multipart_with_appender(
            &state,
            "FolderAppend",
            &folder_append_headers(),
            &folder_append_multipart_body("Uploads", raw),
            &session,
            Duration::from_secs(1),
            move |config, password, folder, raw| {
                let captured_for_append = Arc::clone(&captured_for_append);
                async move {
                    *captured_for_append.lock().unwrap() =
                        Some((config.login, password, folder, raw));
                    Ok(())
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FolderAppend");
        assert_eq!(body["Result"], true);
        assert_eq!(
            *captured.lock().unwrap(),
            Some((
                "work@example.com".to_string(),
                "imap-secret".to_string(),
                "Uploads".to_string(),
                raw.to_vec(),
            ))
        );
    }

    #[tokio::test]
    async fn native_frickmail_import_eml_validates_message_before_account_lookup() {
        let key = [34_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let state = AppState::new(test_config(None));
        let session =
            credential_session(1648, "importer", Some("importer@example.com"), &key).await;

        let response = super::native_frickmail_import_eml_with_appender(
            &state,
            "FrickmailImportEml",
            &json!({
                "account_id": 9999,
                "eml_b64": STANDARD.encode(b"Subject: not accepted by legacy import check\r\n\r\nbody")
            }),
            &session,
            Duration::from_secs(1),
            |_config, _password, _folder, _raw| async move {
                panic!("appender should not run for invalid EML")
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(
            body["Result"]["error"],
            "Invalid EML format: file does not look like an RFC 2822 message"
        );
    }

    #[test]
    fn import_export_helpers_match_plugin_shapes() {
        assert_eq!(
            super::plugin_safe_filename("__Hello?/World__", "message", true),
            "Hello_World"
        );
        assert_eq!(
            super::plugin_safe_filename("Archive?/2026", "folder", false),
            "Archive_2026"
        );
        assert_eq!(
            super::plugin_safe_filename("////", "message", true),
            "message"
        );

        let mbox = super::plugin_mbox_with_date(
            vec![b"From sender\r\nFrom body\r\n".to_vec()],
            RawFolderFetchLimits {
                max_messages: 10,
                max_bytes: 1024,
            },
            "Thu Jan 01 00:00:00 1970",
        )
        .unwrap();
        let mbox = String::from_utf8(mbox).unwrap();
        assert!(mbox.starts_with("From nobody Thu Jan 01 00:00:00 1970\r\n>From sender"));
        assert!(mbox.contains("\r\n>From body\r\n"));
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

    #[test]
    fn uid_list_payload_filters_positive_numeric_values() {
        assert_eq!(
            super::payload_uid_list_optional(
                &json!({"flagsUids": [41, "42", 0, "bad", null]}),
                "flagsUids"
            ),
            Some(vec![41, 42])
        );
        assert_eq!(
            super::payload_uid_list_optional(&json!({"flagsUids": []}), "flagsUids"),
            Some(Vec::new())
        );
        assert_eq!(
            super::payload_uid_list_optional(&json!({}), "flagsUids"),
            None
        );
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

    #[tokio::test]
    async fn native_frickmail_long_poll_new_mail_returns_immediately_on_delta() {
        let key = [14_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1338, 1339, &key).await;
        let calls = Arc::new(Mutex::new(0_usize));
        let calls_for_fetch = Arc::clone(&calls);

        let response = super::native_frickmail_long_poll_new_mail_with_fetcher(
            &state,
            "FrickmailLongPollNewMail",
            &json!({"last_uids": {"1339": 12}}),
            &session,
            super::LongPollNewMailTiming {
                fetch_deadline: Duration::from_secs(1),
                poll_deadline: Duration::from_millis(100),
                poll_interval: Duration::from_millis(1),
            },
            move |config, password, folder| {
                let calls_for_fetch = Arc::clone(&calls_for_fetch);
                async move {
                    assert_eq!(password, "imap-secret");
                    assert_eq!(folder, "INBOX");
                    assert_eq!(config.login, "work@example.com");
                    *calls_for_fetch.lock().unwrap() += 1;
                    Ok(MailboxStatus {
                        uid_next: Some(15),
                        exists: 7,
                    })
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FrickmailLongPollNewMail");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["timeout"], Value::Null);
        let accounts = body["Result"]["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["account_id"], 1339);
        assert_eq!(accounts[0]["uidnext"], 15);
        assert_eq!(accounts[0]["new_count"], 3);
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn native_frickmail_long_poll_new_mail_does_not_wait_for_push_delivery() {
        let key = [17_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1344, 1345, &key).await;
        let pool = state.db_pool().unwrap().clone();
        create_push_subscription_tables(&pool).await;
        create_app_settings_table(&pool).await;
        let (endpoint, capture) = spawn_bridge().await;
        SqlxUserRepository::upsert_push_subscription(
            &pool,
            1344,
            PushSubscription {
                endpoint: endpoint.unwrap(),
                p256dh: "key".to_string(),
                auth_key: "auth".to_string(),
            },
        )
        .await
        .unwrap();

        let started = tokio::time::Instant::now();
        let response = super::native_frickmail_long_poll_new_mail_with_fetcher(
            &state,
            "FrickmailLongPollNewMail",
            &json!({"last_uids": {"1345": 12}}),
            &session,
            super::LongPollNewMailTiming {
                fetch_deadline: Duration::from_secs(1),
                poll_deadline: Duration::from_secs(25),
                poll_interval: Duration::from_secs(5),
            },
            move |_config, _password, _folder| async move {
                Ok(MailboxStatus {
                    uid_next: Some(13),
                    exists: 7,
                })
            },
        )
        .await;
        let elapsed = started.elapsed();
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["accounts"][0]["new_count"], 1);
        assert!(elapsed < Duration::from_millis(500));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(capture.lock().unwrap().method, "");
    }

    #[tokio::test]
    async fn native_frickmail_long_poll_new_mail_updates_inner_last_uids() {
        let key = [15_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1340, 1341, &key).await;
        let calls = Arc::new(Mutex::new(0_usize));
        let calls_for_fetch = Arc::clone(&calls);

        let response = super::native_frickmail_long_poll_new_mail_with_fetcher(
            &state,
            "FrickmailLongPollNewMail",
            &json!({"last_uids": {}}),
            &session,
            super::LongPollNewMailTiming {
                fetch_deadline: Duration::from_secs(1),
                poll_deadline: Duration::from_millis(100),
                poll_interval: Duration::from_millis(1),
            },
            move |_config, _password, _folder| {
                let calls_for_fetch = Arc::clone(&calls_for_fetch);
                async move {
                    let mut calls = calls_for_fetch.lock().unwrap();
                    *calls += 1;
                    let uid_next = if *calls == 1 { 10 } else { 12 };
                    Ok(MailboxStatus {
                        uid_next: Some(uid_next),
                        exists: 4,
                    })
                }
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["timeout"], Value::Null);
        let accounts = body["Result"]["accounts"].as_array().unwrap();
        assert_eq!(accounts[0]["account_id"], 1341);
        assert_eq!(accounts[0]["uidnext"], 12);
        assert_eq!(accounts[0]["new_count"], 2);
        assert_eq!(*calls.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn native_frickmail_long_poll_new_mail_times_out_when_idle() {
        let key = [16_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let (state, session) = message_body_test_state(1342, 1343, &key).await;

        let response = super::native_frickmail_long_poll_new_mail_with_fetcher(
            &state,
            "FrickmailLongPollNewMail",
            &json!({"last_uids": {"1343": 15}}),
            &session,
            super::LongPollNewMailTiming {
                fetch_deadline: Duration::from_secs(1),
                poll_deadline: Duration::from_millis(3),
                poll_interval: Duration::from_millis(1),
            },
            move |_config, _password, _folder| async move {
                Ok(MailboxStatus {
                    uid_next: Some(15),
                    exists: 7,
                })
            },
        )
        .await;
        let body = read_json(response).await;

        assert_eq!(body["Action"], "FrickmailLongPollNewMail");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["timeout"], true);
        let accounts = body["Result"]["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["account_id"], 1343);
        assert_eq!(accounts[0]["new_count"], 0);
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
    async fn native_frickmail_apply_rules_executes_imap_plan_and_updates_last_run() {
        let key = [52_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_mail_rule_tables(&pool).await;
        seed_user(&pool, 148, "apply-rules", Some("apply-rules@example.com")).await;
        seed_mail_account(&pool, 1330, 148, "Primary", true).await;
        seed_mail_rule(&pool, 1430, 148, 1330, "Move newsletters", true).await;
        seed_mail_rule(&pool, 1431, 148, 1330, "Move more newsletters", true).await;
        assert!(SqlxUserRepository::set_mail_account_password(
            &pool,
            148,
            1330,
            "imap-secret".to_string(),
            &key,
        )
        .await
        .unwrap());

        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session =
            credential_session(148, "apply-rules", Some("apply-rules@example.com"), &key).await;
        let captured: Arc<Mutex<Option<(ImapConnectionConfig, String, Vec<RuleExecutionPlan>)>>> =
            Arc::new(Mutex::new(None));
        let captured_for_executor = Arc::clone(&captured);

        let response = super::native_frickmail_apply_rules_with_executor(
            &state,
            "FrickmailApplyRules",
            &json!({"account_id": 1330}),
            &session,
            Duration::from_secs(1),
            move |config, password, rules| {
                let captured_for_executor = Arc::clone(&captured_for_executor);
                async move {
                    let first_rule = rules[0].rule_id;
                    let second_rule = rules[1].rule_id;
                    *captured_for_executor.lock().unwrap() = Some((config, password, rules));
                    Ok(RuleExecutionReport {
                        applied: vec![RuleExecutionResult {
                            rule_id: first_rule,
                            rule_name: "Move newsletters".to_string(),
                            matched_count: 3,
                            action_type: "move".to_string(),
                        }],
                        executed_rule_ids: vec![first_rule, second_rule],
                    })
                }
            },
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["applied"].as_array().unwrap().len(), 1);
        assert_eq!(body["Result"]["applied"][0]["rule_id"], 1430);
        assert_eq!(body["Result"]["applied"][0]["matched_count"], 3);
        assert_eq!(body["Result"]["applied"][0]["action_type"], "move");

        let captured = captured.lock().unwrap().take().unwrap();
        assert_eq!(captured.0.host, "imap.example.com");
        assert_eq!(captured.0.login, "primary@example.com");
        assert_eq!(captured.1, "imap-secret");
        assert_eq!(captured.2.len(), 2);
        assert_eq!(captured.2[0].rule_id, 1430);
        assert_eq!(captured.2[0].conditions_logic, RuleConditionsLogic::All);
        assert_eq!(captured.2[0].conditions[0].field, RuleConditionField::From);
        assert_eq!(captured.2[0].conditions[0].op, RuleConditionOp::Contains);
        assert_eq!(captured.2[0].conditions[0].value, "newsletter");
        assert_eq!(
            captured.2[0].actions[0],
            RuleAction::Move {
                folder: "Newsletters".to_string()
            }
        );

        let rules = SqlxUserRepository::list_mail_rules(&pool, 148, 1330)
            .await
            .unwrap();
        assert!(rules.iter().all(|rule| rule.last_run.is_some()));
    }

    #[tokio::test]
    async fn native_frickmail_apply_rules_preserves_legacy_account_errors() {
        let key = [53_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_mail_rule_tables(&pool).await;
        seed_user(&pool, 149, "apply-errors", Some("apply-errors@example.com")).await;
        seed_mail_account(&pool, 1331, 149, "Primary", true).await;
        seed_mail_rule(&pool, 1432, 149, 1331, "Move newsletters", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session =
            credential_session(149, "apply-errors", Some("apply-errors@example.com"), &key).await;

        let response = super::native_frickmail_apply_rules_with_executor(
            &state,
            "FrickmailApplyRules",
            &json!({"account_id": 1331}),
            &session,
            Duration::from_secs(1),
            |_config, _password, _rules| async {
                panic!("missing credentials must stop before IMAP execution")
            },
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Missing IMAP password");

        set_mail_account_email_and_type(&pool, 1331, "graph@example.com", "o365").await;
        let response = super::native_frickmail_apply_rules_with_executor(
            &state,
            "FrickmailApplyRules",
            &json!({"account_id": 1331}),
            &session,
            Duration::from_secs(1),
            |_config, _password, _rules| async {
                panic!("non-IMAP account must stop before IMAP execution")
            },
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(
            body["Result"]["error"],
            "Rules only supported for IMAP accounts"
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
    async fn web_push_delivery_sends_vapid_payload() {
        let pool = user_db_pool().await;
        create_app_settings_table(&pool).await;
        let bundle = SqlxUserRepository::get_or_create_vapid_key_bundle(&pool)
            .await
            .unwrap();
        let (endpoint, capture) = spawn_bridge().await;
        let subscription = PushSubscription {
            endpoint: endpoint.unwrap(),
            p256dh: "unused-public-key".to_string(),
            auth_key: "unused-auth-key".to_string(),
        };

        let ok = super::send_web_push_subscription(
            &reqwest::Client::new(),
            &subscription,
            &bundle,
            "mailto:Frickmail",
            &json!({
                "title": "2 new messages",
                "body": "work@example.com",
                "tag": "fm-newmail",
                "url": "/"
            }),
        )
        .await
        .unwrap();

        assert!(ok);
        let capture = capture.lock().unwrap().clone();
        assert_eq!(capture.method, "POST");
        assert_eq!(capture.ttl.as_deref(), Some("86400"));
        assert_eq!(capture.content_type.as_deref(), Some("application/json"));
        let authorization = capture.authorization.as_deref().unwrap();
        assert!(authorization.starts_with("vapid t="));
        assert!(authorization.contains(&format!(",k={}", bundle.public_b64u)));
        let body: Value = serde_json::from_str(&capture.body).unwrap();
        assert_eq!(body["title"], "2 new messages");
        assert_eq!(body["body"], "work@example.com");
        assert_eq!(body["tag"], "fm-newmail");
        assert_eq!(body["url"], "/");
    }

    #[tokio::test]
    async fn web_push_delivery_rejects_private_or_cleartext_endpoints() {
        let cleartext = super::validated_web_push_client("http://push.example/sub")
            .await
            .unwrap_err();
        assert!(matches!(cleartext, FrickmailError::BadRequest(_)));

        let loopback = super::validated_web_push_client("https://127.0.0.1/sub")
            .await
            .unwrap_err();
        assert!(matches!(loopback, FrickmailError::BadRequest(_)));
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
    async fn native_frickmail_smime_import_p12_signs_and_verifies_shape() {
        let key = [42_u8; fm_user::CREDENTIAL_KEY_BYTES];
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        create_smime_cert_tables(&pool).await;
        seed_user(&pool, 65, "smime-p12", Some("smime-p12@example.com")).await;
        seed_mail_account(&pool, 407, 65, "Work", true).await;
        let state = AppState::with_db_pool(test_config(None), Some(pool.clone()));
        let session =
            credential_session(65, "smime-p12", Some("smime-p12@example.com"), &key).await;
        let p12_der = test_smime_p12_der("signer@example.com", "p12-secret");

        let response = super::native_frickmail_smime_import_p12(
            &state,
            "FrickmailSmimeImportP12",
            &json!({
                "account_id": 407,
                "p12_b64": STANDARD.encode(&p12_der),
                "password": "p12-secret"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Action"], "FrickmailSmimeImportP12");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["email"], "signer@example.com");

        let response =
            super::native_frickmail_smime_list_certs(&state, "FrickmailSmimeListCerts", &session)
                .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["certs"].as_array().unwrap().len(), 1);
        assert_eq!(body["Result"]["certs"][0]["has_key"], true);

        let response = super::native_frickmail_smime_sign(
            &state,
            "FrickmailSmimeSign",
            &json!({
                "email": "signer@example.com",
                "body": "Subject: Test\r\n\r\nhello"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        let signed = STANDARD
            .decode(body["Result"]["signed_b64"].as_str().unwrap())
            .unwrap();
        assert!(String::from_utf8_lossy(&signed).contains("multipart/signed"));

        let response = super::native_frickmail_smime_verify(
            "FrickmailSmimeVerify",
            &json!({"message_b64": STANDARD.encode(&signed)}),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Action"], "FrickmailSmimeVerify");
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["verified"], false);
        assert!(body["Result"]["error"]
            .as_str()
            .unwrap()
            .starts_with("Signature verification failed:"));

        let response = super::native_frickmail_smime_import_p12(
            &state,
            "FrickmailSmimeImportP12",
            &json!({
                "account_id": 407,
                "p12_b64": STANDARD.encode(&p12_der),
                "password": "wrong"
            }),
            &session,
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(
            body["Result"]["error"],
            "Failed to read PKCS#12 file - wrong password or corrupt file"
        );
    }

    #[tokio::test]
    async fn native_frickmail_smime_verify_rejects_invalid_input_shape() {
        let response =
            super::native_frickmail_smime_verify("FrickmailSmimeVerify", &json!({})).await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "message_b64 required");

        let response = super::native_frickmail_smime_verify(
            "FrickmailSmimeVerify",
            &json!({"message_b64": "not-base64"}),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "Invalid base64 in message_b64");

        let response = super::native_frickmail_smime_verify(
            "FrickmailSmimeVerify",
            &json!({"message_b64": STANDARD.encode("not smime")}),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], true);
        assert_eq!(body["Result"]["verified"], false);
        assert_eq!(
            body["Result"]["error"],
            "Could not parse the signed message"
        );

        let response = super::native_frickmail_smime_verify(
            "FrickmailSmimeVerify",
            &json!({"message_b64": "A".repeat(super::SMIME_VERIFY_MAX_BASE64_CHARS + 1)}),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(body["Result"]["ok"], false);
        assert_eq!(body["Result"]["error"], "message_b64 too large");
    }

    #[tokio::test]
    async fn json_api_respects_disabled_smime_feature_gate() {
        let mut config = test_config(None);
        config.frickmail_user.smime_enabled = false;
        let app = super::build_router(AppState::new(config));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "Action=PluginFrickmailSmimeVerify&message_b64=eA==",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["Action"], "PluginFrickmailSmimeVerify");
        assert_eq!(body["Result"], false);
        assert_eq!(body["code"], 501);
        assert_eq!(
            body["message"],
            "Frickmail compatibility hook 'FrickmailSmimeVerify' is not migrated yet"
        );
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
            frickmail_user: Default::default(),
            transactional_smtp: Default::default(),
        }
    }

    fn test_config_with_message_append(allow_message_append: bool) -> FrickmailConfig {
        let mut config = test_config(None);
        config.frickmail_user.allow_message_append = allow_message_append;
        config
    }

    fn folder_append_headers() -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "multipart/form-data; boundary=frickmail".parse().unwrap(),
        );
        headers
    }

    fn folder_append_multipart_body(folder: &str, raw: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(
            b"--frickmail\r\nContent-Disposition: form-data; name=\"folder\"\r\n\r\n",
        );
        body.extend_from_slice(folder.as_bytes());
        body.extend_from_slice(
            b"\r\n--frickmail\r\nContent-Disposition: form-data; name=\"appendFile\"; filename=\"message.eml\"\r\nContent-Type: message/rfc822\r\n\r\n",
        );
        body.extend_from_slice(raw);
        body.extend_from_slice(b"\r\n--frickmail--\r\n");
        body
    }

    fn folder_append_multipart_body_with_action(action: &str, folder: &str, raw: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(
            b"--frickmail\r\nContent-Disposition: form-data; name=\"Action\"\r\n\r\n",
        );
        body.extend_from_slice(action.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(&folder_append_multipart_body(folder, raw));
        body
    }

    fn test_session() -> Session {
        Session::new(None, Arc::new(MemoryStore::default()), None)
    }

    async fn accept_mail_account_bridge_validation(
        _validation: super::MailAccountBridgeValidation,
    ) -> fm_core::Result<()> {
        Ok(())
    }

    async fn reject_mail_account_bridge_validation(
        validation: super::MailAccountBridgeValidation,
    ) -> fm_core::Result<()> {
        assert!(matches!(
            validation,
            super::MailAccountBridgeValidation::Imap { .. }
        ));
        Err(FrickmailError::Upstream(
            "IMAP authentication failed".to_string(),
        ))
    }

    async fn reject_oauth_bridge_validation(
        validation: super::MailAccountBridgeValidation,
    ) -> fm_core::Result<()> {
        assert!(matches!(
            validation,
            super::MailAccountBridgeValidation::OAuth { .. }
        ));
        Err(FrickmailError::Upstream("OAuth refresh failed".to_string()))
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
        message_body_test_state_with_config_and_settings(
            user_id,
            account_id,
            credential_key,
            test_config(None),
            json!({}),
        )
        .await
    }

    async fn message_body_test_state_with_settings(
        user_id: i64,
        account_id: i64,
        credential_key: &[u8],
        settings: Value,
    ) -> (AppState, Session) {
        message_body_test_state_with_config_and_settings(
            user_id,
            account_id,
            credential_key,
            test_config(None),
            settings,
        )
        .await
    }

    async fn message_body_test_state_with_config(
        user_id: i64,
        account_id: i64,
        credential_key: &[u8],
        config: FrickmailConfig,
    ) -> (AppState, Session) {
        message_body_test_state_with_config_and_settings(
            user_id,
            account_id,
            credential_key,
            config,
            json!({}),
        )
        .await
    }

    async fn message_body_test_state_with_config_and_settings(
        user_id: i64,
        account_id: i64,
        credential_key: &[u8],
        config: FrickmailConfig,
        settings: Value,
    ) -> (AppState, Session) {
        let pool = user_db_pool().await;
        create_mail_account_tables(&pool).await;
        seed_user_with_settings(
            &pool,
            user_id,
            &format!("viewer{user_id}"),
            Some(&format!("viewer{user_id}@example.com")),
            settings,
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
        (AppState::with_db_pool(config, Some(pool)), session)
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

    async fn set_mail_account_oauth_token(
        pool: &AnyPool,
        account_id: i64,
        email: &str,
        refresh_token: &str,
        tenant: Option<&str>,
        credential_key: &[u8],
    ) {
        sqlx::query(
            "UPDATE frickmail_mail_accounts
             SET email = ?, type = 'o365', login = ?, encrypted_password = NULL,
                 encrypted_oauth_refresh_token = ?, oauth_tenant = ?
             WHERE id = ?",
        )
        .bind(email)
        .bind(email)
        .bind(fm_user::encrypt_account_secret(refresh_token, credential_key).unwrap())
        .bind(tenant.map(ToOwned::to_owned))
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

    async fn clear_mail_account_password(pool: &AnyPool, account_id: i64) {
        set_mail_account_password_blob(pool, account_id, None).await;
    }

    async fn set_mail_account_password_blob(
        pool: &AnyPool,
        account_id: i64,
        blob: Option<Vec<u8>>,
    ) {
        sqlx::query("UPDATE frickmail_mail_accounts SET encrypted_password = ? WHERE id = ?")
            .bind(blob)
            .bind(account_id)
            .execute(pool)
            .await
            .unwrap();
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
        let (pem, _, _) = test_smime_cert_material(email);
        pem
    }

    fn test_smime_p12_der(email: &str, password: &str) -> Vec<u8> {
        let (_, key, cert) = test_smime_cert_material(email);
        Pkcs12::builder()
            .name(email)
            .pkey(&key)
            .cert(&cert)
            .build2(password)
            .unwrap()
            .to_der()
            .unwrap()
    }

    fn test_smime_cert_material(email: &str) -> (String, PKey<Private>, X509) {
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

        let cert = builder.build();
        (
            String::from_utf8(cert.to_pem().unwrap()).unwrap(),
            key,
            cert,
        )
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
            authorization: headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            ttl: headers
                .get("ttl")
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

    fn legacy_test_folder_information() -> LegacyFolderInformation {
        LegacyFolderInformation {
            name: "INBOX".to_string(),
            uid_next: Some(52),
            uid_validity: Some(10),
            total_emails: Some(12),
            unread_emails: Some(3),
            highest_modseq: Some(99),
            append_limit: None,
            size: None,
            permanent_flags: vec!["\\seen".to_string()],
            etag: "etag-2".to_string(),
            messages_flags: Some(vec![LegacyMessageFlags {
                uid: 41,
                flags: vec!["\\seen".to_string()],
            }]),
            new_messages: vec![LegacyNewMessage {
                folder: "INBOX".to_string(),
                uid: 51,
                subject: "Fresh mail".to_string(),
                from: "Fresh <fresh@example.com>".to_string(),
            }],
        }
    }

    fn legacy_test_message_summary() -> LegacyMessageSummary {
        LegacyMessageSummary {
            folder: "INBOX".to_string(),
            uid: 44,
            hash: "summary-hash".to_string(),
            subject: "Staged summary".to_string(),
            encrypted: true,
            message_id: "<message@example.com>".to_string(),
            spam_score: 100,
            spam_result: "7.13 / 9.00".to_string(),
            is_spam: true,
            in_reply_to: "<previous@example.com>".to_string(),
            references: "<one@example> <two@example>".to_string(),
            from: "Alice <alice@example.com>".to_string(),
            reply_to: "Reply <reply@example.com>".to_string(),
            to: "Bob <bob@example.com>".to_string(),
            cc: "Carol <carol@example.com>".to_string(),
            bcc: "Hidden <hidden@example.com>".to_string(),
            sender: "Sender <sender@example.com>".to_string(),
            delivered_to: "delivered@example.com".to_string(),
            read_receipt: "Receipt <receipt@example.com>".to_string(),
            date: "Tue, 1 Jul 2003 10:52:37 +0200".to_string(),
            date_timestamp: 1_057_049_557,
            date_timestamp_source: "header".to_string(),
            size: 4096,
            flags: vec!["\\seen".to_string(), "$label1".to_string()],
            has_attachments: true,
            attachments: vec![LegacyAttachmentSummary {
                object: "Object/Attachment".to_string(),
                folder: "INBOX".to_string(),
                uid: 44,
                mime_index: "2".to_string(),
                mime_type: "application/pdf".to_string(),
                file_name: "report.pdf".to_string(),
                estimated_size: 768,
                c_id: "<part@example.com>".to_string(),
                content_location: "cid:report".to_string(),
                is_inline: true,
            }],
            preview: Some("Preview text".to_string()),
        }
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }
}
