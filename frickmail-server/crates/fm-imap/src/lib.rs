use std::{collections::HashSet, fmt, sync::Arc, time::Duration};

use async_imap::{
    types::{Capabilities, Capability, Flag},
    Client, Session,
};
use fm_core::{FrickmailError, Result};
use futures::{pin_mut, TryStreamExt};
use imap_proto::{
    builders::command::{Command, CommandBuilder},
    AttributeValue, BodyStructure, MessageSection, Response, SectionPath, Status,
};
use md5::{Digest, Md5};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore},
    TlsConnector,
};

const DEFAULT_TLS_PORT: u16 = 993;
const DEFAULT_PLAIN_PORT: u16 = 143;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
pub const BODY_PREVIEW_PART_LIMIT_BYTES: usize = 256 * 1024;

trait ImapIo:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + fmt::Debug + 'static
{
}

impl<T> ImapIo for T where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + fmt::Debug + 'static
{
}

type BoxedImapIo = Box<dyn ImapIo>;
type BoxedClient = Client<BoxedImapIo>;
type BoxedSession = Session<BoxedImapIo>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImapSecurity {
    Tls,
    StartTls,
    None,
}

impl ImapSecurity {
    pub fn default_port(self) -> u16 {
        match self {
            Self::Tls => DEFAULT_TLS_PORT,
            Self::StartTls | Self::None => DEFAULT_PLAIN_PORT,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImapLoginProbe {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_security")]
    pub security: ImapSecurity,
    pub login: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImapConnectionConfig {
    pub host: String,
    pub port: u16,
    pub security: ImapSecurity,
    pub login: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawFolderFetchLimits {
    pub max_messages: usize,
    pub max_bytes: usize,
}

impl ImapConnectionConfig {
    pub fn new(
        host: impl Into<String>,
        port: Option<u16>,
        secure: Option<&str>,
        login: impl Into<String>,
    ) -> Result<Self> {
        let security = parse_security(secure)?;
        let host = required_ascii_field("IMAP host", host.into())?;
        let login = required_field("IMAP login", login.into())?;
        let port = port
            .filter(|port| *port > 0)
            .unwrap_or_else(|| security.default_port());

        Ok(Self {
            host,
            port,
            security,
            login,
        })
    }
}

impl TryFrom<ImapLoginProbe> for ImapConnectionConfig {
    type Error = FrickmailError;

    fn try_from(probe: ImapLoginProbe) -> Result<Self> {
        let host = required_ascii_field("IMAP host", probe.host)?;
        let login = required_field("IMAP login", probe.login)?;
        let port = if probe.port == 0 {
            probe.security.default_port()
        } else {
            probe.port
        };

        Ok(Self {
            host,
            port,
            security: probe.security,
            login,
        })
    }
}

pub async fn probe_login(probe: ImapLoginProbe, password: &str) -> Result<()> {
    let session = login(ImapConnectionConfig::try_from(probe)?, password).await?;
    logout_quietly(session).await;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyPreviewPart {
    pub kind: BodyPartKind,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxStatus {
    pub uid_next: Option<u32>,
    pub exists: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyFolderInformation {
    pub name: String,
    pub uid_next: Option<u32>,
    pub uid_validity: Option<u32>,
    pub total_emails: Option<u32>,
    pub unread_emails: Option<u32>,
    pub highest_modseq: Option<u64>,
    pub permanent_flags: Vec<String>,
    pub etag: String,
    pub messages_flags: Option<Vec<LegacyMessageFlags>>,
    pub new_messages: Vec<LegacyNewMessage>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyMessageFlags {
    pub uid: u32,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyNewMessage {
    pub folder: String,
    pub uid: u32,
    pub subject: String,
    pub from: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyMessageList {
    pub folder: LegacyFolderInformation,
    pub total_emails: u32,
    pub offset: u32,
    pub limit: u32,
    pub search: String,
    pub sort: String,
    pub limited: bool,
    pub thread_uid: u32,
    pub messages: Vec<LegacyMessageSummary>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyMessageSummary {
    pub folder: String,
    pub uid: u32,
    pub hash: String,
    pub subject: String,
    pub message_id: String,
    pub in_reply_to: String,
    pub references: String,
    pub from: String,
    pub reply_to: String,
    pub to: String,
    pub cc: String,
    pub date: String,
    pub size: u32,
    pub flags: Vec<String>,
    pub preview: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMessageListRequest {
    pub mailbox: String,
    pub offset: u32,
    pub limit: u32,
    pub search: String,
    pub sort: String,
    pub prev_uid_next: Option<u32>,
    pub thread_uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleExecutionPlan {
    pub rule_id: i64,
    pub rule_name: String,
    pub conditions: Vec<RuleCondition>,
    pub conditions_logic: RuleConditionsLogic,
    pub actions: Vec<RuleAction>,
    pub action_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleConditionsLogic {
    All,
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCondition {
    pub field: RuleConditionField,
    pub op: RuleConditionOp,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleConditionField {
    From,
    Subject,
    To,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleConditionOp {
    Contains,
    NotContains,
    Equals,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Move { folder: String },
    Read,
    Flag,
    Delete,
    Noop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImapMessageFlag {
    Seen,
    Flagged,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImapMoveLearning {
    Spam,
    Ham,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImapMoveOptions {
    pub mark_as_read: bool,
    pub learning: Option<ImapMoveLearning>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleExecutionResult {
    pub rule_id: i64,
    pub rule_name: String,
    pub matched_count: usize,
    pub action_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleExecutionReport {
    pub applied: Vec<RuleExecutionResult>,
    pub executed_rule_ids: Vec<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImapRuleCapabilities {
    supports_move: bool,
    supports_uidplus: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyPartKind {
    Html,
    Plain,
    RawMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BodyPartSpec {
    path: Option<[u32; 8]>,
    depth: usize,
    kind: BodyPartKind,
    octets: u32,
}

impl BodyPartSpec {
    fn path_vec(self) -> Option<Vec<u32>> {
        self.path.map(|path| path[..self.depth].to_vec())
    }
}

pub async fn fetch_message_body_preview(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    uid: u32,
) -> Result<Option<Vec<BodyPreviewPart>>> {
    validate_mailbox(mailbox)?;
    if uid == 0 {
        return Err(FrickmailError::BadRequest("uid required".to_string()));
    }

    let mut session = login(config, password).await?;
    timeout_imap("examine mailbox", session.examine(mailbox)).await?;
    let Some(specs) = fetch_body_part_specs(&mut session, uid).await? else {
        logout_quietly(session).await;
        return Ok(None);
    };
    let parts = fetch_preview_parts(&mut session, uid, &specs).await?;
    logout_quietly(session).await;
    Ok(Some(parts))
}

pub async fn fetch_mailbox_status(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
) -> Result<MailboxStatus> {
    validate_mailbox(mailbox)?;

    let mut session = login(config, password).await?;
    let mailbox = timeout_imap("examine mailbox", session.examine(mailbox)).await?;
    logout_quietly(session).await;

    Ok(MailboxStatus {
        uid_next: mailbox.uid_next,
        exists: mailbox.exists,
    })
}

pub async fn fetch_legacy_folder_information(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    prev_uid_next: Option<u32>,
    flag_uids: Option<Vec<u32>>,
    fetch_new_messages: bool,
) -> Result<LegacyFolderInformation> {
    validate_mailbox(mailbox)?;

    let client_hash = legacy_imap_client_hash(&config);
    let mut session = login(config, password).await?;
    let result = legacy_folder_information_in_session(
        &mut session,
        mailbox,
        prev_uid_next,
        flag_uids.as_deref(),
        fetch_new_messages,
        &client_hash,
    )
    .await;
    logout_quietly(session).await;
    result
}

pub async fn fetch_legacy_message_list(
    config: ImapConnectionConfig,
    password: &str,
    request: LegacyMessageListRequest,
) -> Result<LegacyMessageList> {
    validate_mailbox(&request.mailbox)?;

    let client_hash = legacy_imap_client_hash(&config);
    let mut session = login(config, password).await?;
    let result = legacy_message_list_in_session(&mut session, request, &client_hash).await;
    logout_quietly(session).await;
    result
}

pub async fn fetch_raw_message(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    uid: u32,
) -> Result<Option<Vec<u8>>> {
    validate_mailbox(mailbox)?;
    if uid == 0 {
        return Err(FrickmailError::BadRequest("uid required".to_string()));
    }

    let mut session = login(config, password).await?;
    timeout_imap("examine mailbox", session.examine(mailbox)).await?;
    let raw = fetch_raw_message_in_session(&mut session, uid).await?;
    logout_quietly(session).await;
    Ok(raw)
}

pub async fn fetch_raw_folder_messages(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    limits: RawFolderFetchLimits,
) -> Result<Vec<Vec<u8>>> {
    validate_mailbox(mailbox)?;

    let mut session = login(config, password).await?;
    let folder = timeout_imap("examine mailbox", session.examine(mailbox)).await?;
    let messages = fetch_raw_messages_by_sequence(&mut session, folder.exists, limits).await?;
    logout_quietly(session).await;
    Ok(messages)
}

pub async fn append_raw_message(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    raw: &[u8],
) -> Result<()> {
    append_raw_message_with_flags(config, password, mailbox, raw, Some("(\\Seen)")).await
}

pub async fn append_raw_message_without_flags(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    raw: &[u8],
) -> Result<()> {
    append_raw_message_with_flags(config, password, mailbox, raw, None).await
}

async fn append_raw_message_with_flags(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    raw: &[u8],
    flags: Option<&str>,
) -> Result<()> {
    validate_mailbox(mailbox)?;
    validate_eml(raw)?;

    let mut session = login(config, password).await?;
    timeout_imap(
        "append raw message",
        session.append(mailbox, flags, None, raw),
    )
    .await?;
    logout_quietly(session).await;
    Ok(())
}

pub async fn store_message_flag(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    uid_set: &str,
    flag: ImapMessageFlag,
    set: bool,
) -> Result<()> {
    validate_mailbox(mailbox)?;
    validate_uid_set(uid_set)?;

    let mut session = login(config, password).await?;
    timeout_imap("select mailbox", session.select(mailbox)).await?;
    let query = store_flag_query(flag, set);
    let result = drain_uid_store(&mut session, uid_set, query, "store message flag").await;
    logout_quietly(session).await;
    result
}

pub async fn store_message_keyword(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    uid_set: &str,
    keyword: &str,
    set: bool,
) -> Result<()> {
    validate_mailbox(mailbox)?;
    validate_uid_set(uid_set)?;
    if !keyword_can_be_stored(keyword) {
        return Ok(());
    }

    let mut session = login(config, password).await?;
    let selected = timeout_imap("select mailbox", session.select(mailbox)).await?;
    if !keyword_supported(&selected, keyword) {
        logout_quietly(session).await;
        return Ok(());
    }
    let query = store_keyword_query(keyword, set);
    let result = drain_uid_store(&mut session, uid_set, &query, "store message keyword").await;
    logout_quietly(session).await;
    result
}

pub async fn store_seen_to_all(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    thread_uid_set: Option<&str>,
    set: bool,
) -> Result<()> {
    validate_mailbox(mailbox)?;
    if let Some(uid_set) = thread_uid_set.filter(|value| !value.trim().is_empty()) {
        validate_uid_set(uid_set)?;
    }

    let mut session = login(config, password).await?;
    timeout_imap("select mailbox", session.select(mailbox)).await?;
    let query = store_flag_query(ImapMessageFlag::Seen, set);
    let result = if let Some(uid_set) = thread_uid_set.filter(|value| !value.trim().is_empty()) {
        drain_uid_store(&mut session, uid_set, query, "store seen thread messages").await
    } else {
        drain_sequence_store(&mut session, "1:*", query, "store seen all messages").await
    };
    logout_quietly(session).await;
    result
}

pub async fn copy_messages(
    config: ImapConnectionConfig,
    password: &str,
    from_mailbox: &str,
    to_mailbox: &str,
    uid_set: &str,
) -> Result<()> {
    validate_mailbox(from_mailbox)?;
    validate_mailbox(to_mailbox)?;
    validate_uid_set(uid_set)?;

    let mut session = login(config, password).await?;
    timeout_imap("select source mailbox", session.select(from_mailbox)).await?;
    let result = timeout_imap("copy messages", session.uid_copy(uid_set, to_mailbox)).await;
    logout_quietly(session).await;
    result.map(|_| ())
}

pub async fn move_messages(
    config: ImapConnectionConfig,
    password: &str,
    from_mailbox: &str,
    to_mailbox: &str,
    uid_set: &str,
    options: ImapMoveOptions,
) -> Result<()> {
    validate_mailbox(from_mailbox)?;
    validate_mailbox(to_mailbox)?;
    validate_uid_set(uid_set)?;

    let mut session = login(config, password).await?;
    let capabilities = imap_rule_capabilities(&mut session).await?;
    timeout_imap("select source mailbox", session.select(from_mailbox)).await?;
    apply_legacy_move_pre_flags(&mut session, uid_set, options).await;
    let result = if capabilities.supports_move {
        timeout_imap("move messages", session.uid_mv(uid_set, to_mailbox))
            .await
            .map(|_| ())
    } else {
        match timeout_imap("copy messages", session.uid_copy(uid_set, to_mailbox)).await {
            Ok(_) => delete_rule_messages(&mut session, capabilities, uid_set).await,
            Err(err) => Err(err),
        }
    };
    logout_quietly(session).await;
    result
}

pub async fn delete_messages(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    uid_set: &str,
) -> Result<()> {
    validate_mailbox(mailbox)?;
    validate_uid_set(uid_set)?;

    let mut session = login(config, password).await?;
    let capabilities = imap_rule_capabilities(&mut session).await?;
    timeout_imap("select mailbox", session.select(mailbox)).await?;
    let result = delete_rule_messages(&mut session, capabilities, uid_set).await;
    logout_quietly(session).await;
    result
}

pub async fn apply_imap_rules(
    config: ImapConnectionConfig,
    password: &str,
    rules: &[RuleExecutionPlan],
) -> Result<RuleExecutionReport> {
    if rules.is_empty() {
        return Ok(RuleExecutionReport {
            applied: Vec::new(),
            executed_rule_ids: Vec::new(),
        });
    }

    let mut session = login(config, password).await?;
    let capabilities = imap_rule_capabilities(&mut session).await?;
    timeout_imap("select mailbox", session.select("INBOX")).await?;
    let result = apply_imap_rules_in_session(&mut session, capabilities, rules).await;
    logout_quietly(session).await;
    result
}

pub fn parse_security(secure: Option<&str>) -> Result<ImapSecurity> {
    let value = secure.unwrap_or("SSL").trim();
    if value.is_empty() {
        return Ok(ImapSecurity::Tls);
    }

    match value.to_ascii_uppercase().as_str() {
        "SSL" | "TLS" => Ok(ImapSecurity::Tls),
        "STARTTLS" => Ok(ImapSecurity::StartTls),
        "NONE" | "PLAIN" | "UNENCRYPTED" => Ok(ImapSecurity::None),
        other => Err(FrickmailError::BadRequest(format!(
            "unsupported IMAP secure mode '{other}'"
        ))),
    }
}

pub fn examine_mailbox_command(mailbox: &str) -> Result<Vec<u8>> {
    validate_mailbox(mailbox)?;
    let command: Command = CommandBuilder::examine(mailbox).into();
    Ok(command.args)
}

pub fn uid_fetch_bodystructure_query(uid: u32) -> Result<&'static str> {
    if uid == 0 {
        return Err(FrickmailError::BadRequest("uid required".to_string()));
    }

    Ok("(UID RFC822.SIZE BODYSTRUCTURE)")
}

pub fn uid_fetch_raw_message_query(uid: u32) -> Result<&'static str> {
    if uid == 0 {
        return Err(FrickmailError::BadRequest("uid required".to_string()));
    }

    Ok("(UID BODY.PEEK[])")
}

pub fn sequence_fetch_raw_message_query() -> &'static str {
    "(BODY.PEEK[])"
}

pub fn legacy_message_list_fetch_query() -> &'static str {
    "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER])"
}

pub fn legacy_message_flags_fetch_query() -> &'static str {
    "(UID FLAGS)"
}

pub fn legacy_new_messages_fetch_query() -> &'static str {
    "(UID FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT CONTENT-TYPE)])"
}

pub fn message_list_sequence_range(total: u32, offset: u32, limit: u32) -> Option<String> {
    if total == 0 || limit == 0 || offset >= total {
        return None;
    }
    let last = total - offset;
    let first = last.saturating_sub(limit.saturating_sub(1)).max(1);
    Some(if first == last {
        first.to_string()
    } else {
        format!("{first}:{last}")
    })
}

pub fn legacy_uid_sequence_set(uids: &[u32]) -> Option<String> {
    let mut uids = uids
        .iter()
        .copied()
        .filter(|uid| *uid > 0)
        .collect::<Vec<_>>();
    if uids.is_empty() {
        return None;
    }
    uids.sort_unstable();
    uids.dedup();
    Some(
        uids.into_iter()
            .map(|uid| uid.to_string())
            .collect::<Vec<_>>()
            .join(","),
    )
}

pub fn validate_eml(raw: &[u8]) -> Result<()> {
    let trimmed = trim_ascii_whitespace(raw);
    if trimmed.is_empty() {
        return Err(FrickmailError::BadRequest("Empty EML content".to_string()));
    }
    if !looks_like_rfc2822_message(trimmed) {
        return Err(FrickmailError::BadRequest(
            "Invalid EML format: file does not look like an RFC 2822 message".to_string(),
        ));
    }
    Ok(())
}

pub fn legacy_folder_etag(
    mailbox: &str,
    total: u32,
    uid_next: Option<u32>,
    uid_validity: Option<u32>,
    unread: Option<u32>,
    highest_modseq: Option<u64>,
    client_hash: &str,
) -> String {
    md5_hex(format!(
        "FolderHash/{mailbox}-{total}-{}-{}-{}-{}-{client_hash}",
        uid_next.map(|value| value.to_string()).unwrap_or_default(),
        uid_validity
            .map(|value| value.to_string())
            .unwrap_or_default(),
        unread.map(|value| value.to_string()).unwrap_or_default(),
        highest_modseq
            .map(|value| value.to_string())
            .unwrap_or_default()
    ))
}

pub fn legacy_imap_client_hash(config: &ImapConnectionConfig) -> String {
    md5_hex(format!(
        "ImapClientHash/{}@{}:{}",
        config.login, config.host, config.port
    ))
}

pub fn legacy_new_uid_range(prev_uid_next: Option<u32>, uid_next: Option<u32>) -> Vec<u32> {
    let Some(prev) = prev_uid_next.filter(|value| *value > 0) else {
        return Vec::new();
    };
    let Some(next) = uid_next.filter(|value| *value > prev) else {
        return Vec::new();
    };
    (prev..next).collect()
}

pub fn legacy_message_hash(folder: &str, uid: u32) -> String {
    md5_hex(format!("{folder}{uid}"))
}

fn md5_hex(input: impl AsRef<[u8]>) -> String {
    let mut digest = Md5::new();
    digest.update(input.as_ref());
    format!("{:x}", digest.finalize())
}

fn legacy_flag_string(flag: &Flag<'_>) -> String {
    match flag {
        Flag::Seen => "\\seen".to_string(),
        Flag::Answered => "\\answered".to_string(),
        Flag::Flagged => "\\flagged".to_string(),
        Flag::Deleted => "\\deleted".to_string(),
        Flag::Draft => "\\draft".to_string(),
        Flag::Recent => "\\recent".to_string(),
        Flag::MayCreate => "\\*".to_string(),
        Flag::Custom(value) => value.as_ref().to_ascii_lowercase(),
    }
}

fn header_value(raw: &[u8], name: &str) -> Option<String> {
    let mut matched = false;
    let mut value = String::new();
    let wanted = name.to_ascii_lowercase();

    for line in String::from_utf8_lossy(raw).lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if matched {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        matched = false;
        let Some((key, next)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case(&wanted) {
            value = next.trim().to_string();
            matched = true;
        }
    }

    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

pub fn imap_rule_search_criteria(
    conditions: &[RuleCondition],
    logic: RuleConditionsLogic,
) -> Result<Option<String>> {
    let mut criteria = Vec::new();
    for condition in conditions {
        if condition.value.is_empty() {
            continue;
        }
        let quoted = imap_quote_search_value(&condition.value)?;
        let field = match condition.field {
            RuleConditionField::From => "FROM",
            RuleConditionField::Subject => "SUBJECT",
            RuleConditionField::To => "TO",
        };
        let header = match condition.field {
            RuleConditionField::From => "From",
            RuleConditionField::Subject => "Subject",
            RuleConditionField::To => "To",
        };
        let criterion = match condition.op {
            RuleConditionOp::NotContains => format!("NOT {field} {quoted}"),
            RuleConditionOp::Equals => format!("HEADER {header} {quoted}"),
            RuleConditionOp::Contains => format!("{field} {quoted}"),
        };
        criteria.push(criterion);
    }

    if criteria.is_empty() {
        return Ok(None);
    }
    if logic == RuleConditionsLogic::Any && criteria.len() > 1 {
        return Ok(Some(imap_rule_any_or(&criteria)));
    }
    Ok(Some(criteria.join(" ")))
}

pub fn uid_sequence_set(uids: &HashSet<u32>) -> String {
    let mut sorted = uids.iter().copied().collect::<Vec<_>>();
    sorted.sort_unstable();
    let mut ranges = Vec::new();
    let mut iter = sorted.into_iter();
    let Some(mut start) = iter.next() else {
        return String::new();
    };
    let mut end = start;

    for uid in iter {
        if uid == end.saturating_add(1) {
            end = uid;
            continue;
        }
        ranges.push(uid_range(start, end));
        start = uid;
        end = uid;
    }
    ranges.push(uid_range(start, end));
    ranges.join(",")
}

pub fn parse_uid_fetch_body_preview(input: &[u8], expected_uid: u32) -> Result<Option<Vec<u8>>> {
    if expected_uid == 0 {
        return Err(FrickmailError::BadRequest("uid required".to_string()));
    }

    let mut remaining = input;
    let mut matched_body = None;

    while !remaining.is_empty() {
        let before = remaining.len();
        let (tail, response) = Response::from_bytes(remaining)
            .map_err(|err| FrickmailError::Upstream(format!("invalid IMAP response: {err:?}")))?;
        if tail.len() == before {
            return Err(FrickmailError::Upstream(
                "invalid IMAP response: parser made no progress".to_string(),
            ));
        }
        remaining = tail;

        match response {
            Response::Fetch(_, attrs) => {
                if let Some(body) = fetch_body_for_uid(&attrs, expected_uid) {
                    matched_body = Some(body);
                }
            }
            Response::Done {
                status: Status::Ok, ..
            } => {}
            Response::Done {
                status,
                information,
                ..
            }
            | Response::Data {
                status,
                information,
                ..
            } if matches!(status, Status::No | Status::Bad | Status::Bye) => {
                let message = information
                    .as_deref()
                    .unwrap_or("IMAP command failed")
                    .to_string();
                return Err(FrickmailError::Upstream(message));
            }
            _ => {}
        }
    }

    Ok(matched_body)
}

async fn fetch_raw_message_in_session(
    session: &mut BoxedSession,
    uid: u32,
) -> Result<Option<Vec<u8>>> {
    let mut fetches = timeout_imap(
        "fetch raw message",
        session.uid_fetch(uid.to_string(), uid_fetch_raw_message_query(uid)?),
    )
    .await?;

    while let Some(fetch) = timeout_imap("read raw message", fetches.try_next()).await? {
        if fetch.uid != Some(uid) {
            continue;
        }
        return Ok(fetch.body().map(ToOwned::to_owned));
    }

    Ok(None)
}

async fn legacy_folder_information_in_session(
    session: &mut BoxedSession,
    mailbox: &str,
    prev_uid_next: Option<u32>,
    flag_uids: Option<&[u32]>,
    fetch_new_messages: bool,
    client_hash: &str,
) -> Result<LegacyFolderInformation> {
    let status = timeout_imap(
        "status mailbox",
        session.status(mailbox, "(MESSAGES UIDNEXT UIDVALIDITY UNSEEN)"),
    )
    .await?;
    let selected = if flag_uids.is_some() {
        timeout_imap("select mailbox", session.select(mailbox)).await?
    } else {
        timeout_imap("examine mailbox", session.examine(mailbox)).await?
    };
    let mut info = legacy_folder_information_from_mailboxes(
        mailbox,
        &status,
        &selected,
        prev_uid_next,
        client_hash,
    );
    if let Some(flag_uids) = flag_uids {
        info.messages_flags = Some(fetch_legacy_message_flags(session, flag_uids).await?);
    }
    if fetch_new_messages {
        info.new_messages =
            fetch_legacy_new_messages(session, mailbox, prev_uid_next, info.uid_next).await?;
    }
    Ok(info)
}

async fn legacy_message_list_in_session(
    session: &mut BoxedSession,
    request: LegacyMessageListRequest,
    client_hash: &str,
) -> Result<LegacyMessageList> {
    let folder = legacy_folder_information_in_session(
        session,
        &request.mailbox,
        request.prev_uid_next,
        None,
        true,
        client_hash,
    )
    .await?;
    let total = folder.total_emails.unwrap_or_default();
    let limit = request.limit.clamp(1, 200);
    let range = message_list_sequence_range(total, request.offset, limit);
    let mut messages = Vec::new();

    if let Some(range) = range {
        let mut fetches = timeout_imap(
            "fetch legacy message list",
            session.fetch(range, legacy_message_list_fetch_query()),
        )
        .await?;

        while let Some(fetch) =
            timeout_imap("read legacy message list item", fetches.try_next()).await?
        {
            let Some(uid) = fetch.uid else {
                continue;
            };
            let header = fetch.header().unwrap_or_default();
            messages.push(legacy_message_summary_from_fetch(
                &request.mailbox,
                uid,
                fetch.size.unwrap_or_default(),
                fetch.flags(),
                header,
            ));
        }
        messages.sort_by_key(|message| std::cmp::Reverse(message.uid));
    }

    let limited = (request.offset as u64 + messages.len() as u64) < total as u64;
    Ok(LegacyMessageList {
        folder,
        total_emails: total,
        offset: request.offset,
        limit,
        search: request.search,
        sort: request.sort,
        limited,
        thread_uid: request.thread_uid,
        messages,
    })
}

fn legacy_folder_information_from_mailboxes(
    mailbox: &str,
    status: &async_imap::types::Mailbox,
    examined: &async_imap::types::Mailbox,
    prev_uid_next: Option<u32>,
    client_hash: &str,
) -> LegacyFolderInformation {
    let uid_next = status.uid_next.or(examined.uid_next);
    let uid_validity = status.uid_validity.or(examined.uid_validity);
    let total_emails = Some(status.exists);
    let unread_emails = status.unseen.or(examined.unseen);
    let highest_modseq = status.highest_modseq.or(examined.highest_modseq);
    let permanent_flags = examined
        .permanent_flags
        .iter()
        .map(legacy_flag_string)
        .collect::<Vec<_>>();
    let etag = legacy_folder_etag(
        mailbox,
        status.exists,
        uid_next,
        uid_validity,
        unread_emails,
        highest_modseq,
        client_hash,
    );
    let _new_uid_range = legacy_new_uid_range(prev_uid_next, uid_next);

    LegacyFolderInformation {
        name: mailbox.to_string(),
        uid_next,
        uid_validity,
        total_emails,
        unread_emails,
        highest_modseq,
        permanent_flags,
        etag,
        messages_flags: None,
        new_messages: Vec::new(),
    }
}

async fn fetch_legacy_message_flags(
    session: &mut BoxedSession,
    flag_uids: &[u32],
) -> Result<Vec<LegacyMessageFlags>> {
    let Some(uid_set) = legacy_uid_sequence_set(flag_uids) else {
        return Ok(Vec::new());
    };
    let mut fetches = timeout_imap(
        "fetch legacy message flags",
        session.uid_fetch(uid_set, legacy_message_flags_fetch_query()),
    )
    .await?;
    let mut messages = Vec::new();

    while let Some(fetch) =
        timeout_imap("read legacy message flags item", fetches.try_next()).await?
    {
        let Some(uid) = fetch.uid else {
            continue;
        };
        messages.push(LegacyMessageFlags {
            uid,
            flags: fetch
                .flags()
                .map(|flag| legacy_flag_string(&flag))
                .collect(),
        });
    }

    Ok(messages)
}

async fn fetch_legacy_new_messages(
    session: &mut BoxedSession,
    mailbox: &str,
    prev_uid_next: Option<u32>,
    current_uid_next: Option<u32>,
) -> Result<Vec<LegacyNewMessage>> {
    let Some(prev_uid_next) = prev_uid_next.filter(|value| *value > 0) else {
        return Ok(Vec::new());
    };
    if current_uid_next == Some(prev_uid_next) || !mailbox.eq_ignore_ascii_case("INBOX") {
        return Ok(Vec::new());
    }

    let mut fetches = timeout_imap(
        "fetch legacy new messages",
        session.uid_fetch(
            format!("{prev_uid_next}:*"),
            legacy_new_messages_fetch_query(),
        ),
    )
    .await?;
    let mut messages = Vec::new();

    while let Some(fetch) = timeout_imap("read legacy new message item", fetches.try_next()).await?
    {
        let Some(uid) = fetch.uid else {
            continue;
        };
        let flags = fetch
            .flags()
            .map(|flag| legacy_flag_string(&flag))
            .collect::<Vec<_>>();
        if flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\seen")) {
            continue;
        }
        let header = fetch.header().unwrap_or_default();
        messages.push(LegacyNewMessage {
            folder: mailbox.to_string(),
            uid,
            subject: header_value(header, "Subject").unwrap_or_default(),
            from: header_value(header, "From").unwrap_or_default(),
        });
    }

    Ok(messages)
}

fn legacy_message_summary_from_fetch<'a>(
    folder: &str,
    uid: u32,
    size: u32,
    flags: impl Iterator<Item = Flag<'a>>,
    header: &[u8],
) -> LegacyMessageSummary {
    let subject = header_value(header, "Subject").unwrap_or_default();
    let message_id = header_value(header, "Message-ID")
        .or_else(|| header_value(header, "Message-Id"))
        .unwrap_or_default();
    let in_reply_to = header_value(header, "In-Reply-To").unwrap_or_default();
    let references = header_value(header, "References").unwrap_or_default();
    let from = header_value(header, "From").unwrap_or_default();
    let reply_to = header_value(header, "Reply-To").unwrap_or_default();
    let to = header_value(header, "To").unwrap_or_default();
    let cc = header_value(header, "Cc").unwrap_or_default();
    let date = header_value(header, "Date").unwrap_or_default();
    let flags = flags
        .map(|flag| legacy_flag_string(&flag))
        .collect::<Vec<_>>();

    LegacyMessageSummary {
        folder: folder.to_string(),
        uid,
        hash: legacy_message_hash(folder, uid),
        subject,
        message_id,
        in_reply_to,
        references,
        from,
        reply_to,
        to,
        cc,
        date,
        size,
        flags,
        preview: None,
    }
}

async fn fetch_raw_messages_by_sequence(
    session: &mut BoxedSession,
    total: u32,
    limits: RawFolderFetchLimits,
) -> Result<Vec<Vec<u8>>> {
    if total == 0 {
        return Ok(Vec::new());
    }

    let mut messages = Vec::new();
    let mut total_bytes = 0_usize;
    let batch_size = 50_u32;
    let mut start = 1_u32;
    while start <= total {
        let end = start.saturating_add(batch_size - 1).min(total);
        let range = if start == end {
            start.to_string()
        } else {
            format!("{start}:{end}")
        };
        let mut fetches = timeout_imap(
            "fetch raw folder messages",
            session.fetch(range, sequence_fetch_raw_message_query()),
        )
        .await?;

        while let Some(fetch) = timeout_imap("read raw folder message", fetches.try_next()).await? {
            if let Some(body) = fetch.body().filter(|body| !body.is_empty()) {
                if messages.len() >= limits.max_messages {
                    return Err(FrickmailError::BadRequest(
                        "Folder export exceeds configured message limit".to_string(),
                    ));
                }
                total_bytes = total_bytes
                    .checked_add(body.len())
                    .filter(|bytes| *bytes <= limits.max_bytes)
                    .ok_or_else(|| {
                        FrickmailError::BadRequest(
                            "Folder export exceeds configured size limit".to_string(),
                        )
                    })?;
                messages.push(body.to_vec());
            }
        }
        start = end.saturating_add(1);
    }

    Ok(messages)
}

async fn apply_imap_rules_in_session(
    session: &mut BoxedSession,
    capabilities: ImapRuleCapabilities,
    rules: &[RuleExecutionPlan],
) -> Result<RuleExecutionReport> {
    let mut applied = Vec::new();
    let mut executed_rule_ids = Vec::new();

    for rule in rules {
        if rule.actions.is_empty() {
            continue;
        }
        let Some(criteria) = imap_rule_search_criteria(&rule.conditions, rule.conditions_logic)?
        else {
            continue;
        };
        let uids = timeout_imap("search messages for rule", session.uid_search(criteria)).await?;
        executed_rule_ids.push(rule.rule_id);
        if uids.is_empty() {
            continue;
        }

        let uid_set = uid_sequence_set(&uids);
        for action in &rule.actions {
            apply_rule_action(session, capabilities, &uid_set, action).await?;
        }

        applied.push(RuleExecutionResult {
            rule_id: rule.rule_id,
            rule_name: rule.rule_name.clone(),
            matched_count: uids.len(),
            action_type: rule.action_type.clone(),
        });
    }

    Ok(RuleExecutionReport {
        applied,
        executed_rule_ids,
    })
}

async fn apply_rule_action(
    session: &mut BoxedSession,
    capabilities: ImapRuleCapabilities,
    uid_set: &str,
    action: &RuleAction,
) -> Result<()> {
    match action {
        RuleAction::Move { folder } => {
            validate_mailbox(folder)?;
            if capabilities.supports_move {
                timeout_imap("move rule messages", session.uid_mv(uid_set, folder)).await?;
            } else {
                timeout_imap("copy rule messages", session.uid_copy(uid_set, folder)).await?;
                delete_rule_messages(session, capabilities, uid_set).await?;
            }
        }
        RuleAction::Read => {
            drain_uid_store(
                session,
                uid_set,
                "+FLAGS.SILENT (\\Seen)",
                "mark rule messages read",
            )
            .await?;
        }
        RuleAction::Flag => {
            drain_uid_store(
                session,
                uid_set,
                "+FLAGS.SILENT (\\Flagged)",
                "flag rule messages",
            )
            .await?;
        }
        RuleAction::Delete => {
            delete_rule_messages(session, capabilities, uid_set).await?;
        }
        RuleAction::Noop => {}
    }
    Ok(())
}

async fn delete_rule_messages(
    session: &mut BoxedSession,
    capabilities: ImapRuleCapabilities,
    uid_set: &str,
) -> Result<()> {
    drain_uid_store(
        session,
        uid_set,
        "+FLAGS.SILENT (\\Deleted)",
        "mark rule messages deleted",
    )
    .await?;

    if capabilities.supports_uidplus {
        let expunged = timeout_imap(
            "expunge deleted rule messages",
            session.uid_expunge(uid_set),
        )
        .await?;
        pin_mut!(expunged);
        while timeout_imap("read rule expunge response", expunged.try_next())
            .await?
            .is_some()
        {}
    } else {
        let expunged = timeout_imap("expunge deleted rule messages", session.expunge()).await?;
        pin_mut!(expunged);
        while timeout_imap("read rule expunge response", expunged.try_next())
            .await?
            .is_some()
        {}
    }

    Ok(())
}

async fn drain_uid_store(
    session: &mut BoxedSession,
    uid_set: &str,
    query: &str,
    operation: &'static str,
) -> Result<()> {
    let mut updates = timeout_imap(operation, session.uid_store(uid_set, query)).await?;
    while timeout_imap("read rule store response", updates.try_next())
        .await?
        .is_some()
    {}
    Ok(())
}

async fn drain_sequence_store(
    session: &mut BoxedSession,
    sequence_set: &str,
    query: &str,
    operation: &'static str,
) -> Result<()> {
    let mut updates = timeout_imap(operation, session.store(sequence_set, query)).await?;
    while timeout_imap("read sequence store response", updates.try_next())
        .await?
        .is_some()
    {}
    Ok(())
}

async fn apply_legacy_move_pre_flags(
    session: &mut BoxedSession,
    uid_set: &str,
    options: ImapMoveOptions,
) {
    if options.mark_as_read {
        let _ = drain_uid_store(
            session,
            uid_set,
            "+FLAGS.SILENT (\\Seen)",
            "mark moved messages read",
        )
        .await;
    }

    match options.learning {
        Some(ImapMoveLearning::Spam) => {
            let _ = drain_uid_store(
                session,
                uid_set,
                "+FLAGS.SILENT ($Junk)",
                "mark moved messages junk",
            )
            .await;
            let _ = drain_uid_store(
                session,
                uid_set,
                "-FLAGS.SILENT ($NotJunk)",
                "clear moved messages not-junk",
            )
            .await;
        }
        Some(ImapMoveLearning::Ham) => {
            let _ = drain_uid_store(
                session,
                uid_set,
                "+FLAGS.SILENT ($NotJunk)",
                "mark moved messages not-junk",
            )
            .await;
            let _ = drain_uid_store(
                session,
                uid_set,
                "-FLAGS.SILENT ($Junk)",
                "clear moved messages junk",
            )
            .await;
        }
        None => {}
    }
}

async fn imap_rule_capabilities(session: &mut BoxedSession) -> Result<ImapRuleCapabilities> {
    let capabilities = timeout_imap("read IMAP capabilities", session.capabilities()).await?;
    Ok(ImapRuleCapabilities {
        supports_move: has_capability_ignore_ascii_case(&capabilities, "MOVE"),
        supports_uidplus: has_capability_ignore_ascii_case(&capabilities, "UIDPLUS"),
    })
}

fn fetch_body_for_uid(attrs: &[AttributeValue<'_>], expected_uid: u32) -> Option<Vec<u8>> {
    let uid = attrs.iter().find_map(|attr| match attr {
        AttributeValue::Uid(uid) => Some(*uid),
        _ => None,
    });
    if uid != Some(expected_uid) {
        return None;
    }

    attrs.iter().find_map(|attr| match attr {
        AttributeValue::Rfc822(Some(body))
        | AttributeValue::Rfc822Text(Some(body))
        | AttributeValue::BodySection {
            data: Some(body), ..
        } => Some(body.as_ref().to_vec()),
        _ => None,
    })
}

async fn fetch_body_part_specs(
    session: &mut BoxedSession,
    uid: u32,
) -> Result<Option<Vec<BodyPartSpec>>> {
    let mut fetches = timeout_imap(
        "fetch message body structure",
        session.uid_fetch(uid.to_string(), uid_fetch_bodystructure_query(uid)?),
    )
    .await?;

    while let Some(fetch) = timeout_imap("read body structure", fetches.try_next()).await? {
        if fetch.uid != Some(uid) {
            continue;
        }
        let Some(bodystructure) = fetch.bodystructure() else {
            return Ok(Some(vec![BodyPartSpec {
                path: None,
                depth: 0,
                kind: BodyPartKind::RawMessage,
                octets: BODY_PREVIEW_PART_LIMIT_BYTES as u32,
            }]));
        };
        let specs = body_preview_part_specs(bodystructure);
        if specs.is_empty() {
            return Ok(Some(vec![BodyPartSpec {
                path: None,
                depth: 0,
                kind: BodyPartKind::RawMessage,
                octets: fetch.size.unwrap_or(BODY_PREVIEW_PART_LIMIT_BYTES as u32),
            }]));
        }
        return Ok(Some(specs));
    }

    Ok(None)
}

async fn fetch_preview_parts(
    session: &mut BoxedSession,
    uid: u32,
    specs: &[BodyPartSpec],
) -> Result<Vec<BodyPreviewPart>> {
    let query = body_preview_fetch_query(specs);
    let mut fetches = timeout_imap(
        "fetch message body preview",
        session.uid_fetch(uid.to_string(), query),
    )
    .await?;

    while let Some(fetch) = timeout_imap("read body preview", fetches.try_next()).await? {
        if fetch.uid != Some(uid) {
            continue;
        }

        let mut parts = Vec::new();
        for spec in specs {
            match spec.path_vec() {
                Some(path) => {
                    let mime = fetch
                        .section(&SectionPath::Part(path.clone(), Some(MessageSection::Mime)))
                        .unwrap_or_default();
                    let body = fetch
                        .section(&SectionPath::Part(path, None))
                        .unwrap_or_default();
                    if !body.is_empty() {
                        parts.push(BodyPreviewPart {
                            kind: spec.kind,
                            raw: join_mime_part(mime, body),
                        });
                    }
                }
                None => {
                    if let Some(body) = fetch.body() {
                        parts.push(BodyPreviewPart {
                            kind: BodyPartKind::RawMessage,
                            raw: body.to_vec(),
                        });
                    }
                }
            }
        }

        return Ok(parts);
    }

    Ok(Vec::new())
}

fn body_preview_part_specs(body: &BodyStructure<'_>) -> Vec<BodyPartSpec> {
    let mut html = None;
    let mut plain = None;
    collect_body_preview_part_specs(body, &mut Vec::new(), &mut html, &mut plain);

    [html, plain].into_iter().flatten().collect()
}

fn collect_body_preview_part_specs(
    body: &BodyStructure<'_>,
    path: &mut Vec<u32>,
    html: &mut Option<BodyPartSpec>,
    plain: &mut Option<BodyPartSpec>,
) {
    match body {
        BodyStructure::Text { common, other, .. } if !is_attachment(common) => {
            let Some(path) = path_array(path) else {
                return;
            };
            let kind = if common.ty.subtype.eq_ignore_ascii_case("html") {
                BodyPartKind::Html
            } else if common.ty.subtype.eq_ignore_ascii_case("plain") {
                BodyPartKind::Plain
            } else {
                return;
            };
            let spec = BodyPartSpec {
                path: Some(path),
                depth: path.len(),
                kind,
                octets: other.octets,
            };
            match kind {
                BodyPartKind::Html if html.is_none() => *html = Some(spec),
                BodyPartKind::Plain if plain.is_none() => *plain = Some(spec),
                _ => {}
            }
        }
        BodyStructure::Multipart { bodies, .. } => {
            for (index, child) in bodies.iter().enumerate() {
                path.push((index + 1) as u32);
                collect_body_preview_part_specs(child, path, html, plain);
                path.pop();
                if html.is_some() && plain.is_some() {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn body_preview_fetch_query(specs: &[BodyPartSpec]) -> String {
    let attrs = specs
        .iter()
        .flat_map(|spec| match spec.path_vec() {
            Some(path) => {
                let path = section_path(&path);
                vec![
                    format!("BODY.PEEK[{path}.MIME]"),
                    format!("BODY.PEEK[{path}]<0.{}>", preview_fetch_bytes(spec.octets)),
                ]
            }
            None => vec![format!(
                "BODY.PEEK[]<0.{}>",
                preview_fetch_bytes(spec.octets)
            )],
        })
        .collect::<Vec<_>>()
        .join(" ");

    format!("(UID {attrs})")
}

fn preview_fetch_bytes(octets: u32) -> usize {
    usize::try_from(octets)
        .unwrap_or(BODY_PREVIEW_PART_LIMIT_BYTES)
        .min(BODY_PREVIEW_PART_LIMIT_BYTES)
}

fn section_path(path: &[u32]) -> String {
    path.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn path_array(path: &[u32]) -> Option<[u32; 8]> {
    if path.is_empty() || path.len() > 8 {
        return None;
    }
    let mut out = [0; 8];
    out[..path.len()].copy_from_slice(path);
    Some(out)
}

fn is_attachment(common: &imap_proto::BodyContentCommon<'_>) -> bool {
    common
        .disposition
        .as_ref()
        .is_some_and(|disposition| disposition.ty.eq_ignore_ascii_case("attachment"))
}

fn join_mime_part(mime: &[u8], body: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(mime.len() + body.len() + 4);
    raw.extend_from_slice(mime);
    if !raw.ends_with(b"\r\n\r\n") {
        if !raw.ends_with(b"\r\n") {
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(body);
    raw
}

async fn login(config: ImapConnectionConfig, password: &str) -> Result<BoxedSession> {
    let client = connect_client(&config).await?;
    match timeout_result(
        "IMAP login",
        timeout(COMMAND_TIMEOUT, client.login(&config.login, password)),
    )
    .await?
    {
        Ok(session) => Ok(session),
        Err((err, _client)) => Err(imap_error("IMAP login", err)),
    }
}

async fn connect_client(config: &ImapConnectionConfig) -> Result<BoxedClient> {
    let tcp = timeout_result(
        "connect IMAP socket",
        timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((config.host.as_str(), config.port)),
        ),
    )
    .await?
    .map_err(|err| FrickmailError::Upstream(format!("IMAP socket connect failed: {err}")))?;
    let stream: BoxedImapIo = Box::new(tcp);

    match config.security {
        ImapSecurity::Tls => {
            let tls_stream = connect_tls(&config.host, stream).await?;
            let mut client = Client::new(tls_stream);
            read_greeting(&mut client).await?;
            Ok(client)
        }
        ImapSecurity::StartTls => {
            let mut client = Client::new(stream);
            read_greeting(&mut client).await?;
            timeout_imap(
                "IMAP STARTTLS",
                client.run_command_and_check_ok("STARTTLS", None),
            )
            .await?;
            let tls_stream = connect_tls(&config.host, client.into_inner()).await?;
            Ok(Client::new(tls_stream))
        }
        ImapSecurity::None => {
            let mut client = Client::new(stream);
            read_greeting(&mut client).await?;
            Ok(client)
        }
    }
}

async fn connect_tls(host: &str, stream: BoxedImapIo) -> Result<BoxedImapIo> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|err| FrickmailError::BadRequest(format!("invalid IMAP TLS host: {err}")))?;
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tls_stream = timeout_result(
        "IMAP TLS handshake",
        timeout(CONNECT_TIMEOUT, connector.connect(server_name, stream)),
    )
    .await?
    .map_err(|err| FrickmailError::Upstream(format!("IMAP TLS handshake failed: {err}")))?;
    Ok(Box::new(tls_stream))
}

async fn read_greeting(client: &mut BoxedClient) -> Result<()> {
    match timeout_result(
        "read IMAP greeting",
        timeout(CONNECT_TIMEOUT, client.read_response()),
    )
    .await?
    {
        Ok(Some(_response)) => Ok(()),
        Ok(None) => Err(FrickmailError::Upstream(
            "IMAP server closed connection before greeting".to_string(),
        )),
        Err(err) => Err(FrickmailError::Upstream(format!(
            "IMAP greeting failed: {err}"
        ))),
    }
}

async fn logout_quietly(mut session: BoxedSession) {
    let _ = timeout(COMMAND_TIMEOUT, session.logout()).await;
}

async fn timeout_imap<T, F>(operation: &'static str, future: F) -> Result<T>
where
    F: std::future::Future<Output = async_imap::error::Result<T>>,
{
    timeout_result(operation, timeout(COMMAND_TIMEOUT, future))
        .await?
        .map_err(|err| imap_error(operation, err))
}

async fn timeout_result<T, E>(
    operation: &'static str,
    future: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    future
        .await
        .map_err(|_elapsed| FrickmailError::Upstream(format!("{operation} timed out")))
}

fn imap_error(operation: &str, err: async_imap::error::Error) -> FrickmailError {
    FrickmailError::Upstream(format!("{operation} failed: {err}"))
}

fn required_field(label: &str, value: String) -> Result<String> {
    if contains_crlf(&value) {
        return Err(FrickmailError::BadRequest(format!(
            "{label} must not contain CR or LF"
        )));
    }

    let value = value.trim();
    if value.is_empty() {
        Err(FrickmailError::BadRequest(format!("{label} required")))
    } else {
        Ok(value.to_string())
    }
}

fn required_ascii_field(label: &str, value: String) -> Result<String> {
    let value = required_field(label, value)?;
    if !value.is_ascii() {
        return Err(FrickmailError::BadRequest(format!("{label} must be ASCII")));
    }
    Ok(value)
}

fn validate_mailbox(mailbox: &str) -> Result<()> {
    if mailbox.trim().is_empty() {
        return Err(FrickmailError::BadRequest("mailbox required".to_string()));
    }
    if contains_crlf(mailbox) {
        return Err(FrickmailError::BadRequest(
            "mailbox must not contain CR or LF".to_string(),
        ));
    }
    Ok(())
}

fn contains_crlf(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'\r' | b'\n'))
}

fn validate_uid_set(uid_set: &str) -> Result<()> {
    let uid_set = uid_set.trim();
    if uid_set.is_empty() {
        return Err(FrickmailError::BadRequest("uids required".to_string()));
    }

    for item in uid_set.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err(FrickmailError::BadRequest("invalid uid set".to_string()));
        }
        if let Some((start, end)) = item.split_once(':') {
            validate_uid_set_number(start.trim())?;
            validate_uid_set_number(end.trim())?;
            if end.contains(':') {
                return Err(FrickmailError::BadRequest("invalid uid set".to_string()));
            }
        } else {
            validate_uid_set_number(item)?;
        }
    }

    Ok(())
}

fn validate_uid_set_number(value: &str) -> Result<()> {
    let uid = value
        .parse::<u32>()
        .map_err(|_| FrickmailError::BadRequest("invalid uid set".to_string()))?;
    if uid == 0 {
        return Err(FrickmailError::BadRequest("invalid uid set".to_string()));
    }
    Ok(())
}

#[cfg(test)]
fn validate_keyword(keyword: &str) -> Result<()> {
    if !keyword_can_be_stored(keyword) {
        return Err(FrickmailError::BadRequest("invalid keyword".to_string()));
    }
    Ok(())
}

fn keyword_can_be_stored(keyword: &str) -> bool {
    !keyword.is_empty()
        && keyword.trim() == keyword
        && !keyword.starts_with('\\')
        && keyword.bytes().all(is_imap_keyword_atom_byte)
}

fn is_imap_keyword_atom_byte(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7e)
        && !matches!(
            byte,
            b'(' | b')' | b'{' | b' ' | b'%' | b'*' | b'"' | b'\\' | b']'
        )
}

fn keyword_supported(mailbox: &async_imap::types::Mailbox, keyword: &str) -> bool {
    mailbox.permanent_flags.iter().any(|flag| {
        matches!(flag, Flag::MayCreate)
            || matches!(flag, Flag::Custom(value) if value.as_ref() == keyword)
    })
}

fn store_flag_query(flag: ImapMessageFlag, set: bool) -> &'static str {
    match (flag, set) {
        (ImapMessageFlag::Seen, true) => "+FLAGS.SILENT (\\Seen)",
        (ImapMessageFlag::Seen, false) => "-FLAGS.SILENT (\\Seen)",
        (ImapMessageFlag::Flagged, true) => "+FLAGS.SILENT (\\Flagged)",
        (ImapMessageFlag::Flagged, false) => "-FLAGS.SILENT (\\Flagged)",
        (ImapMessageFlag::Deleted, true) => "+FLAGS.SILENT (\\Deleted)",
        (ImapMessageFlag::Deleted, false) => "-FLAGS.SILENT (\\Deleted)",
    }
}

fn store_keyword_query(keyword: &str, set: bool) -> String {
    let operation = if set {
        "+FLAGS.SILENT"
    } else {
        "-FLAGS.SILENT"
    };
    format!("{operation} ({keyword})")
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[1..];
    }
    while value.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[..value.len() - 1];
    }
    value
}

fn looks_like_rfc2822_message(value: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"From ",
        b"Received:",
        b"Date:",
        b"MIME-Version:",
        b"Content-Type:",
        b"Return-Path:",
        b"Message-ID:",
    ];
    PREFIXES.iter().any(|prefix| {
        value.len() >= prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix)
    })
}

fn imap_quote_search_value(value: &str) -> Result<String> {
    if contains_crlf(value) {
        return Err(FrickmailError::BadRequest(
            "rule condition value must not contain CR or LF".to_string(),
        ));
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

fn imap_rule_any_or(criteria: &[String]) -> String {
    match criteria {
        [] => String::new(),
        [only] => only.clone(),
        [first, rest @ ..] => format!("OR {first} ({})", imap_rule_any_or(rest)),
    }
}

fn uid_range(start: u32, end: u32) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}:{end}")
    }
}

fn has_capability_ignore_ascii_case(capabilities: &Capabilities, name: &str) -> bool {
    capabilities.iter().any(|capability| match capability {
        Capability::Imap4rev1 => name.eq_ignore_ascii_case("IMAP4rev1"),
        Capability::Auth(auth) => name
            .strip_prefix("AUTH=")
            .is_some_and(|name| name.eq_ignore_ascii_case(auth)),
        Capability::Atom(atom) => name.eq_ignore_ascii_case(atom),
    })
}

fn default_security() -> ImapSecurity {
    ImapSecurity::Tls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_legacy_secure_modes_and_ports() {
        assert_eq!(parse_security(None).unwrap(), ImapSecurity::Tls);
        assert_eq!(parse_security(Some("SSL")).unwrap(), ImapSecurity::Tls);
        assert_eq!(parse_security(Some("tls")).unwrap(), ImapSecurity::Tls);
        assert_eq!(
            parse_security(Some("STARTTLS")).unwrap(),
            ImapSecurity::StartTls
        );
        assert_eq!(parse_security(Some("NONE")).unwrap(), ImapSecurity::None);
        assert_eq!(parse_security(Some("plain")).unwrap(), ImapSecurity::None);
        assert!(parse_security(Some("weird")).is_err());

        let tls = ImapConnectionConfig::new("imap.example.com", None, Some("SSL"), "alice")
            .expect("valid TLS config");
        assert_eq!(tls.port, DEFAULT_TLS_PORT);
        assert_eq!(tls.security, ImapSecurity::Tls);

        let starttls =
            ImapConnectionConfig::new("imap.example.com", None, Some("STARTTLS"), "alice")
                .expect("valid STARTTLS config");
        assert_eq!(starttls.port, DEFAULT_PLAIN_PORT);
        assert_eq!(starttls.security, ImapSecurity::StartTls);

        let custom_port = ImapConnectionConfig::new(
            "imap.example.com",
            Some(1143),
            Some("NONE"),
            "alice@example.com",
        )
        .expect("valid custom port config");
        assert_eq!(custom_port.port, 1143);
        assert_eq!(custom_port.login, "alice@example.com");

        let probe_config = ImapConnectionConfig::try_from(ImapLoginProbe {
            host: "imap.example.com".to_string(),
            port: 0,
            security: ImapSecurity::StartTls,
            login: "alice".to_string(),
        })
        .expect("valid probe config");
        assert_eq!(probe_config.port, DEFAULT_PLAIN_PORT);
        assert_eq!(probe_config.security, ImapSecurity::StartTls);
    }

    #[test]
    fn rejects_injection_prone_account_fields() {
        assert!(ImapConnectionConfig::new("", None, Some("SSL"), "alice").is_err());
        assert!(
            ImapConnectionConfig::new("imap.example.com\nNOOP", None, Some("SSL"), "alice")
                .is_err()
        );
        assert!(
            ImapConnectionConfig::new("imap.example.com", None, Some("SSL"), "\r\nNOOP").is_err()
        );
        assert!(ImapConnectionConfig::new("bücher.example", None, Some("SSL"), "alice").is_err());
        assert!(ImapConnectionConfig::try_from(ImapLoginProbe {
            host: "imap.example.com\r\nNOOP".to_string(),
            port: 993,
            security: ImapSecurity::Tls,
            login: "alice".to_string(),
        })
        .is_err());
    }

    #[test]
    fn builds_safe_examine_and_body_preview_commands() {
        assert_eq!(
            examine_mailbox_command("INBOX").unwrap(),
            br#"EXAMINE "INBOX""#
        );
        assert_eq!(
            examine_mailbox_command(r#"Archive "2026""#).unwrap(),
            br#"EXAMINE "Archive \"2026\"""#
        );
        assert!(examine_mailbox_command("INBOX\r\nNOOP").is_err());

        assert_eq!(
            uid_fetch_bodystructure_query(42).unwrap(),
            "(UID RFC822.SIZE BODYSTRUCTURE)"
        );
        assert!(uid_fetch_bodystructure_query(0).is_err());
        assert_eq!(
            uid_fetch_raw_message_query(42).unwrap(),
            "(UID BODY.PEEK[])"
        );
        assert!(uid_fetch_raw_message_query(0).is_err());
        assert_eq!(sequence_fetch_raw_message_query(), "(BODY.PEEK[])");

        let mut path = [0; 8];
        path[0] = 1;
        let specs = [BodyPartSpec {
            path: Some(path),
            depth: 1,
            kind: BodyPartKind::Html,
            octets: u32::MAX,
        }];
        assert_eq!(
            body_preview_fetch_query(&specs),
            "(UID BODY.PEEK[1.MIME] BODY.PEEK[1]<0.262144>)"
        );
        assert!(!body_preview_fetch_query(&specs).contains("RFC822"));
    }

    #[test]
    fn uid_set_validation_accepts_comma_separated_positive_uids_and_ranges() {
        assert!(validate_uid_set("1").is_ok());
        assert!(validate_uid_set("1,2,300").is_ok());
        assert!(validate_uid_set(" 1, 2 ").is_ok());
        assert!(validate_uid_set("1:5").is_ok());
        assert!(validate_uid_set("5:1").is_ok());
        assert!(validate_uid_set("1:5, 8, 10:12").is_ok());

        assert!(validate_uid_set("").is_err());
        assert!(validate_uid_set("0").is_err());
        assert!(validate_uid_set("1:0").is_err());
        assert!(validate_uid_set("1:*").is_err());
        assert!(validate_uid_set("1\r\nNOOP").is_err());
        assert!(validate_uid_set("1,,2").is_err());
        assert!(validate_uid_set("1:2:3").is_err());
    }

    #[test]
    fn keyword_validation_accepts_safe_imap_atoms_only() {
        assert!(validate_keyword("$label1").is_ok());
        assert!(validate_keyword("todo-items").is_ok());
        assert!(validate_keyword("client.label").is_ok());
        assert!(keyword_can_be_stored("$label1"));

        assert!(validate_keyword("").is_err());
        assert!(validate_keyword("\\Seen").is_err());
        assert!(validate_keyword("label one").is_err());
        assert!(validate_keyword(" label").is_err());
        assert!(validate_keyword("label\r\nNOOP").is_err());
        assert!(validate_keyword("bad*label").is_err());
        assert!(validate_keyword("bad]label").is_err());
        assert!(!keyword_can_be_stored(""));
        assert!(!keyword_can_be_stored("\\Seen"));
    }

    #[test]
    fn keyword_support_matches_legacy_permanent_flags() {
        let mut mailbox = async_imap::types::Mailbox::default();
        mailbox.permanent_flags = vec![Flag::Custom("$label1".into())];
        assert!(keyword_supported(&mailbox, "$label1"));
        assert!(!keyword_supported(&mailbox, "$label2"));
        assert!(!keyword_supported(&mailbox, "$Label1"));

        mailbox.permanent_flags = vec![Flag::MayCreate];
        assert!(keyword_supported(&mailbox, "$label2"));
    }

    #[test]
    fn store_flag_queries_are_silent_and_bounded() {
        assert_eq!(
            store_flag_query(ImapMessageFlag::Seen, true),
            "+FLAGS.SILENT (\\Seen)"
        );
        assert_eq!(
            store_flag_query(ImapMessageFlag::Seen, false),
            "-FLAGS.SILENT (\\Seen)"
        );
        assert_eq!(
            store_flag_query(ImapMessageFlag::Flagged, true),
            "+FLAGS.SILENT (\\Flagged)"
        );
        assert_eq!(
            store_flag_query(ImapMessageFlag::Deleted, false),
            "-FLAGS.SILENT (\\Deleted)"
        );
        assert_eq!(
            store_keyword_query("$label1", true),
            "+FLAGS.SILENT ($label1)"
        );
        assert_eq!(
            store_keyword_query("$label1", false),
            "-FLAGS.SILENT ($label1)"
        );
    }

    #[test]
    fn message_list_sequence_range_fetches_newest_page_safely() {
        assert_eq!(
            message_list_sequence_range(100, 0, 20),
            Some("81:100".to_string())
        );
        assert_eq!(
            message_list_sequence_range(100, 20, 20),
            Some("61:80".to_string())
        );
        assert_eq!(
            message_list_sequence_range(5, 0, 20),
            Some("1:5".to_string())
        );
        assert_eq!(message_list_sequence_range(5, 4, 20), Some("1".to_string()));
        assert_eq!(message_list_sequence_range(5, 5, 20), None);
        assert_eq!(message_list_sequence_range(5, 0, 0), None);
    }

    #[test]
    fn legacy_folder_helpers_are_deterministic() {
        let config =
            ImapConnectionConfig::new("imap.example.com", None, Some("SSL"), "alice").unwrap();
        let client_hash = legacy_imap_client_hash(&config);

        assert_eq!(client_hash, "934eb27e7b445be0ee3882969d8bbbaa");
        assert_eq!(legacy_new_uid_range(Some(41), Some(44)), vec![41, 42, 43]);
        assert!(legacy_new_uid_range(None, Some(44)).is_empty());
        assert!(legacy_new_uid_range(Some(44), Some(44)).is_empty());
        assert_eq!(
            legacy_folder_etag(
                "INBOX",
                10,
                Some(11),
                Some(99),
                Some(3),
                Some(7),
                &client_hash
            ),
            "c9cba90bef2b44f616e90a196844cdf3"
        );
        assert_eq!(
            legacy_folder_etag("INBOX", 10, Some(11), None, None, Some(7), &client_hash),
            "8632f0d8c749d9e674566db02fcfb622"
        );
        assert_eq!(
            legacy_message_hash("INBOX", 44),
            "2a7cf377296d50a49291639593793425"
        );
        assert_eq!(
            legacy_uid_sequence_set(&[42, 41, 42, 0]),
            Some("41,42".to_string())
        );
        assert_eq!(legacy_uid_sequence_set(&[0]), None);
        assert_eq!(legacy_message_flags_fetch_query(), "(UID FLAGS)");
        assert_eq!(
            legacy_new_messages_fetch_query(),
            "(UID FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT CONTENT-TYPE)])"
        );
    }

    #[test]
    fn header_value_handles_case_and_folding() {
        let raw = b"Subject: first\r\n\tcontinued\r\nMessage-ID: <id@example.com>\r\n\r\nbody";
        assert_eq!(
            header_value(raw, "subject"),
            Some("first continued".to_string())
        );
        assert_eq!(
            header_value(raw, "Message-ID"),
            Some("<id@example.com>".to_string())
        );
        assert_eq!(header_value(raw, "From"), None);
    }

    #[test]
    fn builds_safe_rule_search_criteria() {
        let conditions = vec![
            RuleCondition {
                field: RuleConditionField::From,
                op: RuleConditionOp::Contains,
                value: "newsletter".to_string(),
            },
            RuleCondition {
                field: RuleConditionField::Subject,
                op: RuleConditionOp::Equals,
                value: "weekly \"digest\"".to_string(),
            },
            RuleCondition {
                field: RuleConditionField::To,
                op: RuleConditionOp::NotContains,
                value: r#"boss\alerts"#.to_string(),
            },
        ];

        assert_eq!(
            imap_rule_search_criteria(&conditions, RuleConditionsLogic::All).unwrap(),
            Some(
                r#"FROM "newsletter" HEADER Subject "weekly \"digest\"" NOT TO "boss\\alerts""#
                    .to_string()
            )
        );
        assert_eq!(
            imap_rule_search_criteria(&conditions, RuleConditionsLogic::Any).unwrap(),
            Some(
                r#"OR FROM "newsletter" (OR HEADER Subject "weekly \"digest\"" (NOT TO "boss\\alerts"))"#
                    .to_string()
            )
        );
        assert!(imap_rule_search_criteria(
            &[RuleCondition {
                field: RuleConditionField::Subject,
                op: RuleConditionOp::Contains,
                value: "hello\r\nNOOP".to_string(),
            }],
            RuleConditionsLogic::All,
        )
        .is_err());
    }

    #[test]
    fn formats_uid_sequence_sets_deterministically() {
        let uids = HashSet::from([42_u32, 7, 19, 20, 21, 43]);
        assert_eq!(uid_sequence_set(&uids), "7,19:21,42:43");
        assert_eq!(uid_sequence_set(&HashSet::new()), "");
    }

    #[test]
    fn validates_imported_eml_like_legacy_php() {
        assert!(validate_eml(b"Subject: missing accepted prefix\r\n\r\nbody").is_err());
        assert!(validate_eml(b"   \r\n").is_err());
        assert!(validate_eml(b"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nbody").is_ok());
        assert!(validate_eml(b"mime-version: 1.0\r\n\r\nbody").is_ok());
    }

    #[test]
    fn extracts_body_peek_for_expected_uid() {
        let response = concat!(
            "* 2 FETCH (UID 41 BODY[1]<0> {47}\r\n",
            "Subject: Hello\r\n",
            "From: alice@example.com\r\n",
            "\r\n",
            "Body)\r\n",
            "A1 OK Fetch completed\r\n"
        );

        let body = parse_uid_fetch_body_preview(response.as_bytes(), 41)
            .expect("valid response")
            .expect("body for UID");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "Subject: Hello\r\nFrom: alice@example.com\r\n\r\nBody"
        );
    }

    #[test]
    fn ignores_other_uids_and_surfaces_command_failures() {
        let other = b"* 2 FETCH (UID 40 BODY[] {5}\r\nHello)\r\nA1 OK done\r\n";
        assert_eq!(parse_uid_fetch_body_preview(other, 41).unwrap(), None);

        let failed = b"A1 NO mailbox unavailable\r\n";
        let err = parse_uid_fetch_body_preview(failed, 41).unwrap_err();
        assert!(err.public_message().contains("mailbox unavailable"));
    }
}
