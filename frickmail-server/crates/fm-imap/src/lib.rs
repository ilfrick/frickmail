use std::{borrow::Cow, collections::HashSet, fmt, sync::Arc, time::Duration};

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
use mail_parser::parsers::MessageStream;
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
    pub is_complete: bool,
    pub flags: Vec<String>,
    pub crypto: LegacyMessageCrypto,
    pub metadata: LegacyMessageFetchMetadata,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyMessageCrypto {
    pub pgp_signed: Option<LegacyPgpSigned>,
    pub pgp_encrypted: Option<LegacyPartId>,
    pub smime_signed: Option<LegacySmimeSigned>,
    pub smime_encrypted: Option<LegacyPartId>,
}

impl LegacyMessageCrypto {
    pub fn is_empty(&self) -> bool {
        self.pgp_signed.is_none()
            && self.pgp_encrypted.is_none()
            && self.smime_signed.is_none()
            && self.smime_encrypted.is_none()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyMessageFetchMetadata {
    pub header: Vec<u8>,
    pub internal_timestamp: Option<i64>,
    pub size: u32,
    pub email_id: Option<String>,
    pub attachments: Vec<LegacyAttachmentSummary>,
    pub envelope: LegacyMessageEnvelope,
}

impl LegacyMessageFetchMetadata {
    pub fn is_empty(&self) -> bool {
        self.header.is_empty()
            && self.internal_timestamp.is_none()
            && self.size == 0
            && self.email_id.is_none()
            && self.attachments.is_empty()
            && self.envelope.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyMessageEnvelope {
    pub subject: String,
    pub message_id: String,
    pub in_reply_to: String,
    pub from: Vec<String>,
    pub sender: Vec<String>,
    pub reply_to: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
}

impl LegacyMessageEnvelope {
    pub fn is_empty(&self) -> bool {
        self.subject.is_empty()
            && self.message_id.is_empty()
            && self.in_reply_to.is_empty()
            && self.from.is_empty()
            && self.sender.is_empty()
            && self.reply_to.is_empty()
            && self.to.is_empty()
            && self.cc.is_empty()
            && self.bcc.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyMessageSpamSummary {
    pub spam_score: u8,
    pub spam_result: String,
    pub is_spam: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyPartId {
    pub part_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyPgpSigned {
    pub part_id: String,
    pub sig_part_id: String,
    pub mic_alg: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacySmimeSigned {
    pub part_id: String,
    pub sig_part_id: Option<String>,
    pub mic_alg: String,
    pub detached: bool,
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
    pub append_limit: Option<u64>,
    pub size: Option<u64>,
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
    pub total_threads: Option<u32>,
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
    pub email_id: Option<String>,
    pub subject: String,
    pub encrypted: bool,
    pub message_id: String,
    pub spam_score: u8,
    pub spam_result: String,
    pub is_spam: bool,
    pub in_reply_to: String,
    pub references: String,
    pub from: String,
    pub reply_to: String,
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub sender: String,
    pub delivered_to: String,
    pub read_receipt: String,
    pub date: String,
    pub date_timestamp: i64,
    pub date_timestamp_source: String,
    pub size: u32,
    pub flags: Vec<String>,
    pub has_attachments: bool,
    pub attachments: Vec<LegacyAttachmentSummary>,
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyAttachmentSummary {
    #[serde(rename = "@Object")]
    pub object: String,
    pub folder: String,
    pub uid: u32,
    #[serde(rename = "mimeIndex")]
    pub mime_index: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    #[serde(rename = "fileName")]
    pub file_name: String,
    #[serde(rename = "estimatedSize")]
    pub estimated_size: u32,
    #[serde(rename = "cId")]
    pub c_id: String,
    #[serde(rename = "contentLocation")]
    pub content_location: String,
    #[serde(rename = "isInline")]
    pub is_inline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMessageListRequest {
    pub mailbox: String,
    pub offset: u32,
    pub limit: u32,
    pub search: String,
    pub sort: String,
    pub prev_uid_next: Option<u32>,
    pub hide_deleted: bool,
    pub use_threads: bool,
    pub thread_uid: u32,
    pub thread_algorithm: String,
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
struct ImapFetchMetadataCapabilities {
    supports_gmail_id: bool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct BodyPreviewFetchSpec {
    parts: Vec<BodyPartSpec>,
    flags: Vec<String>,
    crypto: LegacyMessageCrypto,
    metadata: LegacyMessageFetchMetadata,
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
    let capabilities = imap_fetch_metadata_capabilities(&mut session).await?;
    let Some(specs) = fetch_body_part_specs(&mut session, mailbox, uid, capabilities).await? else {
        logout_quietly(session).await;
        return Ok(None);
    };
    let parts = fetch_preview_parts(
        &mut session,
        uid,
        &specs.parts,
        &specs.flags,
        &specs.crypto,
        &specs.metadata,
    )
    .await?;
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
    let capabilities = imap_fetch_metadata_capabilities(&mut session).await?;
    let result =
        legacy_message_list_in_session(&mut session, request, &client_hash, capabilities).await;
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

pub async fn set_mailbox_subscription(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    subscribe: bool,
) -> Result<()> {
    validate_mailbox(mailbox)?;

    let mut session = login(config, password).await?;
    let result = if subscribe {
        timeout_imap("subscribe mailbox", session.subscribe(mailbox)).await
    } else {
        timeout_imap("unsubscribe mailbox", session.unsubscribe(mailbox)).await
    };
    logout_quietly(session).await;
    result
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
    uid_fetch_bodystructure_query_with_gmail_id(uid, false)
}

pub fn uid_fetch_bodystructure_query_with_gmail_id(
    uid: u32,
    include_gmail_id: bool,
) -> Result<&'static str> {
    if uid == 0 {
        return Err(FrickmailError::BadRequest("uid required".to_string()));
    }

    Ok(if include_gmail_id {
        "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER] X-GM-MSGID)"
    } else {
        "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER])"
    })
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
    legacy_message_list_fetch_query_with_gmail_id(false)
}

pub fn legacy_message_list_fetch_query_with_gmail_id(include_gmail_id: bool) -> &'static str {
    if include_gmail_id {
        "(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER] X-GM-MSGID)"
    } else {
        "(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER])"
    }
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

pub fn legacy_message_list_limit(limit: u32) -> u32 {
    if limit < 10 {
        10
    } else if limit > 999 {
        50
    } else {
        limit
    }
}

pub fn legacy_message_list_fetches_new_messages(thread_uid: u32) -> bool {
    thread_uid == 0
}

pub fn legacy_new_messages_mailbox_matches(mailbox: &str) -> bool {
    mailbox == "INBOX"
}

pub fn legacy_message_list_search(search: &str) -> String {
    legacy_php_trim(search).to_string()
}

pub fn legacy_message_list_sort(sort: &str, use_sort: bool) -> String {
    if !use_sort {
        return String::new();
    }

    let mut sort_types = Vec::new();
    if !sort.is_empty() {
        sort_types.push(sort);
    }
    if !sort.contains("DATE") {
        sort_types.push("REVERSE DATE");
    }
    sort_types.join(" ")
}

pub fn legacy_message_list_reported_sort(sort: &str) -> String {
    legacy_message_list_sort(sort, true)
}

pub fn legacy_message_list_limited(uses_optimized_fetch: bool) -> bool {
    uses_optimized_fetch
}

pub fn legacy_message_list_keeps_flags(flags: &[String], hide_deleted: bool) -> bool {
    !hide_deleted
        || !flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\deleted"))
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

pub fn legacy_message_cache_key(
    folder: &str,
    uid: u32,
    flags: &[String],
    client_hash: &str,
) -> String {
    md5_hex(format!(
        "MessageHash/{folder}/{uid}/{}/{}",
        flags.join(","),
        client_hash
    ))
}

pub fn legacy_message_list_params_hash(
    request: &LegacyMessageListRequest,
    search_fuzzy: bool,
    use_sort: bool,
) -> String {
    md5_hex(
        [
            request.mailbox.clone(),
            request.offset.to_string(),
            request.limit.to_string(),
            if request.hide_deleted { "1" } else { "0" }.to_string(),
            request.search.clone(),
            if search_fuzzy { "1" } else { "0" }.to_string(),
            if use_sort {
                request.sort.clone()
            } else {
                "0".to_string()
            },
            if request.use_threads {
                request.thread_uid.to_string()
            } else {
                String::new()
            },
            if request.use_threads {
                request.thread_algorithm.clone()
            } else {
                String::new()
            },
            request.prev_uid_next.unwrap_or_default().to_string(),
        ]
        .join("-"),
    )
}

pub fn legacy_message_list_cache_key(params_hash: &str, folder_etag: &str) -> String {
    format!("{params_hash}-{folder_etag}")
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

fn legacy_message_flag_string(flag: &Flag<'_>) -> String {
    match flag {
        Flag::Custom(value) => legacy_custom_message_flag_string(value.as_ref()),
        _ => legacy_flag_string(flag),
    }
}

fn legacy_custom_message_flag_string(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "$readreceipt" => "$mdnsent".to_string(),
        "$replied" => "\\answered".to_string(),
        value => value.to_string(),
    }
}

fn legacy_unique_flag_strings(flags: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();

    for flag in flags {
        if seen.insert(flag.clone()) {
            unique.push(flag);
        }
    }

    unique
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
                value.push_str(legacy_php_trim(line));
            }
            continue;
        }
        matched = false;
        let Some((key, next)) = line.split_once(':') else {
            continue;
        };
        if legacy_php_trim(key).eq_ignore_ascii_case(&wanted) {
            value = legacy_php_trim(next).to_string();
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
    capabilities: ImapFetchMetadataCapabilities,
) -> Result<LegacyMessageList> {
    let fetch_new_messages = legacy_message_list_fetches_new_messages(request.thread_uid);
    let folder = legacy_folder_information_in_session(
        session,
        &request.mailbox,
        request.prev_uid_next,
        None,
        fetch_new_messages,
        client_hash,
    )
    .await?;
    let total = folder.total_emails.unwrap_or_default();
    let limit = legacy_message_list_limit(request.limit);
    let range = message_list_sequence_range(total, request.offset, limit);
    let mut messages = Vec::new();

    if let Some(range) = range {
        let mut fetches = timeout_imap(
            "fetch legacy message list",
            session.fetch(
                range,
                legacy_message_list_fetch_query_with_gmail_id(capabilities.supports_gmail_id),
            ),
        )
        .await?;

        while let Some(fetch) =
            timeout_imap("read legacy message list item", fetches.try_next()).await?
        {
            let Some(uid) = fetch.uid else {
                continue;
            };
            let header = fetch.header().unwrap_or_default();
            let summary = legacy_message_summary_from_fetch_with_email_id(
                &request.mailbox,
                uid,
                fetch.internal_date().map(|value| value.timestamp()),
                fetch.size.unwrap_or_default(),
                fetch.flags(),
                fetch.bodystructure(),
                header,
                fetch.gmail_msg_id().map(u64::to_string),
            );
            if legacy_message_list_keeps_flags(&summary.flags, request.hide_deleted) {
                messages.push(summary);
            }
        }
        messages.sort_by_key(|message| std::cmp::Reverse(message.uid));
    }

    Ok(LegacyMessageList {
        folder,
        total_emails: total,
        total_threads: None,
        offset: request.offset,
        limit,
        search: legacy_message_list_search(&request.search),
        sort: legacy_message_list_reported_sort(&request.sort),
        limited: legacy_message_list_limited(false),
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
        append_limit: None,
        size: None,
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
    if current_uid_next == Some(prev_uid_next) || !legacy_new_messages_mailbox_matches(mailbox) {
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
            subject: legacy_message_subject(&header_value(header, "Subject").unwrap_or_default()),
            from: header_value(header, "From").unwrap_or_default(),
        });
    }

    Ok(messages)
}

#[cfg(test)]
fn legacy_message_summary_from_fetch<'a>(
    folder: &str,
    uid: u32,
    internal_timestamp: Option<i64>,
    size: u32,
    flags: impl Iterator<Item = Flag<'a>>,
    bodystructure: Option<&BodyStructure<'_>>,
    header: &[u8],
) -> LegacyMessageSummary {
    legacy_message_summary_from_fetch_with_email_id(
        folder,
        uid,
        internal_timestamp,
        size,
        flags,
        bodystructure,
        header,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn legacy_message_summary_from_fetch_with_email_id<'a>(
    folder: &str,
    uid: u32,
    internal_timestamp: Option<i64>,
    size: u32,
    flags: impl Iterator<Item = Flag<'a>>,
    bodystructure: Option<&BodyStructure<'_>>,
    header: &[u8],
    email_id: Option<String>,
) -> LegacyMessageSummary {
    let subject = legacy_message_subject(&header_value(header, "Subject").unwrap_or_default());
    let message_id = header_value(header, "Message-ID")
        .or_else(|| header_value(header, "Message-Id"))
        .unwrap_or_default();
    let in_reply_to = header_value(header, "In-Reply-To").unwrap_or_default();
    let references = legacy_strip_spaces(&header_value(header, "References").unwrap_or_default());
    let from = header_value(header, "From").unwrap_or_default();
    let reply_to = header_value(header, "Reply-To").unwrap_or_default();
    let to = header_value(header, "To").unwrap_or_default();
    let cc = header_value(header, "Cc").unwrap_or_default();
    let bcc = header_value(header, "Bcc").unwrap_or_default();
    let sender = header_value(header, "Sender").unwrap_or_default();
    let delivered_to = header_value(header, "Delivered-To").unwrap_or_default();
    let read_receipt = legacy_read_receipt(header);
    let date = header_value(header, "Date").unwrap_or_default();
    let encrypted = legacy_message_is_encrypted(
        &header_value(header, "Content-Type").unwrap_or_default(),
        bodystructure,
    );
    let spam = legacy_message_spam_summary(header, &subject);
    let (date_timestamp, date_timestamp_source) =
        legacy_message_timestamp(&date, internal_timestamp);
    let flags = legacy_unique_flag_strings(flags.map(|flag| legacy_message_flag_string(&flag)));
    let attachments = legacy_message_attachments(folder, uid, bodystructure);

    LegacyMessageSummary {
        folder: folder.to_string(),
        uid,
        hash: legacy_message_hash(folder, uid),
        email_id,
        subject,
        encrypted,
        message_id,
        spam_score: spam.spam_score,
        spam_result: spam.spam_result,
        is_spam: spam.is_spam,
        in_reply_to,
        references,
        from,
        reply_to,
        to,
        cc,
        bcc,
        sender,
        delivered_to,
        read_receipt,
        date,
        date_timestamp,
        date_timestamp_source: date_timestamp_source.to_string(),
        size,
        flags,
        has_attachments: !attachments.is_empty(),
        attachments,
        preview: None,
    }
}

fn legacy_header_timestamp(date: &str) -> Option<i64> {
    fm_core::legacy_rfc2822_timestamp(date)
}

fn legacy_message_timestamp(date: &str, internal_timestamp: Option<i64>) -> (i64, &'static str) {
    if let Some(timestamp) = legacy_header_timestamp(date).filter(|value| *value != 0) {
        return (timestamp, "header");
    }

    (internal_timestamp.unwrap_or_default(), "internal")
}

fn legacy_read_receipt(header: &[u8]) -> String {
    let primary = header_value(header, "Disposition-Notification-To")
        .map(|value| legacy_php_trim(&value).to_string())
        .unwrap_or_default();
    let selected = if primary.is_empty() {
        header_value(header, "X-Confirm-Reading-To")
            .map(|value| legacy_php_trim(&value).to_string())
            .unwrap_or_default()
    } else {
        primary
    };

    if legacy_read_receipt_value_matches_mailso(&selected) {
        selected
    } else {
        String::new()
    }
}

fn legacy_read_receipt_value_matches_mailso(value: &str) -> bool {
    let value = legacy_php_trim(value);
    !value.is_empty()
        && legacy_has_non_comment_email_content(value)
        && !legacy_read_receipt_is_empty_angle_address(value)
        && !legacy_read_receipt_is_invalid_quoted_display(value)
}

fn legacy_read_receipt_is_empty_angle_address(value: &str) -> bool {
    let content = legacy_non_comment_email_content(value);
    let content = legacy_php_trim(&content);
    content
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .is_some_and(|value| legacy_php_trim(value).is_empty())
}

fn legacy_read_receipt_is_invalid_quoted_display(value: &str) -> bool {
    let content = legacy_non_comment_email_content(value);
    let content = legacy_php_trim(&content);
    if content
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .is_some()
    {
        return true;
    }

    content
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .is_some_and(|value| legacy_php_trim(value).is_empty())
}

fn legacy_has_non_comment_email_content(value: &str) -> bool {
    !legacy_non_comment_email_content(value).is_empty()
}

fn legacy_non_comment_email_content(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut comment = String::new();
    let mut in_comment = false;
    let mut in_quote = false;
    let mut in_address = false;
    let mut escaped = false;

    for ch in value.chars() {
        if escaped {
            if in_comment {
                comment.push(ch);
            } else {
                output.push(ch);
            }
            escaped = false;
            continue;
        }
        if ch == '\\' {
            if in_comment {
                comment.push(ch);
            } else {
                output.push(ch);
            }
            escaped = true;
            continue;
        }
        if in_comment {
            comment.push(ch);
            if ch == ')' {
                comment.clear();
                in_comment = false;
            }
            continue;
        }
        match ch {
            '"' if !in_address => in_quote = !in_quote,
            '<' if !in_quote => in_address = true,
            '>' if in_address => in_address = false,
            '(' if !in_quote && !in_address => {
                comment.push(ch);
                in_comment = true;
                continue;
            }
            _ => {}
        }
        output.push(ch);
    }
    if in_comment {
        output.push_str(&comment);
    }

    output.trim().to_string()
}

fn legacy_strip_spaces(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn legacy_php_trim(value: &str) -> &str {
    value.trim_matches(|ch| matches!(ch, ' ' | '\t' | '\n' | '\r' | '\0' | '\x0b'))
}

fn legacy_message_subject(value: &str) -> String {
    legacy_php_trim(value).to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacySpamMetadata {
    score: u8,
    result: String,
    is_spam: bool,
}

pub fn legacy_message_spam_summary(header: &[u8], subject: &str) -> LegacyMessageSpamSummary {
    let metadata = legacy_message_spam_metadata(header, subject);
    LegacyMessageSpamSummary {
        spam_score: legacy_serialized_spam_score(&metadata),
        spam_result: metadata.result,
        is_spam: metadata.is_spam,
    }
}

fn legacy_message_spam_metadata(header: &[u8], subject: &str) -> LegacySpamMetadata {
    if let Some(spam) =
        header_value(header, "X-Spamd-Result").filter(|value| legacy_php_truthy(value))
    {
        let mut metadata = LegacySpamMetadata {
            score: 0,
            result: String::new(),
            is_spam: legacy_ascii_contains_ignore_case(subject, "*** SPAM ***"),
        };
        if let Some((score, threshold)) = legacy_parse_rspamd_score(&spam) {
            let score_value = legacy_php_float(score);
            let threshold_value = legacy_php_float(threshold);
            if threshold_value != 0.0 {
                metadata.score = legacy_spam_score(100.0 * score_value / threshold_value);
                metadata.result = format!("{score} / {threshold}");
            }
        }
        return metadata;
    }

    if let Some(spam) = header_value(header, "X-Bogosity").filter(|value| legacy_php_truthy(value))
    {
        let mut metadata = LegacySpamMetadata {
            score: 0,
            result: spam.clone(),
            is_spam: !spam.contains("Ham"),
        };
        if let Some(spamicity) = legacy_number_after(&spam, "spamicity=", false) {
            metadata.score = legacy_spam_score(100.0 * legacy_php_float(spamicity));
        }
        return metadata;
    }

    if let Some(spam) =
        header_value(header, "X-Spam-Status").filter(|value| legacy_php_truthy(value))
    {
        let mut metadata = LegacySpamMetadata {
            score: 0,
            result: spam.clone(),
            is_spam: spam.starts_with("Yes")
                || header_value(header, "X-Spam-Flag")
                    .is_some_and(|flag| legacy_ascii_contains_ignore_case(&flag, "YES")),
        };

        if let (Some(score), Some(threshold)) = (
            legacy_number_after(&spam, "hits=", true)
                .or_else(|| legacy_number_after(&spam, "score=", true)),
            legacy_number_after(&spam, "required=", true),
        ) {
            let score_value = legacy_php_float(score);
            let threshold_value = legacy_php_float(threshold);
            if threshold_value != 0.0 {
                metadata.score = legacy_spam_score(100.0 * score_value / threshold_value);
                metadata.result = format!("{score} / {threshold}");
            }
        } else {
            let ratio = legacy_parse_ratio(&spam)
                .map(|(score, threshold)| (score.to_string(), threshold.to_string()))
                .or_else(|| {
                    header_value(header, "X-Spam-Info").and_then(|info| {
                        legacy_parse_ratio(&info)
                            .map(|(score, threshold)| (score.to_string(), threshold.to_string()))
                    })
                });
            if let Some((score, threshold)) = ratio {
                let score_value = legacy_php_float(&score);
                let threshold_value = legacy_php_float(&threshold);
                if threshold_value != 0.0 {
                    metadata.score = legacy_spam_score(100.0 * score_value / threshold_value);
                    metadata.result = format!("{score} / {threshold}");
                }
            }
        }

        return metadata;
    }

    LegacySpamMetadata {
        score: 0,
        result: String::new(),
        is_spam: false,
    }
}

fn legacy_serialized_spam_score(metadata: &LegacySpamMetadata) -> u8 {
    if metadata.is_spam {
        100
    } else {
        metadata.score
    }
}

fn legacy_spam_score(value: f64) -> u8 {
    if !value.is_finite() {
        return 0;
    }
    value.clamp(0.0, 100.0) as u8
}

fn legacy_parse_rspamd_score(value: &str) -> Option<(&str, &str)> {
    let start = value.find('[')? + '['.len_utf8();
    let rest = &value[start..];
    let slash = rest.find('/')?;
    let score = legacy_php_trim(&rest[..slash]);
    let rest = &rest[slash + '/'.len_utf8()..];
    let end = rest.find("];")?;
    let threshold = legacy_php_trim(&rest[..end]);
    if !legacy_spam_score_token(score) || !legacy_spam_threshold_token(threshold) {
        return None;
    }
    Some((score, threshold))
}

fn legacy_spam_score_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | '-'))
}

fn legacy_spam_threshold_token(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
}

fn legacy_number_after<'a>(value: &'a str, marker: &str, signed: bool) -> Option<&'a str> {
    let start = value.find(marker)? + marker.len();
    let rest = &value[start..];
    let mut end = 0;
    for (index, ch) in rest.char_indices() {
        if ch.is_ascii_digit() || ch == '.' || (signed && ch == '-') {
            end = index + ch.len_utf8();
        } else {
            break;
        }
    }
    (end > 0).then_some(&rest[..end])
}

fn legacy_parse_ratio(value: &str) -> Option<(&str, &str)> {
    for (index, ch) in value.char_indices() {
        if !(ch.is_ascii_digit() || ch == '.') {
            continue;
        }
        let first = &value[index..];
        let first_end = first
            .char_indices()
            .take_while(|(_, ch)| ch.is_ascii_digit() || *ch == '.')
            .last()
            .map(|(index, ch)| index + ch.len_utf8())?;
        let rest = &first[first_end..];
        let rest = rest.strip_prefix('/')?;
        let second_end = rest
            .char_indices()
            .take_while(|(_, ch)| ch.is_ascii_digit() || *ch == '.')
            .last()
            .map(|(index, ch)| index + ch.len_utf8())?;
        if second_end > 0 {
            return Some((&first[..first_end], &rest[..second_end]));
        }
    }
    None
}

fn legacy_ascii_contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn legacy_php_truthy(value: &str) -> bool {
    !value.is_empty() && value != "0"
}

fn legacy_php_float(value: &str) -> f64 {
    let value = legacy_php_trim(value);
    let mut end = 0;
    let mut saw_digit = false;
    for (index, ch) in value.char_indices() {
        let allowed_sign = index == 0 && ch == '-';
        if allowed_sign || ch.is_ascii_digit() || ch == '.' {
            if ch.is_ascii_digit() {
                saw_digit = true;
            }
            end = index + ch.len_utf8();
        } else {
            break;
        }
    }
    if !saw_digit {
        return 0.0;
    }
    value[..end].parse::<f64>().unwrap_or(0.0)
}

fn legacy_message_is_encrypted(
    content_type: &str,
    bodystructure: Option<&BodyStructure<'_>>,
) -> bool {
    legacy_header_content_type_value(content_type) == "multipart/encrypted"
        || bodystructure.is_some_and(legacy_body_has_encrypted_part)
}

fn legacy_header_content_type_value(content_type: &str) -> &str {
    legacy_php_trim(content_type.split(';').next().unwrap_or_default())
}

fn legacy_body_has_encrypted_part(body: &BodyStructure<'_>) -> bool {
    legacy_body_is_pgp_encrypted(body)
        || legacy_body_is_smime_encrypted(body)
        || match body {
            BodyStructure::Message { body, .. } => legacy_body_has_encrypted_part(body),
            BodyStructure::Multipart { bodies, .. } => {
                bodies.iter().any(legacy_body_has_encrypted_part)
            }
            _ => false,
        }
}

fn legacy_message_crypto_metadata(body: &BodyStructure<'_>) -> LegacyMessageCrypto {
    let mut crypto = LegacyMessageCrypto::default();

    legacy_walk_body_parts(body, "", &mut |part, part_id, parent_id| {
        if let BodyStructure::Multipart { .. } = part {
            if legacy_body_is_pgp_encrypted(part) {
                crypto.pgp_encrypted = Some(LegacyPartId {
                    part_id: legacy_body_child_part_id(parent_id, 1),
                });
            }
        }

        if legacy_body_is_smime_encrypted(part) {
            crypto.smime_encrypted = Some(LegacyPartId {
                part_id: part_id.to_string(),
            });
        } else if legacy_body_is_opaque_smime_signed(part) {
            crypto.smime_signed = Some(LegacySmimeSigned {
                part_id: part_id.to_string(),
                sig_part_id: None,
                mic_alg: legacy_body_root_mic_alg(part, parent_id),
                detached: false,
            });
        }
    });

    let mut saw_multipart_signed = false;
    legacy_walk_body_parts(body, "", &mut |part, part_id, parent_id| {
        if saw_multipart_signed || !legacy_body_is_multipart_signed(part) {
            return;
        }
        saw_multipart_signed = true;

        if let BodyStructure::Multipart { bodies, .. } = part {
            if legacy_body_is_pgp_signed(part) {
                crypto.pgp_signed = Some(LegacyPgpSigned {
                    part_id: legacy_body_child_part_id(parent_id, 0),
                    sig_part_id: legacy_body_child_part_id(parent_id, 1),
                    mic_alg: legacy_body_root_mic_alg(part, parent_id),
                });
            } else if legacy_body_is_detached_smime_signed(part, bodies) {
                crypto.smime_signed = Some(LegacySmimeSigned {
                    part_id: part_id.to_string(),
                    sig_part_id: Some(legacy_body_child_part_id(parent_id, 1)),
                    mic_alg: legacy_body_root_mic_alg(part, parent_id),
                    detached: true,
                });
            }
        }
    });

    crypto
}

fn legacy_walk_body_parts<F>(body: &BodyStructure<'_>, part_id: &str, visit: &mut F)
where
    F: FnMut(&BodyStructure<'_>, &str, &str),
{
    let current_part_id = legacy_body_part_id(body, part_id);
    visit(body, &current_part_id, part_id);

    if let BodyStructure::Multipart { bodies, .. } = body {
        for (index, child) in bodies.iter().enumerate() {
            let child_part_id = legacy_body_child_part_id(part_id, index);
            legacy_walk_body_parts(child, &child_part_id, visit);
        }
    }
}

fn legacy_body_child_part_id(parent_part_id: &str, index: usize) -> String {
    format!("{}{}", legacy_child_part_prefix(parent_part_id), index + 1)
}

fn legacy_body_part_is_attachment(body: &BodyStructure<'_>) -> bool {
    let common = match body {
        BodyStructure::Basic { common, .. }
        | BodyStructure::Text { common, .. }
        | BodyStructure::Message { common, .. }
        | BodyStructure::Multipart { common, .. } => common,
    };

    is_attachment(common) || (!legacy_body_is_multipart(common) && !legacy_body_is_text(common))
}

fn legacy_message_attachments(
    folder: &str,
    uid: u32,
    bodystructure: Option<&BodyStructure<'_>>,
) -> Vec<LegacyAttachmentSummary> {
    let mut attachments = Vec::new();
    if let Some(bodystructure) = bodystructure {
        legacy_collect_attachments(folder, uid, bodystructure, "", false, &mut attachments);
    }
    attachments
}

fn legacy_collect_attachments(
    folder: &str,
    uid: u32,
    body: &BodyStructure<'_>,
    part_id: &str,
    parent_pgp_encrypted: bool,
    attachments: &mut Vec<LegacyAttachmentSummary>,
) {
    let current_part_id = legacy_body_part_id(body, part_id);
    let current_pgp_encrypted = legacy_body_is_pgp_encrypted(body);
    let current_is_attachment = legacy_body_part_is_attachment(body);

    if !parent_pgp_encrypted && current_is_attachment {
        attachments.push(legacy_attachment_summary(
            folder,
            uid,
            body,
            &current_part_id,
        ));
    }

    match body {
        BodyStructure::Message { body, .. } if !current_is_attachment => {
            legacy_collect_attachments(
                folder,
                uid,
                body,
                &current_part_id,
                current_pgp_encrypted,
                attachments,
            );
        }
        BodyStructure::Multipart { bodies, .. } => {
            let child_prefix = legacy_child_part_prefix(part_id);
            for (index, child) in bodies.iter().enumerate() {
                let child_part_id = format!("{}{index}", child_prefix, index = index + 1);
                legacy_collect_attachments(
                    folder,
                    uid,
                    child,
                    &child_part_id,
                    current_pgp_encrypted,
                    attachments,
                );
            }
        }
        _ => {}
    }
}

fn legacy_body_part_id(body: &BodyStructure<'_>, part_id: &str) -> String {
    if !part_id.is_empty() {
        return part_id.to_string();
    }

    if matches!(body, BodyStructure::Multipart { .. }) {
        "TEXT".to_string()
    } else {
        "1".to_string()
    }
}

fn legacy_child_part_prefix(part_id: &str) -> String {
    if part_id.is_empty() {
        String::new()
    } else {
        format!("{part_id}.")
    }
}

fn legacy_attachment_summary(
    folder: &str,
    uid: u32,
    body: &BodyStructure<'_>,
    part_id: &str,
) -> LegacyAttachmentSummary {
    let common = legacy_body_common(body);
    let single = legacy_body_single_part(body);
    let mime_type = legacy_body_mime_type(common);
    let is_inline = legacy_body_is_inline(common, single);

    LegacyAttachmentSummary {
        object: "Object/Attachment".to_string(),
        folder: folder.to_string(),
        uid,
        mime_index: part_id.to_string(),
        mime_type: mime_type.clone(),
        file_name: legacy_secure_file_name(&legacy_body_file_name(common, &mime_type, part_id)),
        estimated_size: single.map_or(0, legacy_estimated_attachment_size),
        c_id: single
            .and_then(|single| single.id.as_ref())
            .map_or_else(String::new, |id| id.trim().to_string()),
        content_location: common
            .location
            .as_ref()
            .map_or_else(String::new, ToString::to_string),
        is_inline,
    }
}

fn legacy_body_common<'a>(body: &'a BodyStructure<'a>) -> &'a imap_proto::BodyContentCommon<'a> {
    match body {
        BodyStructure::Basic { common, .. }
        | BodyStructure::Text { common, .. }
        | BodyStructure::Message { common, .. }
        | BodyStructure::Multipart { common, .. } => common,
    }
}

fn legacy_body_single_part<'a>(
    body: &'a BodyStructure<'a>,
) -> Option<&'a imap_proto::BodyContentSinglePart<'a>> {
    match body {
        BodyStructure::Basic { other, .. }
        | BodyStructure::Text { other, .. }
        | BodyStructure::Message { other, .. } => Some(other),
        BodyStructure::Multipart { .. } => None,
    }
}

fn legacy_body_mime_type(common: &imap_proto::BodyContentCommon<'_>) -> String {
    format!("{}/{}", common.ty.ty, common.ty.subtype)
        .trim()
        .to_ascii_lowercase()
}

fn legacy_body_file_name(
    common: &imap_proto::BodyContentCommon<'_>,
    mime_type: &str,
    part_id: &str,
) -> String {
    let content_name =
        legacy_decode_body_attr_parameter(common.ty.params.as_deref(), "name").unwrap_or_default();
    let configured = common
        .disposition
        .as_ref()
        .and_then(|disposition| {
            disposition.params.as_deref().map(|params| {
                legacy_decode_body_attr_parameter(Some(params), "filename").unwrap_or_default()
            })
        })
        .unwrap_or(content_name);
    let configured = legacy_php_trim(&configured);
    if !configured.is_empty() {
        return configured.to_string();
    }

    legacy_default_attachment_file_name(common, mime_type, part_id)
}

fn legacy_decode_body_attr_parameter(
    params: Option<&[(Cow<'_, str>, Cow<'_, str>)]>,
    name: &str,
) -> Option<String> {
    let params = params?;
    if let Some(value) = legacy_body_param_exact(params, name) {
        return Some(value.to_string());
    }

    let encoded_name = format!("{name}*");
    if let Some(value) = legacy_body_param_exact(params, &encoded_name) {
        return Some(legacy_decode_rfc2231_value(value));
    }

    let mut segments = params
        .iter()
        .filter_map(|(key, value)| {
            legacy_body_param_continuation_index(key, name).map(|index| (index, value.as_ref()))
        })
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return None;
    }
    segments.sort_by_key(|(index, _)| *index);

    let mut charset = None;
    let mut charset_index = None;
    let mut joined = String::new();
    for (index, value) in segments {
        let mut value = value;
        if charset_index.is_none_or(|charset_index| charset_index < index) {
            if let Some((candidate_charset, encoded)) = value.split_once("''") {
                if !candidate_charset.is_empty() {
                    charset = Some(candidate_charset.to_string());
                    charset_index = Some(index);
                    value = encoded;
                }
            }
        }
        joined.push_str(value);
    }

    Some(legacy_decode_percent_encoded(&joined, charset.as_deref()))
}

fn legacy_body_param_exact<'a>(
    params: &'a [(Cow<'_, str>, Cow<'a, str>)],
    name: &str,
) -> Option<&'a str> {
    params
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_ref()))
}

fn legacy_body_param_continuation_index(key: &str, name: &str) -> Option<usize> {
    let rest = key.strip_prefix(name).or_else(|| {
        key.get(..name.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(name))
            .then(|| &key[name.len()..])
    })?;
    let rest = rest.strip_prefix('*')?;
    let rest = rest.strip_suffix('*')?;
    (!rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit()))
        .then(|| rest.parse::<usize>().ok())
        .flatten()
}

fn legacy_decode_rfc2231_value(value: &str) -> String {
    if let Some((charset, encoded)) = value.split_once("''") {
        legacy_decode_percent_encoded(encoded, Some(charset))
    } else {
        legacy_decode_percent_encoded(value, None)
    }
}

fn legacy_decode_percent_encoded(value: &str, charset: Option<&str>) -> String {
    let bytes = legacy_percent_decode_bytes(value);
    if charset.is_some_and(|charset| {
        charset.eq_ignore_ascii_case("iso-8859-1") || charset.eq_ignore_ascii_case("latin1")
    }) {
        return bytes.into_iter().map(char::from).collect();
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

fn legacy_percent_decode_bytes(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (
                legacy_hex_value(bytes[index + 1]),
                legacy_hex_value(bytes[index + 2]),
            ) {
                decoded.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    decoded
}

fn legacy_hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn legacy_default_attachment_file_name(
    common: &imap_proto::BodyContentCommon<'_>,
    mime_type: &str,
    part_id: &str,
) -> String {
    let suffix = format!("-{part_id}");
    if mime_type == "message/rfc822" {
        return format!("message{suffix}.eml");
    }
    if mime_type == "text/calendar" {
        return format!("calendar{suffix}.ics");
    }
    if mime_type == "text/plain" {
        return format!("part{suffix}.txt");
    }

    let ty = common.ty.ty.as_ref().to_ascii_lowercase();
    let subtype = common.ty.subtype.as_ref().to_ascii_lowercase();
    if ty == "text"
        && matches!(
            subtype.as_str(),
            "vcard" | "html" | "csv" | "xml" | "css" | "asp"
        )
    {
        return format!("part{suffix}.{subtype}");
    }
    if ty == "image"
        && matches!(
            subtype.as_str(),
            "png" | "jpeg" | "gif" | "bmp" | "cgm" | "ief" | "tiff" | "webp"
        )
    {
        return format!("part{suffix}.{subtype}");
    }
    if !mime_type.is_empty() {
        return mime_type.replace('/', &format!("{suffix}."));
    }

    format!(
        "{}{suffix}",
        if legacy_body_is_inline(common, None) {
            "inline"
        } else {
            "part"
        }
    )
}

fn legacy_estimated_attachment_size(single: &imap_proto::BodyContentSinglePart<'_>) -> u32 {
    let coefficient = match &single.transfer_encoding {
        imap_proto::ContentEncoding::Base64 => 0.75,
        imap_proto::ContentEncoding::QuotedPrintable => 0.44,
        _ => 1.0,
    };
    (f64::from(single.octets) * coefficient) as u32
}

fn legacy_body_is_inline(
    common: &imap_proto::BodyContentCommon<'_>,
    single: Option<&imap_proto::BodyContentSinglePart<'_>>,
) -> bool {
    common
        .disposition
        .as_ref()
        .is_some_and(|disposition| disposition.ty.eq_ignore_ascii_case("inline"))
        || single
            .and_then(|single| single.id.as_ref())
            .is_some_and(|id| !id.trim().is_empty())
}

fn legacy_secure_file_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if legacy_unicode_other(ch)
                || matches!(
                    ch,
                    '|' | '\\' | '?' | '*' | '<' | '"' | ':' | '>' | '+' | '[' | ']' | '/' | '&'
                )
            {
                '-'
            } else {
                ch
            }
        })
        .collect()
}

fn legacy_unicode_other(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{e000}'..='\u{f8ff}'
                | '\u{f0000}'..='\u{ffffd}'
                | '\u{100000}'..='\u{10fffd}'
        )
}

fn legacy_body_is_text(common: &imap_proto::BodyContentCommon<'_>) -> bool {
    legacy_body_content_type_eq(common, "text", "html")
        || legacy_body_content_type_eq(common, "text", "plain")
        || legacy_body_content_type_eq(common, "text", "x-amp-html")
}

fn legacy_body_is_multipart(common: &imap_proto::BodyContentCommon<'_>) -> bool {
    common.ty.ty.eq_ignore_ascii_case("multipart")
}

fn legacy_body_is_pgp_encrypted(body: &BodyStructure<'_>) -> bool {
    let BodyStructure::Multipart { common, bodies, .. } = body else {
        return false;
    };

    legacy_body_content_type_eq(common, "multipart", "encrypted")
        && legacy_body_param_eq(common, "protocol", "application/pgp-encrypted")
        && bodies.len() == 2
        && legacy_body_type_eq(&bodies[0], "application", "pgp-encrypted")
        && legacy_body_type_eq(&bodies[1], "application", "octet-stream")
}

fn legacy_body_is_pgp_signed(body: &BodyStructure<'_>) -> bool {
    let BodyStructure::Multipart { common, bodies, .. } = body else {
        return false;
    };

    legacy_body_content_type_eq(common, "multipart", "signed")
        && legacy_body_param_eq(common, "protocol", "application/pgp-signature")
        && bodies.len() == 2
        && legacy_body_type_eq(&bodies[1], "application", "pgp-signature")
}

fn legacy_body_is_multipart_signed(body: &BodyStructure<'_>) -> bool {
    legacy_body_content_type_eq(legacy_body_common(body), "multipart", "signed")
}

fn legacy_body_type_eq(body: &BodyStructure<'_>, ty: &str, subtype: &str) -> bool {
    let common = match body {
        BodyStructure::Basic { common, .. }
        | BodyStructure::Text { common, .. }
        | BodyStructure::Message { common, .. }
        | BodyStructure::Multipart { common, .. } => common,
    };

    legacy_body_content_type_eq(common, ty, subtype)
}

fn legacy_body_is_smime_encrypted(body: &BodyStructure<'_>) -> bool {
    let common = match body {
        BodyStructure::Basic { common, .. } => common,
        _ => return false,
    };

    (legacy_body_content_type_eq(common, "application", "pkcs7-mime")
        || legacy_body_content_type_eq(common, "application", "x-pkcs7-mime"))
        && common.ty.params.as_ref().is_some_and(|params| {
            params.iter().any(|(param_name, param_value)| {
                param_name.eq_ignore_ascii_case("smime-type")
                    && matches!(
                        legacy_php_trim(param_value).to_ascii_lowercase().as_str(),
                        "enveloped-data" | "authenveloped-data"
                    )
            })
        })
}

fn legacy_body_is_detached_smime_signed(
    body: &BodyStructure<'_>,
    bodies: &[BodyStructure<'_>],
) -> bool {
    let common = legacy_body_common(body);

    legacy_body_content_type_eq(common, "multipart", "signed")
        && legacy_body_param_is_pkcs7_signature(common, "protocol")
        && bodies.len() == 2
        && legacy_body_is_pkcs7_signature(&bodies[1])
}

fn legacy_body_is_opaque_smime_signed(body: &BodyStructure<'_>) -> bool {
    let common = match body {
        BodyStructure::Basic { common, .. } => common,
        _ => return false,
    };

    legacy_body_is_pkcs7_mime(common)
        && common.ty.params.as_ref().is_some_and(|params| {
            params.iter().any(|(param_name, param_value)| {
                param_name.eq_ignore_ascii_case("smime-type")
                    && legacy_php_trim(param_value).eq_ignore_ascii_case("signed-data")
            })
        })
}

fn legacy_body_is_pkcs7_signature(body: &BodyStructure<'_>) -> bool {
    let common = legacy_body_common(body);
    legacy_body_content_type_eq(common, "application", "pkcs7-signature")
        || legacy_body_content_type_eq(common, "application", "x-pkcs7-signature")
}

fn legacy_body_is_pkcs7_mime(common: &imap_proto::BodyContentCommon<'_>) -> bool {
    legacy_body_content_type_eq(common, "application", "pkcs7-mime")
        || legacy_body_content_type_eq(common, "application", "x-pkcs7-mime")
}

fn legacy_body_param_is_pkcs7_signature(
    common: &imap_proto::BodyContentCommon<'_>,
    name: &str,
) -> bool {
    common.ty.params.as_ref().is_some_and(|params| {
        params.iter().any(|(param_name, param_value)| {
            param_name.eq_ignore_ascii_case(name)
                && matches!(
                    legacy_php_trim(param_value).to_ascii_lowercase().as_str(),
                    "application/pkcs7-signature" | "application/x-pkcs7-signature"
                )
        })
    })
}

fn legacy_body_root_mic_alg(body: &BodyStructure<'_>, parent_id: &str) -> String {
    if !parent_id.is_empty() {
        return String::new();
    }

    legacy_decode_body_attr_parameter(legacy_body_common(body).ty.params.as_deref(), "micalg")
        .unwrap_or_default()
}

fn legacy_body_content_type_eq(
    common: &imap_proto::BodyContentCommon<'_>,
    ty: &str,
    subtype: &str,
) -> bool {
    common.ty.ty.eq_ignore_ascii_case(ty) && common.ty.subtype.eq_ignore_ascii_case(subtype)
}

fn legacy_body_param_eq(
    common: &imap_proto::BodyContentCommon<'_>,
    name: &str,
    value: &str,
) -> bool {
    common.ty.params.as_ref().is_some_and(|params| {
        params.iter().any(|(param_name, param_value)| {
            param_name.eq_ignore_ascii_case(name)
                && legacy_php_trim(param_value).eq_ignore_ascii_case(value)
        })
    })
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

async fn imap_fetch_metadata_capabilities(
    session: &mut BoxedSession,
) -> Result<ImapFetchMetadataCapabilities> {
    let capabilities = timeout_imap("read IMAP capabilities", session.capabilities()).await?;
    Ok(ImapFetchMetadataCapabilities {
        supports_gmail_id: has_capability_ignore_ascii_case(&capabilities, "X-GM-EXT-1"),
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

fn legacy_message_envelope_metadata(envelope: &imap_proto::Envelope<'_>) -> LegacyMessageEnvelope {
    LegacyMessageEnvelope {
        subject: legacy_decode_envelope_header(envelope.subject.as_ref()),
        message_id: legacy_envelope_string(envelope.message_id.as_ref()),
        in_reply_to: legacy_envelope_string(envelope.in_reply_to.as_ref()),
        from: legacy_envelope_addresses(envelope.from.as_ref()),
        sender: legacy_envelope_addresses(envelope.sender.as_ref()),
        reply_to: legacy_envelope_addresses(envelope.reply_to.as_ref()),
        to: legacy_envelope_addresses(envelope.to.as_ref()),
        cc: legacy_envelope_addresses(envelope.cc.as_ref()),
        bcc: legacy_envelope_addresses(envelope.bcc.as_ref()),
    }
}

fn legacy_envelope_addresses(addresses: Option<&Vec<imap_proto::Address<'_>>>) -> Vec<String> {
    addresses
        .into_iter()
        .flatten()
        .filter_map(legacy_envelope_address)
        .collect()
}

fn legacy_envelope_address(address: &imap_proto::Address<'_>) -> Option<String> {
    let mailbox = legacy_envelope_string(address.mailbox.as_ref());
    let host = legacy_envelope_string(address.host.as_ref());
    if mailbox.is_empty() || host.is_empty() {
        return None;
    }

    let email = format!("{mailbox}@{host}");
    let name = legacy_decode_envelope_header(address.name.as_ref());
    if name.is_empty() {
        Some(email)
    } else {
        Some(format!("{name} <{email}>"))
    }
}

fn legacy_envelope_string(value: Option<&Cow<'_, [u8]>>) -> String {
    value
        .map(|value| String::from_utf8_lossy(value.as_ref()).trim().to_string())
        .unwrap_or_default()
}

fn legacy_decode_envelope_header(value: Option<&Cow<'_, [u8]>>) -> String {
    legacy_decode_rfc2047_header_value(&legacy_envelope_string(value))
}

fn legacy_decode_rfc2047_header_value(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut index = 0;

    while let Some(relative_start) = value[index..].find("=?") {
        let start = index + relative_start;
        decoded.push_str(&value[index..start]);

        let mut stream = MessageStream::new(&value.as_bytes()[start + 1..]);
        if let Some(token) = stream.decode_rfc2047() {
            decoded.push_str(&token);
            index = start + 1 + stream.offset();

            let whitespace_len = value[index..]
                .chars()
                .take_while(|ch| ch.is_ascii_whitespace())
                .map(char::len_utf8)
                .sum::<usize>();
            if value[index + whitespace_len..].starts_with("=?") {
                index += whitespace_len;
            }
        } else {
            decoded.push_str("=?");
            index = start + 2;
        }
    }

    decoded.push_str(&value[index..]);
    decoded.trim().to_string()
}

async fn fetch_body_part_specs(
    session: &mut BoxedSession,
    folder: &str,
    uid: u32,
    capabilities: ImapFetchMetadataCapabilities,
) -> Result<Option<BodyPreviewFetchSpec>> {
    let mut fetches = timeout_imap(
        "fetch message body structure",
        session.uid_fetch(
            uid.to_string(),
            uid_fetch_bodystructure_query_with_gmail_id(uid, capabilities.supports_gmail_id)?,
        ),
    )
    .await?;

    while let Some(fetch) = timeout_imap("read body structure", fetches.try_next()).await? {
        if fetch.uid != Some(uid) {
            continue;
        }
        let flags =
            legacy_unique_flag_strings(fetch.flags().map(|flag| legacy_message_flag_string(&flag)));
        let header = fetch.header().unwrap_or_default().to_vec();
        let internal_timestamp = fetch.internal_date().map(|value| value.timestamp());
        let size = fetch.size.unwrap_or_default();
        let email_id = fetch.gmail_msg_id().map(u64::to_string);
        let envelope = fetch
            .envelope()
            .map(legacy_message_envelope_metadata)
            .unwrap_or_default();
        let Some(bodystructure) = fetch.bodystructure() else {
            return Ok(Some(BodyPreviewFetchSpec {
                parts: vec![BodyPartSpec {
                    path: None,
                    depth: 0,
                    kind: BodyPartKind::RawMessage,
                    octets: fetch.size.unwrap_or(BODY_PREVIEW_PART_LIMIT_BYTES as u32),
                }],
                flags,
                crypto: LegacyMessageCrypto::default(),
                metadata: LegacyMessageFetchMetadata {
                    header,
                    internal_timestamp,
                    size,
                    email_id,
                    attachments: Vec::new(),
                    envelope,
                },
            }));
        };
        let crypto = legacy_message_crypto_metadata(bodystructure);
        let attachments = legacy_message_attachments(folder, uid, Some(bodystructure));
        let metadata = LegacyMessageFetchMetadata {
            header,
            internal_timestamp,
            size,
            email_id,
            attachments,
            envelope,
        };
        let specs = body_preview_part_specs(bodystructure);
        if specs.is_empty() {
            return Ok(Some(BodyPreviewFetchSpec {
                parts: vec![BodyPartSpec {
                    path: None,
                    depth: 0,
                    kind: BodyPartKind::RawMessage,
                    octets: fetch.size.unwrap_or(BODY_PREVIEW_PART_LIMIT_BYTES as u32),
                }],
                flags,
                crypto,
                metadata,
            }));
        }
        return Ok(Some(BodyPreviewFetchSpec {
            parts: specs,
            flags,
            crypto,
            metadata,
        }));
    }

    Ok(None)
}

async fn fetch_preview_parts(
    session: &mut BoxedSession,
    uid: u32,
    specs: &[BodyPartSpec],
    flags: &[String],
    crypto: &LegacyMessageCrypto,
    metadata: &LegacyMessageFetchMetadata,
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
                            is_complete: false,
                            flags: flags.to_vec(),
                            crypto: crypto.clone(),
                            metadata: metadata.clone(),
                        });
                    }
                }
                None => {
                    if let Some(body) = fetch.body() {
                        parts.push(BodyPreviewPart {
                            kind: BodyPartKind::RawMessage,
                            raw: body.to_vec(),
                            is_complete: raw_message_preview_is_complete(body, spec.octets),
                            flags: flags.to_vec(),
                            crypto: crypto.clone(),
                            metadata: metadata.clone(),
                        });
                    }
                }
            }
        }

        if parts.is_empty() {
            if let Some(part) = metadata_only_body_preview_part(flags, crypto, metadata) {
                parts.push(part);
            }
        }

        return Ok(parts);
    }

    Ok(metadata_only_body_preview_part(flags, crypto, metadata)
        .into_iter()
        .collect())
}

fn metadata_only_body_preview_part(
    flags: &[String],
    crypto: &LegacyMessageCrypto,
    metadata: &LegacyMessageFetchMetadata,
) -> Option<BodyPreviewPart> {
    (!metadata.is_empty()).then(|| BodyPreviewPart {
        kind: BodyPartKind::RawMessage,
        raw: Vec::new(),
        is_complete: false,
        flags: flags.to_vec(),
        crypto: crypto.clone(),
        metadata: metadata.clone(),
    })
}

fn raw_message_preview_is_complete(body: &[u8], expected_octets: u32) -> bool {
    expected_octets < BODY_PREVIEW_PART_LIMIT_BYTES as u32
        && usize::try_from(expected_octets).is_ok_and(|expected| body.len() >= expected)
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
    use std::borrow::Cow;

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
            "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER])"
        );
        assert_eq!(
            uid_fetch_bodystructure_query_with_gmail_id(42, true).unwrap(),
            "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER] X-GM-MSGID)"
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
    fn raw_message_preview_completeness_requires_full_uncapped_body() {
        assert!(raw_message_preview_is_complete(b"abcd", 4));
        assert!(!raw_message_preview_is_complete(b"abc", 4));
        assert!(!raw_message_preview_is_complete(
            b"abcd",
            BODY_PREVIEW_PART_LIMIT_BYTES as u32,
        ));
    }

    #[test]
    fn metadata_only_body_preview_preserves_header_fetch_result() {
        let flags = vec!["\\Seen".to_string()];
        let crypto = LegacyMessageCrypto {
            pgp_encrypted: Some(LegacyPartId {
                part_id: "2".to_string(),
            }),
            ..Default::default()
        };
        let metadata = LegacyMessageFetchMetadata {
            header: b"Subject: Empty body\r\n\r\n".to_vec(),
            internal_timestamp: Some(1_700_000_000),
            size: 1024,
            attachments: Vec::new(),
            ..Default::default()
        };

        let part = metadata_only_body_preview_part(&flags, &crypto, &metadata).unwrap();

        assert_eq!(part.kind, BodyPartKind::RawMessage);
        assert!(part.raw.is_empty());
        assert!(!part.is_complete);
        assert_eq!(part.flags, flags);
        assert_eq!(part.crypto, crypto);
        assert_eq!(part.metadata, metadata);
        assert!(
            metadata_only_body_preview_part(&[], &Default::default(), &Default::default())
                .is_none()
        );
    }

    #[test]
    fn legacy_message_envelope_metadata_formats_mailso_fallback_fields() {
        let envelope = imap_proto::Envelope {
            date: Some(Cow::Borrowed(b"Tue, 1 Jul 2003 10:52:37 CEST")),
            subject: Some(Cow::Borrowed(
                b"=?UTF-8?Q?Envelope_=C3=84?= =?UTF-8?Q?subject?=",
            )),
            from: Some(vec![test_envelope_address(
                Some("=?UTF-8?Q?Envelope_=C3=84_Sender?="),
                Some("sender"),
                Some("example.com"),
            )]),
            sender: Some(vec![test_envelope_address(
                Some("Actual Sender"),
                Some("actual"),
                Some("example.com"),
            )]),
            reply_to: Some(vec![test_envelope_address(
                None,
                Some("reply"),
                Some("example.com"),
            )]),
            to: Some(vec![test_envelope_address(
                Some("Recipient"),
                Some("recipient"),
                Some("example.com"),
            )]),
            cc: Some(vec![test_envelope_address(
                None,
                Some("cc"),
                Some("example.com"),
            )]),
            bcc: Some(vec![test_envelope_address(
                None,
                Some("hidden"),
                Some("example.com"),
            )]),
            in_reply_to: Some(Cow::Borrowed(b"<parent@example.com>")),
            message_id: Some(Cow::Borrowed(b"<message@example.com>")),
        };

        let metadata = legacy_message_envelope_metadata(&envelope);

        assert_eq!(metadata.subject, "Envelope Äsubject");
        assert_eq!(metadata.message_id, "<message@example.com>");
        assert_eq!(metadata.in_reply_to, "<parent@example.com>");
        assert_eq!(
            metadata.from,
            vec!["Envelope Ä Sender <sender@example.com>"]
        );
        assert_eq!(metadata.sender, vec!["Actual Sender <actual@example.com>"]);
        assert_eq!(metadata.reply_to, vec!["reply@example.com"]);
        assert_eq!(metadata.to, vec!["Recipient <recipient@example.com>"]);
        assert_eq!(metadata.cc, vec!["cc@example.com"]);
        assert_eq!(metadata.bcc, vec!["hidden@example.com"]);
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
    fn legacy_message_list_limit_matches_mailso_bounds() {
        assert_eq!(legacy_message_list_limit(0), 10);
        assert_eq!(legacy_message_list_limit(1), 10);
        assert_eq!(legacy_message_list_limit(9), 10);
        assert_eq!(legacy_message_list_limit(10), 10);
        assert_eq!(legacy_message_list_limit(50), 50);
        assert_eq!(legacy_message_list_limit(999), 999);
        assert_eq!(legacy_message_list_limit(1_000), 50);
        assert_eq!(legacy_message_list_limit(u32::MAX), 50);
    }

    #[test]
    fn legacy_message_list_fetches_new_messages_only_outside_threads() {
        assert!(legacy_message_list_fetches_new_messages(0));
        assert!(!legacy_message_list_fetches_new_messages(1));
        assert!(!legacy_message_list_fetches_new_messages(u32::MAX));
    }

    #[test]
    fn legacy_new_messages_mailbox_match_is_exact_inbox() {
        assert!(legacy_new_messages_mailbox_matches("INBOX"));
        assert!(!legacy_new_messages_mailbox_matches("Inbox"));
        assert!(!legacy_new_messages_mailbox_matches("inbox"));
        assert!(!legacy_new_messages_mailbox_matches(" INBOX "));
    }

    #[test]
    fn legacy_message_list_search_matches_mailso_trim() {
        assert_eq!(legacy_message_list_search(""), "");
        assert_eq!(legacy_message_list_search(" subject:test "), "subject:test");
        assert_eq!(
            legacy_message_list_search("\tfrom:a@example.com\r\n"),
            "from:a@example.com"
        );
        assert_eq!(
            legacy_message_list_search("\0\x0bbody:test\x0b\0"),
            "body:test"
        );
        assert_eq!(
            legacy_message_list_search("\u{00a0}body:test\u{00a0}"),
            "\u{00a0}body:test\u{00a0}"
        );
    }

    #[test]
    fn legacy_php_trim_matches_default_php_trim_chars() {
        assert_eq!(legacy_php_trim(" \tHello\r\n"), "Hello");
        assert_eq!(legacy_php_trim("\0\x0bHello\0"), "Hello");
        assert_eq!(
            legacy_php_trim("\u{00a0}Hello\u{00a0}"),
            "\u{00a0}Hello\u{00a0}"
        );
    }

    #[test]
    fn legacy_message_list_sort_matches_mailso_reported_sort() {
        assert_eq!(legacy_message_list_sort("", false), "");
        assert_eq!(legacy_message_list_sort("FROM", false), "");
        assert_eq!(legacy_message_list_sort("", true), "REVERSE DATE");
        assert_eq!(legacy_message_list_sort("FROM", true), "FROM REVERSE DATE");
        assert_eq!(legacy_message_list_reported_sort(""), "REVERSE DATE");
        assert_eq!(
            legacy_message_list_reported_sort("FROM"),
            "FROM REVERSE DATE"
        );
        assert_eq!(
            legacy_message_list_sort("REVERSE DATE", true),
            "REVERSE DATE"
        );
        assert_eq!(legacy_message_list_sort("date", true), "date REVERSE DATE");
    }

    #[test]
    fn legacy_message_list_limited_matches_mailso_optimization_flag() {
        assert!(!legacy_message_list_limited(false));
        assert!(legacy_message_list_limited(true));
    }

    #[test]
    fn legacy_message_list_keeps_flags_hides_deleted_by_default() {
        assert!(legacy_message_list_keeps_flags(&[], true));
        assert!(legacy_message_list_keeps_flags(
            &["\\seen".to_string(), "$label1".to_string()],
            true
        ));
        assert!(!legacy_message_list_keeps_flags(
            &["\\deleted".to_string()],
            true
        ));
        assert!(!legacy_message_list_keeps_flags(
            &["\\Deleted".to_string()],
            true
        ));
        assert!(legacy_message_list_keeps_flags(
            &["\\deleted".to_string()],
            false
        ));
    }

    #[test]
    fn legacy_message_flags_match_mailso_aliases_and_uniqueness() {
        let flags = legacy_unique_flag_strings(
            vec![
                Flag::Answered,
                Flag::Custom("$Replied".into()),
                Flag::Custom("$ReadReceipt".into()),
                Flag::Custom("$MdnSent".into()),
                Flag::Custom("$Label1".into()),
            ]
            .into_iter()
            .map(|flag| legacy_message_flag_string(&flag)),
        );

        assert_eq!(
            flags,
            vec![
                "\\answered".to_string(),
                "$mdnsent".to_string(),
                "$label1".to_string()
            ]
        );
    }

    #[test]
    fn legacy_generic_flag_string_preserves_folder_status_aliases() {
        assert_eq!(
            legacy_flag_string(&Flag::Custom("$ReadReceipt".into())),
            "$readreceipt"
        );
        assert_eq!(
            legacy_flag_string(&Flag::Custom("$Replied".into())),
            "$replied"
        );
        assert_eq!(legacy_flag_string(&Flag::Answered), "\\answered");
    }

    #[test]
    fn legacy_strip_spaces_matches_mailso_whitespace_collapse() {
        assert_eq!(legacy_strip_spaces(""), "");
        assert_eq!(legacy_strip_spaces(" \t\r\n "), "");
        assert_eq!(
            legacy_strip_spaces(" <one@example> \r\n\t <two@example>   <three@example> "),
            "<one@example> <two@example> <three@example>"
        );
        assert_eq!(
            legacy_strip_spaces("<one@example>\u{00a0}<two@example>\u{2003}<three@example>"),
            "<one@example> <two@example> <three@example>"
        );
    }

    #[test]
    fn legacy_message_summary_strips_references_like_mailso() {
        let header =
            b"Subject: Refs\r\nReferences: <one@example>\r\n\t <two@example>   <three@example>\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(
            summary.references,
            "<one@example> <two@example> <three@example>"
        );
    }

    #[test]
    fn legacy_message_summary_trims_subject_like_mailso() {
        let header = b"Subject: \0\x0b Trimmed subject \x0b\0\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.subject, "Trimmed subject");
    }

    #[test]
    fn legacy_message_summary_preserves_subject_nbsp_like_mailso() {
        let header = b"Subject: \xc2\xa0 Trimmed subject \xc2\xa0 \r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.subject, "\u{00a0} Trimmed subject \u{00a0}");
    }

    #[test]
    fn legacy_message_summary_parses_envelope_extra_headers_like_mailso() {
        let header = b"Subject: Envelope\r\nBcc: Hidden <hidden@example.com>\r\nSender: Sender <sender@example.com>\r\nDelivered-To: delivered@example.com\r\nDisposition-Notification-To: Receipt <receipt@example.com>\r\nX-Confirm-Reading-To: fallback@example.com\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.bcc, "Hidden <hidden@example.com>");
        assert_eq!(summary.sender, "Sender <sender@example.com>");
        assert_eq!(summary.delivered_to, "delivered@example.com");
        assert_eq!(summary.read_receipt, "Receipt <receipt@example.com>");
    }

    #[test]
    fn legacy_message_summary_carries_gmail_message_id_like_mailso_fallback() {
        let summary = legacy_message_summary_from_fetch_with_email_id(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            b"Subject: Gmail id\r\n\r\n",
            Some("1278455344230334865".to_string()),
        );

        assert_eq!(summary.email_id.as_deref(), Some("1278455344230334865"));
    }

    #[test]
    fn legacy_message_summary_falls_back_to_confirm_reading_receipt() {
        let header = b"Subject: Receipt\r\nX-Confirm-Reading-To: fallback@example.com\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.read_receipt, "fallback@example.com");
    }

    #[test]
    fn legacy_message_summary_uses_confirm_receipt_when_primary_is_empty() {
        let header = b"Subject: Receipt\r\nDisposition-Notification-To: \r\nX-Confirm-Reading-To: fallback@example.com\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.read_receipt, "fallback@example.com");
    }

    #[test]
    fn legacy_message_summary_keeps_display_name_only_read_receipt_like_mailso() {
        let header = b"Subject: Receipt\r\nDisposition-Notification-To: Manual Receipt\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.read_receipt, "Manual Receipt");

        let single_quoted =
            b"Subject: Receipt\r\nDisposition-Notification-To: 'Manual Receipt'\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            single_quoted,
        );

        assert_eq!(summary.read_receipt, "'Manual Receipt'");
    }

    #[test]
    fn legacy_message_summary_drops_invalid_read_receipts_like_mailso() {
        let empty_address = b"Subject: Receipt\r\nDisposition-Notification-To: <>\r\nX-Confirm-Reading-To: fallback@example.com\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            empty_address,
        );

        assert!(summary.read_receipt.is_empty());

        let whitespace_address = b"Subject: Receipt\r\nDisposition-Notification-To: < >\r\nX-Confirm-Reading-To: fallback@example.com\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            whitespace_address,
        );

        assert!(summary.read_receipt.is_empty());

        let quoted_display = b"Subject: Receipt\r\nDisposition-Notification-To: \"Manual Receipt\"\r\nX-Confirm-Reading-To: fallback@example.com\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            quoted_display,
        );

        assert!(summary.read_receipt.is_empty());

        let empty_single_quotes = b"Subject: Receipt\r\nDisposition-Notification-To: ''\r\nX-Confirm-Reading-To: fallback@example.com\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            empty_single_quotes,
        );

        assert!(summary.read_receipt.is_empty());

        let comment_only = b"Subject: Receipt\r\nDisposition-Notification-To: (comment)\r\nX-Confirm-Reading-To: fallback@example.com\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            comment_only,
        );

        assert!(summary.read_receipt.is_empty());
    }

    #[test]
    fn legacy_message_summary_parses_date_header_timestamp() {
        let header = b"Subject: Timestamped\r\nDate: Tue, 1 Jul 2003 10:52:37 CEST\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            41,
            Some(1_700_000_000),
            123,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.date, "Tue, 1 Jul 2003 10:52:37 CEST");
        assert_eq!(summary.date_timestamp, 1_057_049_557);
        assert_eq!(summary.date_timestamp_source, "header");
    }

    #[test]
    fn legacy_message_summary_falls_back_to_internal_date_timestamp() {
        let header = b"Subject: Bad timestamp\r\nDate: definitely not a date\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            42,
            Some(1_700_000_000),
            456,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.date, "definitely not a date");
        assert_eq!(summary.date_timestamp, 1_700_000_000);
        assert_eq!(summary.date_timestamp_source, "internal");
    }

    #[test]
    fn legacy_message_summary_defaults_to_internal_zero_without_dates() {
        let header = b"Subject: No timestamp\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            43,
            None,
            789,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.date, "");
        assert_eq!(summary.date_timestamp, 0);
        assert_eq!(summary.date_timestamp_source, "internal");
        assert_eq!(summary.spam_score, 0);
        assert_eq!(summary.spam_result, "");
        assert!(!summary.is_spam);
    }

    #[test]
    fn legacy_message_summary_parses_rspamd_spam_metadata() {
        let header = b"Subject: *** SPAM *** sale\r\nX-Spamd-Result: default: False [7.13 / 9.00]; BAYES_SPAM\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            44,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.spam_score, 100);
        assert_eq!(summary.spam_result, "7.13 / 9.00");
        assert!(summary.is_spam);
    }

    #[test]
    fn legacy_message_summary_rejects_rspamd_exponent_score_like_php_regex() {
        let header =
            b"Subject: sale\r\nX-Spamd-Result: default: False [1e2 / 5.0]; BAYES_SPAM\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            44,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.spam_score, 0);
        assert_eq!(summary.spam_result, "");
        assert!(!summary.is_spam);
    }

    #[test]
    fn legacy_message_summary_parses_bogofilter_spam_metadata() {
        let header =
            b"Subject: Bogosity\r\nX-Bogosity: Spam, tests=bogofilter, spamicity=0.42\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            44,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.spam_score, 100);
        assert_eq!(
            summary.spam_result,
            "Spam, tests=bogofilter, spamicity=0.42"
        );
        assert!(summary.is_spam);
    }

    #[test]
    fn legacy_message_summary_treats_zero_spam_header_as_php_falsey() {
        let header = b"Subject: Falsey\r\nX-Spamd-Result: 0\r\nX-Bogosity: Ham, tests=bogofilter, spamicity=0.42\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            44,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.spam_score, 42);
        assert_eq!(summary.spam_result, "Ham, tests=bogofilter, spamicity=0.42");
        assert!(!summary.is_spam);
    }

    #[test]
    fn legacy_message_summary_parses_spamassassin_score_and_flag_metadata() {
        let header = b"Subject: SpamAssassin\r\nX-Spam-Status: No, score=3.0 required=5.0 tests=BAYES\r\nX-Spam-Flag: YES\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            44,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.spam_score, 100);
        assert_eq!(summary.spam_result, "3.0 / 5.0");
        assert!(summary.is_spam);
    }

    #[test]
    fn legacy_message_summary_keeps_spamassassin_score_when_not_spam() {
        let header = b"Subject: SpamAssassin\r\nX-Spam-Status: No, score=3.0 required=5.0 tests=BAYES\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            44,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.spam_score, 60);
        assert_eq!(summary.spam_result, "3.0 / 5.0");
        assert!(!summary.is_spam);
    }

    #[test]
    fn legacy_message_summary_parses_spamassassin_info_ratio_metadata() {
        let header = b"Subject: SpamAssassin\r\nX-Spam-Status: No, tests=BAYES\r\nX-Spam-Info: scanner result 2.5/5.0\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            44,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.spam_score, 50);
        assert_eq!(summary.spam_result, "2.5 / 5.0");
        assert!(!summary.is_spam);
    }

    #[test]
    fn legacy_message_summary_marks_bodystructure_attachments() {
        let attachment = BodyStructure::Basic {
            common: test_body_common("application", "pdf", Some("attachment")),
            other: test_body_single_part(1024),
            extension: None,
        };
        let body = BodyStructure::Multipart {
            common: test_body_common("multipart", "mixed", None),
            bodies: vec![
                BodyStructure::Text {
                    common: test_body_common("text", "plain", None),
                    other: test_body_single_part(42),
                    lines: 1,
                    extension: None,
                },
                attachment,
            ],
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            44,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: Attachment\r\n\r\n",
        );

        assert!(summary.has_attachments);
    }

    #[test]
    fn legacy_message_summary_collects_attachment_metadata_like_mailso() {
        let attachment = BodyStructure::Basic {
            common: test_body_common_full(
                "application",
                "pdf",
                Some(vec![("name", "content-name.pdf")]),
                Some("attachment"),
                Some(vec![("filename", "report/final?.pdf")]),
                Some("cid:report"),
            ),
            other: test_body_single_part_full(
                1024,
                imap_proto::ContentEncoding::Base64,
                Some(" <part-id@example> "),
            ),
            extension: None,
        };
        let body = BodyStructure::Multipart {
            common: test_body_common("multipart", "mixed", None),
            bodies: vec![
                BodyStructure::Text {
                    common: test_body_common("text", "plain", None),
                    other: test_body_single_part(42),
                    lines: 1,
                    extension: None,
                },
                attachment,
            ],
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            44,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: Attachment\r\n\r\n",
        );

        assert!(summary.has_attachments);
        assert_eq!(summary.attachments.len(), 1);
        let attachment = &summary.attachments[0];
        assert_eq!(attachment.object, "Object/Attachment");
        assert_eq!(attachment.folder, "INBOX");
        assert_eq!(attachment.uid, 44);
        assert_eq!(attachment.mime_index, "2");
        assert_eq!(attachment.mime_type, "application/pdf");
        assert_eq!(attachment.file_name, "report-final-.pdf");
        assert_eq!(attachment.estimated_size, 768);
        assert_eq!(attachment.c_id, "<part-id@example>");
        assert_eq!(attachment.content_location, "cid:report");
        assert!(attachment.is_inline);
    }

    #[test]
    fn legacy_message_summary_keeps_content_name_without_disposition_params() {
        let body = BodyStructure::Basic {
            common: test_body_common_full(
                "application",
                "pdf",
                Some(vec![("name", "invoice.pdf")]),
                Some("attachment"),
                None,
                None,
            ),
            other: test_body_single_part(1024),
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            46,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: PDF\r\n\r\n",
        );

        assert_eq!(summary.attachments.len(), 1);
        assert_eq!(summary.attachments[0].file_name, "invoice.pdf");
    }

    #[test]
    fn legacy_message_summary_decodes_rfc2231_attachment_names() {
        let body = BodyStructure::Basic {
            common: test_body_common_full(
                "application",
                "octet-stream",
                None,
                Some("attachment"),
                Some(vec![("filename*", "UTF-8''invoice%20%E2%82%AC.pdf")]),
                None,
            ),
            other: test_body_single_part(1024),
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            46,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: PDF\r\n\r\n",
        );

        assert_eq!(summary.attachments.len(), 1);
        assert_eq!(summary.attachments[0].file_name, "invoice €.pdf");
    }

    #[test]
    fn legacy_message_summary_decodes_continued_rfc2231_attachment_names() {
        let body = BodyStructure::Basic {
            common: test_body_common_full(
                "application",
                "octet-stream",
                None,
                Some("attachment"),
                Some(vec![
                    ("filename*1*", "name.txt"),
                    ("filename*0*", "UTF-8''long%20"),
                ]),
                None,
            ),
            other: test_body_single_part(1024),
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            46,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: PDF\r\n\r\n",
        );

        assert_eq!(summary.attachments.len(), 1);
        assert_eq!(summary.attachments[0].file_name, "long name.txt");
    }

    #[test]
    fn legacy_message_summary_secures_attachment_names_like_mailso() {
        let body = BodyStructure::Basic {
            common: test_body_common_full(
                "application",
                "pdf",
                None,
                Some("attachment"),
                Some(vec![("filename", "bad\u{200b}\u{e000}&name?.pdf")]),
                None,
            ),
            other: test_body_single_part(1024),
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            46,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: PDF\r\n\r\n",
        );

        assert_eq!(summary.attachments.len(), 1);
        assert_eq!(summary.attachments[0].file_name, "bad---name-.pdf");
    }

    #[test]
    fn legacy_message_summary_generates_default_attachment_names_like_mailso() {
        let body = BodyStructure::Basic {
            common: test_body_common("application", "pdf", None),
            other: test_body_single_part(1024),
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            46,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: PDF\r\n\r\n",
        );

        assert_eq!(summary.attachments.len(), 1);
        assert_eq!(summary.attachments[0].mime_index, "1");
        assert_eq!(summary.attachments[0].file_name, "application-1.pdf");
        assert_eq!(summary.attachments[0].estimated_size, 1024);
        assert!(!summary.attachments[0].is_inline);
    }

    #[test]
    fn legacy_message_summary_keeps_inline_bodystructure_unattached() {
        let body = BodyStructure::Text {
            common: test_body_common("text", "plain", None),
            other: test_body_single_part(42),
            lines: 1,
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            42,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: Inline\r\n\r\n",
        );

        assert!(!summary.has_attachments);
        assert!(summary.attachments.is_empty());
    }

    #[test]
    fn legacy_message_summary_marks_non_text_leaf_attachment() {
        let body = BodyStructure::Basic {
            common: test_body_common("application", "pdf", None),
            other: test_body_single_part(1024),
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            46,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: PDF\r\n\r\n",
        );

        assert!(summary.has_attachments);
        assert_eq!(summary.attachments.len(), 1);
        assert_eq!(summary.attachments[0].file_name, "application-1.pdf");
    }

    #[test]
    fn legacy_message_summary_skips_pgp_encrypted_payload_attachment_icon() {
        let body = BodyStructure::Multipart {
            common: test_body_common_with_params(
                "multipart",
                "encrypted",
                None,
                Some(vec![("protocol", "application/pgp-encrypted")]),
            ),
            bodies: vec![
                BodyStructure::Basic {
                    common: test_body_common("application", "pgp-encrypted", None),
                    other: test_body_single_part(11),
                    extension: None,
                },
                BodyStructure::Basic {
                    common: test_body_common("application", "octet-stream", None),
                    other: test_body_single_part(1024),
                    extension: None,
                },
            ],
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            47,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: Encrypted\r\n\r\n",
        );

        assert!(!summary.has_attachments);
        assert!(summary.attachments.is_empty());
    }

    #[test]
    fn legacy_message_summary_marks_top_level_encrypted_content_type() {
        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            48,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            b"Subject: Encrypted\r\nContent-Type: multipart/encrypted\r\n\r\n",
        );

        assert!(summary.encrypted);
    }

    #[test]
    fn legacy_message_summary_marks_parameterized_top_level_encrypted_content_type() {
        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            48,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            b"Subject: Encrypted\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"\r\n\r\n",
        );

        assert!(summary.encrypted);
    }

    #[test]
    fn legacy_message_summary_marks_pgp_encrypted_bodystructure() {
        let body = BodyStructure::Multipart {
            common: test_body_common_with_params(
                "multipart",
                "encrypted",
                None,
                Some(vec![("protocol", " application/pgp-encrypted ")]),
            ),
            bodies: vec![
                BodyStructure::Basic {
                    common: test_body_common("application", "pgp-encrypted", None),
                    other: test_body_single_part(11),
                    extension: None,
                },
                BodyStructure::Basic {
                    common: test_body_common("application", "octet-stream", None),
                    other: test_body_single_part(1024),
                    extension: None,
                },
            ],
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            49,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: Encrypted\r\n\r\n",
        );

        assert!(summary.encrypted);
    }

    #[test]
    fn legacy_message_crypto_marks_pgp_encrypted_bodystructure() {
        let body = BodyStructure::Multipart {
            common: test_body_common_with_params(
                "multipart",
                "encrypted",
                None,
                Some(vec![("protocol", " application/pgp-encrypted ")]),
            ),
            bodies: vec![
                BodyStructure::Basic {
                    common: test_body_common("application", "pgp-encrypted", None),
                    other: test_body_single_part(11),
                    extension: None,
                },
                BodyStructure::Basic {
                    common: test_body_common("application", "octet-stream", None),
                    other: test_body_single_part(1024),
                    extension: None,
                },
            ],
            extension: None,
        };

        let crypto = legacy_message_crypto_metadata(&body);

        assert_eq!(crypto.pgp_encrypted.unwrap().part_id, "2");
        assert!(crypto.pgp_signed.is_none());
    }

    #[test]
    fn legacy_message_crypto_marks_pgp_signed_bodystructure() {
        let body = BodyStructure::Multipart {
            common: test_body_common_with_params(
                "multipart",
                "signed",
                None,
                Some(vec![
                    ("protocol", "application/pgp-signature"),
                    ("micalg", "pgp-sha256"),
                ]),
            ),
            bodies: vec![
                BodyStructure::Text {
                    common: test_body_common("text", "plain", None),
                    other: test_body_single_part(128),
                    lines: 1,
                    extension: None,
                },
                BodyStructure::Basic {
                    common: test_body_common("application", "pgp-signature", None),
                    other: test_body_single_part(256),
                    extension: None,
                },
            ],
            extension: None,
        };

        let crypto = legacy_message_crypto_metadata(&body);
        let signed = crypto.pgp_signed.unwrap();

        assert_eq!(signed.part_id, "1");
        assert_eq!(signed.sig_part_id, "2");
        assert_eq!(signed.mic_alg, "pgp-sha256");
    }

    #[test]
    fn legacy_message_crypto_blanks_nested_signed_micalg_like_mailso() {
        let body = BodyStructure::Multipart {
            common: test_body_common("multipart", "mixed", None),
            bodies: vec![BodyStructure::Multipart {
                common: test_body_common_with_params(
                    "multipart",
                    "signed",
                    None,
                    Some(vec![
                        ("protocol", "application/pgp-signature"),
                        ("micalg", "pgp-sha256"),
                    ]),
                ),
                bodies: vec![
                    BodyStructure::Text {
                        common: test_body_common("text", "plain", None),
                        other: test_body_single_part(128),
                        lines: 1,
                        extension: None,
                    },
                    BodyStructure::Basic {
                        common: test_body_common("application", "pgp-signature", None),
                        other: test_body_single_part(256),
                        extension: None,
                    },
                ],
                extension: None,
            }],
            extension: None,
        };

        let signed = legacy_message_crypto_metadata(&body).pgp_signed.unwrap();

        assert_eq!(signed.part_id, "1.1");
        assert_eq!(signed.sig_part_id, "1.2");
        assert_eq!(signed.mic_alg, "");
    }

    #[test]
    fn legacy_message_crypto_does_not_promote_embedded_message_crypto() {
        let embedded = BodyStructure::Multipart {
            common: test_body_common_with_params(
                "multipart",
                "encrypted",
                None,
                Some(vec![("protocol", "application/pgp-encrypted")]),
            ),
            bodies: vec![
                BodyStructure::Basic {
                    common: test_body_common("application", "pgp-encrypted", None),
                    other: test_body_single_part(11),
                    extension: None,
                },
                BodyStructure::Basic {
                    common: test_body_common("application", "octet-stream", None),
                    other: test_body_single_part(1024),
                    extension: None,
                },
            ],
            extension: None,
        };
        let body = BodyStructure::Message {
            common: test_body_common("message", "rfc822", Some("attachment")),
            other: test_body_single_part(2048),
            envelope: test_envelope(),
            body: Box::new(embedded),
            lines: 42,
            extension: None,
        };

        let crypto = legacy_message_crypto_metadata(&body);

        assert!(crypto.is_empty());
    }

    #[test]
    fn legacy_message_summary_marks_smime_encrypted_bodystructure() {
        let body = BodyStructure::Basic {
            common: test_body_common_with_params(
                "application",
                "x-pkcs7-mime",
                None,
                Some(vec![("smime-type", " AuthEnveloped-Data ")]),
            ),
            other: test_body_single_part(1024),
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            50,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: Encrypted\r\n\r\n",
        );

        assert!(summary.encrypted);
    }

    #[test]
    fn legacy_message_crypto_marks_smime_bodystructure() {
        let encrypted = BodyStructure::Basic {
            common: test_body_common_with_params(
                "application",
                "x-pkcs7-mime",
                None,
                Some(vec![("smime-type", " AuthEnveloped-Data ")]),
            ),
            other: test_body_single_part(1024),
            extension: None,
        };
        let opaque_signed = BodyStructure::Basic {
            common: test_body_common_with_params(
                "application",
                "pkcs7-mime",
                None,
                Some(vec![("smime-type", " signed-data ")]),
            ),
            other: test_body_single_part(1024),
            extension: None,
        };
        let detached_signed = BodyStructure::Multipart {
            common: test_body_common_with_params(
                "multipart",
                "signed",
                None,
                Some(vec![
                    ("protocol", "application/x-pkcs7-signature"),
                    ("micalg", "sha-256"),
                ]),
            ),
            bodies: vec![
                BodyStructure::Text {
                    common: test_body_common("text", "plain", None),
                    other: test_body_single_part(128),
                    lines: 1,
                    extension: None,
                },
                BodyStructure::Basic {
                    common: test_body_common("application", "pkcs7-signature", None),
                    other: test_body_single_part(256),
                    extension: None,
                },
            ],
            extension: None,
        };

        let smime_encrypted = legacy_message_crypto_metadata(&encrypted)
            .smime_encrypted
            .unwrap();
        let opaque = legacy_message_crypto_metadata(&opaque_signed)
            .smime_signed
            .unwrap();
        let detached = legacy_message_crypto_metadata(&detached_signed)
            .smime_signed
            .unwrap();

        assert_eq!(smime_encrypted.part_id, "1");
        assert_eq!(opaque.part_id, "1");
        assert_eq!(opaque.sig_part_id, None);
        assert_eq!(opaque.detached, false);
        assert_eq!(detached.part_id, "TEXT");
        assert_eq!(detached.sig_part_id.as_deref(), Some("2"));
        assert_eq!(detached.mic_alg, "sha-256");
        assert_eq!(detached.detached, true);
    }

    #[test]
    fn legacy_message_summary_does_not_mark_smime_signed_as_encrypted() {
        let body = BodyStructure::Basic {
            common: test_body_common_with_params(
                "application",
                "pkcs7-mime",
                None,
                Some(vec![("smime-type", "signed-data")]),
            ),
            other: test_body_single_part(1024),
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            51,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: Signed\r\n\r\n",
        );

        assert!(!summary.encrypted);
    }

    #[test]
    fn legacy_message_summary_does_not_mark_non_pkcs7_smime_type_as_encrypted() {
        let body = BodyStructure::Basic {
            common: test_body_common_with_params(
                "application",
                "octet-stream",
                None,
                Some(vec![("smime-type", "enveloped-data")]),
            ),
            other: test_body_single_part(1024),
            extension: None,
        };

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            52,
            None,
            1024,
            Vec::<Flag<'_>>::new().into_iter(),
            Some(&body),
            b"Subject: Not encrypted\r\n\r\n",
        );

        assert!(!summary.encrypted);
    }

    fn test_body_common(
        ty: &'static str,
        subtype: &'static str,
        disposition: Option<&'static str>,
    ) -> imap_proto::BodyContentCommon<'static> {
        test_body_common_with_params(ty, subtype, disposition, None)
    }

    fn test_body_common_with_params(
        ty: &'static str,
        subtype: &'static str,
        disposition: Option<&'static str>,
        params: Option<Vec<(&'static str, &'static str)>>,
    ) -> imap_proto::BodyContentCommon<'static> {
        test_body_common_full(ty, subtype, params, disposition, None, None)
    }

    fn test_body_common_full(
        ty: &'static str,
        subtype: &'static str,
        params: Option<Vec<(&'static str, &'static str)>>,
        disposition: Option<&'static str>,
        disposition_params: Option<Vec<(&'static str, &'static str)>>,
        location: Option<&'static str>,
    ) -> imap_proto::BodyContentCommon<'static> {
        imap_proto::BodyContentCommon {
            ty: imap_proto::ContentType {
                ty: Cow::Borrowed(ty),
                subtype: Cow::Borrowed(subtype),
                params: params.map(|params| {
                    params
                        .into_iter()
                        .map(|(name, value)| (Cow::Borrowed(name), Cow::Borrowed(value)))
                        .collect()
                }),
            },
            disposition: disposition.map(|ty| imap_proto::ContentDisposition {
                ty: Cow::Borrowed(ty),
                params: disposition_params.map(|params| {
                    params
                        .into_iter()
                        .map(|(name, value)| (Cow::Borrowed(name), Cow::Borrowed(value)))
                        .collect()
                }),
            }),
            language: None,
            location: location.map(Cow::Borrowed),
        }
    }

    fn test_body_single_part(octets: u32) -> imap_proto::BodyContentSinglePart<'static> {
        test_body_single_part_full(octets, imap_proto::ContentEncoding::SevenBit, None)
    }

    fn test_body_single_part_full(
        octets: u32,
        transfer_encoding: imap_proto::ContentEncoding<'static>,
        id: Option<&'static str>,
    ) -> imap_proto::BodyContentSinglePart<'static> {
        imap_proto::BodyContentSinglePart {
            id: id.map(Cow::Borrowed),
            md5: None,
            description: None,
            transfer_encoding,
            octets,
        }
    }

    fn test_envelope() -> imap_proto::Envelope<'static> {
        imap_proto::Envelope {
            date: None,
            subject: None,
            from: None,
            sender: None,
            reply_to: None,
            to: None,
            cc: None,
            bcc: None,
            in_reply_to: None,
            message_id: None,
        }
    }

    fn test_envelope_address(
        name: Option<&'static str>,
        mailbox: Option<&'static str>,
        host: Option<&'static str>,
    ) -> imap_proto::Address<'static> {
        imap_proto::Address {
            name: name.map(|value| Cow::Borrowed(value.as_bytes())),
            adl: None,
            mailbox: mailbox.map(|value| Cow::Borrowed(value.as_bytes())),
            host: host.map(|value| Cow::Borrowed(value.as_bytes())),
        }
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
            legacy_message_cache_key(
                "INBOX",
                44,
                &["\\seen".to_string(), "$label1".to_string()],
                "alice"
            ),
            "b405b4bd83194401eb79e798ed2423c6"
        );
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
        assert_eq!(
            legacy_message_list_params_hash(&request, false, true),
            "8ae7bf17ace2089e3708d4eda1bb88ff"
        );
        assert_eq!(
            legacy_message_list_cache_key(
                &legacy_message_list_params_hash(&request, false, true),
                "etag"
            ),
            "8ae7bf17ace2089e3708d4eda1bb88ff-etag"
        );
        assert_eq!(
            legacy_uid_sequence_set(&[42, 41, 42, 0]),
            Some("41,42".to_string())
        );
        assert_eq!(legacy_uid_sequence_set(&[0]), None);
        assert_eq!(legacy_message_flags_fetch_query(), "(UID FLAGS)");
        assert_eq!(
            legacy_message_list_fetch_query(),
            "(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER])"
        );
        assert_eq!(
            legacy_message_list_fetch_query_with_gmail_id(true),
            "(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER] X-GM-MSGID)"
        );
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
    fn header_value_preserves_non_php_trim_whitespace() {
        let raw = b"Subject: \xc2\xa0first\xc2\xa0 \r\n\t \xc2\xa0continued\xc2\xa0 \r\n\r\n";
        assert_eq!(
            header_value(raw, "subject"),
            Some("\u{00a0}first\u{00a0} \u{00a0}continued\u{00a0}".to_string())
        );
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
