use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex, OnceLock},
    time::{Duration, SystemTime},
};

use async_imap::{
    types::{Capabilities, Capability, Flag, NameAttribute},
    Client, Session,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Datelike, Duration as ChronoDuration, NaiveDate, Utc};
use fm_core::{FrickmailError, Result};
use futures::{pin_mut, Stream, TryStreamExt};
use imap_proto::{
    builders::command::{Command, CommandBuilder},
    AclRight, AttributeValue, BodyStructure, MailboxDatum, RequestId, Response, SectionPath,
    Status, StatusAttribute,
};
use mail_parser::{
    decoders::{base64::base64_decode, charsets::map::charset_decoder},
    MimeHeaders,
};
use md5::{Digest, Md5};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{timeout, Instant},
};
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore},
    TlsConnector,
};

const DEFAULT_TLS_PORT: u16 = 993;
const DEFAULT_PLAIN_PORT: u16 = 143;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const FOLDER_METADATA_FALLBACK_BUDGET: Duration = Duration::from_secs(30);
const MULTISEARCH_MAILBOX_RESULT_LIMIT: usize = 4_096;
const MULTISEARCH_PAGE_MAILBOX_LIMIT: usize = 32;
const MULTISEARCH_UID_ENUMERATION_LIMIT: u32 = 100_000;
const MULTISEARCH_PAGE_BUDGET: Duration = Duration::from_secs(45);
const MESSAGE_LIST_CACHE_WARM_BUDGET: Duration = Duration::from_secs(45);
const MESSAGE_LIST_CACHE_WARM_CONCURRENCY: usize = 4;
static MESSAGE_LIST_CACHE_WARM_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
static MESSAGE_LIST_CACHE_WARM_KEYS: OnceLock<StdMutex<HashSet<String>>> = OnceLock::new();
pub const BODY_PREVIEW_PART_LIMIT_BYTES: usize = 256 * 1024;
const BODY_PREVIEW_TEXT_PART_LIMIT: usize = 32;
const BODY_PREVIEW_TOTAL_LIMIT_BYTES: usize = 1024 * 1024;
const BODY_PREVIEW_HEADER_LIMIT_BYTES: usize = 64 * 1024;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxMetadata {
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxAclEntry {
    pub identifier: String,
    pub rights: String,
    pub mine: bool,
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
    pub pgp_encrypted: Option<LegacyPgpEncrypted>,
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
    pub preview: Option<String>,
    pub attachments: Vec<LegacyAttachmentSummary>,
    pub envelope: LegacyMessageEnvelope,
}

impl LegacyMessageFetchMetadata {
    pub fn is_empty(&self) -> bool {
        self.header.is_empty()
            && self.internal_timestamp.is_none()
            && self.size == 0
            && self.email_id.is_none()
            && self.preview.is_none()
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
pub struct LegacyPgpEncrypted {
    pub part_id: String,
    pub key_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyPgpSigned {
    pub part_id: String,
    pub sig_part_id: Option<String>,
    pub mic_alg: Option<String>,
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
pub struct LegacyFolder {
    pub name: String,
    pub full_name: String,
    pub delimiter: String,
    pub attributes: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub uid_next: Option<u32>,
    pub total_emails: Option<u32>,
    pub unread_emails: Option<u32>,
    pub id: Option<String>,
    pub size: Option<u64>,
    pub role: Option<String>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyFolderCollection {
    pub folders: Vec<LegacyFolder>,
    pub quota_usage: Option<u64>,
    pub quota_limit: Option<u64>,
    pub namespace: String,
    pub namespaces: Option<LegacyNamespaces>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyNamespaces {
    pub personal: Vec<LegacyNamespaceEntry>,
    pub users: Vec<LegacyNamespaceEntry>,
    pub shared: Vec<LegacyNamespaceEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyNamespaceEntry {
    pub prefix: String,
    #[serde(skip)]
    pub wire_prefix: String,
    pub delimiter: Option<String>,
    pub extension: Vec<LegacyNamespaceValue>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum LegacyNamespaceValue {
    Null,
    String(String),
    List(Vec<LegacyNamespaceValue>),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyFolderInformation {
    pub id: Option<String>,
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
    pub threads: Vec<u32>,
    pub thread_unseen: Vec<u32>,
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
    pub fast_simple_search: bool,
    pub permanent_filter: String,
    pub message_list_limit: u32,
    pub use_threads: bool,
    pub thread_uid: u32,
    pub thread_algorithm: String,
}

#[async_trait::async_trait]
pub trait LegacyMessageListUidCache: Send + Sync {
    fn max_uid_entries(&self) -> usize {
        usize::MAX
    }

    fn coordination_namespace(&self) -> String {
        String::new()
    }

    async fn get(&self, raw_key: &str, folder_hash: &str) -> Option<Vec<u32>>;
    async fn set(&self, raw_key: &str, folder_hash: &str, uids: &[u32]);

    async fn get_thread_map(&self, _raw_key: &str) -> Option<Vec<Vec<u32>>> {
        None
    }

    async fn set_thread_map(&self, _raw_key: &str, _threads: &[Vec<u32>]) {}

    async fn get_thread_uids(&self, _raw_key: &str) -> Option<Vec<u32>> {
        None
    }

    async fn set_thread_uids(&self, _raw_key: &str, _uids: &[u32]) {}
}

struct LegacyMessageListCacheWarmGuard {
    key: String,
    _permit: OwnedSemaphorePermit,
}

impl Drop for LegacyMessageListCacheWarmGuard {
    fn drop(&mut self) {
        let Some(keys) = MESSAGE_LIST_CACHE_WARM_KEYS.get() else {
            return;
        };
        keys.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.key);
    }
}

fn try_start_legacy_message_list_cache_warm(
    key: String,
) -> Option<LegacyMessageListCacheWarmGuard> {
    let semaphore = MESSAGE_LIST_CACHE_WARM_SEMAPHORE
        .get_or_init(|| Arc::new(Semaphore::new(MESSAGE_LIST_CACHE_WARM_CONCURRENCY)))
        .clone();
    let permit = semaphore.try_acquire_owned().ok()?;
    let mut keys = MESSAGE_LIST_CACHE_WARM_KEYS
        .get_or_init(|| StdMutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !keys.insert(key.clone()) {
        return None;
    }
    Some(LegacyMessageListCacheWarmGuard {
        key,
        _permit: permit,
    })
}

fn legacy_message_list_cache_warm_cacheable(
    folder_total: Option<u32>,
    max_uid_entries: usize,
) -> bool {
    folder_total
        .and_then(|total| usize::try_from(total).ok())
        .is_some_and(|total| total <= max_uid_entries)
}

fn legacy_message_list_cache_warm_key(
    request: &LegacyMessageListRequest,
    client_hash: &str,
    capabilities: &ImapFetchMetadataCapabilities,
    uid_cache: &dyn LegacyMessageListUidCache,
) -> Result<String> {
    let sort = capabilities
        .supports_sort
        .then(|| {
            legacy_message_list_sort_for_command(&request.sort, capabilities.supports_sort_display)
        })
        .transpose()?;
    let raw_key = legacy_message_list_uid_cache_key(
        &request.mailbox,
        client_hash,
        "",
        LegacyMessageListQueryOptions {
            hide_deleted: request.hide_deleted,
            fast_simple_search: request.fast_simple_search,
            permanent_filter: &request.permanent_filter,
            sort: sort.as_deref(),
            utf8_mode: capabilities.uses_utf8_search,
            supports_within: capabilities.supports_within,
            supports_literal_plus: capabilities.supports_literal_plus,
        },
    )?;
    Ok(format!("{}\0{raw_key}", uid_cache.coordination_namespace()))
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImapFetchMetadataCapabilities {
    supports_gmail_id: bool,
    supports_object_id: bool,
    supports_preview: bool,
    supports_literal_plus: bool,
    uses_utf8_search: bool,
    supports_within: bool,
    supports_multisearch: bool,
    supports_sort: bool,
    supports_sort_display: bool,
    thread_algorithms: Vec<String>,
}

fn legacy_message_fetches_gmail_id(capabilities: &ImapFetchMetadataCapabilities) -> bool {
    capabilities.supports_gmail_id && !capabilities.supports_object_id
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyMessageListMultiSearchScope {
    Mailboxes,
    Subtree,
    SubtreeOne,
}

impl LegacyMessageListMultiSearchScope {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Mailboxes => "mailboxes",
            Self::Subtree => "subtree",
            Self::SubtreeOne => "subtree-one",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyMessageListMailboxMatches {
    mailbox: String,
    uid_validity: u32,
    count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyMessageListMailboxPage {
    mailbox: String,
    uid_validity: u32,
    expected_count: u32,
    offset: u32,
    limit: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyPartKind {
    Html,
    Plain,
    RawMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BodyPartSpec {
    path: Option<[u32; 8]>,
    depth: usize,
    kind: BodyPartKind,
    octets: u32,
    charset: String,
    transfer_encoding: BodyPartTransferEncoding,
    decode_flowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyPartTransferEncoding {
    Identity,
    Base64,
    QuotedPrintable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BodyPreviewFetchSpec {
    parts: Vec<BodyPartSpec>,
    flags: Vec<String>,
    crypto: LegacyMessageCrypto,
    metadata: LegacyMessageFetchMetadata,
}

impl BodyPartSpec {
    fn path_vec(&self) -> Option<Vec<u32>> {
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
    let Some(mut specs) = fetch_body_part_specs(&mut session, mailbox, uid, &capabilities).await?
    else {
        logout_quietly(session).await;
        return Ok(None);
    };
    // Fetch EMAILID and PREVIEW in a single IMAP round trip rather than two
    // separate commands. Both are simple FetchAttributes that can be combined.
    let (mut email_ids, mut previews) = fetch_legacy_message_email_ids_and_previews(
        &mut session,
        &[uid],
        capabilities.supports_object_id,
        capabilities.supports_preview,
        "fetch message EMAILID and PREVIEW",
    )
    .await?;
    if let Some(email_id) = email_ids.remove(&uid) {
        specs.metadata.email_id = Some(email_id);
    }
    specs.metadata.preview = previews.remove(&uid);
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

#[cfg(test)]
async fn fetch_legacy_message_email_id(
    session: &mut BoxedSession,
    uid: u32,
    capabilities: &ImapFetchMetadataCapabilities,
) -> Result<Option<String>> {
    if !capabilities.supports_object_id {
        return Ok(None);
    }

    let (mut email_ids, _) = fetch_legacy_message_email_ids_and_previews(
        session,
        &[uid],
        true,
        false,
        "fetch message EMAILID",
    )
    .await?;
    Ok(email_ids.remove(&uid))
}

/// Fetches EMAILID and/or PREVIEW for a set of UIDs in a single IMAP
/// `UID FETCH` round trip, reducing what was previously two separate commands
/// (one for EMAILID, one for PREVIEW) into one.
async fn fetch_legacy_message_email_ids_and_previews(
    session: &mut BoxedSession,
    uids: &[u32],
    include_email_id: bool,
    include_preview: bool,
    operation: &'static str,
) -> Result<(HashMap<u32, String>, HashMap<u32, String>)> {
    match fetch_legacy_message_email_ids_and_previews_once(
        session,
        uids,
        include_email_id,
        include_preview,
        operation,
    )
    .await
    {
        Ok(OptionalMetadataFetchAttempt::Accepted(metadata)) => return Ok(metadata),
        Ok(OptionalMetadataFetchAttempt::Rejected) => {
            tracing::warn!(
                "optional combined IMAP EMAILID/PREVIEW fetch was rejected; retrying independently"
            );
        }
        Err(error) => {
            tracing::warn!(
                "optional IMAP EMAILID/PREVIEW fetch ended uncertainly; retiring session: {error}"
            );
            return Err(error);
        }
    };

    // An uncertain/early failure can leave the command outstanding. Retry only
    // after a fully consumed matching tagged rejection.

    // A server can advertise both extensions but reject one attribute. Retry
    // them independently so a broken EMAILID implementation does not suppress a
    // usable PREVIEW (and vice versa). Tagged rejections omit that field; an
    // uncertain failure retires the session by propagating the error.
    let email_ids = if include_email_id && include_preview {
        match fetch_legacy_message_email_ids_and_previews_once(
            session,
            uids,
            true,
            false,
            "retry optional EMAILID fetch",
        )
        .await
        {
            Ok(OptionalMetadataFetchAttempt::Accepted(metadata)) => metadata.0,
            Ok(OptionalMetadataFetchAttempt::Rejected) => HashMap::new(),
            Err(error) => {
                tracing::warn!(
                    "optional IMAP EMAILID retry ended uncertainly; retiring session: {error}"
                );
                return Err(error);
            }
        }
    } else {
        HashMap::new()
    };
    let previews = if include_email_id && include_preview {
        match fetch_legacy_message_email_ids_and_previews_once(
            session,
            uids,
            false,
            true,
            "retry optional PREVIEW fetch",
        )
        .await
        {
            Ok(OptionalMetadataFetchAttempt::Accepted(metadata)) => metadata.1,
            Ok(OptionalMetadataFetchAttempt::Rejected) => HashMap::new(),
            Err(error) => {
                tracing::warn!(
                    "optional IMAP PREVIEW retry ended uncertainly; retiring session: {error}"
                );
                return Err(error);
            }
        }
    } else {
        HashMap::new()
    };
    Ok((email_ids, previews))
}

enum OptionalMetadataFetchAttempt {
    Accepted((HashMap<u32, String>, HashMap<u32, String>)),
    Rejected,
}

async fn fetch_legacy_message_email_ids_and_previews_once(
    session: &mut BoxedSession,
    uids: &[u32],
    include_email_id: bool,
    include_preview: bool,
    operation: &'static str,
) -> Result<OptionalMetadataFetchAttempt> {
    if !include_email_id && !include_preview {
        return Ok(OptionalMetadataFetchAttempt::Accepted((
            HashMap::new(),
            HashMap::new(),
        )));
    }

    let requested_uids = uids
        .iter()
        .copied()
        .filter(|uid| *uid > 0)
        .collect::<HashSet<_>>();
    let Some(uid_set) = legacy_uid_sequence_set(uids) else {
        return Ok(OptionalMetadataFetchAttempt::Accepted((
            HashMap::new(),
            HashMap::new(),
        )));
    };

    let mut attrs: Vec<&str> = vec!["UID"];
    if include_email_id {
        attrs.push("EMAILID");
    }
    if include_preview {
        attrs.push("PREVIEW");
    }
    let command = format!("UID FETCH {uid_set} ({})", attrs.join(" "));

    timeout_result(
        operation,
        timeout(COMMAND_TIMEOUT, async {
            let request_id = session
                .run_command(&command)
                .await
                .map_err(|error| imap_error(operation, error))?;
            let mut email_ids = HashMap::new();
            let mut previews = HashMap::new();
            loop {
                let response = session
                    .read_response()
                    .await
                    .map_err(|error| {
                        FrickmailError::Upstream(format!("{operation} failed: {error}"))
                    })?
                    .ok_or_else(|| {
                        FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP connection closed"
                        ))
                    })?;
                if let Response::Fetch(_, fetch_attrs) = response.parsed() {
                    let response_uid = fetch_attrs.iter().find_map(|attr| match attr {
                        AttributeValue::Uid(value) => Some(*value),
                        _ => None,
                    });
                    if let Some(response_uid) = response_uid {
                        if !requested_uids.contains(&response_uid) {
                            continue;
                        }
                        if include_email_id {
                            if let Some(email_id) = fetch_attrs.iter().find_map(|attr| match attr {
                                AttributeValue::EmailId(value) => Some(value.to_string()),
                                _ => None,
                            }) {
                                email_ids.insert(response_uid, email_id);
                            }
                        }
                        if include_preview {
                            if let Some(preview) = fetch_attrs.iter().find_map(|attr| match attr {
                                AttributeValue::Preview(Some(preview)) => Some(preview.as_ref()),
                                _ => None,
                            }) {
                                if let Ok(preview) = std::str::from_utf8(preview) {
                                    previews.insert(response_uid, preview.to_string());
                                } else {
                                    tracing::warn!(
                                        "ignoring IMAP PREVIEW response that was not valid UTF-8"
                                    );
                                }
                            }
                        }
                    }
                }
                if matches!(response.parsed(), Response::Continue { .. }) {
                    return Err(FrickmailError::Upstream(format!(
                        "{operation} failed: unexpected IMAP continuation"
                    )));
                }
                match response.parsed() {
                    Response::Done {
                        tag,
                        status: Status::Ok,
                        ..
                    } if tag == &request_id => {
                        return Ok(OptionalMetadataFetchAttempt::Accepted((
                            email_ids, previews,
                        )))
                    }
                    Response::Done { tag, .. } if tag == &request_id => {
                        return Ok(OptionalMetadataFetchAttempt::Rejected)
                    }
                    Response::Data {
                        status: Status::Bye,
                        ..
                    } => {
                        return Err(FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP server closed the session"
                        )))
                    }
                    _ => {}
                }
            }
        }),
    )
    .await?
}

#[cfg(test)]
async fn fetch_legacy_message_preview(
    session: &mut BoxedSession,
    uid: u32,
    capabilities: &ImapFetchMetadataCapabilities,
) -> Result<Option<String>> {
    if !capabilities.supports_preview {
        return Ok(None);
    }

    let (_, mut previews) = fetch_legacy_message_email_ids_and_previews(
        session,
        &[uid],
        false,
        true,
        "fetch message PREVIEW",
    )
    .await?;
    Ok(previews.remove(&uid))
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

pub async fn fetch_legacy_folders(
    config: ImapConnectionConfig,
    password: &str,
    discover_subscriptions: bool,
) -> Result<LegacyFolderCollection> {
    let namespaces = fetch_legacy_namespaces(config.clone(), password)
        .await
        .unwrap_or(None);
    let client_hash = legacy_imap_client_hash(&config);
    let mut session = login(config, password).await?;
    let result = async {
        let capabilities =
            timeout_imap("read folder-list capabilities", session.capabilities()).await?;
        let utf8_mode = enable_legacy_utf8(&mut session, &capabilities).await?;
        let capability_names = legacy_visible_capabilities(&capabilities);
        let list_extended = has_capability_ignore_ascii_case(&capabilities, "LIST-EXTENDED");
        let list_status = has_capability_ignore_ascii_case(&capabilities, "LIST-STATUS");
        let options = LegacyFolderListOptions {
            discover_subscriptions,
            list_extended,
            list_status,
            special_use: has_capability_ignore_ascii_case(&capabilities, "SPECIAL-USE"),
            highest_modseq: has_capability_ignore_ascii_case(&capabilities, "CONDSTORE")
                || has_capability_ignore_ascii_case(&capabilities, "QRESYNC"),
            append_limit: has_capability_ignore_ascii_case(&capabilities, "APPENDLIMIT"),
            size: has_capability_ignore_ascii_case(&capabilities, "STATUS=SIZE"),
            mailbox_id: has_capability_ignore_ascii_case(&capabilities, "OBJECTID"),
            utf8_mode,
        };

        let mut references = vec![String::new()];
        if let Some(namespaces) = namespaces.as_ref() {
            if let Some(namespace) = namespaces.users.first() {
                references.push(namespace.wire_prefix.clone());
            }
            if let Some(namespace) = namespaces.shared.first() {
                references.push(namespace.wire_prefix.clone());
            }
        }
        references.dedup();

        let mut listed_folders = Vec::new();
        let mut seen = HashSet::new();
        for (index, reference) in references.iter().enumerate() {
            let listed = legacy_folders_for_reference(&mut session, reference, &options).await;
            let listed = match listed {
                Ok(listed) => listed,
                Err(error) if index > 0 => {
                    let _ = error;
                    continue;
                }
                Err(error) => return Err(error),
            };
            for folder in listed {
                if seen.insert(folder.full_name.clone()) {
                    listed_folders.push(folder);
                }
            }
        }

        let metadata_supported = has_capability_ignore_ascii_case(&capabilities, "METADATA");
        let mut session_usable = true;
        let mut all_metadata = if metadata_supported {
            match legacy_all_metadata(&mut session, utf8_mode).await {
                Ok(metadata) => metadata,
                Err(_) => {
                    session_usable = false;
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };
        if metadata_supported && session_usable && all_metadata.is_empty() {
            let fallback_deadline = Instant::now() + FOLDER_METADATA_FALLBACK_BUDGET;
            for folder in listed_folders.iter().filter(|folder| folder.selectable()) {
                let remaining = fallback_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match legacy_folder_metadata_with_timeout(
                    &mut session,
                    &folder.wire_name,
                    remaining.min(COMMAND_TIMEOUT),
                )
                .await
                {
                    Ok(Some(metadata)) => {
                        all_metadata.insert(folder.full_name.clone(), metadata);
                    }
                    Ok(None) => break,
                    Err(_) => {
                        session_usable = false;
                        break;
                    }
                }
            }
        }

        let folders = listed_folders
            .into_iter()
            .map(|folder| {
                let metadata = all_metadata.remove(&folder.full_name).unwrap_or_default();
                folder.into_legacy_folder(metadata, &client_hash)
            })
            .collect();
        let (quota_usage, quota_limit) = if session_usable {
            legacy_storage_quota(&mut session, &capabilities).await
        } else {
            (None, None)
        };
        let namespace = namespaces
            .as_ref()
            .map(LegacyNamespaces::personal_prefix)
            .unwrap_or_default();

        Ok(LegacyFolderCollection {
            folders,
            quota_usage,
            quota_limit,
            namespace,
            namespaces,
            capabilities: capability_names,
        })
    }
    .await;
    logout_quietly(session).await;
    result
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
    fetch_legacy_message_list_with_uid_cache(config, password, request, None).await
}

pub async fn fetch_legacy_message_list_with_uid_cache(
    config: ImapConnectionConfig,
    password: &str,
    request: LegacyMessageListRequest,
    uid_cache: Option<Arc<dyn LegacyMessageListUidCache>>,
) -> Result<LegacyMessageList> {
    fetch_legacy_message_list_with_uid_cache_if_changed(config, password, request, uid_cache, None)
        .await?
        .ok_or_else(|| {
            FrickmailError::Upstream("message list fetch was unexpectedly skipped".to_string())
        })
}

pub async fn fetch_legacy_message_list_with_uid_cache_if_changed(
    config: ImapConnectionConfig,
    password: &str,
    request: LegacyMessageListRequest,
    uid_cache: Option<Arc<dyn LegacyMessageListUidCache>>,
    unchanged_folder_etag: Option<String>,
) -> Result<Option<LegacyMessageList>> {
    validate_mailbox(&request.mailbox)?;

    let client_hash = legacy_imap_client_hash(&config);
    let warm_config = config.clone();
    let warm_password = password.to_string();
    let warm_request = request.clone();
    let mut session = login(config, password).await?;
    let capabilities = imap_fetch_metadata_capabilities(&mut session).await?;
    let warm_key = uid_cache
        .as_deref()
        .map(|cache| {
            legacy_message_list_cache_warm_key(&request, &client_hash, &capabilities, cache)
        })
        .transpose()
        .ok()
        .flatten();
    let result = legacy_message_list_in_session_if_changed(
        &mut session,
        request,
        &client_hash,
        capabilities,
        uid_cache.as_deref(),
        unchanged_folder_etag.as_deref(),
    )
    .await;
    logout_quietly(session).await;
    if let (Ok(Some(list)), Some(uid_cache), Some(warm_key)) = (&result, uid_cache, warm_key) {
        let cacheable = legacy_message_list_cache_warm_cacheable(
            list.folder.total_emails,
            uid_cache.max_uid_entries(),
        );
        if list.limited && cacheable {
            let folder_hash = list.folder.etag.clone();
            if let Some(guard) = try_start_legacy_message_list_cache_warm(warm_key) {
                tokio::spawn(async move {
                    let _guard = guard;
                    let _ = timeout(
                        MESSAGE_LIST_CACHE_WARM_BUDGET,
                        warm_legacy_message_list_cache(
                            warm_config,
                            &warm_password,
                            warm_request,
                            folder_hash,
                            uid_cache,
                        ),
                    )
                    .await;
                });
            }
        }
    }
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

/// Fetches a single MIME part from a message via IMAP.
///
/// Opens a connection, EXAMINEs the given mailbox, and issues a
/// `UID FETCH <uid> BODY.PEEK[<mime_index>]` command. Returns the
/// raw bytes of the requested part, or `None` if the UID was not found.
///
/// When `mime_index` is empty, fetches the entire raw message body
/// (equivalent to `BODY.PEEK[]`).
pub async fn fetch_mime_part(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    uid: u32,
    mime_index: &str,
) -> Result<Option<Vec<u8>>> {
    validate_mailbox(mailbox)?;
    if uid == 0 {
        return Err(FrickmailError::BadRequest("uid required".to_string()));
    }
    if !mime_index.is_empty() && !is_valid_mime_index(mime_index) {
        return Err(FrickmailError::BadRequest("invalid mimeIndex".to_string()));
    }

    let mut session = login(config, password).await?;
    timeout_imap("examine mailbox", session.examine(mailbox)).await?;

    let query = if mime_index.is_empty() {
        "(UID BODY.PEEK[])".to_string()
    } else {
        format!("(UID BODY.PEEK[{mime_index}])")
    };

    let result = {
        let mut fetches =
            timeout_imap("fetch mime part", session.uid_fetch(uid.to_string(), query)).await?;

        let mut result = None;
        while let Some(fetch) = timeout_imap("read mime part", fetches.try_next()).await? {
            if fetch.uid != Some(uid) {
                continue;
            }
            if mime_index.is_empty() {
                result = fetch.body().map(ToOwned::to_owned);
            } else if let Some(path) = parse_mime_index_path(mime_index) {
                result = fetch
                    .section(&SectionPath::Part(path, None))
                    .map(ToOwned::to_owned);
                if result.as_deref() == Some(&[]) {
                    result = None;
                }
            }
            break;
        }

        result
    };

    logout_quietly(session).await;
    Ok(result)
}

/// Validates a MIME part index (e.g. `"1"`, `"1.2"`, `"1.2.3"`) so it cannot
/// inject IMAP command separators into the `BODY.PEEK[…]` fetch argument.
/// Only digits and dots are permitted; an empty or all-dot index is rejected.
fn is_valid_mime_index(mime_index: &str) -> bool {
    if mime_index.is_empty() {
        return false;
    }
    if mime_index.bytes().all(|b| b == b'.') {
        return false;
    }
    mime_index.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

fn parse_mime_index_path(mime_index: &str) -> Option<Vec<u32>> {
    let mut path = Vec::new();
    for part in mime_index.split('.') {
        let n: u32 = part.parse().ok()?;
        path.push(n);
    }
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
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

/// Failure classification for an IMAP APPEND. A definitive failure is known to
/// have happened before commit (or is a tagged NO/BAD), so callers may safely
/// try another mailbox. An uncertain failure may have committed and must not be
/// retried automatically because that can create duplicate messages.
#[derive(Debug)]
pub enum AppendRawMessageFailure {
    Definitive(String),
    Uncertain(String),
}

impl AppendRawMessageFailure {
    pub fn public_message(&self) -> &str {
        match self {
            Self::Definitive(message) | Self::Uncertain(message) => message,
        }
    }
}

pub async fn append_raw_message_classified(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    raw: &[u8],
) -> std::result::Result<(), AppendRawMessageFailure> {
    validate_mailbox(mailbox)
        .and_then(|_| validate_eml(raw))
        .map_err(|err| AppendRawMessageFailure::Definitive(err.public_message()))?;
    let mut session = login(config, password)
        .await
        .map_err(|err| AppendRawMessageFailure::Definitive(err.public_message()))?;

    let result = match timeout(
        COMMAND_TIMEOUT,
        session.append(mailbox, Some("(\\Seen)"), None, raw),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(async_imap::error::Error::No(message) | async_imap::error::Error::Bad(message))) => {
            Err(AppendRawMessageFailure::Definitive(format!(
                "append raw message failed: {message}"
            )))
        }
        Ok(Err(err)) => Err(AppendRawMessageFailure::Uncertain(format!(
            "append raw message failed: {err}"
        ))),
        Err(_) => Err(AppendRawMessageFailure::Uncertain(
            "append raw message timed out".to_string(),
        )),
    };
    logout_quietly(session).await;
    result
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

/// Appends a draft as `\Seen` and resolves the resulting UID.
///
/// The `async-imap` `APPEND` helper consumes the tagged completion internally, so
/// the RFC 4315 `APPENDUID` response code is not reachable through it. Legacy PHP
/// has the same gap for servers without UIDPLUS and falls back to locating the
/// message by its `Message-ID`; this does the same lookup unconditionally.
///
/// Returns `None` when the append succeeded but the UID could not be resolved,
/// which callers must treat as a successful save with an unknown UID.
pub async fn append_draft_message(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    raw: &[u8],
    message_id: Option<&str>,
) -> Result<Option<u32>> {
    validate_mailbox(mailbox)?;
    validate_eml(raw)?;

    let mut session = login(config.clone(), password).await?;
    let result = append_draft_message_in_session(&mut session, mailbox, raw, message_id).await;
    logout_quietly(session).await;
    match result? {
        DraftAppendAttempt::Saved(uid) => Ok(uid),
        DraftAppendAttempt::Uncertain(message) => {
            tracing::warn!("draft APPEND has an uncertain outcome: {message}");
            let Some(message_id) = message_id.map(str::trim).filter(|id| !id.is_empty()) else {
                return Ok(None);
            };
            // Reconnect because the original stream may be desynchronized or
            // closed. Locating the unique Message-ID proves that APPEND committed.
            let Ok(mut recovery) = login(config, password).await else {
                return Ok(None);
            };
            let recovered =
                if timeout_imap("select draft recovery mailbox", recovery.select(mailbox))
                    .await
                    .is_ok()
                {
                    find_uid_by_message_id(&mut recovery, message_id)
                        .await
                        .unwrap_or(None)
                } else {
                    None
                };
            logout_quietly(recovery).await;
            Ok(recovered)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DraftAppendAttempt {
    Saved(Option<u32>),
    Uncertain(String),
}

async fn append_draft_message_in_session(
    session: &mut BoxedSession,
    mailbox: &str,
    raw: &[u8],
    message_id: Option<&str>,
) -> Result<DraftAppendAttempt> {
    match timeout(
        COMMAND_TIMEOUT,
        session.append(mailbox, Some("(\\Seen)"), None, raw),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(async_imap::error::Error::No(message) | async_imap::error::Error::Bad(message))) => {
            return Err(FrickmailError::Upstream(format!(
                "append draft message failed: {message}"
            )))
        }
        Ok(Err(error)) => {
            return Ok(DraftAppendAttempt::Uncertain(format!(
                "append draft message failed: {error}"
            )))
        }
        Err(_) => {
            return Ok(DraftAppendAttempt::Uncertain(
                "append draft message timed out".to_string(),
            ))
        }
    }

    let Some(message_id) = message_id.map(str::trim).filter(|id| !id.is_empty()) else {
        return Ok(DraftAppendAttempt::Saved(None));
    };

    // The APPEND is already committed at this point. A later SELECT/SEARCH
    // failure must not turn the save into an API failure that encourages the
    // client to retry and create another copy of the same draft.
    if let Err(error) = timeout_imap("select draft mailbox", session.select(mailbox)).await {
        tracing::warn!("draft was appended but selecting it for UID lookup failed: {error}");
        return Ok(DraftAppendAttempt::Saved(None));
    }
    match find_uid_by_message_id(session, message_id).await {
        Ok(uid) => Ok(DraftAppendAttempt::Saved(uid)),
        Err(error) => {
            tracing::warn!("draft was appended but its UID lookup failed: {error}");
            Ok(DraftAppendAttempt::Saved(None))
        }
    }
}

/// Finds the highest UID whose `Message-ID` header matches, mirroring legacy
/// PHP's `FindMessageUidByMessageId`. The newest match wins because a redundant
/// append of the same draft leaves older copies behind.
async fn find_uid_by_message_id(
    session: &mut BoxedSession,
    message_id: &str,
) -> Result<Option<u32>> {
    let quoted = quote_imap_string("message id", message_id)?;
    let criteria = format!("HEADER MESSAGE-ID {quoted}");
    let uids = timeout_imap("search draft by message id", session.uid_search(&criteria)).await?;
    Ok(uids.into_iter().max())
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

pub async fn set_mailbox_metadata(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    metadata: MailboxMetadata,
) -> Result<()> {
    let mut session = login(config, password).await?;
    let result = async {
        if mailbox_metadata_supported(&mut session).await? {
            let command = set_metadata_command(mailbox, &metadata)?;
            timeout_imap(
                "set mailbox metadata",
                session.run_command_and_check_ok(&command),
            )
            .await?;
        }
        Ok(())
    }
    .await;
    logout_quietly(session).await;
    result
}

pub async fn update_mailbox_settings(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    subscribe: bool,
    metadata: Option<MailboxMetadata>,
) -> Result<()> {
    let mut session = login(config, password).await?;

    if validate_mailbox(mailbox).is_ok() {
        let subscription_result = if subscribe {
            timeout_imap("subscribe mailbox", session.subscribe(mailbox)).await
        } else {
            timeout_imap("unsubscribe mailbox", session.unsubscribe(mailbox)).await
        };
        let _ = subscription_result;
    }

    if let Some(metadata) = metadata.as_ref() {
        if let Some(command) = best_effort_metadata_command(mailbox, metadata) {
            if mailbox_metadata_supported(&mut session)
                .await
                .unwrap_or(false)
            {
                let _ = timeout_imap(
                    "set mailbox metadata",
                    session.run_command_and_check_ok(&command),
                )
                .await;
            }
        }
    }

    logout_quietly(session).await;
    Ok(())
}

pub async fn fetch_mailbox_acl(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
) -> Result<Vec<MailboxAclEntry>> {
    validate_mailbox(mailbox)?;

    let login_identifier = config.login.clone();
    let mut session = login(config, password).await?;
    let result = async {
        require_mailbox_acl_support(&mut session).await?;

        let mailbox_arg = quote_imap_string("mailbox", mailbox)?;
        let my_rights = run_acl_command(
            &mut session,
            &format!("MYRIGHTS {mailbox_arg}"),
            "read mailbox rights",
            mailbox,
        )
        .await?
        .my_rights
        .unwrap_or_default();
        let mut entries = vec![MailboxAclEntry {
            identifier: login_identifier.clone(),
            rights: my_rights.clone(),
            mine: true,
        }];

        if my_rights.contains('a') {
            let responses = run_acl_command(
                &mut session,
                &format!("GETACL {mailbox_arg}"),
                "read mailbox ACL",
                mailbox,
            )
            .await?;
            entries.extend(
                responses
                    .entries
                    .into_iter()
                    .filter(|entry| entry.identifier != login_identifier)
                    .map(|entry| MailboxAclEntry {
                        identifier: entry.identifier,
                        rights: entry.rights,
                        mine: false,
                    }),
            );
        }

        Ok(entries)
    }
    .await;
    logout_quietly(session).await;
    result
}

pub async fn set_mailbox_acl(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    identifier: &str,
    rights: &str,
) -> Result<()> {
    validate_mailbox(mailbox)?;
    let command = set_acl_command(mailbox, identifier, rights)?;

    let mut session = login(config, password).await?;
    let result = async {
        require_mailbox_acl_support(&mut session).await?;
        timeout_imap(
            "set mailbox ACL",
            session.run_command_and_check_ok(&command),
        )
        .await
    }
    .await;
    logout_quietly(session).await;
    result
}

pub async fn delete_mailbox_acl(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    identifier: &str,
) -> Result<()> {
    validate_mailbox(mailbox)?;
    let command = delete_acl_command(mailbox, identifier)?;

    let mut session = login(config, password).await?;
    let result = async {
        require_mailbox_acl_support(&mut session).await?;
        timeout_imap(
            "delete mailbox ACL",
            session.run_command_and_check_ok(&command),
        )
        .await
    }
    .await;
    logout_quietly(session).await;
    result
}

pub async fn create_mailbox(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
    parent: &str,
    subscribe: bool,
) -> Result<Option<LegacyFolder>> {
    let mailbox = mailbox.trim();
    let parent = parent.trim();
    validate_mailbox(mailbox)?;
    if !parent.is_empty() {
        validate_mailbox(parent)?;
    }

    let mut session = login(config, password).await?;
    let result = async {
        let delimiter = mailbox_hierarchy_delimiter(&mut session, parent).await?;
        let full_name = create_mailbox_full_name(mailbox, parent, delimiter.as_str());
        validate_mailbox(&full_name)?;

        timeout_imap("create mailbox", session.create(&full_name)).await?;
        if subscribe {
            timeout_imap("subscribe created mailbox", session.subscribe(&full_name)).await?;
        }

        created_legacy_folder(&mut session, &full_name, subscribe).await
    }
    .await;
    logout_quietly(session).await;
    result
}

pub async fn rename_mailbox(
    config: ImapConnectionConfig,
    password: &str,
    old_name: &str,
    new_name: &str,
    subscribe: bool,
    metadata: Option<MailboxMetadata>,
) -> Result<String> {
    validate_mailbox(old_name)?;
    validate_mailbox(new_name)?;

    let mut session = login(config, password).await?;
    let result = async {
        let delimiter = mailbox_hierarchy_delimiter(&mut session, old_name).await?;
        let subscribed =
            subscribed_mailbox_subtree(&mut session, old_name, delimiter.as_str()).await?;

        timeout_imap("rename mailbox", session.rename(old_name, new_name)).await?;
        for old_subscription in subscribed {
            let new_subscription =
                renamed_mailbox_name(&old_subscription, old_name, new_name, delimiter.as_str());
            timeout_imap(
                "unsubscribe renamed mailbox",
                session.unsubscribe(&old_subscription),
            )
            .await?;
            timeout_imap(
                "subscribe renamed mailbox",
                session.subscribe(&new_subscription),
            )
            .await?;
        }

        let subscription_result = if subscribe {
            timeout_imap("subscribe renamed mailbox", session.subscribe(new_name)).await
        } else {
            timeout_imap("unsubscribe renamed mailbox", session.unsubscribe(new_name)).await
        };
        let _ = subscription_result;

        if let Some(metadata) = metadata.as_ref() {
            if let Some(command) = best_effort_metadata_command(new_name, metadata) {
                if mailbox_metadata_supported(&mut session)
                    .await
                    .unwrap_or(false)
                {
                    let _ = timeout_imap(
                        "set renamed mailbox metadata",
                        session.run_command_and_check_ok(&command),
                    )
                    .await;
                }
            }
        }

        Ok(delimiter)
    }
    .await;
    logout_quietly(session).await;
    result
}

pub async fn clear_mailbox(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
) -> Result<()> {
    validate_mailbox(mailbox)?;

    let mut session = login(config, password).await?;
    let selected = timeout_imap("select mailbox", session.select(mailbox)).await?;
    let result = clear_mailbox_in_session(&mut session, selected.exists).await;
    logout_quietly(session).await;
    result
}

pub async fn delete_mailbox(
    config: ImapConnectionConfig,
    password: &str,
    mailbox: &str,
) -> Result<()> {
    validate_mailbox(mailbox)?;

    let mut session = login(config, password).await?;
    let status = timeout_imap(
        "check mailbox before delete",
        session.status(mailbox, "(MESSAGES)"),
    )
    .await?;
    let result = async {
        validate_deletable_mailbox(mailbox, status.exists)?;
        timeout_imap(
            "unsubscribe mailbox before delete",
            session.unsubscribe(mailbox),
        )
        .await?;
        timeout_imap("delete mailbox", session.delete(mailbox)).await
    }
    .await;
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

pub fn uid_fetch_bodystructure_query(uid: u32) -> Result<String> {
    uid_fetch_bodystructure_query_with_gmail_id(uid, false)
}

pub fn uid_fetch_bodystructure_query_with_gmail_id(
    uid: u32,
    include_gmail_id: bool,
) -> Result<String> {
    if uid == 0 {
        return Err(FrickmailError::BadRequest("uid required".to_string()));
    }

    Ok(if include_gmail_id {
        format!(
            "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER]<0.{BODY_PREVIEW_HEADER_LIMIT_BYTES}> X-GM-MSGID)"
        )
    } else {
        format!(
            "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER]<0.{BODY_PREVIEW_HEADER_LIMIT_BYTES}>)"
        )
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

pub fn legacy_message_list_optimization_enabled(configured_limit: u32, total: u32) -> bool {
    configured_limit >= 100 && configured_limit <= total
}

fn legacy_message_list_optimized_sequence_ids(
    total: u32,
    offset: u32,
    limit: u32,
    sorted: bool,
) -> Vec<u32> {
    if total == 0 || limit == 0 || offset > total {
        return Vec::new();
    }
    let (start, end) = if sorted {
        let end = u64::from(total)
            .min(
                u64::from(total)
                    .saturating_sub(u64::from(offset))
                    .saturating_add(u64::from(limit))
                    .max(1),
            )
            .try_into()
            .unwrap_or(total);
        let start = end
            .saturating_sub(limit.saturating_mul(3).saturating_sub(1))
            .max(1);
        (start, end)
    } else {
        let end = total.saturating_sub(offset).max(1);
        let start = end.saturating_sub(limit.saturating_sub(1)).max(1);
        (start, end)
    };
    (start..=end).rev().collect()
}

fn legacy_message_list_optimized_sorted_page(
    sorted_ids: &[u32],
    offset: u32,
    limit: u32,
) -> Vec<u32> {
    let skip = if offset > 0 { limit } else { 0 };
    sorted_ids
        .iter()
        .copied()
        .skip(usize::try_from(skip).unwrap_or(usize::MAX))
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .collect()
}

fn legacy_sequence_set_preserving_order(ids: &[u32]) -> Option<String> {
    (!ids.is_empty() && ids.iter().all(|id| *id > 0))
        .then(|| ids.iter().map(u32::to_string).collect::<Vec<_>>().join(","))
}

pub fn legacy_message_list_fetches_new_messages(thread_uid: u32) -> bool {
    thread_uid == 0
}

const LEGACY_MESSAGE_LIST_SEARCH_NAMES: &[&str] = &[
    "IN",
    "EMAIL",
    "MAIL",
    "FROM",
    "TO",
    "SUBJECT",
    "HAS",
    "IS",
    "DATE",
    "SINCE",
    "BEFORE",
    "TEXT",
    "BODY",
    "SIZE",
    "LARGER",
    "BIGGER",
    "SMALLER",
    "MAXSIZE",
    "MINSIZE",
    "KEYWORD",
    "OLDER_THAN",
    "NEWER_THAN",
    "ON",
    "SENTON",
    "SENTSINCE",
    "SENTBEFORE",
    "HEADER",
];

fn legacy_message_list_search_name(name: &str) -> Option<&'static str> {
    let name = name.trim_end_matches("[]");
    LEGACY_MESSAGE_LIST_SEARCH_NAMES
        .iter()
        .copied()
        .find(|candidate| candidate.eq_ignore_ascii_case(name))
}

fn legacy_message_list_search_fields(search: &str) -> Vec<(String, String)> {
    let starts_with_prefixed_field = search
        .split_once(':')
        .is_some_and(|(name, _)| legacy_message_list_search_name(name).is_some());
    if !starts_with_prefixed_field {
        enum QueryValue {
            Scalar(String),
            Array(Vec<String>),
        }

        let mut params = Vec::<(String, QueryValue)>::new();
        for (raw_name, value) in
            serde_urlencoded::from_str::<Vec<(String, String)>>(search).unwrap_or_default()
        {
            let (name, is_array) = raw_name
                .strip_suffix("[]")
                .map(|name| (name, true))
                .unwrap_or((raw_name.as_str(), false));
            if let Some((_, current)) = params
                .iter_mut()
                .find(|(current_name, _)| current_name == name)
            {
                if is_array {
                    match current {
                        QueryValue::Array(values) => values.push(value),
                        QueryValue::Scalar(_) => *current = QueryValue::Array(vec![value]),
                    }
                } else {
                    *current = QueryValue::Scalar(value);
                }
            } else {
                params.push((
                    name.to_string(),
                    if is_array {
                        QueryValue::Array(vec![value])
                    } else {
                        QueryValue::Scalar(value)
                    },
                ));
            }
        }

        let fields = params
            .into_iter()
            .flat_map(|(name, value)| {
                let value = match value {
                    QueryValue::Scalar(value) => value,
                    QueryValue::Array(values) => values.join(","),
                };
                if name.eq_ignore_ascii_case("IS") {
                    return value
                        .split(',')
                        .map(|flag| (flag.trim().to_ascii_uppercase(), String::new()))
                        .collect::<Vec<_>>();
                }
                let uppercase = name.to_ascii_uppercase();
                let name = match uppercase.as_str() {
                    "MAIL" => "EMAIL",
                    "TEXT" => "BODY",
                    "SIZE" | "BIGGER" | "MINSIZE" => "LARGER",
                    "MAXSIZE" => "SMALLER",
                    name => name,
                };
                let value = if name == "DATE" {
                    format!("{}/", value.trim_end_matches('/'))
                } else {
                    value
                };
                if matches!(
                    name,
                    "DATE"
                        | "BODY"
                        | "EMAIL"
                        | "FROM"
                        | "TO"
                        | "SUBJECT"
                        | "KEYWORD"
                        | "IN"
                        | "SMALLER"
                        | "LARGER"
                        | "SINCE"
                        | "ON"
                        | "SENTON"
                        | "SENTSINCE"
                        | "SENTBEFORE"
                        | "BEFORE"
                        | "OLDER"
                        | "YOUNGER"
                        | "HEADER"
                        | "ATTACHMENT"
                        | "FLAGGED"
                        | "UNFLAGGED"
                        | "SEEN"
                        | "UNSEEN"
                        | "ANSWERED"
                        | "UNANSWERED"
                        | "DELETED"
                        | "UNDELETED"
                ) {
                    vec![(name.to_string(), value)]
                } else {
                    Vec::new()
                }
            })
            .collect::<Vec<_>>();
        return legacy_message_list_unique_search_fields(fields);
    }

    let bytes = search.as_bytes();
    let mut fields = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            cursor += 1;
        }
        let name_start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b':')
        {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b':') {
            while bytes
                .get(cursor)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
            {
                cursor += 1;
            }
            continue;
        }
        let name = &search[name_start..cursor];
        cursor += 1;
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            cursor += 1;
        }

        let mut value = Vec::new();
        if let Some(quote @ (b'"' | b'\'')) = bytes.get(cursor).copied() {
            cursor += 1;
            while let Some(byte) = bytes.get(cursor).copied() {
                cursor += 1;
                if byte == quote {
                    break;
                }
                if byte == b'\\' {
                    if let Some(escaped) = bytes.get(cursor).copied() {
                        value.push(escaped);
                        cursor += 1;
                    }
                } else {
                    value.push(byte);
                }
            }
        } else {
            while let Some(byte) = bytes.get(cursor).copied() {
                if byte.is_ascii_whitespace() {
                    break;
                }
                value.push(byte);
                cursor += 1;
            }
        }

        if let Some(name) = legacy_message_list_search_name(name) {
            let value = String::from_utf8_lossy(&value).into_owned();
            if name == "HAS"
                && matches!(
                    value.to_ascii_lowercase().as_str(),
                    "file" | "files" | "attachment" | "attachments"
                )
            {
                fields.push(("ATTACHMENT".to_string(), String::new()));
            } else if name == "IS" {
                fields.extend(
                    value
                        .split(',')
                        .map(|flag| (flag.trim().to_ascii_uppercase(), String::new())),
                );
            } else {
                let normalized = match name {
                    "MAIL" => "EMAIL",
                    "TEXT" => "BODY",
                    "SIZE" | "BIGGER" | "MINSIZE" => "LARGER",
                    "MAXSIZE" => "SMALLER",
                    _ => name,
                };
                let value = if normalized == "DATE" {
                    value.replace('.', "-")
                } else {
                    value
                };
                fields.push((normalized.to_string(), value));
            }
        }
    }
    legacy_message_list_unique_search_fields(fields)
}

fn legacy_message_list_unique_search_fields(
    fields: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut unique = Vec::<(String, String)>::new();
    for (name, value) in fields {
        if let Some((_, current)) = unique.iter_mut().find(|(current, _)| current == &name) {
            *current = value;
        } else {
            unique.push((name, value));
        }
    }
    unique
}

fn legacy_message_list_multisearch_scope(
    search: &str,
) -> Option<LegacyMessageListMultiSearchScope> {
    let value = legacy_message_list_search_fields(legacy_php_trim(search))
        .into_iter()
        .find(|(name, _)| name == "IN")?
        .1;
    match value.trim().to_ascii_lowercase().as_str() {
        "mailboxes" => Some(LegacyMessageListMultiSearchScope::Mailboxes),
        "subtree" => Some(LegacyMessageListMultiSearchScope::Subtree),
        "subtree-one" => Some(LegacyMessageListMultiSearchScope::SubtreeOne),
        _ => None,
    }
}

fn legacy_message_list_search_date(value: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}

fn legacy_message_list_search_date_wire(value: NaiveDate) -> String {
    value.format("%-d-%b-%Y").to_string()
}

fn legacy_message_list_friendly_size(value: &str) -> Result<u32> {
    let normalized = value
        .chars()
        .flat_map(char::to_uppercase)
        .filter(|character| character.is_ascii_digit() || matches!(character, 'K' | 'M'))
        .collect::<String>();
    let digits = normalized
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    let number = if digits.is_empty() {
        0
    } else {
        digits.parse::<u64>().map_err(|_| {
            FrickmailError::BadRequest("message-list search size is too large".to_string())
        })?
    };
    let bytes = match normalized.chars().last() {
        Some('M') => number.checked_mul(1024 * 1024).ok_or_else(|| {
            FrickmailError::BadRequest("message-list search size is too large".to_string())
        })?,
        Some('K') => number.checked_mul(1024).ok_or_else(|| {
            FrickmailError::BadRequest("message-list search size is too large".to_string())
        })?,
        _ => number,
    };
    u32::try_from(bytes).map_err(|_| {
        FrickmailError::BadRequest(
            "message-list search size exceeds the IMAP4rev1 numeric limit".to_string(),
        )
    })
}

fn legacy_message_list_positive_seconds(value: &str) -> Result<Option<u32>> {
    let value = legacy_php_trim(value);
    let bytes = value.as_bytes();
    let mut cursor = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    let mut digits = 0;
    while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
        digits += 1;
    }
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        return Ok(None);
    }
    if matches!(bytes.get(cursor), Some(b'e' | b'E')) {
        let exponent = cursor;
        cursor += 1;
        if matches!(bytes.get(cursor), Some(b'+' | b'-')) {
            cursor += 1;
        }
        let exponent_digits = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == exponent_digits {
            cursor = exponent;
        }
    }
    let seconds = value[..cursor].parse::<f64>().map_err(|_| {
        FrickmailError::BadRequest("message-list search interval is too large".to_string())
    })?;
    if !seconds.is_finite() {
        return Err(FrickmailError::BadRequest(
            "message-list search interval is too large".to_string(),
        ));
    }
    let seconds = seconds.trunc();
    if seconds <= 0.0 {
        return Ok(None);
    }
    if seconds > f64::from(u32::MAX) {
        return Err(FrickmailError::BadRequest(
            "message-list search interval exceeds the IMAP4rev1 numeric limit".to_string(),
        ));
    }
    Ok(Some(seconds as u32))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct LegacyMessageListInterval {
    years: u64,
    months: u64,
    days: u64,
    hours: u64,
    minutes: u64,
    seconds: u64,
}

fn legacy_message_list_interval_error() -> FrickmailError {
    FrickmailError::BadRequest("invalid message-list relative date interval".to_string())
}

fn legacy_message_list_interval_section(value: &str, designators: &[u8]) -> Result<Vec<(u64, u8)>> {
    let bytes = value.as_bytes();
    let mut cursor = 0;
    let mut last_designator = None;
    let mut parts = Vec::new();
    while cursor < bytes.len() {
        let number_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == number_start {
            return Err(legacy_message_list_interval_error());
        }
        let number = value[number_start..cursor]
            .parse::<u64>()
            .map_err(|_| legacy_message_list_interval_error())?;
        let designator = *bytes
            .get(cursor)
            .ok_or_else(legacy_message_list_interval_error)?;
        cursor += 1;
        let position = designators
            .iter()
            .position(|candidate| *candidate == designator)
            .ok_or_else(legacy_message_list_interval_error)?;
        if last_designator.is_some_and(|last| position <= last) {
            return Err(legacy_message_list_interval_error());
        }
        last_designator = Some(position);
        parts.push((number, designator));
    }
    Ok(parts)
}

fn legacy_message_list_interval(value: &str) -> Result<LegacyMessageListInterval> {
    if value.len() == 19
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.as_bytes().get(13) == Some(&b':')
        && value.as_bytes().get(16) == Some(&b':')
    {
        let numeric = [0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
            .into_iter()
            .map(|range| {
                let part = &value[range];
                if !part.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(legacy_message_list_interval_error());
                }
                part.parse::<u64>()
                    .map_err(|_| legacy_message_list_interval_error())
            })
            .collect::<Result<Vec<_>>>()?;
        if numeric[1] > 12
            || numeric[2] > 31
            || numeric[3] > 24
            || numeric[4] > 59
            || numeric[5] > 59
        {
            return Err(legacy_message_list_interval_error());
        }
        return Ok(LegacyMessageListInterval {
            years: numeric[0],
            months: numeric[1],
            days: numeric[2],
            hours: numeric[3],
            minutes: numeric[4],
            seconds: numeric[5],
        });
    }

    let (date, time) = match value.split_once('T') {
        Some((date, time)) if !time.is_empty() && !time.contains('T') => (date, Some(time)),
        Some(_) => return Err(legacy_message_list_interval_error()),
        None => (value, None),
    };
    if date.is_empty() && time.is_none() {
        return Err(legacy_message_list_interval_error());
    }

    let mut interval = LegacyMessageListInterval::default();
    let mut populated = false;
    if !date.is_empty() {
        for (number, designator) in legacy_message_list_interval_section(date, b"YMWD")? {
            populated = true;
            match designator {
                b'Y' => interval.years = number,
                b'M' => interval.months = number,
                b'W' => {
                    interval.days = interval
                        .days
                        .checked_add(
                            number
                                .checked_mul(7)
                                .ok_or_else(legacy_message_list_interval_error)?,
                        )
                        .ok_or_else(legacy_message_list_interval_error)?;
                }
                b'D' => {
                    interval.days = interval
                        .days
                        .checked_add(number)
                        .ok_or_else(legacy_message_list_interval_error)?;
                }
                _ => unreachable!(),
            }
        }
    }
    if let Some(time) = time {
        for (number, designator) in legacy_message_list_interval_section(time, b"HMS")? {
            populated = true;
            match designator {
                b'H' => interval.hours = number,
                b'M' => interval.minutes = number,
                b'S' => interval.seconds = number,
                _ => unreachable!(),
            }
        }
    }
    if !populated {
        return Err(legacy_message_list_interval_error());
    }
    Ok(interval)
}

fn legacy_message_list_subtract_interval(
    now: &DateTime<Utc>,
    value: &str,
) -> Result<DateTime<Utc>> {
    let interval = legacy_message_list_interval(value)?;
    let source_month = i64::from(now.year())
        .checked_mul(12)
        .and_then(|year| year.checked_add(i64::from(now.month0())))
        .ok_or_else(legacy_message_list_interval_error)?;
    let interval_months = i64::try_from(interval.years)
        .map_err(|_| legacy_message_list_interval_error())?
        .checked_mul(12)
        .and_then(|years| {
            i64::try_from(interval.months)
                .ok()
                .and_then(|months| years.checked_add(months))
        })
        .ok_or_else(legacy_message_list_interval_error)?;
    let target_month = source_month
        .checked_sub(interval_months)
        .ok_or_else(legacy_message_list_interval_error)?;
    let target_year = i32::try_from(target_month.div_euclid(12))
        .map_err(|_| legacy_message_list_interval_error())?;
    let target_month = u32::try_from(target_month.rem_euclid(12) + 1)
        .map_err(|_| legacy_message_list_interval_error())?;
    let base = NaiveDate::from_ymd_opt(target_year, target_month, 1)
        .ok_or_else(legacy_message_list_interval_error)?
        .and_time(now.time())
        .checked_add_signed(ChronoDuration::days(i64::from(now.day() - 1)))
        .ok_or_else(legacy_message_list_interval_error)?;
    let days = i64::try_from(interval.days)
        .ok()
        .and_then(ChronoDuration::try_days)
        .ok_or_else(legacy_message_list_interval_error)?;
    let hours = i64::try_from(interval.hours)
        .ok()
        .and_then(ChronoDuration::try_hours)
        .ok_or_else(legacy_message_list_interval_error)?;
    let minutes = i64::try_from(interval.minutes)
        .ok()
        .and_then(ChronoDuration::try_minutes)
        .ok_or_else(legacy_message_list_interval_error)?;
    let seconds = i64::try_from(interval.seconds)
        .ok()
        .and_then(ChronoDuration::try_seconds)
        .ok_or_else(legacy_message_list_interval_error)?;
    let relative = base
        .checked_sub_signed(days)
        .and_then(|date| date.checked_sub_signed(hours))
        .and_then(|date| date.checked_sub_signed(minutes))
        .and_then(|date| date.checked_sub_signed(seconds))
        .ok_or_else(legacy_message_list_interval_error)?;
    if !(1..=9999).contains(&relative.year()) {
        return Err(legacy_message_list_interval_error());
    }
    Ok(DateTime::from_naive_utc_and_offset(relative, Utc))
}

fn legacy_message_list_relative_seconds(
    now: &DateTime<Utc>,
    relative: &DateTime<Utc>,
) -> Result<u32> {
    let seconds = now.signed_duration_since(relative).num_seconds();
    if seconds <= 0 {
        return Err(FrickmailError::BadRequest(
            "message-list relative date interval must be positive".to_string(),
        ));
    }
    u32::try_from(seconds).map_err(|_| {
        FrickmailError::BadRequest(
            "message-list relative date interval exceeds the IMAP4rev1 numeric limit".to_string(),
        )
    })
}

fn legacy_message_list_header_criterion(value: &str) -> Result<String> {
    let Some((field, search)) = value.split_once(' ') else {
        return Err(FrickmailError::BadRequest(
            "message-list HEADER search requires a field name and value".to_string(),
        ));
    };
    if field.is_empty() {
        return Err(FrickmailError::BadRequest(
            "message-list HEADER search requires a field name and value".to_string(),
        ));
    }
    Ok(format!(
        "HEADER {} {}",
        imap_quote_message_list_search_value(field)?,
        imap_quote_message_list_search_value(search)?
    ))
}

pub fn legacy_message_list_search_criteria(search: &str, hide_deleted: bool) -> Result<String> {
    legacy_message_list_search_criteria_with_fast_simple_search(search, hide_deleted, true)
}

pub fn legacy_message_list_search_criteria_with_fast_simple_search(
    search: &str,
    hide_deleted: bool,
    fast_simple_search: bool,
) -> Result<String> {
    legacy_message_list_search_criteria_with_capabilities(
        search,
        hide_deleted,
        fast_simple_search,
        false,
    )
}

fn legacy_message_list_search_criteria_with_capabilities(
    search: &str,
    hide_deleted: bool,
    fast_simple_search: bool,
    supports_within: bool,
) -> Result<String> {
    legacy_message_list_search_criteria_with_settings(
        search,
        hide_deleted,
        fast_simple_search,
        supports_within,
        "",
    )
}

fn legacy_message_list_search_criteria_with_settings(
    search: &str,
    hide_deleted: bool,
    fast_simple_search: bool,
    supports_within: bool,
    permanent_filter: &str,
) -> Result<String> {
    legacy_message_list_search_criteria_at_with_settings(
        search,
        hide_deleted,
        fast_simple_search,
        supports_within,
        permanent_filter,
        DateTime::<Utc>::from(SystemTime::now()),
    )
}

#[cfg(test)]
fn legacy_message_list_search_criteria_at(
    search: &str,
    hide_deleted: bool,
    fast_simple_search: bool,
    supports_within: bool,
    now: DateTime<Utc>,
) -> Result<String> {
    legacy_message_list_search_criteria_at_with_settings(
        search,
        hide_deleted,
        fast_simple_search,
        supports_within,
        "",
        now,
    )
}

fn legacy_message_list_search_criteria_at_with_settings(
    search: &str,
    hide_deleted: bool,
    fast_simple_search: bool,
    supports_within: bool,
    permanent_filter: &str,
    now: DateTime<Utc>,
) -> Result<String> {
    let search = legacy_php_trim(search);
    let fields = legacy_message_list_search_fields(search);
    let has_parsed_fields = fields.iter().any(|(name, value)| {
        matches!(
            name.as_str(),
            "ATTACHMENT"
                | "FLAGGED"
                | "UNFLAGGED"
                | "SEEN"
                | "UNSEEN"
                | "ANSWERED"
                | "UNANSWERED"
                | "DELETED"
                | "UNDELETED"
                | "READ"
                | "UNREAD"
        ) || !value.trim().is_empty()
    });
    let mut criteria = Vec::new();
    let mut since_filter = None::<NaiveDate>;

    if !search.is_empty() && !has_parsed_fields {
        let value = imap_quote_message_list_search_value(search)?;
        criteria.push(if fast_simple_search {
            format!("OR OR OR FROM {value} TO {value} CC {value} SUBJECT {value}")
        } else {
            format!("TEXT {value}")
        });
    } else {
        let email = fields
            .iter()
            .rev()
            .find(|(name, value)| name == "EMAIL" && !value.trim().is_empty())
            .map(|(_, value)| value.as_str());
        if let Some(email) = email {
            let value = imap_quote_message_list_search_value(email)?;
            criteria.push(format!("OR OR FROM {value} TO {value} CC {value}"));
        }

        for (name, value) in &fields {
            if value.trim().is_empty()
                && !matches!(
                    name.as_str(),
                    "ATTACHMENT"
                        | "FLAGGED"
                        | "UNFLAGGED"
                        | "SEEN"
                        | "UNSEEN"
                        | "ANSWERED"
                        | "UNANSWERED"
                        | "DELETED"
                        | "UNDELETED"
                        | "READ"
                        | "UNREAD"
                )
            {
                continue;
            }
            match name.as_str() {
                "EMAIL" => {}
                "FROM" if email.is_none() => criteria.push(format!(
                    "FROM {}",
                    imap_quote_message_list_search_value(value)?
                )),
                "TO" if email.is_none() => {
                    let value = imap_quote_message_list_search_value(value)?;
                    criteria.push(format!("OR TO {value} CC {value}"));
                }
                "SUBJECT" | "BODY" => criteria.push(format!(
                    "{name} {}",
                    imap_quote_message_list_search_value(value)?
                )),
                "KEYWORD" => {
                    let keyword = modified_utf7_from_utf8(value);
                    if !keyword_can_be_stored(&keyword) {
                        return Err(FrickmailError::BadRequest(
                            "message-list KEYWORD search requires a valid IMAP atom".to_string(),
                        ));
                    }
                    criteria.push(format!("KEYWORD {keyword}"));
                }
                "HEADER" => criteria.push(legacy_message_list_header_criterion(value)?),
                "LARGER" | "SMALLER" => criteria.push(format!(
                    "{name} {}",
                    legacy_message_list_friendly_size(value)?
                )),
                "OLDER" | "YOUNGER" => {
                    if supports_within {
                        if let Some(seconds) = legacy_message_list_positive_seconds(value)? {
                            criteria.push(format!("{name} {seconds}"));
                        }
                    }
                }
                "OLDER_THAN" | "NEWER_THAN" => {
                    let relative = legacy_message_list_subtract_interval(&now, value)?;
                    if supports_within {
                        let seconds = legacy_message_list_relative_seconds(&now, &relative)?;
                        let criterion = if name == "OLDER_THAN" {
                            "OLDER"
                        } else {
                            "YOUNGER"
                        };
                        criteria.push(format!("{criterion} {seconds}"));
                    } else if name == "OLDER_THAN" {
                        criteria.push(format!(
                            "BEFORE {}",
                            legacy_message_list_search_date_wire(relative.date_naive())
                        ));
                    } else {
                        let date = relative.date_naive();
                        since_filter = Some(
                            since_filter
                                .map(|current| current.max(date))
                                .unwrap_or(date),
                        );
                    }
                }
                "SINCE" => {
                    if let Some(date) = legacy_message_list_search_date(value) {
                        since_filter = Some(
                            since_filter
                                .map(|current| current.max(date))
                                .unwrap_or(date),
                        );
                    }
                }
                "ON" | "SENTON" | "SENTSINCE" | "SENTBEFORE" | "BEFORE" => {
                    if let Some(date) = legacy_message_list_search_date(value) {
                        criteria.push(format!(
                            "{name} {}",
                            legacy_message_list_search_date_wire(date)
                        ));
                    }
                }
                "DATE" => {
                    let segments = value.split('/').collect::<Vec<_>>();
                    let (from, before) = match segments.as_slice() {
                        [from, through] => (
                            legacy_message_list_search_date(from),
                            legacy_message_list_search_date(through)
                                .and_then(|date| date.succ_opt()),
                        ),
                        [only] if !only.is_empty() => {
                            let from = legacy_message_list_search_date(only);
                            (from, from.and_then(|date| date.succ_opt()))
                        }
                        _ => (None, None),
                    };
                    if let Some(from) = from {
                        since_filter = Some(
                            since_filter
                                .map(|current| current.max(from))
                                .unwrap_or(from),
                        );
                    }
                    if let Some(before) = before {
                        criteria.push(format!(
                            "BEFORE {}",
                            legacy_message_list_search_date_wire(before)
                        ));
                    }
                }
                "ATTACHMENT" => criteria.push(
                    "OR OR OR HEADER Content-Type \"application/\" \
                     HEADER Content-Type \"multipart/m\" \
                     HEADER Content-Type \"multipart/signed\" \
                     HEADER Content-Type \"multipart/report\""
                        .to_string(),
                ),
                "READ" => criteria.push("SEEN".to_string()),
                "UNREAD" => criteria.push("UNSEEN".to_string()),
                "FLAGGED" | "UNFLAGGED" | "SEEN" | "UNSEEN" | "ANSWERED" | "UNANSWERED"
                | "DELETED" | "UNDELETED" => criteria.push(name.clone()),
                "FROM" | "TO" | "IN" => {}
                unsupported => {
                    return Err(FrickmailError::BadRequest(format!(
                        "message-list search filter '{unsupported}' is not migrated yet"
                    )));
                }
            }
        }
    }

    if let Some(since) = since_filter {
        criteria.push(format!(
            "SINCE {}",
            legacy_message_list_search_date_wire(since)
        ));
    }
    if hide_deleted
        && !criteria
            .iter()
            .any(|criterion| criterion == "DELETED" || criterion == "UNDELETED")
    {
        criteria.push("UNDELETED".to_string());
    }
    if let Some(permanent_filter) =
        legacy_message_list_validated_permanent_filter(permanent_filter)?
    {
        criteria.push(permanent_filter.to_string());
    }
    Ok(if criteria.is_empty() {
        "ALL".to_string()
    } else {
        criteria.join(" ")
    })
}

fn legacy_message_list_validated_permanent_filter(permanent_filter: &str) -> Result<Option<&str>> {
    if !legacy_php_truthy(permanent_filter) {
        return Ok(None);
    }
    if permanent_filter
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'))
    {
        return Err(FrickmailError::BadRequest(
            "message-list permanent filter contains invalid command bytes".to_string(),
        ));
    }
    Ok(Some(permanent_filter))
}

#[derive(Debug, PartialEq, Eq)]
struct LegacyMessageListSearchWire {
    chunks: Vec<String>,
    needs_utf8_charset: bool,
}

#[cfg(test)]
fn legacy_message_list_search_wire(
    search: &str,
    hide_deleted: bool,
    fast_simple_search: bool,
    utf8_mode: bool,
    supports_within: bool,
) -> Result<LegacyMessageListSearchWire> {
    legacy_message_list_search_wire_with_settings(
        search,
        hide_deleted,
        fast_simple_search,
        "",
        utf8_mode,
        supports_within,
    )
}

fn legacy_message_list_search_wire_with_settings(
    search: &str,
    hide_deleted: bool,
    fast_simple_search: bool,
    permanent_filter: &str,
    utf8_mode: bool,
    supports_within: bool,
) -> Result<LegacyMessageListSearchWire> {
    let criteria = legacy_message_list_search_criteria_with_settings(
        search,
        hide_deleted,
        fast_simple_search,
        supports_within,
        permanent_filter,
    )?;
    let needs_utf8_charset = !utf8_mode && !criteria.is_ascii();
    if !needs_utf8_charset {
        return Ok(LegacyMessageListSearchWire {
            chunks: vec![criteria],
            needs_utf8_charset,
        });
    }

    let bytes = criteria.as_bytes();
    let mut chunks = Vec::new();
    let mut chunk = String::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'"' {
            let ch = criteria[cursor..].chars().next().ok_or_else(|| {
                FrickmailError::Upstream("invalid message-list search criteria".to_string())
            })?;
            chunk.push(ch);
            cursor += ch.len_utf8();
            continue;
        }

        let quoted_start = cursor;
        cursor += 1;
        let mut value = String::new();
        let mut closed = false;
        while cursor < bytes.len() {
            let ch = criteria[cursor..].chars().next().ok_or_else(|| {
                FrickmailError::Upstream("invalid message-list search criteria".to_string())
            })?;
            cursor += ch.len_utf8();
            if ch == '"' {
                closed = true;
                break;
            }
            if ch == '\\' {
                let escaped = criteria[cursor..].chars().next().ok_or_else(|| {
                    FrickmailError::Upstream(
                        "invalid escaped message-list search criteria".to_string(),
                    )
                })?;
                value.push(escaped);
                cursor += escaped.len_utf8();
            } else {
                value.push(ch);
            }
        }
        if !closed {
            return Err(FrickmailError::Upstream(
                "unterminated message-list search criteria".to_string(),
            ));
        }
        if value.is_ascii() {
            chunk.push_str(&criteria[quoted_start..cursor]);
            continue;
        }

        chunk.push_str(&format!("{{{}}}", value.len()));
        chunks.push(chunk);
        chunk = value;
    }
    chunks.push(chunk);
    Ok(LegacyMessageListSearchWire {
        chunks,
        needs_utf8_charset,
    })
}

#[derive(Debug, Clone, Copy)]
struct LegacyMessageListQueryOptions<'a> {
    hide_deleted: bool,
    fast_simple_search: bool,
    permanent_filter: &'a str,
    sort: Option<&'a str>,
    utf8_mode: bool,
    supports_within: bool,
    supports_literal_plus: bool,
}

async fn legacy_message_list_visible_uids_cached(
    session: &mut BoxedSession,
    mailbox: &str,
    folder_hash: &str,
    client_hash: &str,
    search: &str,
    options: LegacyMessageListQueryOptions<'_>,
    cache: Option<&dyn LegacyMessageListUidCache>,
) -> Result<Vec<u32>> {
    legacy_message_list_visible_uids_cached_bounded(
        session,
        mailbox,
        folder_hash,
        client_hash,
        search,
        options,
        cache,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn legacy_message_list_visible_uids_cached_bounded(
    session: &mut BoxedSession,
    mailbox: &str,
    folder_hash: &str,
    client_hash: &str,
    search: &str,
    options: LegacyMessageListQueryOptions<'_>,
    cache: Option<&dyn LegacyMessageListUidCache>,
    uid_limit: Option<usize>,
) -> Result<Vec<u32>> {
    let Some(cache) = cache.filter(|_| legacy_message_list_uid_cache_eligible(search)) else {
        return legacy_message_list_visible_uids_with_settings_bounded(
            session, search, options, uid_limit,
        )
        .await;
    };
    let raw_key = legacy_message_list_uid_cache_key(mailbox, client_hash, search, options)?;
    if let Some(uids) = cache.get(&raw_key, folder_hash).await {
        return Ok(uids);
    }

    let uids =
        legacy_message_list_visible_uids_with_settings_bounded(session, search, options, uid_limit)
            .await?;
    cache.set(&raw_key, folder_hash, &uids).await;
    Ok(uids)
}

async fn legacy_message_list_visible_uids_from_cache(
    mailbox: &str,
    folder_hash: &str,
    client_hash: &str,
    search: &str,
    options: LegacyMessageListQueryOptions<'_>,
    cache: Option<&dyn LegacyMessageListUidCache>,
) -> Result<Option<Vec<u32>>> {
    let Some(cache) = cache.filter(|_| legacy_message_list_uid_cache_eligible(search)) else {
        return Ok(None);
    };
    let raw_key = legacy_message_list_uid_cache_key(mailbox, client_hash, search, options)?;
    Ok(cache.get(&raw_key, folder_hash).await)
}

fn legacy_message_list_uid_cache_key(
    mailbox: &str,
    client_hash: &str,
    search: &str,
    options: LegacyMessageListQueryOptions<'_>,
) -> Result<String> {
    let mut criteria = if options.supports_literal_plus {
        legacy_message_list_search_wire_with_settings(
            search,
            options.hide_deleted,
            options.fast_simple_search,
            "",
            false,
            options.supports_within,
        )?
        .chunks
        .join("\r\n")
    } else {
        legacy_message_list_search_criteria_with_settings(
            search,
            options.hide_deleted,
            options.fast_simple_search,
            options.supports_within,
            "",
        )?
    };
    if let Some(permanent_filter) =
        legacy_message_list_validated_permanent_filter(options.permanent_filter)?
    {
        if criteria == "ALL" {
            criteria.clear();
        } else {
            criteria.push(' ');
        }
        criteria.push_str(permanent_filter);
    }
    Ok(format!(
        "GetUIDS/{}/{client_hash}/{mailbox}/{criteria}",
        options.sort.unwrap_or_default()
    ))
}

fn legacy_message_list_uid_cache_eligible(search: &str) -> bool {
    !legacy_message_list_search_fields(legacy_php_trim(search))
        .iter()
        .any(|(name, _)| {
            matches!(
                name.as_str(),
                "FLAGGED"
                    | "UNFLAGGED"
                    | "SEEN"
                    | "UNSEEN"
                    | "ANSWERED"
                    | "UNANSWERED"
                    | "DELETED"
                    | "UNDELETED"
                    | "READ"
                    | "UNREAD"
            )
        })
}

async fn legacy_message_list_visible_uids_with_settings_bounded(
    session: &mut BoxedSession,
    search: &str,
    options: LegacyMessageListQueryOptions<'_>,
    uid_limit: Option<usize>,
) -> Result<Vec<u32>> {
    legacy_message_list_ids_with_settings_bounded(session, search, options, uid_limit, true, None)
        .await
}

async fn legacy_message_list_ids_with_settings_bounded(
    session: &mut BoxedSession,
    search: &str,
    options: LegacyMessageListQueryOptions<'_>,
    id_limit: Option<usize>,
    return_uid: bool,
    sequence_set: Option<&str>,
) -> Result<Vec<u32>> {
    let operation = if options.sort.is_some() {
        "sort legacy message list"
    } else {
        "search legacy message list"
    };
    let wire = legacy_message_list_search_wire_with_settings(
        search,
        options.hide_deleted,
        options.fast_simple_search,
        options.permanent_filter,
        options.utf8_mode,
        options.supports_within,
    )?;
    timeout_result(
        operation,
        timeout(COMMAND_TIMEOUT, async {
            let mut chunks = wire.chunks.into_iter();
            let first = chunks.next().ok_or_else(|| {
                FrickmailError::Upstream("empty message-list search command".to_string())
            })?;
            let first = if let Some(sequence_set) = sequence_set {
                format!("{sequence_set} {first}")
            } else {
                first
            };
            let command = if let Some(sort) = options.sort {
                let uid = if return_uid { "UID " } else { "" };
                format!("{uid}SORT ({sort}) UTF-8 {first}")
            } else {
                let charset = if wire.needs_utf8_charset {
                    " CHARSET UTF-8"
                } else {
                    ""
                };
                let uid = if return_uid { "UID " } else { "" };
                format!("{uid}SEARCH{charset} {first}")
            };
            let request_id = session
                .run_command(&command)
                .await
                .map_err(|error| imap_error(operation, error))?;
            let mut uids = Vec::new();

            for chunk in chunks {
                loop {
                    let response = session
                        .read_response()
                        .await
                        .map_err(|error| {
                            FrickmailError::Upstream(format!("{operation} failed: {error}"))
                        })?
                        .ok_or_else(|| {
                            FrickmailError::Upstream(format!(
                                "{operation} failed: IMAP connection closed"
                            ))
                        })?;
                    collect_legacy_message_list_uids(
                        response.parsed(),
                        options.sort.is_some(),
                        &mut uids,
                        id_limit,
                    )?;
                    if matches!(response.parsed(), Response::Continue { .. }) {
                        break;
                    }
                    if imap_command_completion(response.parsed(), &request_id, operation)?.is_some()
                    {
                        return Err(FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP server completed before literal continuation"
                        )));
                    }
                }
                session
                    .run_command_untagged(&chunk)
                    .await
                    .map_err(|error| imap_error(operation, error))?;
            }

            loop {
                let response = session
                    .read_response()
                    .await
                    .map_err(|error| {
                        FrickmailError::Upstream(format!("{operation} failed: {error}"))
                    })?
                    .ok_or_else(|| {
                        FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP connection closed"
                        ))
                    })?;
                collect_legacy_message_list_uids(
                    response.parsed(),
                    options.sort.is_some(),
                    &mut uids,
                    id_limit,
                )?;
                if matches!(response.parsed(), Response::Continue { .. }) {
                    return Err(FrickmailError::Upstream(format!(
                        "{operation} failed: unexpected IMAP continuation"
                    )));
                }
                if imap_command_completion(response.parsed(), &request_id, operation)?.is_some() {
                    return Ok(uids);
                }
            }
        }),
    )
    .await?
}

async fn legacy_message_list_multisearch_matches(
    session: &mut BoxedSession,
    mailbox: &str,
    search: &str,
    options: LegacyMessageListQueryOptions<'_>,
    supports_multisearch: bool,
) -> Result<Option<Vec<LegacyMessageListMailboxMatches>>> {
    let Some(scope) = legacy_message_list_multisearch_scope(search) else {
        return Ok(None);
    };
    if !supports_multisearch {
        return Ok(None);
    }
    let operation = "multisearch legacy message list";
    let wire = legacy_message_list_search_wire_with_settings(
        search,
        options.hide_deleted,
        options.fast_simple_search,
        options.permanent_filter,
        options.utf8_mode,
        options.supports_within,
    )?;
    let wire_mailbox = imap_mailbox_from_utf8(mailbox, options.utf8_mode);
    let mailbox = quote_imap_string("message-list multisearch mailbox", &wire_mailbox)?;

    timeout_result(
        operation,
        timeout(COMMAND_TIMEOUT, async {
            let mut chunks = wire.chunks.into_iter();
            let first = chunks.next().ok_or_else(|| {
                FrickmailError::Upstream("empty message-list multisearch command".to_string())
            })?;
            let charset = if wire.needs_utf8_charset {
                " CHARSET UTF-8"
            } else {
                ""
            };
            let command = format!(
                "ESEARCH IN ({} {mailbox}) RETURN (COUNT){charset} {first}",
                scope.wire_name()
            );
            let request_id = session
                .run_command(&command)
                .await
                .map_err(|error| imap_error(operation, error))?;
            let mut matches = Vec::new();
            let mut seen_mailboxes = HashSet::new();

            for chunk in chunks {
                loop {
                    let response = session
                        .read_response()
                        .await
                        .map_err(|error| {
                            FrickmailError::Upstream(format!("{operation} failed: {error}"))
                        })?
                        .ok_or_else(|| {
                            FrickmailError::Upstream(format!(
                                "{operation} failed: IMAP connection closed"
                            ))
                        })?;
                    collect_legacy_message_list_multisearch_match(
                        response.parsed(),
                        &request_id,
                        options.utf8_mode,
                        &mut seen_mailboxes,
                        &mut matches,
                    )?;
                    if matches!(response.parsed(), Response::Continue { .. }) {
                        break;
                    }
                    if imap_command_completion(response.parsed(), &request_id, operation)?.is_some()
                    {
                        return Err(FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP server completed before literal continuation"
                        )));
                    }
                }
                session
                    .run_command_untagged(&chunk)
                    .await
                    .map_err(|error| imap_error(operation, error))?;
            }

            loop {
                let response = session
                    .read_response()
                    .await
                    .map_err(|error| {
                        FrickmailError::Upstream(format!("{operation} failed: {error}"))
                    })?
                    .ok_or_else(|| {
                        FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP connection closed"
                        ))
                    })?;
                collect_legacy_message_list_multisearch_match(
                    response.parsed(),
                    &request_id,
                    options.utf8_mode,
                    &mut seen_mailboxes,
                    &mut matches,
                )?;
                if matches!(response.parsed(), Response::Continue { .. }) {
                    return Err(FrickmailError::Upstream(format!(
                        "{operation} failed: unexpected IMAP continuation"
                    )));
                }
                if imap_command_completion(response.parsed(), &request_id, operation)?.is_some() {
                    return Ok(Some(matches));
                }
            }
        }),
    )
    .await?
}

fn collect_legacy_message_list_multisearch_match(
    response: &Response<'_>,
    request_id: &RequestId,
    utf8_mode: bool,
    seen_mailboxes: &mut HashSet<String>,
    matches: &mut Vec<LegacyMessageListMailboxMatches>,
) -> Result<()> {
    let Response::MailboxData(MailboxDatum::ESearch(result)) = response else {
        return Ok(());
    };
    let Some(tag) = result.tag.as_deref() else {
        return Ok(());
    };
    if tag.as_bytes() != request_id.as_bytes() {
        return Ok(());
    }
    if !result.uid {
        return Err(FrickmailError::Upstream(
            "multisearch legacy message list returned non-UID results".to_string(),
        ));
    }
    let mailbox = result.mailbox.as_deref().ok_or_else(|| {
        FrickmailError::Upstream(
            "multisearch legacy message list returned ESEARCH without MAILBOX".to_string(),
        )
    })?;
    let uid_validity = result.uid_validity.ok_or_else(|| {
        FrickmailError::Upstream(
            "multisearch legacy message list returned ESEARCH without UIDVALIDITY".to_string(),
        )
    })?;
    let count = result.count.ok_or_else(|| {
        FrickmailError::Upstream(
            "multisearch legacy message list returned ESEARCH without COUNT".to_string(),
        )
    })?;
    if count == 0 {
        return Err(FrickmailError::Upstream(
            "multisearch legacy message list returned an empty mailbox result".to_string(),
        ));
    }
    if matches.len() >= MULTISEARCH_MAILBOX_RESULT_LIMIT {
        return Err(FrickmailError::Upstream(
            "multisearch legacy message list returned too many mailboxes".to_string(),
        ));
    }
    let mailbox = imap_mailbox_to_utf8(mailbox, utf8_mode);
    if !seen_mailboxes.insert(mailbox.clone()) {
        return Err(FrickmailError::Upstream(
            "multisearch legacy message list returned a duplicate mailbox result".to_string(),
        ));
    }
    matches.push(LegacyMessageListMailboxMatches {
        mailbox,
        uid_validity,
        count,
    });
    Ok(())
}

fn legacy_message_list_multisearch_page_plan(
    matches: &[LegacyMessageListMailboxMatches],
    offset: u32,
    limit: u32,
) -> Result<(u32, Vec<LegacyMessageListMailboxPage>)> {
    let mut matches = matches.iter().collect::<Vec<_>>();
    matches.sort_by(|left, right| left.mailbox.as_bytes().cmp(right.mailbox.as_bytes()));

    let mut total = 0u64;
    let mut skip = u64::from(offset);
    let mut remaining = u64::from(limit);
    let mut page = Vec::new();

    for mailbox_matches in matches {
        let mailbox_total = u64::from(mailbox_matches.count);
        total = total.checked_add(mailbox_total).ok_or_else(|| {
            FrickmailError::Upstream(
                "multisearch legacy message list total count overflowed".to_string(),
            )
        })?;

        if remaining == 0 || skip >= mailbox_total {
            skip = skip.saturating_sub(mailbox_total);
            continue;
        }

        if page.len() >= MULTISEARCH_PAGE_MAILBOX_LIMIT {
            return Err(FrickmailError::Upstream(
                "multisearch legacy message list page spans too many mailboxes".to_string(),
            ));
        }
        let available = mailbox_total - skip;
        let take = available.min(remaining);
        page.push(LegacyMessageListMailboxPage {
            mailbox: mailbox_matches.mailbox.clone(),
            uid_validity: mailbox_matches.uid_validity,
            expected_count: mailbox_matches.count,
            offset: u32::try_from(skip).unwrap_or(u32::MAX),
            limit: u32::try_from(take).unwrap_or(u32::MAX),
        });
        remaining -= take;
        skip = 0;
    }

    Ok((u32::try_from(total).unwrap_or(u32::MAX), page))
}

fn collect_legacy_message_list_uids(
    response: &Response<'_>,
    sorted: bool,
    uids: &mut Vec<u32>,
    uid_limit: Option<usize>,
) -> Result<()> {
    let found = match response {
        Response::MailboxData(MailboxDatum::Sort(found)) if sorted => Some(found.as_slice()),
        Response::MailboxData(MailboxDatum::Search(found)) if !sorted => Some(found.as_slice()),
        _ => None,
    };
    if let Some(found) = found {
        if uid_limit.is_some_and(|limit| uids.len().saturating_add(found.len()) > limit) {
            return Err(FrickmailError::Upstream(
                "legacy message list search returned too many UIDs".to_string(),
            ));
        }
        uids.extend(found.iter().copied());
    }
    Ok(())
}

async fn fetch_legacy_message_threads(
    session: &mut BoxedSession,
    algorithm: &str,
) -> Result<Vec<Vec<u32>>> {
    let operation = "thread legacy message list";
    let command = format!("UID THREAD {algorithm} UTF-8 ALL");
    timeout_result(
        operation,
        timeout(COMMAND_TIMEOUT, async {
            let request_id = session
                .run_command(&command)
                .await
                .map_err(|error| imap_error(operation, error))?;
            let mut threads = Vec::new();
            loop {
                let response = session
                    .read_response()
                    .await
                    .map_err(|error| {
                        FrickmailError::Upstream(format!("{operation} failed: {error}"))
                    })?
                    .ok_or_else(|| {
                        FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP connection closed"
                        ))
                    })?;
                if let Response::MailboxData(MailboxDatum::Thread(found)) = response.parsed() {
                    threads.extend(found.iter().map(imap_proto::Thread::flatten));
                }
                if matches!(response.parsed(), Response::Continue { .. }) {
                    return Err(FrickmailError::Upstream(format!(
                        "{operation} failed: unexpected IMAP continuation"
                    )));
                }
                if imap_command_completion(response.parsed(), &request_id, operation)?.is_some() {
                    return Ok(threads);
                }
            }
        }),
    )
    .await?
}

async fn fetch_legacy_message_threads_compat(
    session: &mut BoxedSession,
    algorithm: &str,
) -> Vec<Vec<u32>> {
    fetch_legacy_message_threads(session, algorithm)
        .await
        .unwrap_or_default()
}

fn legacy_message_list_thread_map_cache_key(algorithm: &str, folder_hash: &str) -> String {
    format!("ThreadsMap/{algorithm}/ALL/{folder_hash}")
}

fn legacy_message_list_thread_uids_cache_key(folder_hash: &str) -> String {
    format!("ThreadsOldUids/{folder_hash}/N")
}

async fn fetch_legacy_message_threads_cached(
    session: &mut BoxedSession,
    algorithm: &str,
    folder_hash: &str,
    cache: Option<&dyn LegacyMessageListUidCache>,
) -> Vec<Vec<u32>> {
    let Some(cache) = cache else {
        return fetch_legacy_message_threads_compat(session, algorithm).await;
    };
    let raw_key = legacy_message_list_thread_map_cache_key(algorithm, folder_hash);
    if let Some(threads) = cache.get_thread_map(&raw_key).await {
        return threads;
    }

    let threads = fetch_legacy_message_threads_compat(session, algorithm).await;
    cache.set_thread_map(&raw_key, &threads).await;
    threads
}

fn legacy_thread_old_uids(threads: &[Vec<u32>]) -> Vec<u32> {
    threads
        .iter()
        .flat_map(|thread| {
            let newest = thread.iter().copied().max();
            thread
                .iter()
                .copied()
                .filter(move |uid| Some(*uid) != newest)
        })
        .collect()
}

async fn legacy_thread_old_uids_cached(
    threads: &[Vec<u32>],
    folder_hash: &str,
    cache: Option<&dyn LegacyMessageListUidCache>,
) -> Vec<u32> {
    let Some(cache) = cache else {
        return legacy_thread_old_uids(threads);
    };
    let raw_key = legacy_message_list_thread_uids_cache_key(folder_hash);
    if let Some(uids) = cache.get_thread_uids(&raw_key).await {
        return uids;
    }

    let uids = legacy_thread_old_uids(threads);
    cache.set_thread_uids(&raw_key, &uids).await;
    uids
}

fn legacy_thread_representatives(uids: &mut Vec<u32>, old_uids: &[u32]) {
    let old_uids = old_uids.iter().copied().collect::<HashSet<_>>();
    uids.retain(|uid| !old_uids.contains(uid));
}

fn legacy_selected_thread_uids(thread_uid: u32, threads: &[Vec<u32>]) -> Vec<u32> {
    threads
        .iter()
        .find(|thread| thread.contains(&thread_uid))
        .cloned()
        .unwrap_or_else(|| vec![thread_uid])
}

fn legacy_filter_thread_search_results(
    uids: &mut Vec<u32>,
    searched_uids: &[u32],
    threads: &[Vec<u32>],
) {
    let searched = searched_uids.iter().copied().collect::<HashSet<_>>();
    let matching_thread_uids = threads
        .iter()
        .filter(|thread| thread.iter().any(|uid| searched.contains(uid)))
        .flatten()
        .copied()
        .collect::<HashSet<_>>();
    uids.retain(|uid| searched.contains(uid) || matching_thread_uids.contains(uid));
}

fn legacy_message_thread_metadata(
    uid: u32,
    threads: &[Vec<u32>],
    unseen_uids: &[u32],
) -> (Vec<u32>, Vec<u32>) {
    let Some(thread) = threads.iter().find(|thread| thread.contains(&uid)) else {
        return (Vec::new(), Vec::new());
    };
    let thread_unseen = unseen_uids
        .iter()
        .copied()
        .filter(|unseen_uid| thread.contains(unseen_uid))
        .collect();
    (thread.clone(), thread_unseen)
}

#[derive(Clone, Copy)]
enum LegacyMessageListFetchMode {
    Uids,
    Sequences,
}

struct LegacyMessageSummaryAccumulator {
    summary: LegacyMessageSummary,
    header_seen: bool,
    bodystructure_seen: bool,
    internal_date_seen: bool,
    size_seen: bool,
    flags_seen: bool,
    email_id_seen: bool,
}

#[derive(Clone, Copy)]
struct LegacyMessageSummaryFragment {
    header: bool,
    bodystructure: bool,
    internal_date: bool,
    size: bool,
    flags: bool,
    email_id: bool,
}

impl LegacyMessageSummaryAccumulator {
    fn new(summary: LegacyMessageSummary, fragment: LegacyMessageSummaryFragment) -> Self {
        Self {
            summary,
            header_seen: fragment.header,
            bodystructure_seen: fragment.bodystructure,
            internal_date_seen: fragment.internal_date,
            size_seen: fragment.size,
            flags_seen: fragment.flags,
            email_id_seen: fragment.email_id,
        }
    }

    fn merge(&mut self, incoming: LegacyMessageSummary, fragment: LegacyMessageSummaryFragment) {
        if fragment.header && !self.header_seen {
            self.summary.subject = incoming.subject;
            self.summary.message_id = incoming.message_id;
            self.summary.spam_score = incoming.spam_score;
            self.summary.spam_result = incoming.spam_result;
            self.summary.is_spam = incoming.is_spam;
            self.summary.in_reply_to = incoming.in_reply_to;
            self.summary.references = incoming.references;
            self.summary.from = incoming.from;
            self.summary.reply_to = incoming.reply_to;
            self.summary.to = incoming.to;
            self.summary.cc = incoming.cc;
            self.summary.bcc = incoming.bcc;
            self.summary.sender = incoming.sender;
            self.summary.delivered_to = incoming.delivered_to;
            self.summary.read_receipt = incoming.read_receipt;
            self.summary.date = incoming.date;
            if incoming.date_timestamp_source == "header" || !self.internal_date_seen {
                self.summary.date_timestamp = incoming.date_timestamp;
                self.summary.date_timestamp_source = incoming.date_timestamp_source.clone();
            }
            self.summary.encrypted |= incoming.encrypted;
            self.header_seen = true;
        }
        if fragment.bodystructure && !self.bodystructure_seen {
            self.summary.has_attachments = incoming.has_attachments;
            self.summary.attachments = incoming.attachments;
            self.summary.encrypted |= incoming.encrypted;
            self.bodystructure_seen = true;
        }
        if fragment.internal_date && !self.internal_date_seen {
            if self.summary.date_timestamp_source != "header" {
                self.summary.date_timestamp = incoming.date_timestamp;
                self.summary.date_timestamp_source = incoming.date_timestamp_source;
            }
            self.internal_date_seen = true;
        }
        if fragment.size && !self.size_seen {
            self.summary.size = incoming.size;
            self.size_seen = true;
        }
        if fragment.flags && !self.flags_seen {
            self.summary.flags = incoming.flags;
            self.flags_seen = true;
        }
        if fragment.email_id && !self.email_id_seen {
            self.summary.email_id = incoming.email_id;
            self.email_id_seen = true;
        }
    }
}

async fn fetch_legacy_message_list_summaries(
    session: &mut BoxedSession,
    mailbox: &str,
    ids: &[u32],
    mode: LegacyMessageListFetchMode,
    capabilities: &ImapFetchMetadataCapabilities,
    message_threads: &[Vec<u32>],
    unseen_uids: &[u32],
) -> Result<Vec<LegacyMessageSummary>> {
    let Some(id_set) = (match mode {
        LegacyMessageListFetchMode::Uids => legacy_uid_sequence_set(ids),
        LegacyMessageListFetchMode::Sequences => legacy_sequence_set_preserving_order(ids),
    }) else {
        return Ok(Vec::new());
    };
    let query = legacy_message_list_fetch_query_with_gmail_id(legacy_message_fetches_gmail_id(
        capabilities,
    ));
    let requested_ids = ids.iter().copied().collect::<HashSet<_>>();
    let mut fetches: Pin<
        Box<
            dyn Stream<
                    Item = std::result::Result<async_imap::types::Fetch, async_imap::error::Error>,
                > + Send
                + '_,
        >,
    > = match mode {
        LegacyMessageListFetchMode::Uids => Box::pin(
            timeout_imap(
                "fetch legacy message list",
                session.uid_fetch(id_set, query),
            )
            .await?,
        ),
        LegacyMessageListFetchMode::Sequences => Box::pin(
            timeout_imap(
                "fetch limited legacy message list",
                session.fetch(id_set, query),
            )
            .await?,
        ),
    };
    let mut messages_by_id: HashMap<u32, LegacyMessageSummaryAccumulator> = HashMap::new();
    while let Some(fetch) =
        timeout_imap("read legacy message list item", fetches.try_next()).await?
    {
        let Some(uid) = fetch.uid else {
            continue;
        };
        let bodystructure = fetch.bodystructure();
        let id = match mode {
            LegacyMessageListFetchMode::Uids => uid,
            LegacyMessageListFetchMode::Sequences => fetch.message,
        };
        if !requested_ids.contains(&id) {
            continue;
        }
        let header = fetch.header();
        let internal_timestamp = fetch.internal_date().map(|value| value.timestamp());
        let size = fetch.size;
        let flags = fetch.flags().collect::<Vec<_>>();
        let email_id = fetch.gmail_msg_id().map(u64::to_string);
        let fragment = LegacyMessageSummaryFragment {
            header: header.is_some(),
            bodystructure: bodystructure.is_some(),
            internal_date: internal_timestamp.is_some(),
            size: size.is_some(),
            flags: !flags.is_empty(),
            email_id: email_id.is_some(),
        };
        let mut summary = legacy_message_summary_from_fetch_with_email_id(
            mailbox,
            uid,
            internal_timestamp,
            size.unwrap_or_default(),
            flags.into_iter(),
            bodystructure,
            header.unwrap_or_default(),
            email_id,
        );
        (summary.threads, summary.thread_unseen) =
            legacy_message_thread_metadata(uid, message_threads, unseen_uids);
        if let Some(existing) = messages_by_id.get_mut(&id) {
            existing.merge(summary, fragment);
        } else {
            messages_by_id.insert(id, LegacyMessageSummaryAccumulator::new(summary, fragment));
        }
    }
    drop(fetches);

    let fetched_uids = messages_by_id
        .values()
        .map(|message| message.summary.uid)
        .filter(|uid| *uid > 0)
        .collect::<Vec<_>>();
    if !fetched_uids.is_empty() {
        let (email_ids, previews) = fetch_legacy_message_email_ids_and_previews(
            session,
            &fetched_uids,
            capabilities.supports_object_id,
            capabilities.supports_preview,
            "fetch legacy message-list EMAILIDs and previews",
        )
        .await?;
        for message in messages_by_id.values_mut() {
            if let Some(email_id) = email_ids.get(&message.summary.uid) {
                message.summary.email_id = Some(email_id.clone());
            }
            if let Some(preview) = previews.get(&message.summary.uid) {
                message.summary.preview = Some(preview.clone());
            }
        }
    }

    Ok(ids
        .iter()
        .filter_map(|id| messages_by_id.remove(id).map(|message| message.summary))
        .collect())
}

async fn fetch_legacy_message_list_multisearch_page(
    session: &mut BoxedSession,
    page: &[LegacyMessageListMailboxPage],
    search: &str,
    query_options: LegacyMessageListQueryOptions<'_>,
    capabilities: &ImapFetchMetadataCapabilities,
) -> Result<Vec<LegacyMessageSummary>> {
    let message_capacity = page
        .iter()
        .map(|mailbox_page| mailbox_page.limit as usize)
        .sum();
    let mut messages = Vec::with_capacity(message_capacity);

    for mailbox_page in page {
        let mailbox = &mailbox_page.mailbox;
        if mailbox_page.expected_count > MULTISEARCH_UID_ENUMERATION_LIMIT {
            return Err(FrickmailError::Upstream(format!(
                "multisearch legacy message list has too many matching UIDs in {mailbox}"
            )));
        }
        let wire_mailbox = imap_mailbox_from_utf8(mailbox, capabilities.uses_utf8_search);
        let examined = timeout_imap(
            "examine multisearch result mailbox",
            session.examine(&wire_mailbox),
        )
        .await?;
        if examined.uid_validity != Some(mailbox_page.uid_validity) {
            return Err(FrickmailError::Upstream(format!(
                "multisearch legacy message list UIDVALIDITY changed for {mailbox}"
            )));
        }

        let mut matching_uids = legacy_message_list_visible_uids_with_settings_bounded(
            session,
            search,
            query_options,
            Some(MULTISEARCH_UID_ENUMERATION_LIMIT as usize),
        )
        .await?;
        matching_uids.sort_unstable_by(|left, right| right.cmp(left));
        matching_uids.dedup();
        if matching_uids.len() != mailbox_page.expected_count as usize {
            return Err(FrickmailError::Upstream(format!(
                "multisearch legacy message list changed while paging {mailbox}"
            )));
        }
        let page_uids =
            legacy_message_list_page_uids(&matching_uids, mailbox_page.offset, mailbox_page.limit);
        if page_uids.len() != mailbox_page.limit as usize {
            return Err(FrickmailError::Upstream(format!(
                "multisearch legacy message list returned a short page for {mailbox}"
            )));
        }
        let uid_set = legacy_uid_sequence_set(&page_uids).ok_or_else(|| {
            FrickmailError::Upstream(
                "multisearch legacy message list produced an empty UID page".to_string(),
            )
        })?;
        let requested_uids = page_uids.iter().copied().collect::<HashSet<_>>();
        let mut messages_by_uid: HashMap<u32, LegacyMessageSummaryAccumulator> = HashMap::new();
        let mut fetches = timeout_imap(
            "fetch multisearch legacy message list",
            session.uid_fetch(
                uid_set.clone(),
                legacy_message_list_fetch_query_with_gmail_id(legacy_message_fetches_gmail_id(
                    capabilities,
                )),
            ),
        )
        .await?;

        while let Some(fetch) = timeout_imap(
            "read multisearch legacy message list item",
            fetches.try_next(),
        )
        .await?
        {
            let Some(uid) = fetch.uid else {
                continue;
            };
            let bodystructure = fetch.bodystructure();
            if !requested_uids.contains(&uid) {
                continue;
            }
            let header = fetch.header();
            let internal_timestamp = fetch.internal_date().map(|value| value.timestamp());
            let size = fetch.size;
            let flags = fetch.flags().collect::<Vec<_>>();
            let email_id = fetch.gmail_msg_id().map(u64::to_string);
            let fragment = LegacyMessageSummaryFragment {
                header: header.is_some(),
                bodystructure: bodystructure.is_some(),
                internal_date: internal_timestamp.is_some(),
                size: size.is_some(),
                flags: !flags.is_empty(),
                email_id: email_id.is_some(),
            };
            let summary = legacy_message_summary_from_fetch_with_email_id(
                mailbox,
                uid,
                internal_timestamp,
                size.unwrap_or_default(),
                flags.into_iter(),
                bodystructure,
                header.unwrap_or_default(),
                email_id,
            );
            if let Some(existing) = messages_by_uid.get_mut(&uid) {
                existing.merge(summary, fragment);
            } else {
                messages_by_uid
                    .insert(uid, LegacyMessageSummaryAccumulator::new(summary, fragment));
            }
        }
        drop(fetches);

        if page_uids
            .iter()
            .any(|uid| !messages_by_uid.contains_key(uid))
        {
            return Err(FrickmailError::Upstream(format!(
                "multisearch legacy message list changed while fetching {mailbox}"
            )));
        }
        if capabilities.supports_object_id || capabilities.supports_preview {
            let (email_ids, previews) = fetch_legacy_message_email_ids_and_previews(
                session,
                &page_uids,
                capabilities.supports_object_id,
                capabilities.supports_preview,
                "fetch multisearch legacy message-list EMAILIDs and previews",
            )
            .await?;
            for (uid, email_id) in email_ids {
                if let Some(message) = messages_by_uid.get_mut(&uid) {
                    message.summary.email_id = Some(email_id);
                }
            }
            for (uid, preview) in previews {
                if let Some(message) = messages_by_uid.get_mut(&uid) {
                    message.summary.preview = Some(preview);
                }
            }
        }
        messages.extend(
            page_uids
                .iter()
                .filter_map(|uid| messages_by_uid.remove(uid).map(|message| message.summary)),
        );
    }

    Ok(messages)
}

fn legacy_message_list_page_uids(uids: &[u32], offset: u32, limit: u32) -> Vec<u32> {
    uids.iter()
        .copied()
        .skip(offset as usize)
        .take(limit as usize)
        .collect()
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

fn legacy_message_list_sort_for_command(sort: &str, supports_sort_display: bool) -> Result<String> {
    if sort
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'))
    {
        return Err(FrickmailError::BadRequest(
            "message-list sort contains invalid command bytes".to_string(),
        ));
    }
    let mut tokens = sort.split_ascii_whitespace();
    while let Some(token) = tokens.next() {
        let criterion = if token.eq_ignore_ascii_case("REVERSE") {
            tokens.next().ok_or_else(|| {
                FrickmailError::BadRequest(
                    "message-list REVERSE sort requires a criterion".to_string(),
                )
            })?
        } else {
            token
        };
        let criterion = criterion.to_ascii_uppercase();
        let supported = matches!(
            criterion.as_str(),
            "ARRIVAL" | "CC" | "DATE" | "FROM" | "SIZE" | "SUBJECT" | "TO"
        ) || (supports_sort_display
            && matches!(criterion.as_str(), "DISPLAYFROM" | "DISPLAYTO"));
        if !supported {
            return Err(FrickmailError::BadRequest(
                "message-list sort contains an unsupported criterion".to_string(),
            ));
        }
    }
    Ok(legacy_message_list_sort(sort, true))
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
    header_value_bytes(raw, name).map(|value| String::from_utf8_lossy(&value).into_owned())
}

fn header_value_bytes(raw: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut collecting = false;
    let mut found = false;
    let mut value = Vec::new();
    let wanted = name.as_bytes();

    for line in raw.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            if collecting {
                value.push(b' ');
                value.extend_from_slice(legacy_php_trim_bytes(line));
            }
            continue;
        }
        collecting = false;
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let key = legacy_php_trim_bytes(&line[..separator]);
        if !found && key.eq_ignore_ascii_case(wanted) {
            value = legacy_php_trim_bytes(&line[separator + 1..]).to_vec();
            collecting = true;
            found = true;
        }
    }

    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn legacy_php_trim_bytes(value: &[u8]) -> &[u8] {
    legacy_php_rtrim_bytes(legacy_php_ltrim_bytes(value))
}

fn legacy_php_ltrim_bytes(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !legacy_php_trim_byte(*byte))
        .unwrap_or(value.len());
    &value[start..]
}

fn legacy_php_rtrim_bytes(value: &[u8]) -> &[u8] {
    let end = value
        .iter()
        .rposition(|byte| !legacy_php_trim_byte(*byte))
        .map(|index| index + 1)
        .unwrap_or_default();
    &value[..end]
}

fn legacy_php_trim_byte(value: u8) -> bool {
    matches!(value, b' ' | b'\t' | b'\n' | b'\r' | b'\0' | 0x0b)
}

fn legacy_header_collection_first_value(raw: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut has_current = false;
    let mut current_name = Vec::new();
    let mut current_value = Vec::new();
    let wanted = name.as_bytes();

    for raw_line in raw.split(|byte| *byte == b'\n') {
        let line = raw_line
            .iter()
            .copied()
            .filter(|byte| *byte != b'\r')
            .collect::<Vec<_>>();
        if line.is_empty() {
            continue;
        }
        let continuation = matches!(line.first(), Some(b' ' | b'\t'));
        let separator = line.iter().position(|byte| *byte == b':');
        if !continuation && separator.is_none() {
            continue;
        }

        if has_current && continuation {
            let mut continuation = line.as_slice();
            let without_trailing_space = legacy_php_rtrim_bytes(continuation);
            if without_trailing_space.ends_with(b"?=") {
                continuation = without_trailing_space;
            }
            let without_leading_space = legacy_php_ltrim_bytes(continuation);
            if without_leading_space.starts_with(b"=?") {
                continuation = without_leading_space;
            }
            if continuation.starts_with(b"=?") {
                current_value.extend_from_slice(continuation);
            } else {
                current_value.push(b'\n');
                current_value.extend_from_slice(continuation);
            }
            continue;
        }

        if has_current && legacy_php_trim_bytes(&current_name).eq_ignore_ascii_case(wanted) {
            let value = legacy_php_trim_bytes(&current_value);
            return Some(value.to_vec());
        }

        let separator = separator.unwrap_or(line.len());
        has_current = true;
        current_name = line[..separator].to_vec();
        current_value = line.get(separator + 1..).unwrap_or_default().to_vec();
        let without_trailing_space = legacy_php_rtrim_bytes(&current_value);
        if without_trailing_space.ends_with(b"?=") {
            current_value.truncate(without_trailing_space.len());
        }
    }

    if has_current && legacy_php_trim_bytes(&current_name).eq_ignore_ascii_case(wanted) {
        let value = legacy_php_trim_bytes(&current_value);
        return Some(value.to_vec());
    }
    None
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
    let capabilities =
        timeout_imap("read folder-status capabilities", session.capabilities()).await?;
    let utf8_mode = enable_legacy_utf8(session, &capabilities).await?;
    let wire_mailbox = imap_mailbox_from_utf8(mailbox, utf8_mode);
    let options = LegacyFolderStatusOptions::from_capabilities(&capabilities);
    let status = legacy_extended_folder_status(session, &wire_mailbox, &options).await?;
    let selected = if flag_uids.is_some() {
        timeout_imap("select mailbox", session.select(&wire_mailbox)).await?
    } else {
        timeout_imap("examine mailbox", session.examine(&wire_mailbox)).await?
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

async fn warm_legacy_message_list_cache(
    config: ImapConnectionConfig,
    password: &str,
    request: LegacyMessageListRequest,
    folder_hash: String,
    uid_cache: Arc<dyn LegacyMessageListUidCache>,
) -> Result<()> {
    let client_hash = legacy_imap_client_hash(&config);
    let mut session = login(config, password).await?;
    let result = async {
        let mut capabilities = imap_fetch_metadata_capabilities(&mut session).await?;
        let advertised = timeout_imap(
            "read message-list warm capabilities",
            session.capabilities(),
        )
        .await?;
        capabilities.uses_utf8_search = enable_legacy_utf8(&mut session, &advertised).await?;
        let wire_mailbox = imap_mailbox_from_utf8(&request.mailbox, capabilities.uses_utf8_search);
        timeout_imap(
            "examine mailbox for message-list cache warm",
            session.examine(&wire_mailbox),
        )
        .await?;
        warm_legacy_message_list_cache_in_session(
            &mut session,
            &request,
            &folder_hash,
            &client_hash,
            &capabilities,
            uid_cache.as_ref(),
        )
        .await
    }
    .await;
    logout_quietly(session).await;
    result
}

async fn warm_legacy_message_list_cache_in_session(
    session: &mut BoxedSession,
    request: &LegacyMessageListRequest,
    folder_hash: &str,
    client_hash: &str,
    capabilities: &ImapFetchMetadataCapabilities,
    uid_cache: &dyn LegacyMessageListUidCache,
) -> Result<()> {
    let sort = capabilities
        .supports_sort
        .then(|| {
            legacy_message_list_sort_for_command(&request.sort, capabilities.supports_sort_display)
        })
        .transpose()?;
    legacy_message_list_visible_uids_cached_bounded(
        session,
        &request.mailbox,
        folder_hash,
        client_hash,
        "",
        LegacyMessageListQueryOptions {
            hide_deleted: request.hide_deleted,
            fast_simple_search: request.fast_simple_search,
            permanent_filter: &request.permanent_filter,
            sort: sort.as_deref(),
            utf8_mode: capabilities.uses_utf8_search,
            supports_within: capabilities.supports_within,
            supports_literal_plus: capabilities.supports_literal_plus,
        },
        Some(uid_cache),
        Some(uid_cache.max_uid_entries()),
    )
    .await?;

    if request.use_threads {
        if let Some(algorithm) = legacy_message_list_thread_algorithm(
            &capabilities.thread_algorithms,
            &request.thread_algorithm,
        ) {
            fetch_legacy_message_threads_cached(session, &algorithm, folder_hash, Some(uid_cache))
                .await;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn legacy_message_list_optimized_in_session(
    session: &mut BoxedSession,
    request: &LegacyMessageListRequest,
    folder: LegacyFolderInformation,
    folder_total: u32,
    limit: u32,
    used_sort: bool,
    sort: Option<&str>,
    client_hash: &str,
    capabilities: &ImapFetchMetadataCapabilities,
    uid_cache: Option<&dyn LegacyMessageListUidCache>,
) -> Result<LegacyMessageList> {
    let search = legacy_message_list_search(&request.search);
    let query_options = |sort| LegacyMessageListQueryOptions {
        hide_deleted: request.hide_deleted,
        fast_simple_search: request.fast_simple_search,
        permanent_filter: &request.permanent_filter,
        sort,
        utf8_mode: capabilities.uses_utf8_search,
        supports_within: capabilities.supports_within,
        supports_literal_plus: capabilities.supports_literal_plus,
    };

    let (total_emails, sort, mode, page_ids) = if !search.is_empty() {
        let uids = legacy_message_list_visible_uids_cached(
            session,
            &request.mailbox,
            &folder.etag,
            client_hash,
            &request.search,
            query_options(None),
            uid_cache,
        )
        .await?;
        (
            u32::try_from(uids.len()).unwrap_or(u32::MAX),
            String::new(),
            LegacyMessageListFetchMode::Uids,
            legacy_message_list_page_uids(&uids, request.offset, limit),
        )
    } else if used_sort {
        let candidates =
            legacy_message_list_optimized_sequence_ids(folder_total, request.offset, limit, true);
        let sequence_set = legacy_sequence_set_preserving_order(&candidates);
        let sorted_ids = if let Some(sequence_set) = sequence_set.as_deref() {
            legacy_message_list_ids_with_settings_bounded(
                session,
                "",
                query_options(sort),
                Some(candidates.len()),
                false,
                Some(sequence_set),
            )
            .await?
        } else {
            Vec::new()
        };
        (
            folder_total,
            legacy_message_list_sort(&request.sort, true),
            LegacyMessageListFetchMode::Sequences,
            legacy_message_list_optimized_sorted_page(&sorted_ids, request.offset, limit),
        )
    } else {
        (
            folder_total,
            String::new(),
            LegacyMessageListFetchMode::Sequences,
            legacy_message_list_optimized_sequence_ids(folder_total, request.offset, limit, false),
        )
    };
    let messages = fetch_legacy_message_list_summaries(
        session,
        &request.mailbox,
        &page_ids,
        mode,
        capabilities,
        &[],
        &[],
    )
    .await?;

    Ok(LegacyMessageList {
        folder,
        total_emails,
        total_threads: None,
        offset: request.offset,
        limit,
        search,
        sort,
        limited: legacy_message_list_limited(true),
        thread_uid: 0,
        messages,
    })
}

#[cfg(test)]
async fn legacy_message_list_in_session(
    session: &mut BoxedSession,
    request: LegacyMessageListRequest,
    client_hash: &str,
    capabilities: ImapFetchMetadataCapabilities,
    uid_cache: Option<&dyn LegacyMessageListUidCache>,
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
    legacy_message_list_for_folder_in_session(
        session,
        request,
        client_hash,
        capabilities,
        uid_cache,
        folder,
    )
    .await
}

async fn legacy_message_list_in_session_if_changed(
    session: &mut BoxedSession,
    request: LegacyMessageListRequest,
    client_hash: &str,
    capabilities: ImapFetchMetadataCapabilities,
    uid_cache: Option<&dyn LegacyMessageListUidCache>,
    unchanged_folder_etag: Option<&str>,
) -> Result<Option<LegacyMessageList>> {
    let fetch_new_messages = legacy_message_list_fetches_new_messages(request.thread_uid);
    let mut folder = legacy_folder_information_in_session(
        session,
        &request.mailbox,
        request.prev_uid_next,
        None,
        false,
        client_hash,
    )
    .await?;
    if unchanged_folder_etag.is_some_and(|etag| etag == folder.etag) {
        return Ok(None);
    }
    if fetch_new_messages {
        folder.new_messages = fetch_legacy_new_messages(
            session,
            &request.mailbox,
            request.prev_uid_next,
            folder.uid_next,
        )
        .await?;
    }

    legacy_message_list_for_folder_in_session(
        session,
        request,
        client_hash,
        capabilities,
        uid_cache,
        folder,
    )
    .await
    .map(Some)
}

async fn legacy_message_list_for_folder_in_session(
    session: &mut BoxedSession,
    request: LegacyMessageListRequest,
    client_hash: &str,
    capabilities: ImapFetchMetadataCapabilities,
    uid_cache: Option<&dyn LegacyMessageListUidCache>,
    folder: LegacyFolderInformation,
) -> Result<LegacyMessageList> {
    let folder_total = folder.total_emails.unwrap_or_default();
    let limit = legacy_message_list_limit(request.limit);
    let uses_multisearch = capabilities.supports_multisearch
        && legacy_message_list_multisearch_scope(&request.search).is_some();
    if uses_multisearch && request.thread_uid > 0 {
        return Err(FrickmailError::BadRequest(
            "thread views are unavailable for cross-mailbox searches".to_string(),
        ));
    }
    if uses_multisearch {
        let matches = legacy_message_list_multisearch_matches(
            session,
            &request.mailbox,
            &request.search,
            LegacyMessageListQueryOptions {
                hide_deleted: request.hide_deleted,
                fast_simple_search: request.fast_simple_search,
                permanent_filter: &request.permanent_filter,
                sort: None,
                utf8_mode: capabilities.uses_utf8_search,
                supports_within: capabilities.supports_within,
                supports_literal_plus: capabilities.supports_literal_plus,
            },
            true,
        )
        .await?
        .ok_or_else(|| {
            FrickmailError::Upstream(
                "multisearch legacy message list scope disappeared".to_string(),
            )
        })?;
        let (total_emails, page) =
            legacy_message_list_multisearch_page_plan(&matches, request.offset, limit)?;
        let query_options = LegacyMessageListQueryOptions {
            hide_deleted: request.hide_deleted,
            fast_simple_search: request.fast_simple_search,
            permanent_filter: &request.permanent_filter,
            sort: None,
            utf8_mode: capabilities.uses_utf8_search,
            supports_within: capabilities.supports_within,
            supports_literal_plus: capabilities.supports_literal_plus,
        };
        let messages = timeout_result(
            "fetch multisearch legacy message-list page",
            timeout(
                MULTISEARCH_PAGE_BUDGET,
                fetch_legacy_message_list_multisearch_page(
                    session,
                    &page,
                    &request.search,
                    query_options,
                    &capabilities,
                ),
            ),
        )
        .await??;
        return Ok(LegacyMessageList {
            folder,
            total_emails,
            total_threads: None,
            offset: request.offset,
            limit,
            search: legacy_message_list_search(&request.search),
            sort: String::new(),
            limited: legacy_message_list_limited(false),
            thread_uid: 0,
            messages,
        });
    }
    let thread_algorithm = request
        .use_threads
        .then(|| {
            legacy_message_list_thread_algorithm(
                &capabilities.thread_algorithms,
                &request.thread_algorithm,
            )
        })
        .flatten();
    if request.thread_uid > 0 && thread_algorithm.is_none() {
        return Err(FrickmailError::Upstream(
            "THREAD is not supported by the IMAP server".to_string(),
        ));
    }
    let can_query = folder_total > 0 && request.offset <= folder_total;
    let used_sort = can_query && capabilities.supports_sort;
    let sort = used_sort
        .then(|| {
            legacy_message_list_sort_for_command(&request.sort, capabilities.supports_sort_display)
        })
        .transpose()?;
    let optimization_enabled = can_query
        && request.thread_uid == 0
        && legacy_message_list_optimization_enabled(request.message_list_limit, folder_total);
    let mut cached_full_uids = if optimization_enabled {
        legacy_message_list_visible_uids_from_cache(
            &request.mailbox,
            &folder.etag,
            client_hash,
            "",
            LegacyMessageListQueryOptions {
                hide_deleted: request.hide_deleted,
                fast_simple_search: request.fast_simple_search,
                permanent_filter: &request.permanent_filter,
                sort: sort.as_deref(),
                utf8_mode: capabilities.uses_utf8_search,
                supports_within: capabilities.supports_within,
                supports_literal_plus: capabilities.supports_literal_plus,
            },
            uid_cache,
        )
        .await?
    } else {
        None
    };
    if optimization_enabled && cached_full_uids.is_none() {
        return legacy_message_list_optimized_in_session(
            session,
            &request,
            folder,
            folder_total,
            limit,
            used_sort,
            sort.as_deref(),
            client_hash,
            &capabilities,
            uid_cache,
        )
        .await;
    }
    let used_cached_full_uids = cached_full_uids.is_some();
    let mut message_threads = Vec::new();
    let mut unseen_uids = Vec::new();
    let mut total_threads = None;
    let matching_uids = if !can_query {
        Vec::new()
    } else {
        let initial_search = if thread_algorithm.is_some() {
            ""
        } else {
            &request.search
        };
        let mut uids = if let Some(cached_uids) = cached_full_uids.take() {
            cached_uids
        } else {
            legacy_message_list_visible_uids_cached(
                session,
                &request.mailbox,
                &folder.etag,
                client_hash,
                initial_search,
                LegacyMessageListQueryOptions {
                    hide_deleted: request.hide_deleted,
                    fast_simple_search: request.fast_simple_search,
                    permanent_filter: &request.permanent_filter,
                    sort: sort.as_deref(),
                    utf8_mode: capabilities.uses_utf8_search,
                    supports_within: capabilities.supports_within,
                    supports_literal_plus: capabilities.supports_literal_plus,
                },
                uid_cache,
            )
            .await?
        };
        if !used_sort {
            uids.sort_unstable_by(|left, right| right.cmp(left));
        }

        if let Some(algorithm) = thread_algorithm.as_deref() {
            let threads =
                fetch_legacy_message_threads_cached(session, algorithm, &folder.etag, uid_cache)
                    .await;
            total_threads = Some(u32::try_from(threads.len()).unwrap_or(u32::MAX));

            if request.thread_uid > 0 {
                uids = legacy_selected_thread_uids(request.thread_uid, &threads);
                message_threads = vec![uids.clone()];
            } else {
                let old_uids =
                    legacy_thread_old_uids_cached(&threads, &folder.etag, uid_cache).await;
                legacy_thread_representatives(&mut uids, &old_uids);
                unseen_uids = legacy_message_list_visible_uids_cached(
                    session,
                    &request.mailbox,
                    &folder.etag,
                    client_hash,
                    "unseen",
                    LegacyMessageListQueryOptions {
                        hide_deleted: request.hide_deleted,
                        fast_simple_search: request.fast_simple_search,
                        permanent_filter: &request.permanent_filter,
                        sort: None,
                        utf8_mode: capabilities.uses_utf8_search,
                        supports_within: capabilities.supports_within,
                        supports_literal_plus: capabilities.supports_literal_plus,
                    },
                    uid_cache,
                )
                .await?;
                message_threads = threads;
            }

            if !legacy_message_list_search(&request.search).is_empty() {
                let searched_uids = legacy_message_list_visible_uids_cached(
                    session,
                    &request.mailbox,
                    &folder.etag,
                    client_hash,
                    &request.search,
                    LegacyMessageListQueryOptions {
                        hide_deleted: request.hide_deleted,
                        fast_simple_search: request.fast_simple_search,
                        permanent_filter: &request.permanent_filter,
                        sort: None,
                        utf8_mode: capabilities.uses_utf8_search,
                        supports_within: capabilities.supports_within,
                        supports_literal_plus: capabilities.supports_literal_plus,
                    },
                    uid_cache,
                )
                .await?;
                if request.thread_uid > 0 {
                    let searched = searched_uids.into_iter().collect::<HashSet<_>>();
                    uids.retain(|uid| searched.contains(uid));
                } else {
                    legacy_filter_thread_search_results(
                        &mut uids,
                        &searched_uids,
                        &message_threads,
                    );
                }
            }
        } else if used_cached_full_uids && !legacy_message_list_search(&request.search).is_empty() {
            let searched_uids = legacy_message_list_visible_uids_cached(
                session,
                &request.mailbox,
                &folder.etag,
                client_hash,
                &request.search,
                LegacyMessageListQueryOptions {
                    hide_deleted: request.hide_deleted,
                    fast_simple_search: request.fast_simple_search,
                    permanent_filter: &request.permanent_filter,
                    sort: None,
                    utf8_mode: capabilities.uses_utf8_search,
                    supports_within: capabilities.supports_within,
                    supports_literal_plus: capabilities.supports_literal_plus,
                },
                uid_cache,
            )
            .await?;
            let searched = searched_uids.into_iter().collect::<HashSet<_>>();
            uids.retain(|uid| searched.contains(uid));
        }
        uids
    };
    let total = if can_query {
        u32::try_from(matching_uids.len()).unwrap_or(u32::MAX)
    } else {
        folder_total
    };
    let page_uids = legacy_message_list_page_uids(&matching_uids, request.offset, limit);
    let messages = fetch_legacy_message_list_summaries(
        session,
        &request.mailbox,
        &page_uids,
        LegacyMessageListFetchMode::Uids,
        &capabilities,
        &message_threads,
        &unseen_uids,
    )
    .await?;

    Ok(LegacyMessageList {
        folder,
        total_emails: total,
        total_threads,
        offset: request.offset,
        limit,
        search: legacy_message_list_search(&request.search),
        sort: legacy_message_list_sort(&request.sort, used_sort),
        limited: legacy_message_list_limited(false),
        thread_uid: request.thread_uid,
        messages,
    })
}

fn legacy_folder_information_from_mailboxes(
    mailbox: &str,
    status: &ListedLegacyFolderStatus,
    examined: &async_imap::types::Mailbox,
    prev_uid_next: Option<u32>,
    client_hash: &str,
) -> LegacyFolderInformation {
    let uid_next = status.uid_next.or(examined.uid_next);
    let uid_validity = status.uid_validity.or(examined.uid_validity);
    let total_emails = status.total_emails.or(Some(examined.exists));
    let unread_emails = status.unread_emails;
    let highest_modseq = status.highest_modseq.or(examined.highest_modseq);
    let permanent_flags = examined
        .permanent_flags
        .iter()
        .map(legacy_flag_string)
        .collect::<Vec<_>>();
    let etag = legacy_folder_etag(
        mailbox,
        total_emails.unwrap_or_default(),
        uid_next,
        uid_validity,
        unread_emails,
        highest_modseq,
        client_hash,
    );
    let _new_uid_range = legacy_new_uid_range(prev_uid_next, uid_next);

    LegacyFolderInformation {
        id: status.mailbox_id.clone(),
        name: mailbox.to_string(),
        uid_next,
        uid_validity,
        total_emails,
        unread_emails,
        highest_modseq,
        append_limit: status.append_limit,
        size: status.size,
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
            subject: legacy_new_message_subject(header),
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
    let header_subject = legacy_header_subject(&legacy_decoded_header_value(header, "Subject"));
    let subject = legacy_message_subject(&header_subject);
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
    let spam = legacy_message_spam_summary(header, &header_subject);
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
        threads: Vec::new(),
        thread_unseen: Vec::new(),
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
    let primary = legacy_header_subject(&legacy_decoded_header_value(
        header,
        "Disposition-Notification-To",
    ));
    let selected = if primary.is_empty() {
        legacy_header_subject(&legacy_decoded_header_value(header, "X-Confirm-Reading-To"))
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

fn legacy_header_subject(value: &str) -> String {
    legacy_php_trim(value).to_string()
}

fn legacy_decoded_header_value(header: &[u8], name: &str) -> String {
    header_value(header, name)
        .map(|value| legacy_decode_rfc2047_header_value(&value))
        .unwrap_or_default()
}

fn legacy_new_message_subject(header: &[u8]) -> String {
    let Some(raw_subject) = legacy_header_collection_first_value(header, "Subject") else {
        return String::new();
    };
    let charset =
        legacy_new_message_header_charset(header).unwrap_or_else(|| "iso-8859-1".to_string());
    let subject = legacy_decode_rfc2047_charset(&charset, &raw_subject);
    legacy_header_subject(&legacy_decode_rfc2047_header_value(&subject))
}

fn legacy_new_message_header_charset(header: &[u8]) -> Option<String> {
    let content_type = legacy_header_collection_first_value(header, "Content-Type")?;
    let content_type = legacy_decode_rfc2047_charset("iso-8859-1", &content_type);
    let content_type = legacy_decode_rfc2047_header_value(&content_type);
    let mut parameters = Vec::<(String, String)>::new();
    let mut parameter_indices = HashMap::<String, usize>::new();
    for parameter in content_type.split(';').skip(1) {
        let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        let name = legacy_php_trim(name).trim_matches(['"', '\'']).to_string();
        let value = legacy_php_trim(value).trim_matches(['"', '\'']).to_string();
        legacy_set_parameter(&mut parameters, &mut parameter_indices, name, value);
    }

    let mut extended_charset = "utf-8".to_string();
    let mut extended_groups = Vec::<(String, HashMap<usize, String>)>::new();
    let mut extended_group_indices = HashMap::<String, usize>::new();
    let mut final_parameters = Vec::<(String, String)>::new();
    let mut final_parameter_indices = HashMap::<String, usize>::new();
    for (name, value) in parameters {
        let Some((base, index)) = legacy_rfc2231_parameter_name(&name) else {
            legacy_set_parameter(
                &mut final_parameters,
                &mut final_parameter_indices,
                name,
                value,
            );
            continue;
        };
        let mut segment = value;
        if let Some((candidate_charset, encoded)) = segment.split_once("''") {
            if !encoded.is_empty() {
                extended_charset = candidate_charset.to_string();
                segment = encoded.to_string();
            }
        }

        let group_index = if let Some(index) = extended_group_indices.get(base) {
            *index
        } else {
            let group_index = extended_groups.len();
            extended_groups.push((base.to_string(), HashMap::new()));
            extended_group_indices.insert(base.to_string(), group_index);
            group_index
        };
        extended_groups[group_index].1.insert(index, segment);
    }

    for (base, segments) in extended_groups {
        let mut segments = segments.into_iter().collect::<Vec<_>>();
        segments.sort_by_key(|(index, _)| *index);
        let encoded = segments
            .into_iter()
            .map(|(_, value)| value)
            .collect::<String>()
            .replace('+', " ");
        let bytes = legacy_percent_decode_bytes(&encoded);
        let value = if extended_charset.is_empty() {
            String::from_utf8_lossy(&bytes).into_owned()
        } else {
            let charset = legacy_normalize_rfc2047_charset(&extended_charset);
            legacy_decode_rfc2047_charset(&charset, &bytes)
        };
        legacy_set_parameter(
            &mut final_parameters,
            &mut final_parameter_indices,
            base,
            value,
        );
    }

    let charset = final_parameter_indices
        .get("charset")
        .map(|index| final_parameters[*index].1.clone());
    charset
        .filter(|charset| !charset.is_empty() && charset != "0")
        .map(|charset| legacy_normalize_body_charset(&charset, false))
        .filter(|charset| !charset.is_empty())
}

fn legacy_set_parameter(
    parameters: &mut Vec<(String, String)>,
    indices: &mut HashMap<String, usize>,
    name: String,
    value: String,
) {
    let key = name.to_ascii_lowercase();
    if let Some(index) = indices.get(&key) {
        parameters[*index] = (name, value);
    } else {
        let index = parameters.len();
        parameters.push((name, value));
        indices.insert(key, index);
    }
}

fn legacy_rfc2231_parameter_name(name: &str) -> Option<(&str, usize)> {
    let bytes = name.as_bytes();
    for (separator, _) in name.match_indices('*') {
        let base_start = bytes[..separator]
            .iter()
            .rposition(|byte| *byte == b'*')
            .map(|index| index + 1)
            .unwrap_or_default();
        if base_start == separator {
            continue;
        }
        let digit_count = bytes[separator + 1..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if (1..=2).contains(&digit_count) && bytes.get(separator + 1 + digit_count) == Some(&b'*') {
            let index = name[separator + 1..separator + 1 + digit_count]
                .parse::<usize>()
                .ok()?;
            return Some((&name[base_start..separator], index));
        }
    }

    for (separator, _) in name.match_indices('*') {
        let base_start = bytes[..separator]
            .iter()
            .rposition(|byte| *byte == b'*')
            .map(|index| index + 1)
            .unwrap_or_default();
        if base_start < separator {
            return Some((&name[base_start..separator], 0));
        }
    }
    None
}

pub fn legacy_message_subject(value: &str) -> String {
    let without_preview = value
        .strip_prefix("[Preview]")
        .map(|value| value.chars().skip(1).collect::<String>());
    legacy_header_subject(without_preview.as_deref().unwrap_or(value))
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
                crypto.pgp_encrypted = Some(LegacyPgpEncrypted {
                    part_id: legacy_body_child_part_id(parent_id, 1),
                    key_ids: None,
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
                    sig_part_id: Some(legacy_body_child_part_id(parent_id, 1)),
                    mic_alg: Some(legacy_body_root_mic_alg(part, parent_id)),
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

async fn clear_mailbox_in_session(session: &mut BoxedSession, exists: u32) -> Result<()> {
    if exists == 0 {
        return Ok(());
    }

    drain_sequence_store(
        session,
        "1:*",
        "+FLAGS.SILENT (\\Deleted)",
        "mark folder messages deleted",
    )
    .await?;

    let expunged = timeout_imap("expunge cleared folder messages", session.expunge()).await?;
    pin_mut!(expunged);
    while timeout_imap("read clear folder expunge response", expunged.try_next())
        .await?
        .is_some()
    {}

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
        supports_object_id: has_capability_ignore_ascii_case(&capabilities, "OBJECTID"),
        supports_preview: has_capability_ignore_ascii_case(&capabilities, "PREVIEW"),
        supports_literal_plus: has_capability_ignore_ascii_case(&capabilities, "LITERAL+"),
        uses_utf8_search: capabilities.iter().any(is_legacy_utf8_capability),
        supports_within: has_capability_ignore_ascii_case(&capabilities, "WITHIN"),
        supports_multisearch: has_capability_ignore_ascii_case(&capabilities, "MULTISEARCH"),
        supports_sort: has_capability_ignore_ascii_case(&capabilities, "SORT"),
        supports_sort_display: has_capability_ignore_ascii_case(&capabilities, "SORT=DISPLAY"),
        thread_algorithms: legacy_thread_algorithms(&capabilities),
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

pub fn legacy_decode_rfc2047_header_value(value: &str) -> String {
    let value = legacy_collapse_encoded_word_whitespace(value);
    let bytes = value.as_bytes();
    let mut words = Vec::new();
    let mut index = 0;

    while let Some(relative_start) = value[index..].find("=?") {
        let start = index + relative_start;
        let charset_start = start + 2;
        let Some(charset_end) = value[charset_start..]
            .find('?')
            .map(|offset| charset_start + offset)
        else {
            break;
        };
        if charset_end == charset_start {
            index = charset_start;
            continue;
        }
        let encoding_index = charset_end + 1;
        if encoding_index + 1 >= bytes.len()
            || bytes[encoding_index + 1] != b'?'
            || !matches!(bytes[encoding_index], b'q' | b'Q' | b'b' | b'B')
        {
            index = charset_end + 1;
            continue;
        }
        let data_start = encoding_index + 2;
        let Some(end) = value[data_start..]
            .find("?=")
            .map(|offset| data_start + offset + 2)
        else {
            break;
        };
        let data = &bytes[data_start..end - 2];
        let decoded = if matches!(bytes[encoding_index], b'q' | b'Q') {
            legacy_php_quoted_printable_decode(data)
        } else {
            legacy_php_base64_decode(data)
        };
        let charset = legacy_normalize_rfc2047_charset(&value[charset_start..charset_end]);
        words.push(LegacyEncodedWord {
            start,
            end,
            charset,
            decoded,
        });
        index = end;
    }

    if words.is_empty() {
        return value;
    }

    let one_charset = words.iter().all(|word| word.charset == words[0].charset);
    if one_charset {
        let mut output = Vec::with_capacity(value.len());
        let mut previous = 0;
        for word in &words {
            output.extend_from_slice(&bytes[previous..word.start]);
            output.extend_from_slice(&word.decoded);
            previous = word.end;
        }
        output.extend_from_slice(&bytes[previous..]);
        return legacy_decode_rfc2047_charset(&words[0].charset, &output);
    }

    let mut output = String::with_capacity(value.len());
    let mut previous = 0;
    for word in &words {
        output.push_str(&value[previous..word.start]);
        output.push_str(&legacy_decode_rfc2047_charset(&word.charset, &word.decoded));
        previous = word.end;
    }
    output.push_str(&value[previous..]);
    output
}

struct LegacyEncodedWord {
    start: usize,
    end: usize,
    charset: String,
    decoded: Vec<u8>,
}

fn legacy_collapse_encoded_word_whitespace(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index..].starts_with(b"?=") {
            output.extend_from_slice(b"?=");
            index += 2;
            let whitespace_start = index;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            let whitespace_len = index - whitespace_start;
            if (1..=5).contains(&whitespace_len) && bytes[index..].starts_with(b"=?") {
                continue;
            }
            output.extend_from_slice(&bytes[whitespace_start..index]);
            continue;
        }
        if matches!(bytes[index], b'\r' | b'\n' | b'\t') {
            output.push(b' ');
            while index < bytes.len() && matches!(bytes[index], b'\r' | b'\n' | b'\t') {
                index += 1;
            }
            continue;
        }
        output.push(bytes[index]);
        index += 1;
    }

    String::from_utf8(output)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

fn legacy_php_quoted_printable_decode(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len());
    let mut index = 0;

    while index < value.len() {
        match value[index] {
            b'_' => {
                output.push(b' ');
                index += 1;
            }
            b'=' if index + 2 < value.len()
                && value[index + 1] == b'\r'
                && value[index + 2] == b'\n' =>
            {
                index += 3;
            }
            b'=' if index + 2 < value.len() => {
                if let (Some(high), Some(low)) = (
                    legacy_hex_nibble(value[index + 1]),
                    legacy_hex_nibble(value[index + 2]),
                ) {
                    output.push((high << 4) | low);
                    index += 3;
                } else {
                    output.push(b'=');
                    index += 1;
                }
            }
            b'=' if index + 1 == value.len() => {
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }

    output
}

fn legacy_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn legacy_php_base64_decode(value: &[u8]) -> Vec<u8> {
    if let Some(decoded) = base64_decode(value) {
        return decoded;
    }

    let compact = value
        .iter()
        .copied()
        .filter(|byte| !matches!(byte, b' ' | b'\r' | b'\n' | b'\t'))
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'=' | b'+' | b'/'))
        .collect::<Vec<_>>();
    base64_decode(&compact).unwrap_or_default()
}

fn legacy_normalize_rfc2047_charset(value: &str) -> String {
    let mut value = value.to_ascii_lowercase();
    if let Some(suffix) = value.strip_prefix("iso8") {
        value = format!("iso-8{suffix}");
    }
    match value.as_str() {
        "asci" | "ascii" | "us-asci" | "us-ascii" | "utf8" | "utf-8" => "utf-8".to_string(),
        "unicode-1-1-utf-7" | "unicode-1-utf-7" | "unicode-utf-7" => "utf-7".to_string(),
        "ks-c-5601-1987" | "ks_c_5601-1987" | "ks_c_5601_1987" => "euc-kr".to_string(),
        "x-gbk" => "gb2312".to_string(),
        "iso-8859-i" | "iso-8859-8-i" => "iso-8859-8".to_string(),
        _ => {
            let windows_code_page = value
                .strip_prefix("cp")
                .or_else(|| value.strip_prefix("windows"))
                .map(|suffix| suffix.strip_prefix('-').unwrap_or(suffix))
                .filter(|suffix| {
                    suffix.starts_with("12")
                        && suffix.len() > 2
                        && suffix.bytes().all(|byte| byte.is_ascii_digit())
                });
            windows_code_page
                .map(|suffix| format!("windows-{suffix}"))
                .unwrap_or(value)
        }
    }
}

fn legacy_decode_rfc2047_charset(charset: &str, value: &[u8]) -> String {
    let effective_charset = if charset != "utf-8"
        && !charset.contains("iso-2022-jp")
        && std::str::from_utf8(value).is_ok()
    {
        "utf-8"
    } else {
        charset
    };
    charset_decoder(effective_charset.as_bytes())
        .map(|decoder| decoder(value))
        .unwrap_or_else(|| String::from_utf8_lossy(value).into_owned())
}

async fn fetch_body_part_specs(
    session: &mut BoxedSession,
    folder: &str,
    uid: u32,
    capabilities: &ImapFetchMetadataCapabilities,
) -> Result<Option<BodyPreviewFetchSpec>> {
    let mut fetches = timeout_imap(
        "fetch message body structure",
        session.uid_fetch(
            uid.to_string(),
            uid_fetch_bodystructure_query_with_gmail_id(
                uid,
                legacy_message_fetches_gmail_id(capabilities),
            )?,
        ),
    )
    .await?;

    let mut header = Vec::new();
    let mut flags = Vec::new();
    let mut internal_timestamp = None;
    let mut size = None;
    let mut email_id = None;
    let mut envelope = LegacyMessageEnvelope::default();
    let mut bodystructure: Option<BodyStructure<'static>> = None;
    let mut matched = false;

    while let Some(fetch) = timeout_imap("read body structure", fetches.try_next()).await? {
        if fetch.uid != Some(uid) {
            continue;
        }
        matched = true;
        if let Some(value) = fetch.header() {
            header = value.to_vec();
        }
        let fetched_flags =
            legacy_unique_flag_strings(fetch.flags().map(|flag| legacy_message_flag_string(&flag)));
        if !fetched_flags.is_empty() {
            flags = fetched_flags;
        }
        internal_timestamp = fetch
            .internal_date()
            .map(|value| value.timestamp())
            .or(internal_timestamp);
        size = fetch.size.or(size);
        email_id = fetch.gmail_msg_id().map(u64::to_string).or(email_id);
        if let Some(value) = fetch.envelope() {
            envelope = legacy_message_envelope_metadata(value);
        }
        if let Some(value) = fetch.bodystructure() {
            bodystructure = Some(value.clone().into_owned());
        }
    }

    if !matched {
        return Ok(None);
    }
    let size = size.unwrap_or_default();
    let crypto = bodystructure
        .as_ref()
        .map(legacy_message_crypto_metadata)
        .unwrap_or_default();
    let attachments = legacy_message_attachments(folder, uid, bodystructure.as_ref());
    let mut parts = bodystructure
        .as_ref()
        .map(|bodystructure| body_preview_part_specs(bodystructure, &header))
        .unwrap_or_default();
    if parts.is_empty() {
        parts.push(BodyPartSpec {
            path: None,
            depth: 0,
            kind: BodyPartKind::RawMessage,
            octets: if size == 0 {
                BODY_PREVIEW_PART_LIMIT_BYTES as u32
            } else {
                size
            },
            charset: String::new(),
            transfer_encoding: BodyPartTransferEncoding::Identity,
            decode_flowed: false,
        });
    }
    Ok(Some(BodyPreviewFetchSpec {
        parts,
        flags,
        crypto,
        metadata: LegacyMessageFetchMetadata {
            header,
            internal_timestamp,
            size,
            email_id,
            preview: None,
            attachments,
            envelope,
        },
    }))
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

    let mut fetched_sections: HashMap<Vec<u32>, Vec<u8>> = HashMap::new();
    let mut fetched_raw = None;
    while let Some(fetch) = timeout_imap("read body preview", fetches.try_next()).await? {
        if fetch.uid != Some(uid) {
            continue;
        }
        for spec in specs {
            match spec.path_vec() {
                Some(path) => {
                    if let Some(body) = fetch.section(&SectionPath::Part(path.clone(), None)) {
                        fetched_sections
                            .entry(path)
                            .or_insert_with(|| body.to_vec());
                    }
                }
                None => {
                    if let Some(body) = fetch.body() {
                        fetched_raw.get_or_insert_with(|| body.to_vec());
                    }
                }
            }
        }
    }

    let mut parts = Vec::new();
    let mut detected_crypto = crypto.clone();
    for spec in specs {
        match spec.path_vec() {
            Some(path) => {
                let Some(body) = fetched_sections.get(&path) else {
                    continue;
                };
                let text = decode_body_preview_text(spec, body);
                detect_armored_pgp_metadata(
                    &mut detected_crypto,
                    &section_path(&path),
                    text.as_bytes(),
                );
                parts.push(BodyPreviewPart {
                    kind: spec.kind,
                    raw: render_decoded_body_preview_part(spec, text),
                    is_complete: false,
                    flags: flags.to_vec(),
                    crypto: LegacyMessageCrypto::default(),
                    metadata: metadata.clone(),
                });
            }
            None => {
                if let Some(body) = &fetched_raw {
                    parts.push(BodyPreviewPart {
                        kind: BodyPartKind::RawMessage,
                        raw: body.clone(),
                        is_complete: raw_message_preview_is_complete(body, spec.octets),
                        flags: flags.to_vec(),
                        crypto: crypto.clone(),
                        metadata: metadata.clone(),
                    });
                }
            }
        }
    }

    for part in &mut parts {
        part.crypto = detected_crypto.clone();
    }
    if parts.is_empty() {
        parts.extend(metadata_only_body_preview_part(flags, crypto, metadata));
    }
    Ok(parts)
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

fn body_preview_part_specs(body: &BodyStructure<'_>, header: &[u8]) -> Vec<BodyPartSpec> {
    let shared_charset = body_preview_shared_charset(body, header);
    let mut specs = Vec::new();
    let mut remaining_bytes = BODY_PREVIEW_TOTAL_LIMIT_BYTES;
    collect_body_preview_text_part_specs(
        body,
        &mut Vec::new(),
        false,
        &shared_charset,
        &mut remaining_bytes,
        &mut specs,
    );

    if specs.is_empty() {
        collect_pgp_encrypted_preview_part_spec(
            body,
            &mut Vec::new(),
            &shared_charset,
            &mut remaining_bytes,
            &mut specs,
        );
    }
    if specs.is_empty() {
        collect_body_preview_text_part_specs(
            body,
            &mut Vec::new(),
            true,
            &shared_charset,
            &mut remaining_bytes,
            &mut specs,
        );
    }

    specs
}

fn collect_body_preview_text_part_specs(
    body: &BodyStructure<'_>,
    path: &mut Vec<u32>,
    include_attachments: bool,
    shared_charset: &str,
    remaining_bytes: &mut usize,
    specs: &mut Vec<BodyPartSpec>,
) -> bool {
    if specs.len() >= BODY_PREVIEW_TEXT_PART_LIMIT || *remaining_bytes == 0 {
        return true;
    }

    match body {
        BodyStructure::Text { common, other, .. }
            if include_attachments || !is_attachment(common) =>
        {
            let depth = path.len().max(1);
            let Some(path) = path_array(path) else {
                return false;
            };
            let kind = if common.ty.subtype.eq_ignore_ascii_case("html") {
                BodyPartKind::Html
            } else if common.ty.subtype.eq_ignore_ascii_case("plain")
                || common.ty.subtype.eq_ignore_ascii_case("x-amp-html")
            {
                BodyPartKind::Plain
            } else {
                return false;
            };
            let spec = BodyPartSpec {
                path: Some(path),
                depth,
                kind,
                octets: other.octets,
                charset: body_preview_part_charset(common, shared_charset),
                transfer_encoding: body_preview_transfer_encoding(&other.transfer_encoding),
                decode_flowed: kind != BodyPartKind::Html
                    && legacy_body_param_eq(common, "format", "flowed")
                    && !matches!(
                        other.transfer_encoding,
                        imap_proto::ContentEncoding::Base64
                            | imap_proto::ContentEncoding::QuotedPrintable
                    ),
            };
            return push_bounded_body_preview_spec(spec, remaining_bytes, specs);
        }
        BodyStructure::Multipart { bodies, .. } => {
            for (index, child) in bodies.iter().enumerate() {
                path.push((index + 1) as u32);
                let complete = collect_body_preview_text_part_specs(
                    child,
                    path,
                    include_attachments,
                    shared_charset,
                    remaining_bytes,
                    specs,
                );
                path.pop();
                if complete {
                    return true;
                }
            }
        }
        _ => {}
    }
    false
}

fn collect_pgp_encrypted_preview_part_spec(
    body: &BodyStructure<'_>,
    path: &mut Vec<u32>,
    shared_charset: &str,
    remaining_bytes: &mut usize,
    specs: &mut Vec<BodyPartSpec>,
) -> bool {
    let BodyStructure::Multipart { bodies, .. } = body else {
        return false;
    };

    if legacy_body_is_pgp_encrypted(body) {
        let Some(payload) = bodies.get(1) else {
            return false;
        };
        path.push(2);
        let depth = path.len();
        let path_value = path_array(path);
        path.pop();
        if let (Some(path), Some(single)) = (path_value, legacy_body_single_part(payload)) {
            let spec = BodyPartSpec {
                path: Some(path),
                depth,
                kind: BodyPartKind::Plain,
                octets: single.octets,
                charset: body_preview_part_charset(legacy_body_common(payload), shared_charset),
                transfer_encoding: body_preview_transfer_encoding(&single.transfer_encoding),
                decode_flowed: false,
            };
            push_bounded_body_preview_spec(spec, remaining_bytes, specs);
            return !specs.is_empty();
        }
    }

    for (index, child) in bodies.iter().enumerate() {
        path.push((index + 1) as u32);
        let found = collect_pgp_encrypted_preview_part_spec(
            child,
            path,
            shared_charset,
            remaining_bytes,
            specs,
        );
        path.pop();
        if found {
            return true;
        }
    }
    false
}

fn push_bounded_body_preview_spec(
    spec: BodyPartSpec,
    remaining_bytes: &mut usize,
    specs: &mut Vec<BodyPartSpec>,
) -> bool {
    let requested = preview_fetch_bytes(spec.octets);
    if specs.len() >= BODY_PREVIEW_TEXT_PART_LIMIT || requested > *remaining_bytes {
        return true;
    }
    *remaining_bytes -= requested;
    specs.push(spec);
    specs.len() >= BODY_PREVIEW_TEXT_PART_LIMIT || *remaining_bytes == 0
}

fn body_preview_part_charset(
    common: &imap_proto::BodyContentCommon<'_>,
    shared_charset: &str,
) -> String {
    common
        .ty
        .params
        .as_deref()
        .and_then(|params| legacy_body_param_exact(params, "charset"))
        .map(|charset| legacy_normalize_body_charset(charset, true))
        .filter(|charset| !charset.is_empty())
        .unwrap_or_else(|| shared_charset.to_string())
}

fn body_preview_shared_charset(body: &BodyStructure<'_>, header: &[u8]) -> String {
    if let Some(charset) = body_preview_header_charset(header) {
        return charset;
    }

    body_preview_find_charset(body, false, false)
        .or_else(|| body_preview_find_charset(body, true, false))
        .unwrap_or_else(|| "utf-8".to_string())
}

fn body_preview_header_charset(header: &[u8]) -> Option<String> {
    let message = mail_parser::MessageParser::default().parse(header)?;
    message
        .content_type()?
        .attribute("charset")
        .map(|charset| legacy_normalize_body_charset(charset, false))
        .filter(|charset| !charset.is_empty())
}

fn body_preview_find_charset(
    body: &BodyStructure<'_>,
    attachments: bool,
    parent_pgp_encrypted: bool,
) -> Option<String> {
    let common = legacy_body_common(body);
    let charset = common
        .ty
        .params
        .as_deref()
        .and_then(|params| legacy_body_param_exact(params, "charset"))
        .map(|charset| legacy_normalize_body_charset(charset, false))
        .filter(|charset| !charset.is_empty());
    let is_attachment = !parent_pgp_encrypted && legacy_body_part_is_attachment(body);
    let is_eligible_text = matches!(body, BodyStructure::Text { .. })
        && (common.ty.subtype.eq_ignore_ascii_case("plain")
            || common.ty.subtype.eq_ignore_ascii_case("html")
            || common.ty.subtype.eq_ignore_ascii_case("x-amp-html"));
    if charset.is_some()
        && ((attachments && is_attachment) || (!attachments && is_eligible_text && !is_attachment))
    {
        return charset;
    }

    if let BodyStructure::Multipart { bodies, .. } = body {
        let current_pgp_encrypted = legacy_body_is_pgp_encrypted(body);
        for child in bodies {
            if let Some(charset) =
                body_preview_find_charset(child, attachments, current_pgp_encrypted)
            {
                return Some(charset);
            }
        }
    }
    None
}

fn body_preview_transfer_encoding(
    encoding: &imap_proto::ContentEncoding<'_>,
) -> BodyPartTransferEncoding {
    match encoding {
        imap_proto::ContentEncoding::Base64 => BodyPartTransferEncoding::Base64,
        imap_proto::ContentEncoding::QuotedPrintable => BodyPartTransferEncoding::QuotedPrintable,
        _ => BodyPartTransferEncoding::Identity,
    }
}

fn legacy_normalize_body_charset(value: &str, ascii_as_utf8: bool) -> String {
    let value = value.to_ascii_lowercase();
    if matches!(value.as_str(), "asci" | "ascii" | "us-asci" | "us-ascii") {
        return if ascii_as_utf8 {
            "utf-8".to_string()
        } else {
            "iso-8859-1".to_string()
        };
    }
    legacy_normalize_rfc2047_charset(&value)
}

fn body_preview_fetch_query(specs: &[BodyPartSpec]) -> String {
    let attrs = specs
        .iter()
        .map(|spec| match spec.path_vec() {
            Some(path) => {
                let path = section_path(&path);
                format!("BODY.PEEK[{path}]<0.{}>", preview_fetch_bytes(spec.octets))
            }
            None => format!("BODY.PEEK[]<0.{}>", preview_fetch_bytes(spec.octets)),
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
    if path.len() > 8 {
        return None;
    }
    let mut out = [0; 8];
    if path.is_empty() {
        out[0] = 1;
    } else {
        out[..path.len()].copy_from_slice(path);
    }
    Some(out)
}

fn is_attachment(common: &imap_proto::BodyContentCommon<'_>) -> bool {
    common
        .disposition
        .as_ref()
        .is_some_and(|disposition| disposition.ty.eq_ignore_ascii_case("attachment"))
}

#[cfg(test)]
fn decode_body_preview_part(spec: &BodyPartSpec, body: &[u8]) -> Vec<u8> {
    render_decoded_body_preview_part(spec, decode_body_preview_text(spec, body))
}

fn decode_body_preview_text(spec: &BodyPartSpec, body: &[u8]) -> String {
    let decoded = match spec.transfer_encoding {
        BodyPartTransferEncoding::Identity => body.to_vec(),
        BodyPartTransferEncoding::Base64 => legacy_php_base64_decode(body),
        BodyPartTransferEncoding::QuotedPrintable => legacy_php_body_quoted_printable_decode(body),
    };
    if spec.charset.eq_ignore_ascii_case("utf-8") {
        decode_utf8_without_invalid_bytes(&decoded)
    } else {
        charset_decoder(spec.charset.as_bytes())
            .map(|decoder| decoder(&decoded))
            .unwrap_or_else(|| decode_utf8_without_invalid_bytes(&decoded))
    }
}

fn render_decoded_body_preview_part(spec: &BodyPartSpec, mut text: String) -> Vec<u8> {
    if spec.decode_flowed {
        text = decode_legacy_flowed_text(&text);
    }

    let mime_type = match spec.kind {
        BodyPartKind::Html => "text/html",
        BodyPartKind::Plain | BodyPartKind::RawMessage => "text/plain",
    };
    let mut raw = Vec::with_capacity(text.len() + 48);
    raw.extend_from_slice(format!("Content-Type: {mime_type}; charset=utf-8\r\n\r\n").as_bytes());
    raw.extend_from_slice(text.as_bytes());
    raw
}

fn detect_armored_pgp_metadata(
    crypto: &mut LegacyMessageCrypto,
    part_id: &str,
    decoded_part: &[u8],
) {
    if crypto.pgp_signed.is_none()
        && find_bytes(decoded_part, b"-----BEGIN PGP SIGNED MESSAGE-----").is_some()
    {
        crypto.pgp_signed = Some(LegacyPgpSigned {
            part_id: part_id.to_string(),
            sig_part_id: None,
            mic_alg: None,
        });
    }

    if find_bytes(decoded_part, b"-----BEGIN PGP MESSAGE-----").is_some() {
        crypto.pgp_encrypted = Some(LegacyPgpEncrypted {
            part_id: part_id.to_string(),
            key_ids: Some(armored_pgp_recipient_key_ids(decoded_part)),
        });
    }
}

fn armored_pgp_recipient_key_ids(value: &[u8]) -> Vec<String> {
    const BEGIN: &[u8] = b"-----BEGIN PGP MESSAGE-----";
    const END: &[u8] = b"-----END PGP MESSAGE-----";
    const MAX_RECIPIENTS: usize = 256;

    let mut key_ids = Vec::new();
    let mut search_start = 0;
    while search_start < value.len() && key_ids.len() < MAX_RECIPIENTS {
        let Some((_, relative_block_start)) =
            find_openpgp_armor_delimiter_line(&value[search_start..], BEGIN, false)
        else {
            break;
        };
        let block_start = search_start + relative_block_start;
        let (block, next_search) =
            match find_openpgp_armor_delimiter_line(&value[block_start..], END, true) {
                Some((relative_end, relative_after_end)) => (
                    &value[block_start..block_start + relative_end],
                    block_start + relative_after_end,
                ),
                None => (&value[block_start..], value.len()),
            };
        let Some(packets) = decode_openpgp_armor_block(block) else {
            break;
        };
        collect_openpgp_recipient_key_ids(&packets, &mut key_ids, MAX_RECIPIENTS);
        search_start = next_search;
    }
    key_ids
}

fn find_openpgp_armor_delimiter_line(
    value: &[u8],
    delimiter: &[u8],
    allow_leading_whitespace: bool,
) -> Option<(usize, usize)> {
    let mut line_start = 0;
    while line_start < value.len() {
        let relative_end = value[line_start..].iter().position(|byte| *byte == b'\n');
        let line_end = relative_end
            .map(|offset| line_start + offset)
            .unwrap_or(value.len());
        let raw_line = value[line_start..line_end]
            .strip_suffix(b"\r")
            .unwrap_or(&value[line_start..line_end]);
        let line = if allow_leading_whitespace {
            trim_ascii_horizontal_whitespace(raw_line)
        } else {
            trim_ascii_horizontal_whitespace_end(raw_line)
        };
        if line == delimiter {
            let after_line = relative_end.map_or(line_end, |_| line_end + 1);
            return Some((line_start, after_line));
        }
        if relative_end.is_none() {
            break;
        }
        line_start = line_end + 1;
    }
    None
}

fn decode_openpgp_armor_block(block: &[u8]) -> Option<Vec<u8>> {
    let mut armor_body = Vec::new();
    let mut checksum = None;
    let mut in_headers = true;
    for raw_line in block.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let line = trim_ascii_horizontal_whitespace(line);
        if in_headers {
            if line.is_empty() {
                in_headers = false;
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if checksum.is_some() {
            continue;
        }
        if let Some(encoded_checksum) = line.strip_prefix(b"=") {
            if encoded_checksum.len() != 4 {
                return None;
            }
            let decoded = base64_decode(encoded_checksum)?;
            if decoded.len() != 3 {
                return None;
            }
            checksum = Some(decoded);
            continue;
        }
        if !line
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return None;
        }
        armor_body.extend_from_slice(line);
    }

    let packets = base64_decode(&armor_body)?;
    if packets.is_empty() {
        return None;
    }
    if let Some(checksum) = checksum {
        if openpgp_crc24(&packets).to_be_bytes()[1..] != checksum {
            return None;
        }
    }
    Some(packets)
}

fn trim_ascii_horizontal_whitespace(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn trim_ascii_horizontal_whitespace_end(mut value: &[u8]) -> &[u8] {
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn openpgp_crc24(value: &[u8]) -> u32 {
    let mut crc = 0x00B7_04CE_u32;
    for byte in value {
        crc ^= u32::from(*byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    crc & 0x00FF_FFFF
}

fn collect_openpgp_recipient_key_ids(packets: &[u8], key_ids: &mut Vec<String>, limit: usize) {
    let mut cursor = 0;
    while cursor < packets.len() && key_ids.len() < limit {
        let Some((tag, body, next)) = openpgp_packet_at(packets, cursor) else {
            break;
        };
        if tag == 1 && gpg_reports_pkesk_recipient(body) {
            key_ids.push(
                body[1..9]
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect(),
            );
        }
        cursor = next;
    }
}

fn gpg_reports_pkesk_recipient(body: &[u8]) -> bool {
    if body.len() <= 10 || !matches!(body[0], 2 | 3) {
        return false;
    }

    let algorithm = body[9];
    let mut cursor = 10;
    let valid = match algorithm {
        1..=3 => read_openpgp_mpi(body, &mut cursor, true),
        16 | 20 => {
            read_openpgp_mpi(body, &mut cursor, true) && read_openpgp_mpi(body, &mut cursor, true)
        }
        18 => {
            if !read_openpgp_mpi(body, &mut cursor, false) {
                return false;
            }
            let Some(wrapped_len) = body.get(cursor).copied().map(usize::from) else {
                return false;
            };
            cursor = cursor.saturating_add(1);
            let Some(end) = cursor.checked_add(wrapped_len) else {
                return false;
            };
            wrapped_len >= 2 && end <= body.len()
        }
        // GnuPG emits ENC_TO for unknown algorithms once the fixed fields are
        // followed by at least two packet octets, without interpreting them.
        // The PHP implementation copies that status verbatim.
        _ => body.len() >= 12,
    };
    valid
}

fn read_openpgp_mpi(value: &[u8], cursor: &mut usize, allow_zero: bool) -> bool {
    let Some(length_bytes) = value.get(*cursor..cursor.saturating_add(2)) else {
        return false;
    };
    let bits = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    if bits == 0 && !allow_zero {
        return false;
    }
    let octets = bits.div_ceil(8);
    let Some(start) = cursor.checked_add(2) else {
        return false;
    };
    let Some(end) = start.checked_add(octets) else {
        return false;
    };
    if value.get(start..end).is_none() {
        return false;
    }
    *cursor = end;
    true
}

fn openpgp_packet_at(value: &[u8], cursor: usize) -> Option<(u8, &[u8], usize)> {
    let packet = *value.get(cursor)?;
    if packet & 0x80 == 0 {
        return None;
    }

    let (tag, body_start, body_len) = if packet & 0x40 != 0 {
        let tag = packet & 0x3f;
        let length = *value.get(cursor + 1)?;
        match length {
            0..=191 => (tag, cursor + 2, usize::from(length)),
            192..=223 => {
                let second = usize::from(*value.get(cursor + 2)?);
                let length = ((usize::from(length) - 192) << 8) + second + 192;
                (tag, cursor + 3, length)
            }
            255 => {
                let bytes: [u8; 4] = value.get(cursor + 2..cursor + 6)?.try_into().ok()?;
                (tag, cursor + 6, u32::from_be_bytes(bytes) as usize)
            }
            _ => return None,
        }
    } else {
        let tag = (packet >> 2) & 0x0f;
        match packet & 0x03 {
            0 => (tag, cursor + 2, usize::from(*value.get(cursor + 1)?)),
            1 => {
                let bytes: [u8; 2] = value.get(cursor + 1..cursor + 3)?.try_into().ok()?;
                (tag, cursor + 3, usize::from(u16::from_be_bytes(bytes)))
            }
            2 => {
                let bytes: [u8; 4] = value.get(cursor + 1..cursor + 5)?.try_into().ok()?;
                (tag, cursor + 5, u32::from_be_bytes(bytes) as usize)
            }
            _ => return None,
        }
    };
    let body_end = body_start.checked_add(body_len)?;
    Some((tag, value.get(body_start..body_end)?, body_end))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

fn decode_legacy_flowed_text(value: &str) -> String {
    value.replace(" \r\n", " ").replace(" \n", " ")
}

fn decode_utf8_without_invalid_bytes(mut value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len());
    while !value.is_empty() {
        match std::str::from_utf8(value) {
            Ok(valid) => {
                output.push_str(valid);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                output.push_str(
                    std::str::from_utf8(&value[..valid])
                        .expect("from_utf8 valid_up_to prefix must be valid UTF-8"),
                );
                let skip = error.error_len().unwrap_or(value.len() - valid);
                value = &value[valid + skip..];
            }
        }
    }
    output
}

fn legacy_php_body_quoted_printable_decode(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'=' {
            output.push(value[index]);
            index += 1;
            continue;
        }
        if index + 1 == value.len() {
            break;
        }
        if index + 2 < value.len() {
            if let (Some(high), Some(low)) = (
                legacy_hex_nibble(value[index + 1]),
                legacy_hex_nibble(value[index + 2]),
            ) {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }

        let mut newline = index + 1;
        while newline < value.len() && matches!(value[newline], b' ' | b'\t') {
            newline += 1;
        }
        if newline < value.len() && value[newline] == b'\r' {
            index = newline + 1;
            if index < value.len() && value[index] == b'\n' {
                index += 1;
            }
            continue;
        }
        if newline < value.len() && value[newline] == b'\n' {
            index = newline + 1;
            continue;
        }

        output.push(b'=');
        index += 1;
    }
    output
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

async fn mailbox_hierarchy_delimiter(session: &mut BoxedSession, parent: &str) -> Result<String> {
    let pattern = quote_mailbox_pattern(parent)?;
    let folders = timeout_imap(
        "list mailbox hierarchy delimiter",
        session.list(Some(""), Some(&pattern)),
    )
    .await?;
    pin_mut!(folders);

    if let Some(folder) =
        timeout_imap("read mailbox hierarchy delimiter", folders.try_next()).await?
    {
        return folder.delimiter().map(str::to_string).ok_or_else(|| {
            if parent.is_empty() {
                FrickmailError::Upstream("Cannot get folder delimiter.".to_string())
            } else {
                FrickmailError::Upstream(
                    "Cannot create folder in non-existent parent folder.".to_string(),
                )
            }
        });
    }

    Err(if parent.is_empty() {
        FrickmailError::Upstream("Cannot get folder delimiter.".to_string())
    } else {
        FrickmailError::Upstream("Cannot create folder in non-existent parent folder.".to_string())
    })
}

async fn subscribed_mailbox_subtree(
    session: &mut BoxedSession,
    old_name: &str,
    delimiter: &str,
) -> Result<Vec<String>> {
    let folders = timeout_imap(
        "list renamed mailbox subscriptions",
        session.lsub(Some(old_name), Some("*")),
    )
    .await?;
    pin_mut!(folders);

    let mut subscribed = Vec::new();
    while let Some(folder) =
        timeout_imap("read renamed mailbox subscriptions", folders.try_next()).await?
    {
        if mailbox_is_in_subtree(folder.name(), old_name, delimiter) {
            subscribed.push(folder.name().to_string());
        }
    }
    Ok(subscribed)
}

fn mailbox_is_in_subtree(mailbox: &str, root: &str, delimiter: &str) -> bool {
    mailbox == root
        || (!delimiter.is_empty()
            && mailbox
                .strip_prefix(root)
                .is_some_and(|suffix| suffix.starts_with(delimiter)))
}

fn renamed_mailbox_name(mailbox: &str, old_name: &str, new_name: &str, delimiter: &str) -> String {
    if mailbox == old_name {
        return new_name.to_string();
    }
    if mailbox_is_in_subtree(mailbox, old_name, delimiter) {
        return format!(
            "{new_name}{}",
            mailbox.strip_prefix(old_name).unwrap_or_default()
        );
    }
    mailbox.to_string()
}

impl LegacyNamespaces {
    fn apply_wire_encoding(&mut self, utf8_mode: bool) {
        for namespace in self
            .personal
            .iter_mut()
            .chain(self.users.iter_mut())
            .chain(self.shared.iter_mut())
        {
            namespace.prefix = imap_mailbox_to_utf8(&namespace.wire_prefix, utf8_mode);
        }
    }

    fn personal_prefix(&self) -> String {
        let Some(namespace) = self.personal.first() else {
            return String::new();
        };
        let mut prefix = namespace.prefix.clone();
        let Some(delimiter) = namespace.delimiter.as_deref() else {
            return prefix;
        };
        let inbox_prefix = format!("INBOX{delimiter}");
        if prefix
            .get(..inbox_prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(&inbox_prefix))
        {
            prefix.replace_range(..inbox_prefix.len(), &inbox_prefix);
        }
        prefix
    }
}

async fn fetch_legacy_namespaces(
    config: ImapConnectionConfig,
    password: &str,
) -> Result<Option<LegacyNamespaces>> {
    let mut session = login(config, password).await?;
    let capabilities =
        timeout_imap("read IMAP namespace capability", session.capabilities()).await?;
    let utf8_mode = enable_legacy_utf8(&mut session, &capabilities).await?;
    if !has_capability_ignore_ascii_case(&capabilities, "NAMESPACE") {
        logout_quietly(session).await;
        return Ok(None);
    }

    let request_id =
        timeout_imap("request IMAP namespaces", session.run_command("NAMESPACE")).await?;
    let result = timeout(
        COMMAND_TIMEOUT,
        read_namespace_response(session.as_mut(), &request_id),
    )
    .await
    .map_err(|_| FrickmailError::Upstream("read IMAP namespaces timed out".to_string()))?;
    drop(session);
    result.map(|mut namespaces| {
        namespaces.apply_wire_encoding(utf8_mode);
        Some(namespaces)
    })
}

async fn read_namespace_response(
    stream: &mut BoxedImapIo,
    request_id: &RequestId,
) -> Result<LegacyNamespaces> {
    const MAX_NAMESPACE_RESPONSE_BYTES: usize = 256 * 1024;

    let tag = std::str::from_utf8(request_id.as_bytes())
        .map_err(|_| FrickmailError::Upstream("invalid IMAP namespace tag".to_string()))?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];

    loop {
        let count = stream.read(&mut chunk).await.map_err(|error| {
            FrickmailError::Upstream(format!("read IMAP namespaces failed: {error}"))
        })?;
        if count == 0 {
            return Err(FrickmailError::Upstream(
                "read IMAP namespaces failed: IMAP connection closed".to_string(),
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > MAX_NAMESPACE_RESPONSE_BYTES {
            return Err(FrickmailError::Upstream(
                "read IMAP namespaces failed: response too large".to_string(),
            ));
        }

        let mut parsed = None;
        let mut cursor = 0;
        while cursor < bytes.len() {
            let remaining = &bytes[cursor..];
            if let Some(payload) = strip_imap_prefix(remaining, b"* NAMESPACE ") {
                let Ok((namespaces, consumed)) =
                    parse_namespace_response_payload_with_consumed(payload)
                else {
                    break;
                };
                let suffix = &payload[consumed..];
                let whitespace = suffix
                    .iter()
                    .take_while(|byte| matches!(byte, b' ' | b'\t'))
                    .count();
                let suffix = &suffix[whitespace..];
                if suffix.len() < 2 {
                    break;
                }
                if !suffix.starts_with(b"\r\n") {
                    return Err(FrickmailError::Upstream(
                        "read IMAP namespaces failed: invalid trailing NAMESPACE data".to_string(),
                    ));
                }
                parsed = Some(namespaces);
                cursor += "* NAMESPACE ".len() + consumed + whitespace + 2;
                continue;
            }

            let Ok((remaining, response)) = Response::from_bytes(remaining) else {
                break;
            };
            cursor = bytes.len().saturating_sub(remaining.len());
            match response {
                Response::Done {
                    tag: response_tag,
                    status: Status::Ok,
                    ..
                } if response_tag.0 == tag => {
                    return parsed.ok_or_else(|| {
                        FrickmailError::Upstream(
                            "read IMAP namespaces failed: response missing NAMESPACE data"
                                .to_string(),
                        )
                    });
                }
                Response::Done {
                    tag: response_tag,
                    status,
                    information,
                    ..
                } if response_tag.0 == tag => {
                    return Err(imap_acl_status_error(
                        "read IMAP namespaces",
                        &status,
                        information.as_deref(),
                    ));
                }
                Response::Data {
                    status: Status::Bye,
                    information,
                    ..
                } => {
                    return Err(imap_acl_status_error(
                        "read IMAP namespaces",
                        &Status::Bye,
                        information.as_deref(),
                    ));
                }
                _ => {}
            }
        }
    }
}

fn strip_imap_prefix<'a>(frame: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    frame
        .get(..prefix.len())
        .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
        .then(|| &frame[prefix.len()..])
}

#[cfg(test)]
fn parse_namespace_response_line(line: &str) -> Result<LegacyNamespaces> {
    let payload = line
        .get("* NAMESPACE ".len()..)
        .ok_or_else(|| FrickmailError::Upstream("invalid IMAP NAMESPACE response".to_string()))?;
    parse_namespace_response_payload(payload.as_bytes(), true)
}

#[cfg(test)]
fn parse_namespace_response_payload(
    payload: &[u8],
    require_finished: bool,
) -> Result<LegacyNamespaces> {
    let (namespaces, consumed) = parse_namespace_response_payload_with_consumed(payload)?;
    let mut parser = NamespaceParser {
        input: payload,
        cursor: consumed,
    };
    parser.skip_spaces();
    if require_finished && !parser.is_finished() {
        return Err(FrickmailError::Upstream(
            "invalid trailing IMAP NAMESPACE data".to_string(),
        ));
    }
    Ok(namespaces)
}

fn parse_namespace_response_payload_with_consumed(
    payload: &[u8],
) -> Result<(LegacyNamespaces, usize)> {
    let mut parser = NamespaceParser::new(payload);
    let personal = namespace_entries(parser.parse_value()?)?;
    let users = namespace_entries(parser.parse_value()?)?;
    let shared = namespace_entries(parser.parse_value()?)?;
    Ok((
        LegacyNamespaces {
            personal,
            users,
            shared,
        },
        parser.cursor,
    ))
}

fn namespace_entries(value: LegacyNamespaceValue) -> Result<Vec<LegacyNamespaceEntry>> {
    let LegacyNamespaceValue::List(entries) = value else {
        return match value {
            LegacyNamespaceValue::Null => Ok(Vec::new()),
            _ => Err(FrickmailError::Upstream(
                "invalid IMAP NAMESPACE group".to_string(),
            )),
        };
    };

    entries
        .into_iter()
        .map(|entry| {
            let LegacyNamespaceValue::List(mut values) = entry else {
                return Err(FrickmailError::Upstream(
                    "invalid IMAP NAMESPACE entry".to_string(),
                ));
            };
            if values.len() < 2 {
                return Err(FrickmailError::Upstream(
                    "invalid IMAP NAMESPACE entry".to_string(),
                ));
            }
            let wire_prefix = match values.remove(0) {
                LegacyNamespaceValue::String(value) => value,
                _ => {
                    return Err(FrickmailError::Upstream(
                        "invalid IMAP NAMESPACE prefix".to_string(),
                    ))
                }
            };
            let delimiter = match values.remove(0) {
                LegacyNamespaceValue::String(value) => Some(value),
                LegacyNamespaceValue::Null => None,
                _ => {
                    return Err(FrickmailError::Upstream(
                        "invalid IMAP NAMESPACE delimiter".to_string(),
                    ))
                }
            };
            Ok(LegacyNamespaceEntry {
                prefix: wire_prefix.clone(),
                wire_prefix,
                delimiter,
                extension: values,
            })
        })
        .collect()
}

struct NamespaceParser<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> NamespaceParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn parse_value(&mut self) -> Result<LegacyNamespaceValue> {
        self.skip_spaces();
        match self.input.get(self.cursor).copied() {
            Some(b'(') => self.parse_list(),
            Some(b'"') => self.parse_quoted().map(LegacyNamespaceValue::String),
            Some(b'{') => self.parse_literal().map(LegacyNamespaceValue::String),
            Some(_) => {
                let atom = self.parse_atom()?;
                if atom.eq_ignore_ascii_case("NIL") {
                    Ok(LegacyNamespaceValue::Null)
                } else {
                    Ok(LegacyNamespaceValue::String(atom))
                }
            }
            None => Err(FrickmailError::Upstream(
                "truncated IMAP NAMESPACE response".to_string(),
            )),
        }
    }

    fn parse_list(&mut self) -> Result<LegacyNamespaceValue> {
        self.cursor += 1;
        let mut values = Vec::new();
        loop {
            self.skip_spaces();
            match self.input.get(self.cursor).copied() {
                Some(b')') => {
                    self.cursor += 1;
                    return Ok(LegacyNamespaceValue::List(values));
                }
                Some(_) => values.push(self.parse_value()?),
                None => {
                    return Err(FrickmailError::Upstream(
                        "unterminated IMAP NAMESPACE list".to_string(),
                    ))
                }
            }
        }
    }

    fn parse_quoted(&mut self) -> Result<String> {
        self.cursor += 1;
        let mut value = Vec::new();
        loop {
            match self.input.get(self.cursor).copied() {
                Some(b'"') => {
                    self.cursor += 1;
                    return String::from_utf8(value).map_err(|_| {
                        FrickmailError::Upstream(
                            "invalid UTF-8 in IMAP NAMESPACE string".to_string(),
                        )
                    });
                }
                Some(b'\\') => {
                    self.cursor += 1;
                    let escaped = self.input.get(self.cursor).copied().ok_or_else(|| {
                        FrickmailError::Upstream("truncated IMAP NAMESPACE escape".to_string())
                    })?;
                    value.push(escaped);
                    self.cursor += 1;
                }
                Some(byte) => {
                    value.push(byte);
                    self.cursor += 1;
                }
                None => {
                    return Err(FrickmailError::Upstream(
                        "unterminated IMAP NAMESPACE string".to_string(),
                    ))
                }
            }
        }
    }

    fn parse_atom(&mut self) -> Result<String> {
        let start = self.cursor;
        while self
            .input
            .get(self.cursor)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && !matches!(byte, b'(' | b')'))
        {
            self.cursor += 1;
        }
        if start == self.cursor {
            return Err(FrickmailError::Upstream(
                "invalid IMAP NAMESPACE atom".to_string(),
            ));
        }
        std::str::from_utf8(&self.input[start..self.cursor])
            .map(str::to_string)
            .map_err(|_| {
                FrickmailError::Upstream("invalid UTF-8 in IMAP NAMESPACE atom".to_string())
            })
    }

    fn parse_literal(&mut self) -> Result<String> {
        self.cursor += 1;
        let length_start = self.cursor;
        while self
            .input
            .get(self.cursor)
            .is_some_and(|byte| byte.is_ascii_digit())
        {
            self.cursor += 1;
        }
        let length_end = self.cursor;
        if self.input.get(self.cursor) == Some(&b'+') {
            self.cursor += 1;
        }
        if self.input.get(self.cursor..self.cursor + 3) != Some(b"}\r\n") {
            return Err(FrickmailError::Upstream(
                "invalid IMAP NAMESPACE literal".to_string(),
            ));
        }
        let length = std::str::from_utf8(&self.input[length_start..length_end])
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                FrickmailError::Upstream("invalid IMAP NAMESPACE literal length".to_string())
            })?;
        self.cursor += 3;
        let end = self.cursor.checked_add(length).ok_or_else(|| {
            FrickmailError::Upstream("IMAP NAMESPACE literal length overflow".to_string())
        })?;
        let value = self.input.get(self.cursor..end).ok_or_else(|| {
            FrickmailError::Upstream("truncated IMAP NAMESPACE literal".to_string())
        })?;
        self.cursor = end;
        String::from_utf8(value.to_vec()).map_err(|_| {
            FrickmailError::Upstream("invalid UTF-8 in IMAP NAMESPACE literal".to_string())
        })
    }

    fn skip_spaces(&mut self) {
        while self
            .input
            .get(self.cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            self.cursor += 1;
        }
    }

    #[cfg(test)]
    fn is_finished(&self) -> bool {
        self.cursor == self.input.len()
    }
}

#[derive(Debug)]
struct LegacyFolderListOptions {
    discover_subscriptions: bool,
    list_extended: bool,
    list_status: bool,
    special_use: bool,
    highest_modseq: bool,
    append_limit: bool,
    size: bool,
    mailbox_id: bool,
    utf8_mode: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct LegacyFolderStatusOptions {
    highest_modseq: bool,
    append_limit: bool,
    size: bool,
    mailbox_id: bool,
}

impl LegacyFolderStatusOptions {
    fn from_capabilities(capabilities: &Capabilities) -> Self {
        Self {
            highest_modseq: has_capability_ignore_ascii_case(capabilities, "CONDSTORE")
                || has_capability_ignore_ascii_case(capabilities, "QRESYNC"),
            append_limit: has_capability_ignore_ascii_case(capabilities, "APPENDLIMIT"),
            size: has_capability_ignore_ascii_case(capabilities, "STATUS=SIZE"),
            mailbox_id: has_capability_ignore_ascii_case(capabilities, "OBJECTID"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ListedLegacyFolderStatus {
    total_emails: Option<u32>,
    uid_next: Option<u32>,
    uid_validity: Option<u32>,
    unread_emails: Option<u32>,
    highest_modseq: Option<u64>,
    append_limit: Option<u64>,
    size: Option<u64>,
    mailbox_id: Option<String>,
}

async fn legacy_extended_folder_status(
    session: &mut BoxedSession,
    mailbox: &str,
    options: &LegacyFolderStatusOptions,
) -> Result<ListedLegacyFolderStatus> {
    let operation = "read extended mailbox status";
    let command = legacy_folder_status_command(mailbox, options)?;
    timeout_result(
        operation,
        timeout(COMMAND_TIMEOUT, async {
            let request_id = session
                .run_command(&command)
                .await
                .map_err(|error| imap_error(operation, error))?;
            let mut collected = ListedLegacyFolderStatus::default();
            loop {
                let response = session
                    .read_response()
                    .await
                    .map_err(|error| {
                        FrickmailError::Upstream(format!("{operation} failed: {error}"))
                    })?
                    .ok_or_else(|| {
                        FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP connection closed"
                        ))
                    })?;
                if let Response::MailboxData(MailboxDatum::Status {
                    mailbox: response_mailbox,
                    status,
                }) = response.parsed()
                {
                    if response_mailbox == mailbox {
                        collect_legacy_status_attributes(status, &mut collected);
                    }
                }
                if imap_command_completion(response.parsed(), &request_id, operation)?.is_some() {
                    return Ok(collected);
                }
            }
        }),
    )
    .await?
}

fn legacy_folder_status_command(
    mailbox: &str,
    options: &LegacyFolderStatusOptions,
) -> Result<String> {
    let mailbox = quote_imap_string("mailbox", mailbox)?;
    let mut items = vec!["MESSAGES", "UNSEEN", "UIDNEXT", "UIDVALIDITY"];
    if options.highest_modseq {
        items.push("HIGHESTMODSEQ");
    }
    if options.append_limit {
        items.push("APPENDLIMIT");
    }
    if options.size {
        items.push("SIZE");
    }
    if options.mailbox_id {
        items.push("MAILBOXID");
    }
    Ok(format!("STATUS {mailbox} ({})", items.join(" ")))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListedLegacyFolder {
    wire_name: String,
    full_name: String,
    delimiter: String,
    attributes: Vec<String>,
    status: Option<ListedLegacyFolderStatus>,
}

impl ListedLegacyFolder {
    fn selectable(&self) -> bool {
        !self
            .attributes
            .iter()
            .any(|value| matches!(value.as_str(), "\\noselect" | "\\nonexistent"))
    }

    fn into_legacy_folder(
        self,
        metadata: HashMap<String, String>,
        client_hash: &str,
    ) -> LegacyFolder {
        let role = legacy_folder_role_with_metadata(&self.full_name, &self.attributes, &metadata);
        let etag = self.status.as_ref().and_then(|status| {
            status.total_emails.map(|total| {
                legacy_folder_etag(
                    &self.full_name,
                    total,
                    status.uid_next,
                    status.uid_validity,
                    status.unread_emails,
                    status.highest_modseq,
                    client_hash,
                )
            })
        });
        LegacyFolder {
            name: legacy_folder_name(&self.full_name, &self.delimiter),
            full_name: self.full_name,
            delimiter: self.delimiter,
            attributes: self.attributes,
            metadata,
            uid_next: self.status.as_ref().and_then(|status| status.uid_next),
            total_emails: self.status.as_ref().and_then(|status| status.total_emails),
            unread_emails: self.status.as_ref().and_then(|status| status.unread_emails),
            id: self
                .status
                .as_ref()
                .and_then(|status| status.mailbox_id.clone()),
            size: self.status.as_ref().and_then(|status| status.size),
            role,
            etag,
        }
    }
}

#[derive(Debug, Default)]
struct LegacyListCommandResponses {
    folders: Vec<ListedLegacyFolder>,
    statuses: HashMap<String, ListedLegacyFolderStatus>,
}

async fn legacy_folders_for_reference(
    session: &mut BoxedSession,
    reference: &str,
    options: &LegacyFolderListOptions,
) -> Result<Vec<ListedLegacyFolder>> {
    let command = legacy_list_command(reference, false, options)?;
    let mut listed =
        run_legacy_list_command(session, &command, "list mailboxes", options.utf8_mode).await?;

    if reference.is_empty()
        && !listed.iter().any(|folder| {
            folder.full_name.eq_ignore_ascii_case("INBOX")
                || folder.attributes.iter().any(|value| value == "\\inbox")
        })
    {
        let delimiter = listed
            .iter()
            .find_map(|folder| (!folder.delimiter.is_empty()).then(|| folder.delimiter.clone()))
            .unwrap_or_default();
        listed.push(ListedLegacyFolder {
            wire_name: "INBOX".to_string(),
            full_name: "INBOX".to_string(),
            delimiter,
            attributes: Vec::new(),
            status: None,
        });
    }

    if !options.list_extended && options.discover_subscriptions {
        let subscribed = match legacy_list_command(reference, true, options) {
            Ok(command) => {
                run_legacy_list_command(
                    session,
                    &command,
                    "list mailbox subscriptions",
                    options.utf8_mode,
                )
                .await
            }
            Err(error) => Err(error),
        };
        match subscribed {
            Ok(subscribed) => {
                let subscribed = subscribed
                    .into_iter()
                    .map(|folder| folder.full_name)
                    .collect::<HashSet<_>>();
                for folder in &mut listed {
                    if subscribed.contains(&folder.full_name)
                        && !folder
                            .attributes
                            .iter()
                            .any(|attribute| attribute == "\\subscribed")
                    {
                        folder.attributes.push("\\subscribed".to_string());
                    }
                }
            }
            Err(_) => {
                for folder in &mut listed {
                    if !folder
                        .attributes
                        .iter()
                        .any(|attribute| attribute == "\\subscribed")
                    {
                        folder.attributes.push("\\subscribed".to_string());
                    }
                }
            }
        }
    }

    Ok(listed)
}

fn legacy_list_command(
    reference: &str,
    subscribed_only: bool,
    options: &LegacyFolderListOptions,
) -> Result<String> {
    let reference = quote_imap_string("namespace reference", reference)?;
    let pattern = quote_mailbox_pattern("*")?;
    if subscribed_only {
        return Ok(format!("LSUB {reference} {pattern}"));
    }
    if !options.list_extended {
        return Ok(format!("LIST {reference} {pattern}"));
    }

    let mut return_items = vec!["SUBSCRIBED".to_string()];
    if options.special_use {
        return_items.push("SPECIAL-USE".to_string());
    }
    if options.list_status {
        let mut status_items = vec!["MESSAGES", "UNSEEN", "UIDNEXT", "UIDVALIDITY"];
        if options.highest_modseq {
            status_items.push("HIGHESTMODSEQ");
        }
        if options.append_limit {
            status_items.push("APPENDLIMIT");
        }
        if options.size {
            status_items.push("SIZE");
        }
        if options.mailbox_id {
            status_items.push("MAILBOXID");
        }
        return_items.push(format!("STATUS ({})", status_items.join(" ")));
    }
    Ok(format!(
        "LIST {reference} {pattern} RETURN ({})",
        return_items.join(" ")
    ))
}

async fn run_legacy_list_command(
    session: &mut BoxedSession,
    command: &str,
    operation: &'static str,
    utf8_mode: bool,
) -> Result<Vec<ListedLegacyFolder>> {
    timeout_result(
        operation,
        timeout(COMMAND_TIMEOUT, async {
            let request_id = session
                .run_command(command)
                .await
                .map_err(|error| imap_error(operation, error))?;
            let mut collected = LegacyListCommandResponses::default();
            loop {
                let response = session
                    .read_response()
                    .await
                    .map_err(|error| {
                        FrickmailError::Upstream(format!("{operation} failed: {error}"))
                    })?
                    .ok_or_else(|| {
                        FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP connection closed"
                        ))
                    })?;
                collect_legacy_list_response(response.parsed(), &mut collected, utf8_mode);
                if imap_command_completion(response.parsed(), &request_id, operation)?.is_some() {
                    for folder in &mut collected.folders {
                        folder.status = collected.statuses.remove(&folder.full_name);
                    }
                    return Ok(collected.folders);
                }
            }
        }),
    )
    .await?
}

fn collect_legacy_list_response(
    response: &Response<'_>,
    collected: &mut LegacyListCommandResponses,
    utf8_mode: bool,
) {
    match response {
        Response::MailboxData(MailboxDatum::List {
            name_attributes,
            delimiter,
            name,
        }) => {
            let wire_name = name.to_string();
            let full_name = imap_mailbox_to_utf8(&wire_name, utf8_mode);
            collected.folders.push(ListedLegacyFolder {
                wire_name,
                full_name,
                delimiter: delimiter.as_deref().unwrap_or_default().to_string(),
                attributes: legacy_name_attributes(name_attributes),
                status: None,
            });
        }
        Response::MailboxData(MailboxDatum::Status { mailbox, status }) => {
            let mailbox = imap_mailbox_to_utf8(mailbox, utf8_mode);
            let entry = collected.statuses.entry(mailbox).or_default();
            collect_legacy_status_attributes(status, entry);
        }
        _ => {}
    }
}

fn collect_legacy_status_attributes(
    attributes: &[StatusAttribute],
    status: &mut ListedLegacyFolderStatus,
) {
    for attribute in attributes {
        match attribute {
            StatusAttribute::AppendLimit(value) => {
                status.append_limit = Some(value.unwrap_or_default())
            }
            StatusAttribute::HighestModSeq(value) => status.highest_modseq = Some(*value),
            StatusAttribute::MailboxId(value) => {
                status.mailbox_id = Some(STANDARD.encode(value.as_bytes()))
            }
            StatusAttribute::Messages(value) => status.total_emails = Some(*value),
            StatusAttribute::Recent(_) => {}
            StatusAttribute::Size(value) => status.size = Some(*value),
            StatusAttribute::UidNext(value) => status.uid_next = Some(*value),
            StatusAttribute::UidValidity(value) => status.uid_validity = Some(*value),
            StatusAttribute::Unseen(value) => status.unread_emails = Some(*value),
            _ => {}
        }
    }
}

async fn legacy_all_metadata(
    session: &mut BoxedSession,
    utf8_mode: bool,
) -> Result<HashMap<String, HashMap<String, String>>> {
    let operation = "read all mailbox metadata";
    timeout_result(
        operation,
        timeout(COMMAND_TIMEOUT, async {
            let request_id = session
                .run_command(r#"GETMETADATA (DEPTH infinity) "*" ("/shared" "/private")"#)
                .await
                .map_err(|error| imap_error(operation, error))?;
            let mut all = HashMap::<String, HashMap<String, String>>::new();
            loop {
                let response = session
                    .read_response()
                    .await
                    .map_err(|error| {
                        FrickmailError::Upstream(format!("{operation} failed: {error}"))
                    })?
                    .ok_or_else(|| {
                        FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP connection closed"
                        ))
                    })?;
                if let Response::MailboxData(MailboxDatum::MetadataSolicited { mailbox, values }) =
                    response.parsed()
                {
                    let metadata = all
                        .entry(imap_mailbox_to_utf8(mailbox, utf8_mode))
                        .or_default();
                    metadata.extend(values.iter().filter_map(|entry| {
                        entry
                            .value
                            .as_ref()
                            .map(|value| (entry.entry.clone(), value.clone()))
                    }));
                }
                match response.parsed() {
                    Response::Done {
                        tag,
                        status: Status::Ok,
                        ..
                    } if tag == &request_id => return Ok(all),
                    Response::Done { tag, .. } if tag == &request_id => {
                        return Ok(HashMap::new());
                    }
                    Response::Data {
                        status: Status::Bye,
                        information,
                        ..
                    } => {
                        return Err(imap_acl_status_error(
                            operation,
                            &Status::Bye,
                            information.as_deref(),
                        ));
                    }
                    _ => {}
                }
            }
        }),
    )
    .await?
}

async fn legacy_folder_metadata_with_timeout(
    session: &mut BoxedSession,
    wire_name: &str,
    command_timeout: Duration,
) -> Result<Option<HashMap<String, String>>> {
    let entries = match timeout(
        command_timeout,
        session.get_metadata(wire_name, "(DEPTH infinity)", "(\"/shared\" \"/private\")"),
    )
    .await
    {
        Err(_) => {
            return Err(FrickmailError::Upstream(
                "read listed mailbox metadata timed out".to_string(),
            ));
        }
        Ok(Err(async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_))) => {
            return Ok(None);
        }
        Ok(Err(error)) => return Err(imap_error("read listed mailbox metadata", error)),
        Ok(Ok(entries)) => entries,
    };
    Ok(Some(
        entries
            .into_iter()
            .filter_map(|entry| entry.value.map(|value| (entry.entry, value)))
            .collect(),
    ))
}

async fn legacy_storage_quota(
    session: &mut BoxedSession,
    capabilities: &Capabilities,
) -> (Option<u64>, Option<u64>) {
    if !has_capability_ignore_ascii_case(capabilities, "QUOTA") {
        return (None, None);
    }
    legacy_storage_quota_result(session)
        .await
        .unwrap_or((None, None))
}

async fn legacy_storage_quota_result(
    session: &mut BoxedSession,
) -> Result<(Option<u64>, Option<u64>)> {
    let operation = "read mailbox quota";
    timeout_result(
        operation,
        timeout(COMMAND_TIMEOUT, async {
            let request_id = session
                .run_command(r#"GETQUOTAROOT "INBOX""#)
                .await
                .map_err(|error| imap_error(operation, error))?;
            let mut storage = None;
            loop {
                let response = session
                    .read_response()
                    .await
                    .map_err(|error| {
                        FrickmailError::Upstream(format!("{operation} failed: {error}"))
                    })?
                    .ok_or_else(|| {
                        FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP connection closed"
                        ))
                    })?;
                if let Response::Quota(quota) = response.parsed() {
                    if let Some(resource) = quota
                        .resources
                        .iter()
                        .find(|resource| resource.name == imap_proto::QuotaResourceName::Storage)
                    {
                        storage = Some((resource.usage, resource.limit));
                    }
                }
                if imap_command_completion(response.parsed(), &request_id, operation)?.is_some() {
                    return Ok(match storage {
                        Some((usage, limit)) => (
                            Some(usage.saturating_mul(1024)),
                            Some(limit.saturating_mul(1024)),
                        ),
                        None => (Some(0), Some(0)),
                    });
                }
            }
        }),
    )
    .await?
}

fn legacy_visible_capabilities(capabilities: &Capabilities) -> Vec<String> {
    let mut visible = capabilities
        .iter()
        .map(|capability| match capability {
            Capability::Imap4rev1 => "IMAP4rev1".to_string(),
            Capability::Auth(mechanism) => format!("AUTH={mechanism}"),
            Capability::Atom(atom) => atom.clone(),
        })
        .filter(|capability| {
            let capability = capability.to_ascii_uppercase();
            !["IMAP", "AUTH", "LOGIN", "SASL"]
                .iter()
                .any(|prefix| capability.starts_with(prefix))
        })
        .collect::<Vec<_>>();
    visible.sort_unstable();
    visible
}

async fn enable_legacy_utf8(
    session: &mut BoxedSession,
    capabilities: &Capabilities,
) -> Result<bool> {
    let utf8_mode = capabilities.iter().any(is_legacy_utf8_capability);
    if utf8_mode {
        timeout_imap(
            "enable IMAP UTF-8",
            session.run_command_and_check_ok("ENABLE UTF8=ACCEPT"),
        )
        .await?;
    }
    Ok(utf8_mode)
}

fn is_legacy_utf8_capability(capability: &Capability) -> bool {
    matches!(
        capability,
        Capability::Atom(atom)
            if atom.eq_ignore_ascii_case("UTF8=ACCEPT")
                || atom.eq_ignore_ascii_case("UTF8=ONLY")
    )
}

async fn mailbox_metadata_supported(session: &mut BoxedSession) -> Result<bool> {
    let capabilities =
        timeout_imap("read IMAP metadata capability", session.capabilities()).await?;
    Ok(has_capability_ignore_ascii_case(&capabilities, "METADATA"))
}

async fn require_mailbox_acl_support(session: &mut BoxedSession) -> Result<()> {
    let capabilities = timeout_imap("read IMAP ACL capability", session.capabilities()).await?;
    if has_capability_ignore_ascii_case(&capabilities, "ACL") {
        Ok(())
    } else {
        Err(FrickmailError::BadRequest(
            "IMAP server does not support ACL".to_string(),
        ))
    }
}

#[derive(Debug, Default)]
struct AclCommandResponses {
    my_rights: Option<String>,
    entries: Vec<MailboxAclEntry>,
}

async fn run_acl_command(
    session: &mut BoxedSession,
    command: &str,
    operation: &'static str,
    expected_mailbox: &str,
) -> Result<AclCommandResponses> {
    timeout_result(
        operation,
        timeout(COMMAND_TIMEOUT, async {
            let request_id = session
                .run_command(command)
                .await
                .map_err(|error| imap_error(operation, error))?;
            let mut collected = AclCommandResponses::default();

            loop {
                let response = session
                    .read_response()
                    .await
                    .map_err(|error| {
                        FrickmailError::Upstream(format!("{operation} failed: {error}"))
                    })?
                    .ok_or_else(|| {
                        FrickmailError::Upstream(format!(
                            "{operation} failed: IMAP connection closed"
                        ))
                    })?;

                collect_acl_data_response(response.parsed(), expected_mailbox, &mut collected);
                if acl_command_completion(response.parsed(), &request_id, operation)?.is_some() {
                    return Ok(collected);
                }
            }
        }),
    )
    .await?
}

fn collect_acl_data_response(
    response: &Response<'_>,
    expected_mailbox: &str,
    collected: &mut AclCommandResponses,
) {
    match response {
        Response::MyRights(rights) if rights.mailbox == expected_mailbox => {
            collected.my_rights = Some(acl_rights_string(&rights.rights));
        }
        Response::Acl(acl) if acl.mailbox == expected_mailbox => {
            collected
                .entries
                .extend(acl.acls.iter().map(|entry| MailboxAclEntry {
                    identifier: entry.identifier.to_string(),
                    rights: acl_rights_string(&entry.rights),
                    mine: false,
                }));
        }
        _ => {}
    }
}

fn acl_command_completion(
    response: &Response<'_>,
    request_id: &RequestId,
    operation: &str,
) -> Result<Option<()>> {
    match response {
        Response::Done {
            tag,
            status: Status::Ok,
            ..
        } if tag == request_id => Ok(Some(())),
        Response::Done {
            tag,
            status,
            information,
            ..
        } if tag == request_id => Err(imap_acl_status_error(
            operation,
            status,
            information.as_deref(),
        )),
        Response::Data {
            status: Status::Bye,
            information,
            ..
        } => Err(imap_acl_status_error(
            operation,
            &Status::Bye,
            information.as_deref(),
        )),
        _ => Ok(None),
    }
}

fn imap_command_completion(
    response: &Response<'_>,
    request_id: &RequestId,
    operation: &str,
) -> Result<Option<()>> {
    match response {
        Response::Done {
            tag,
            status: Status::Ok,
            ..
        } if tag == request_id => Ok(Some(())),
        Response::Done {
            tag,
            status,
            information,
            ..
        } if tag == request_id => Err(imap_acl_status_error(
            operation,
            status,
            information.as_deref(),
        )),
        Response::Data {
            status: Status::Bye,
            information,
            ..
        } => Err(imap_acl_status_error(
            operation,
            &Status::Bye,
            information.as_deref(),
        )),
        _ => Ok(None),
    }
}

fn imap_acl_status_error(
    operation: &str,
    status: &Status,
    information: Option<&str>,
) -> FrickmailError {
    FrickmailError::Upstream(format!(
        "{operation} failed ({status:?}): {}",
        information.unwrap_or("IMAP command failed")
    ))
}

fn acl_rights_string(rights: &[AclRight]) -> String {
    rights.iter().copied().map(char::from).collect()
}

fn set_acl_command(mailbox: &str, identifier: &str, rights: &str) -> Result<String> {
    validate_mailbox(mailbox)?;
    Ok(format!(
        "SETACL {} {} {}",
        quote_imap_string("mailbox", mailbox)?,
        quote_imap_string("ACL identifier", identifier)?,
        quote_imap_string("ACL rights", rights)?,
    ))
}

fn delete_acl_command(mailbox: &str, identifier: &str) -> Result<String> {
    validate_mailbox(mailbox)?;
    Ok(format!(
        "DELETEACL {} {}",
        quote_imap_string("mailbox", mailbox)?,
        quote_imap_string("ACL identifier", identifier)?,
    ))
}

fn validate_metadata(metadata: &MailboxMetadata) -> Result<()> {
    required_field("metadata key", metadata.key.clone())?;
    if let Some(value) = metadata.value.as_deref() {
        if contains_crlf(value) {
            return Err(FrickmailError::BadRequest(
                "metadata value must not contain CR or LF".to_string(),
            ));
        }
    }
    Ok(())
}

fn set_metadata_command(mailbox: &str, metadata: &MailboxMetadata) -> Result<String> {
    validate_mailbox(mailbox)?;
    validate_metadata(metadata)?;
    let mailbox = quote_imap_string("mailbox", mailbox)?;
    let key = quote_imap_string("metadata key", metadata.key.trim())?;
    let value = match metadata.value.as_deref() {
        Some(value) => quote_imap_string("metadata value", value)?,
        None => "NIL".to_string(),
    };
    Ok(format!("SETMETADATA {mailbox} ({key} {value})"))
}

fn best_effort_metadata_command(mailbox: &str, metadata: &MailboxMetadata) -> Option<String> {
    set_metadata_command(mailbox, metadata).ok()
}

fn create_mailbox_full_name(mailbox: &str, parent: &str, delimiter: &str) -> String {
    if parent.is_empty() || delimiter.is_empty() {
        format!("{parent}{mailbox}")
    } else {
        format!("{parent}{delimiter}{mailbox}")
    }
}

async fn created_legacy_folder(
    session: &mut BoxedSession,
    full_name: &str,
    subscribed: bool,
) -> Result<Option<LegacyFolder>> {
    let listed = {
        let folders = timeout_imap(
            "list created mailbox",
            session.list(Some(full_name), Some("\"\"")),
        )
        .await?;
        pin_mut!(folders);
        let mut fallback = None;

        while let Some(folder) = timeout_imap("read created mailbox", folders.try_next()).await? {
            let item = (
                folder.name().to_string(),
                folder.delimiter().unwrap_or_default().to_string(),
                legacy_name_attributes(folder.attributes()),
            );
            if folder.name() == full_name {
                fallback = Some(item);
                break;
            }
            fallback.get_or_insert(item);
        }
        fallback
    };

    let Some((listed_full_name, delimiter, mut attributes)) = listed else {
        return Ok(None);
    };

    if subscribed
        && !attributes
            .iter()
            .any(|attribute| attribute == "\\subscribed")
    {
        attributes.push("\\subscribed".to_string());
    }

    let status = timeout_imap(
        "status created mailbox",
        session.status(&listed_full_name, "(MESSAGES UIDNEXT UNSEEN)"),
    )
    .await?;

    Ok(Some(LegacyFolder {
        name: legacy_folder_name(&listed_full_name, &delimiter),
        full_name: listed_full_name,
        delimiter,
        role: legacy_folder_role(&attributes),
        attributes,
        metadata: HashMap::new(),
        uid_next: status.uid_next,
        total_emails: Some(status.exists),
        unread_emails: status.unseen,
        id: None,
        size: None,
        etag: None,
    }))
}

fn quote_mailbox_pattern(value: &str) -> Result<String> {
    quote_imap_string("mailbox", value)
}

fn quote_imap_string(label: &str, value: &str) -> Result<String> {
    if contains_crlf(value) || value.contains('\0') {
        return Err(FrickmailError::BadRequest(format!(
            "{label} must not contain NUL, CR, or LF"
        )));
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    Ok(quoted)
}

fn legacy_name_attributes(attributes: &[NameAttribute<'_>]) -> Vec<String> {
    attributes
        .iter()
        .filter_map(legacy_name_attribute)
        .collect()
}

fn legacy_name_attribute(attribute: &NameAttribute<'_>) -> Option<String> {
    let value = match attribute {
        NameAttribute::NoInferiors => "\\noinferiors",
        NameAttribute::NoSelect => "\\noselect",
        NameAttribute::Marked => "\\marked",
        NameAttribute::Unmarked => "\\unmarked",
        NameAttribute::All => "\\all",
        NameAttribute::Archive => "\\archive",
        NameAttribute::Drafts => "\\drafts",
        NameAttribute::Flagged => "\\flagged",
        NameAttribute::Junk => "\\junk",
        NameAttribute::Sent => "\\sent",
        NameAttribute::Trash => "\\trash",
        NameAttribute::Extension(value) => return Some(value.to_ascii_lowercase()),
        _ => return None,
    };
    Some(value.to_string())
}

fn modified_utf7_to_utf8(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(relative_start) = value[cursor..].find('&') {
        let start = cursor + relative_start;
        decoded.push_str(&value[cursor..start]);
        let Some(relative_end) = value[start + 1..].find('-') else {
            decoded.push_str(&value[start..]);
            return decoded;
        };
        let end = start + 1 + relative_end;
        let encoded = &value[start + 1..end];
        if encoded.is_empty() {
            decoded.push('&');
            cursor = end + 1;
            continue;
        }

        let mut standard = encoded.replace(',', "/");
        while !standard.len().is_multiple_of(4) {
            standard.push('=');
        }
        let converted = STANDARD.decode(standard).ok().and_then(|bytes| {
            if bytes.len() % 2 != 0 {
                return None;
            }
            let utf16 = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&utf16).ok()
        });
        if let Some(converted) = converted {
            decoded.push_str(&converted);
        } else {
            decoded.push_str(&value[start..=end]);
        }
        cursor = end + 1;
    }
    decoded.push_str(&value[cursor..]);
    decoded
}

fn modified_utf7_from_utf8(value: &str) -> String {
    fn flush_utf16(encoded: &mut String, utf16: &mut Vec<u16>) {
        if utf16.is_empty() {
            return;
        }

        let bytes = utf16
            .iter()
            .flat_map(|unit| unit.to_be_bytes())
            .collect::<Vec<_>>();
        let mut base64 = STANDARD.encode(bytes);
        while base64.ends_with('=') {
            base64.pop();
        }
        encoded.push('&');
        encoded.push_str(&base64.replace('/', ","));
        encoded.push('-');
        utf16.clear();
    }

    let mut encoded = String::with_capacity(value.len());
    let mut utf16 = Vec::new();
    for character in value.chars() {
        if (' '..='~').contains(&character) {
            flush_utf16(&mut encoded, &mut utf16);
            if character == '&' {
                encoded.push_str("&-");
            } else {
                encoded.push(character);
            }
        } else {
            let mut units = [0_u16; 2];
            utf16.extend_from_slice(character.encode_utf16(&mut units));
        }
    }
    flush_utf16(&mut encoded, &mut utf16);
    encoded
}

fn imap_mailbox_to_utf8(value: &str, utf8_mode: bool) -> String {
    if utf8_mode {
        value.to_string()
    } else {
        modified_utf7_to_utf8(value)
    }
}

fn imap_mailbox_from_utf8(value: &str, utf8_mode: bool) -> String {
    if utf8_mode {
        value.to_string()
    } else {
        modified_utf7_from_utf8(value)
    }
}

fn legacy_folder_name(full_name: &str, delimiter: &str) -> String {
    if delimiter.is_empty() {
        return full_name.to_string();
    }
    full_name
        .rsplit(delimiter)
        .next()
        .unwrap_or(full_name)
        .to_string()
}

fn legacy_folder_role(attributes: &[String]) -> Option<String> {
    let role = [
        ("\\inbox", "inbox"),
        ("\\all", "all"),
        ("\\archive", "archive"),
        ("\\drafts", "drafts"),
        ("\\flagged", "flagged"),
        ("\\important", "important"),
        ("\\junk", "junk"),
        ("\\sent", "sent"),
        ("\\trash", "trash"),
    ]
    .into_iter()
    .find_map(|(attribute, role)| {
        attributes
            .iter()
            .any(|value| value == attribute)
            .then_some(role)
    });

    role.map(str::to_string)
}

fn legacy_folder_role_with_metadata(
    full_name: &str,
    attributes: &[String],
    metadata: &HashMap<String, String>,
) -> Option<String> {
    metadata
        .get("/private/specialuse")
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_start_matches('\\').to_string())
        .or_else(|| legacy_folder_role(attributes))
        .or_else(|| {
            full_name
                .eq_ignore_ascii_case("INBOX")
                .then(|| "inbox".to_string())
        })
}

fn validate_deletable_mailbox(mailbox: &str, messages: u32) -> Result<()> {
    if mailbox == "INBOX" {
        return Err(FrickmailError::BadRequest(
            "Cannot delete INBOX".to_string(),
        ));
    }
    if messages > 0 {
        return Err(FrickmailError::BadRequest(
            "Cannot delete non-empty folder".to_string(),
        ));
    }
    Ok(())
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

fn imap_quote_message_list_search_value(value: &str) -> Result<String> {
    if contains_crlf(value) || value.contains('\0') {
        return Err(FrickmailError::BadRequest(
            "message-list search value must not contain CR, LF, or NUL".to_string(),
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

fn legacy_thread_algorithms(capabilities: &Capabilities) -> Vec<String> {
    let mut algorithms = Vec::new();
    for capability in capabilities.iter() {
        let Capability::Atom(atom) = capability else {
            continue;
        };
        let Some(prefix) = atom.get(..7) else {
            continue;
        };
        let Some(algorithm) = atom.get(7..) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case("THREAD=") || algorithm.is_empty() {
            continue;
        }
        let algorithm = algorithm.to_ascii_uppercase();
        if !algorithms.contains(&algorithm) {
            algorithms.push(algorithm);
        }
    }
    algorithms
}

fn legacy_message_list_thread_algorithm(advertised: &[String], requested: &str) -> Option<String> {
    let requested = requested.trim();
    if !requested.is_empty() {
        if let Some(algorithm) = advertised
            .iter()
            .find(|algorithm| algorithm.eq_ignore_ascii_case(requested))
        {
            return Some(algorithm.clone());
        }
    }

    ["REFS", "REFERENCES", "ORDEREDSUBJECT"]
        .iter()
        .find_map(|preferred| {
            advertised
                .iter()
                .find(|algorithm| algorithm.eq_ignore_ascii_case(preferred))
                .cloned()
        })
}

fn default_security() -> ImapSecurity {
    ImapSecurity::Tls
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::sync::Mutex;

    struct RecordingUidCache {
        returned_uids: Option<Vec<u32>>,
        gets: Mutex<Vec<(String, String)>>,
        sets: Mutex<Vec<(String, String, Vec<u32>)>>,
    }

    #[derive(Default)]
    struct StatefulUidCache {
        uids: Mutex<Option<(String, String, Vec<u32>)>>,
        thread_map: Mutex<Option<(String, Vec<Vec<u32>>)>>,
    }

    #[async_trait::async_trait]
    impl LegacyMessageListUidCache for RecordingUidCache {
        async fn get(&self, raw_key: &str, folder_hash: &str) -> Option<Vec<u32>> {
            self.gets
                .lock()
                .unwrap()
                .push((raw_key.to_string(), folder_hash.to_string()));
            self.returned_uids.clone()
        }

        async fn set(&self, raw_key: &str, folder_hash: &str, uids: &[u32]) {
            self.sets.lock().unwrap().push((
                raw_key.to_string(),
                folder_hash.to_string(),
                uids.to_vec(),
            ));
        }
    }

    #[async_trait::async_trait]
    impl LegacyMessageListUidCache for StatefulUidCache {
        async fn get(&self, raw_key: &str, folder_hash: &str) -> Option<Vec<u32>> {
            self.uids
                .lock()
                .unwrap()
                .as_ref()
                .filter(|(key, hash, _)| key == raw_key && hash == folder_hash)
                .map(|(_, _, uids)| uids.clone())
        }

        async fn set(&self, raw_key: &str, folder_hash: &str, uids: &[u32]) {
            *self.uids.lock().unwrap() =
                Some((raw_key.to_string(), folder_hash.to_string(), uids.to_vec()));
        }

        async fn get_thread_map(&self, raw_key: &str) -> Option<Vec<Vec<u32>>> {
            self.thread_map
                .lock()
                .unwrap()
                .as_ref()
                .filter(|(key, _)| key == raw_key)
                .map(|(_, threads)| threads.clone())
        }

        async fn set_thread_map(&self, raw_key: &str, threads: &[Vec<u32>]) {
            *self.thread_map.lock().unwrap() = Some((raw_key.to_string(), threads.to_vec()));
        }
    }

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
            "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER]<0.65536>)"
        );
        assert_eq!(
            uid_fetch_bodystructure_query_with_gmail_id(42, true).unwrap(),
            "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER]<0.65536> X-GM-MSGID)"
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
            charset: "utf-8".to_string(),
            transfer_encoding: BodyPartTransferEncoding::Identity,
            decode_flowed: false,
        }];
        assert_eq!(
            body_preview_fetch_query(&specs),
            "(UID BODY.PEEK[1]<0.262144>)"
        );
        assert!(!body_preview_fetch_query(&specs).contains(".MIME"));
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
    fn body_preview_selects_all_non_attachment_text_parts_in_tree_order() {
        let body = BodyStructure::Multipart {
            common: test_body_common("multipart", "mixed", None),
            bodies: vec![
                BodyStructure::Text {
                    common: test_body_common("text", "plain", None),
                    other: test_body_single_part(10),
                    lines: 1,
                    extension: None,
                },
                BodyStructure::Multipart {
                    common: test_body_common("multipart", "alternative", None),
                    bodies: vec![
                        BodyStructure::Text {
                            common: test_body_common("text", "x-amp-html", None),
                            other: test_body_single_part(20),
                            lines: 1,
                            extension: None,
                        },
                        BodyStructure::Text {
                            common: test_body_common("text", "html", None),
                            other: test_body_single_part(30),
                            lines: 1,
                            extension: None,
                        },
                    ],
                    extension: None,
                },
                BodyStructure::Text {
                    common: test_body_common("text", "plain", Some("attachment")),
                    other: test_body_single_part(40),
                    lines: 1,
                    extension: None,
                },
                BodyStructure::Text {
                    common: test_body_common("text", "calendar", None),
                    other: test_body_single_part(50),
                    lines: 1,
                    extension: None,
                },
            ],
            extension: None,
        };

        let specs = body_preview_part_specs(&body, b"");

        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].path_vec(), Some(vec![1]));
        assert_eq!(specs[0].kind, BodyPartKind::Plain);
        assert_eq!(specs[1].path_vec(), Some(vec![2, 1]));
        assert_eq!(specs[1].kind, BodyPartKind::Plain);
        assert_eq!(specs[2].path_vec(), Some(vec![2, 2]));
        assert_eq!(specs[2].kind, BodyPartKind::Html);
    }

    #[test]
    fn body_preview_uses_pgp_payload_before_text_attachment_fallback() {
        let body = BodyStructure::Multipart {
            common: test_body_common("multipart", "mixed", None),
            bodies: vec![
                BodyStructure::Text {
                    common: test_body_common("text", "plain", Some("attachment")),
                    other: test_body_single_part(40),
                    lines: 1,
                    extension: None,
                },
                BodyStructure::Multipart {
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
                },
            ],
            extension: None,
        };

        let specs = body_preview_part_specs(&body, b"");

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].path_vec(), Some(vec![2, 2]));
        assert_eq!(specs[0].kind, BodyPartKind::Plain);
    }

    #[test]
    fn body_preview_falls_back_to_text_attachments_when_no_body_exists() {
        let body = BodyStructure::Text {
            common: test_body_common("text", "plain", Some("attachment")),
            other: test_body_single_part(40),
            lines: 1,
            extension: None,
        };

        let specs = body_preview_part_specs(&body, b"");

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].path_vec(), Some(vec![1]));
        assert_eq!(specs[0].kind, BodyPartKind::Plain);
    }

    #[test]
    fn body_preview_bounds_selected_part_count_and_total_bytes() {
        let small_parts = (0..(BODY_PREVIEW_TEXT_PART_LIMIT + 1))
            .map(|_| BodyStructure::Text {
                common: test_body_common("text", "plain", None),
                other: test_body_single_part(1),
                lines: 1,
                extension: None,
            })
            .collect();
        let many = BodyStructure::Multipart {
            common: test_body_common("multipart", "mixed", None),
            bodies: small_parts,
            extension: None,
        };
        assert_eq!(
            body_preview_part_specs(&many, b"").len(),
            BODY_PREVIEW_TEXT_PART_LIMIT
        );

        let large_parts = (0..5)
            .map(|_| BodyStructure::Text {
                common: test_body_common("text", "plain", None),
                other: test_body_single_part(BODY_PREVIEW_PART_LIMIT_BYTES as u32),
                lines: 1,
                extension: None,
            })
            .collect();
        let large = BodyStructure::Multipart {
            common: test_body_common("multipart", "mixed", None),
            bodies: large_parts,
            extension: None,
        };
        assert_eq!(body_preview_part_specs(&large, b"").len(), 4);
    }

    #[test]
    fn body_preview_decodes_flowed_only_for_unencoded_plain_parts() {
        let body = BodyStructure::Multipart {
            common: test_body_common("multipart", "mixed", None),
            bodies: vec![
                BodyStructure::Text {
                    common: test_body_common_with_params(
                        "text",
                        "plain",
                        None,
                        Some(vec![("format", "flowed")]),
                    ),
                    other: test_body_single_part_full(
                        32,
                        imap_proto::ContentEncoding::SevenBit,
                        None,
                    ),
                    lines: 2,
                    extension: None,
                },
                BodyStructure::Text {
                    common: test_body_common_with_params(
                        "text",
                        "plain",
                        None,
                        Some(vec![("format", "flowed")]),
                    ),
                    other: test_body_single_part_full(
                        32,
                        imap_proto::ContentEncoding::Base64,
                        None,
                    ),
                    lines: 2,
                    extension: None,
                },
                BodyStructure::Text {
                    common: test_body_common_with_params(
                        "text",
                        "plain",
                        None,
                        Some(vec![("format", "flowed")]),
                    ),
                    other: test_body_single_part_full(
                        32,
                        imap_proto::ContentEncoding::QuotedPrintable,
                        None,
                    ),
                    lines: 2,
                    extension: None,
                },
                BodyStructure::Text {
                    common: test_body_common_with_params(
                        "text",
                        "html",
                        None,
                        Some(vec![("format", "flowed")]),
                    ),
                    other: test_body_single_part_full(
                        32,
                        imap_proto::ContentEncoding::SevenBit,
                        None,
                    ),
                    lines: 2,
                    extension: None,
                },
            ],
            extension: None,
        };

        let specs = body_preview_part_specs(&body, b"");

        assert!(specs[0].decode_flowed);
        assert!(!specs[1].decode_flowed);
        assert!(!specs[2].decode_flowed);
        assert!(!specs[3].decode_flowed);
        let decoded = decode_body_preview_part(&specs[0], b"first \r\nsecond \nthird");
        assert!(String::from_utf8(decoded)
            .unwrap()
            .ends_with("first second third"));
        let html = decode_body_preview_part(&specs[3], b"first \r\nsecond");
        assert!(String::from_utf8(html)
            .unwrap()
            .ends_with("first \r\nsecond"));
        let base64 = decode_body_preview_part(&specs[1], b"Zmlyc3QgDQpzZWNvbmQ=");
        assert!(String::from_utf8(base64)
            .unwrap()
            .ends_with("first \r\nsecond"));
        let quoted_printable = decode_body_preview_part(&specs[2], b"first=20\r\nsecond=3D");
        assert!(String::from_utf8(quoted_printable)
            .unwrap()
            .ends_with("first \r\nsecond="));
        let malformed = decode_body_preview_part(&specs[2], b"abc=\rX");
        assert!(String::from_utf8(malformed).unwrap().ends_with("abcX"));

        let split_marker = decode_body_preview_text(&specs[0], b"-----BEGIN PGP \r\nMESSAGE-----");
        let mut crypto = LegacyMessageCrypto::default();
        detect_armored_pgp_metadata(&mut crypto, "1", split_marker.as_bytes());
        assert!(crypto.pgp_encrypted.is_none());
        assert!(
            String::from_utf8(render_decoded_body_preview_part(&specs[0], split_marker))
                .unwrap()
                .ends_with("-----BEGIN PGP MESSAGE-----")
        );
    }

    #[test]
    fn body_preview_detects_armored_openpgp_metadata_and_recipient_key_ids() {
        const ARMORED: &[u8] = b"-----BEGIN PGP MESSAGE-----\n\n\
hIwDV7lfsBK4eqEBBACL9v0/kcOWeynLGEVVwWdlotHEf9h7Vj8VQhb3mysyXL0s\n\
P1AofPgSjB7M4w+F2enESDNR1dSnB347o4+Ii3utpH4YeHE9B9uk1jzdf48Jp417\n\
SMp2qx4dLv+3bRl+hKDwwtPI9HispRfV+ZF/MlYEFpLewF5TYHbPsB+TNMRGndRe\n\
AQkCEBcF2cYHRVuWN9gmPXNugVEiKgYMCNxCFTBrWQ+7oMiIR6aTD2Kammp4qdq3\n\
H+A5nkHbF0uq2xPAkDYsN4kc9rN1JqYnKONuJya4rxhjtaHLwJnJ8/VyYGq5QA==\n\
=93SZ\n-----END PGP MESSAGE-----\n";
        let armored = [
            b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\ntext\n".as_slice(),
            ARMORED,
        ]
        .concat();
        let mut crypto = LegacyMessageCrypto::default();

        detect_armored_pgp_metadata(&mut crypto, "3.2", &armored);

        let signed = crypto.pgp_signed.as_ref().unwrap();
        assert_eq!(signed.part_id, "3.2");
        assert!(signed.sig_part_id.is_none());
        assert!(signed.mic_alg.is_none());
        let encrypted = crypto.pgp_encrypted.as_ref().unwrap();
        assert_eq!(encrypted.part_id, "3.2");
        assert_eq!(
            encrypted.key_ids.as_deref(),
            Some(["57B95FB012B87AA1".to_string()].as_slice())
        );

        let doubled = [ARMORED, ARMORED].concat();
        assert_eq!(
            armored_pgp_recipient_key_ids(&doubled),
            vec![
                "57B95FB012B87AA1".to_string(),
                "57B95FB012B87AA1".to_string()
            ]
        );
        let capped = armored_pgp_recipient_key_ids(&ARMORED.repeat(257));
        assert_eq!(capped.len(), 256);
        assert!(capped.iter().all(|key_id| key_id == "57B95FB012B87AA1"));

        let end = find_bytes(ARMORED, b"-----END PGP MESSAGE-----").unwrap();
        assert_eq!(
            armored_pgp_recipient_key_ids(&ARMORED[..end]),
            vec!["57B95FB012B87AA1".to_string()]
        );
        let without_crc = String::from_utf8(ARMORED.to_vec())
            .unwrap()
            .replace("=93SZ\n", "");
        assert_eq!(
            armored_pgp_recipient_key_ids(without_crc.as_bytes()),
            vec!["57B95FB012B87AA1".to_string()]
        );
        let leading_space_end =
            without_crc.replace("-----END PGP MESSAGE-----", " \t-----END PGP MESSAGE-----");
        assert_eq!(
            armored_pgp_recipient_key_ids(leading_space_end.as_bytes()),
            vec!["57B95FB012B87AA1".to_string()]
        );
        let end_in_header = String::from_utf8(ARMORED.to_vec())
            .unwrap()
            .replace("\n\nhIw", "\nComment: -----END PGP MESSAGE-----\n\nhIw");
        assert_eq!(
            armored_pgp_recipient_key_ids(end_in_header.as_bytes()),
            vec!["57B95FB012B87AA1".to_string()]
        );
        let prefixed_begin = String::from_utf8(ARMORED.to_vec()).unwrap().replacen(
            "-----BEGIN PGP MESSAGE-----",
            "x-----BEGIN PGP MESSAGE-----",
            1,
        );
        assert!(armored_pgp_recipient_key_ids(prefixed_begin.as_bytes()).is_empty());
        let trailing_space_delimiters = String::from_utf8(ARMORED.to_vec())
            .unwrap()
            .replace(
                "-----BEGIN PGP MESSAGE-----",
                "-----BEGIN PGP MESSAGE-----\t ",
            )
            .replace("-----END PGP MESSAGE-----", "-----END PGP MESSAGE----- ");
        assert_eq!(
            armored_pgp_recipient_key_ids(trailing_space_delimiters.as_bytes()),
            vec!["57B95FB012B87AA1".to_string()]
        );
        for prefix in [" ", "\t"] {
            let leading_space_begin = String::from_utf8(ARMORED.to_vec()).unwrap().replacen(
                "-----BEGIN PGP MESSAGE-----",
                &format!("{prefix}-----BEGIN PGP MESSAGE-----"),
                1,
            );
            assert!(armored_pgp_recipient_key_ids(leading_space_begin.as_bytes()).is_empty());
        }
        let bad_crc = String::from_utf8(ARMORED.to_vec())
            .unwrap()
            .replace("=93SZ", "=AAAA");
        assert!(armored_pgp_recipient_key_ids(bad_crc.as_bytes()).is_empty());
        assert!(armored_pgp_recipient_key_ids(&[bad_crc.as_bytes(), ARMORED].concat()).is_empty());
        assert_eq!(
            armored_pgp_recipient_key_ids(&[ARMORED, bad_crc.as_bytes()].concat()),
            vec!["57B95FB012B87AA1".to_string()]
        );
        let corrupt_body = String::from_utf8(ARMORED.to_vec())
            .unwrap()
            .replace("=93SZ", "not!base64\n=93SZ");
        assert!(armored_pgp_recipient_key_ids(corrupt_body.as_bytes()).is_empty());
        for after_checksum in ["=93SZ\njunk", "=93SZ\n=AAAA"] {
            let trailing_corruption = String::from_utf8(ARMORED.to_vec())
                .unwrap()
                .replace("=93SZ", after_checksum);
            assert_eq!(
                armored_pgp_recipient_key_ids(trailing_corruption.as_bytes()),
                vec!["57B95FB012B87AA1".to_string()]
            );
        }

        let existing_signed = crypto.pgp_signed.clone();
        detect_armored_pgp_metadata(
            &mut crypto,
            "4",
            b"-----BEGIN PGP SIGNED MESSAGE-----\n-----BEGIN PGP MESSAGE-----",
        );
        assert_eq!(crypto.pgp_signed, existing_signed);
        assert_eq!(crypto.pgp_encrypted.as_ref().unwrap().part_id, "4");
        assert_eq!(crypto.pgp_encrypted.unwrap().key_ids, Some(Vec::new()));

        assert!(armored_pgp_recipient_key_ids(
            b"-----BEGIN PGP MESSAGE-----\n\n\
wQoDASNFZ4mrze8B\n-----END PGP MESSAGE-----"
        )
        .is_empty());

        let valid_rsa = [3, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 1, 0, 1, 1];
        assert!(gpg_reports_pkesk_recipient(&valid_rsa));
        let mut legacy_v2 = valid_rsa;
        legacy_v2[0] = 2;
        assert!(gpg_reports_pkesk_recipient(&legacy_v2));
        for rejected_version in [4, 6] {
            let mut rejected = valid_rsa;
            rejected[0] = rejected_version;
            assert!(!gpg_reports_pkesk_recipient(&rejected));
        }
        let mut unknown_algorithm = valid_rsa;
        unknown_algorithm[9] = 99;
        assert!(gpg_reports_pkesk_recipient(&unknown_algorithm));
        assert!(!gpg_reports_pkesk_recipient(&unknown_algorithm[..11]));
        let mut rsa_sign_only = valid_rsa;
        rsa_sign_only[9] = 3;
        assert!(gpg_reports_pkesk_recipient(&rsa_sign_only));
        let mut short_mpi = valid_rsa;
        short_mpi[10] = 0;
        short_mpi[11] = 16;
        assert!(!gpg_reports_pkesk_recipient(&short_mpi));
        let mut elgamal_one_mpi = valid_rsa;
        elgamal_one_mpi[9] = 20;
        assert!(!gpg_reports_pkesk_recipient(&elgamal_one_mpi));
        let rsa_zero_mpi = [3, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 1, 0, 0];
        assert!(gpg_reports_pkesk_recipient(&rsa_zero_mpi));
        assert!(gpg_reports_pkesk_recipient(&[
            3, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 1, 0, 0, 0
        ]));
        let rsa_noncanonical_mpi = [
            3, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 1, 0, 16, 0, 1,
        ];
        assert!(gpg_reports_pkesk_recipient(&rsa_noncanonical_mpi));
        let elgamal_zero_mpis = [
            3, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 20, 0, 0, 0, 0,
        ];
        assert!(gpg_reports_pkesk_recipient(&elgamal_zero_mpis));
        let ecdh_zero_mpi = [
            3, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 18, 0, 0, 1, 0,
        ];
        assert!(!gpg_reports_pkesk_recipient(&ecdh_zero_mpi));
        let ecdh_wrapped_len_one = [
            3, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 18, 0, 1, 1, 1, 0,
        ];
        assert!(!gpg_reports_pkesk_recipient(&ecdh_wrapped_len_one));
        assert!(gpg_reports_pkesk_recipient(&[
            3, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 18, 0, 1, 1, 2, 0, 0
        ]));
        assert!(gpg_reports_pkesk_recipient(&[
            3, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 18, 0, 1, 1, 2, 0, 0, 0
        ]));

        let new_packet = [vec![0xc1, 13], valid_rsa.to_vec()].concat();
        let old_packet = [vec![0x84, 13], valid_rsa.to_vec()].concat();
        for packet in [&new_packet, &old_packet] {
            let (tag, body, next) = openpgp_packet_at(packet, 0).unwrap();
            assert_eq!(tag, 1);
            assert_eq!(next, packet.len());
            assert!(gpg_reports_pkesk_recipient(body));
        }
    }

    #[test]
    fn openpgp_packet_parser_covers_legacy_and_modern_length_forms() {
        let cases = [
            (vec![0xc1, 191], 191_usize),
            (vec![0xc1, 192, 0], 192),
            (vec![0xc1, 223, 255], 8_383),
            (vec![0xc1, 255, 0, 0, 0x20, 0xc0], 8_384),
            (vec![0x85, 0x01, 0x00], 256),
            (vec![0x86, 0, 1, 0, 0], 65_536),
        ];
        for (header, body_len) in cases {
            let packet = [header, vec![0; body_len]].concat();
            let (tag, body, next) = openpgp_packet_at(&packet, 0).unwrap();
            assert_eq!(tag, 1);
            assert_eq!(body.len(), body_len);
            assert_eq!(next, packet.len());
        }

        for truncated in [
            vec![0xc1],
            vec![0xc1, 192],
            vec![0xc1, 255, 0, 0],
            vec![0xc1, 2, 0],
            vec![0x85, 0],
            vec![0x86, 0, 0, 0],
        ] {
            assert!(openpgp_packet_at(&truncated, 0).is_none());
        }
    }

    #[test]
    fn body_preview_applies_shared_and_top_header_charset_fallbacks() {
        let body = BodyStructure::Multipart {
            common: test_body_common("multipart", "mixed", None),
            bodies: vec![
                BodyStructure::Text {
                    common: test_body_common_with_params(
                        "text",
                        "plain",
                        None,
                        Some(vec![("charset", "US-ASCII")]),
                    ),
                    other: test_body_single_part(16),
                    lines: 1,
                    extension: None,
                },
                BodyStructure::Text {
                    common: test_body_common("text", "plain", None),
                    other: test_body_single_part(16),
                    lines: 1,
                    extension: None,
                },
            ],
            extension: None,
        };

        let specs = body_preview_part_specs(&body, b"");
        assert_eq!(specs[0].charset, "utf-8");
        assert_eq!(specs[1].charset, "iso-8859-1");
        let decoded = decode_body_preview_part(&specs[1], b"caf\xe9");
        assert!(String::from_utf8(decoded).unwrap().ends_with("café"));
        let explicit_ascii = decode_body_preview_part(&specs[0], b"a\xffb\xef\xbf\xbdc");
        assert!(String::from_utf8(explicit_ascii).unwrap().ends_with("ab�c"));

        let overridden = body_preview_part_specs(
            &body,
            b"Content-Type: multipart/mixed; charset=windows-1252\r\n\r\n",
        );
        assert_eq!(overridden[0].charset, "utf-8");
        assert_eq!(overridden[1].charset, "windows-1252");

        let ascii_header = body_preview_part_specs(
            &body,
            b"Content-Type: multipart/mixed; charset=US-ASCII\r\n\r\n",
        );
        assert_eq!(ascii_header[0].charset, "utf-8");
        assert_eq!(ascii_header[1].charset, "iso-8859-1");
    }

    #[test]
    fn metadata_only_body_preview_preserves_header_fetch_result() {
        let flags = vec!["\\Seen".to_string()];
        let crypto = LegacyMessageCrypto {
            pgp_encrypted: Some(LegacyPgpEncrypted {
                part_id: "2".to_string(),
                key_ids: None,
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
        let mut mailbox = async_imap::types::Mailbox {
            permanent_flags: vec![Flag::Custom("$label1".into())],
            ..Default::default()
        };
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
    fn validate_deletable_mailbox_matches_mailso_guards() {
        assert!(validate_deletable_mailbox("Archive", 0).is_ok());
        assert!(validate_deletable_mailbox("inbox", 0).is_ok());

        let inbox = validate_deletable_mailbox("INBOX", 0).unwrap_err();
        assert_eq!(inbox.public_message(), "Cannot delete INBOX");

        let non_empty = validate_deletable_mailbox("Archive", 1).unwrap_err();
        assert_eq!(non_empty.public_message(), "Cannot delete non-empty folder");
    }

    #[test]
    fn create_mailbox_helpers_match_mailso_folder_create_shape() {
        assert_eq!(
            create_mailbox_full_name("Child", "Parent", "/"),
            "Parent/Child"
        );
        assert_eq!(create_mailbox_full_name("Root", "", "/"), "Root");
        assert_eq!(legacy_folder_name("Parent/Child", "/"), "Child");
        assert_eq!(legacy_folder_name("Flat", ""), "Flat");
        assert_eq!(
            quote_mailbox_pattern(r#"A "quoted" \ folder"#).unwrap(),
            r#""A \"quoted\" \\ folder""#
        );
        assert!(quote_mailbox_pattern("Bad\r\nFolder").is_err());
    }

    #[test]
    fn rename_mailbox_helpers_preserve_hierarchy_boundaries() {
        assert!(mailbox_is_in_subtree("Projects", "Projects", "/"));
        assert!(mailbox_is_in_subtree("Projects/Active", "Projects", "/"));
        assert!(!mailbox_is_in_subtree("Projects-old", "Projects", "/"));
        assert!(!mailbox_is_in_subtree("ProjectsChild", "Projects", ""));
        assert_eq!(
            renamed_mailbox_name("Projects/Active", "Projects", "Work", "/"),
            "Work/Active"
        );
        assert_eq!(
            renamed_mailbox_name("Projects-old", "Projects", "Work", "/"),
            "Projects-old"
        );
    }

    #[test]
    fn metadata_command_quotes_values_and_rejects_injection() {
        assert_eq!(
            set_metadata_command(
                r#"Work "shared""#,
                &MailboxMetadata {
                    key: "/private/vendor/kolab/folder-type".to_string(),
                    value: Some(r#"event "default""#.to_string()),
                },
            )
            .unwrap(),
            r#"SETMETADATA "Work \"shared\"" ("/private/vendor/kolab/folder-type" "event \"default\"")"#
        );
        assert_eq!(
            set_metadata_command(
                "Work",
                &MailboxMetadata {
                    key: "/private/vendor/kolab/folder-type".to_string(),
                    value: None,
                },
            )
            .unwrap(),
            r#"SETMETADATA "Work" ("/private/vendor/kolab/folder-type" NIL)"#
        );
        assert!(set_metadata_command(
            "Work",
            &MailboxMetadata {
                key: "/private/vendor/kolab/folder-type\r\nNOOP".to_string(),
                value: None,
            },
        )
        .is_err());
        assert!(set_metadata_command(
            "Work",
            &MailboxMetadata {
                key: "/private/vendor/kolab/folder-type".to_string(),
                value: Some("event\r\nNOOP".to_string()),
            },
        )
        .is_err());
        assert_eq!(
            best_effort_metadata_command(
                "Work",
                &MailboxMetadata {
                    key: "/private/vendor/kolab/folder-type\r\nNOOP".to_string(),
                    value: Some("event".to_string()),
                },
            ),
            None
        );
    }

    #[test]
    fn acl_commands_quote_fields_and_reject_command_injection() {
        assert_eq!(
            set_acl_command(r#"Team "A""#, r#"user\name"#, "lrswipkxtea").unwrap(),
            r#"SETACL "Team \"A\"" "user\\name" "lrswipkxtea""#
        );
        assert_eq!(
            set_acl_command("Shared", "bob@example.com", "").unwrap(),
            r#"SETACL "Shared" "bob@example.com" """#
        );
        assert_eq!(
            delete_acl_command("Shared", "bob@example.com").unwrap(),
            r#"DELETEACL "Shared" "bob@example.com""#
        );
        assert!(set_acl_command("Shared", "bob@example.com\r\nNOOP", "lr").is_err());
        assert!(set_acl_command("Shared", "bob@example.com", "lr\r\nNOOP").is_err());
        assert!(delete_acl_command("Shared", "bob\0@example.com").is_err());
    }

    #[test]
    fn acl_response_collection_preserves_mailbox_entries_and_rights_order() {
        let mut input = concat!(
            "* MYRIGHTS \"Shared\" lrswipkxtea\r\n",
            "* ACL \"Shared\" \"alice@example.com\" lrswipkxtea \"bob@example.com\" lr\r\n",
            "* ACL \"Other\" \"ignored@example.com\" a\r\n",
        )
        .as_bytes();
        let mut collected = AclCommandResponses::default();

        while !input.is_empty() {
            let (remaining, response) = Response::from_bytes(input).unwrap();
            collect_acl_data_response(&response, "Shared", &mut collected);
            input = remaining;
        }

        assert_eq!(collected.my_rights.as_deref(), Some("lrswipkxtea"));
        assert_eq!(
            collected.entries,
            vec![
                MailboxAclEntry {
                    identifier: "alice@example.com".to_string(),
                    rights: "lrswipkxtea".to_string(),
                    mine: false,
                },
                MailboxAclEntry {
                    identifier: "bob@example.com".to_string(),
                    rights: "lr".to_string(),
                    mine: false,
                },
            ]
        );
    }

    #[test]
    fn acl_command_completion_ignores_advisory_status_and_requires_matching_tag() {
        let request_id = RequestId("A1".to_string());
        let (_, advisory) = Response::from_bytes(b"* NO [ALERT] mailbox is read-only\r\n").unwrap();
        assert!(acl_command_completion(&advisory, &request_id, "read ACL")
            .unwrap()
            .is_none());

        let (_, other_tag) = Response::from_bytes(b"A2 NO other command failed\r\n").unwrap();
        assert!(acl_command_completion(&other_tag, &request_id, "read ACL")
            .unwrap()
            .is_none());

        let (_, success) = Response::from_bytes(b"A1 OK ACL completed\r\n").unwrap();
        assert!(acl_command_completion(&success, &request_id, "read ACL")
            .unwrap()
            .is_some());

        let (_, rejected) = Response::from_bytes(b"A1 NO permission denied\r\n").unwrap();
        assert!(acl_command_completion(&rejected, &request_id, "read ACL").is_err());

        let (_, bye) = Response::from_bytes(b"* BYE server shutting down\r\n").unwrap();
        assert!(acl_command_completion(&bye, &request_id, "read ACL").is_err());
    }

    #[test]
    fn legacy_folder_attributes_are_lowercase_and_role_aware() {
        let attributes = legacy_name_attributes(&[
            NameAttribute::NoSelect,
            NameAttribute::Archive,
            NameAttribute::Extension(Cow::Borrowed("\\Subscribed")),
        ]);

        assert_eq!(attributes, vec!["\\noselect", "\\archive", "\\subscribed"]);
        assert_eq!(legacy_folder_role(&attributes), Some("archive".to_string()));
    }

    #[test]
    fn namespace_response_parser_preserves_groups_extensions_and_nil() {
        let namespaces = parse_namespace_response_line(
            r#"* NAMESPACE (("INbox/" "/" "X-PARAM" ("one" "two"))) (("Other Users/" "/")) NIL"#,
        )
        .unwrap();

        assert_eq!(namespaces.personal_prefix(), "INBOX/");
        assert_eq!(namespaces.personal[0].prefix, "INbox/");
        assert_eq!(namespaces.personal[0].delimiter.as_deref(), Some("/"));
        assert_eq!(
            namespaces.personal[0].extension,
            vec![
                LegacyNamespaceValue::String("X-PARAM".to_string()),
                LegacyNamespaceValue::List(vec![
                    LegacyNamespaceValue::String("one".to_string()),
                    LegacyNamespaceValue::String("two".to_string()),
                ]),
            ]
        );
        assert_eq!(namespaces.users[0].prefix, "Other Users/");
        assert!(namespaces.shared.is_empty());
    }

    #[test]
    fn namespace_response_parser_handles_quoted_escapes_and_rejects_trailing_data() {
        let namespaces =
            parse_namespace_response_line(r#"* NAMESPACE (("Shared\\\"" NIL)) NIL NIL"#).unwrap();
        assert_eq!(namespaces.personal[0].prefix, "Shared\\\"");
        assert_eq!(namespaces.personal[0].delimiter, None);

        assert!(
            parse_namespace_response_line(r#"* NAMESPACE (("" "/")) NIL NIL unexpected"#).is_err()
        );
        assert!(parse_namespace_response_line("* NAMESPACE ((\"\" \"/\") NIL NIL").is_err());
    }

    #[test]
    fn namespace_response_parser_accepts_synchronizing_and_non_synchronizing_literals() {
        let namespaces = parse_namespace_response_payload(
            b"(({5}\r\nINBOX {1+}\r\n/)) NIL ((\"Shared/\" \"/\"))\r\n",
            false,
        )
        .unwrap();

        assert_eq!(namespaces.personal[0].prefix, "INBOX");
        assert_eq!(namespaces.personal[0].delimiter.as_deref(), Some("/"));
        assert_eq!(namespaces.shared[0].prefix, "Shared/");
    }

    #[tokio::test]
    async fn namespace_response_reader_waits_for_matching_tag_across_partial_reads() {
        use tokio::io::AsyncWriteExt;

        let (client, mut server) = tokio::io::duplex(256);
        let writer = tokio::spawn(async move {
            server.write_all(b"* OK advisory\r\n* NAMES").await.unwrap();
            server
                .write_all(b"PACE ((\"\" \"/\")) NIL NIL\r\nA2 OK unrelated\r\n")
                .await
                .unwrap();
            server.write_all(b"A1 OK completed\r\n").await.unwrap();
        });
        let mut stream: BoxedImapIo = Box::new(client);

        let namespaces = read_namespace_response(&mut stream, &RequestId("A1".to_string()))
            .await
            .unwrap();
        writer.await.unwrap();
        assert_eq!(namespaces.personal[0].prefix, "");
        assert_eq!(namespaces.personal[0].delimiter.as_deref(), Some("/"));
    }

    #[tokio::test]
    async fn namespace_response_reader_ignores_tag_looking_lines_inside_literals() {
        use tokio::io::AsyncWriteExt;

        let response = concat!(
            "* NAMESPACE ((\"\" \"/\" \"X\" {12}\r\n",
            "A1 OK fake\r\n",
            ")) NIL NIL\r\n",
            "A1 OK completed\r\n",
        );
        let (client, mut server) = tokio::io::duplex(256);
        let writer = tokio::spawn(async move {
            server.write_all(response.as_bytes()).await.unwrap();
        });
        let mut stream: BoxedImapIo = Box::new(client);

        let namespaces = read_namespace_response(&mut stream, &RequestId("A1".to_string()))
            .await
            .unwrap();
        writer.await.unwrap();
        assert_eq!(
            namespaces.personal[0].extension,
            vec![
                LegacyNamespaceValue::String("X".to_string()),
                LegacyNamespaceValue::String("A1 OK fake\r\n".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn namespace_response_reader_ignores_namespace_prefix_inside_preceding_literal() {
        use tokio::io::AsyncWriteExt;

        let fake_namespace = b"header\r\n* NAMESPACE NIL NIL NIL";
        let mut response =
            format!("* 1 FETCH (BODY[] {{{}}}\r\n", fake_namespace.len()).into_bytes();
        response.extend_from_slice(fake_namespace);
        response.extend_from_slice(
            concat!(
                ")\r\n",
                "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n",
                "A1 OK completed\r\n",
            )
            .as_bytes(),
        );
        let (client, mut server) = tokio::io::duplex(512);
        let writer = tokio::spawn(async move {
            server.write_all(&response).await.unwrap();
        });
        let mut stream: BoxedImapIo = Box::new(client);

        let namespaces = read_namespace_response(&mut stream, &RequestId("A1".to_string()))
            .await
            .unwrap();
        writer.await.unwrap();
        assert_eq!(namespaces.personal[0].wire_prefix, "");
        assert_eq!(namespaces.personal[0].delimiter.as_deref(), Some("/"));
    }

    #[tokio::test]
    async fn namespace_response_reader_does_not_treat_status_text_braces_as_literal() {
        use tokio::io::AsyncWriteExt;

        let response = concat!(
            "* OK advisory {12}\r\n",
            "* NAMESPACE ((\"INBOX/\" \"/\")) NIL NIL\r\n",
            "A1 OK completed\r\n",
        );
        let (client, mut server) = tokio::io::duplex(256);
        let writer = tokio::spawn(async move {
            server.write_all(response.as_bytes()).await.unwrap();
        });
        let mut stream: BoxedImapIo = Box::new(client);

        let namespaces = read_namespace_response(&mut stream, &RequestId("A1".to_string()))
            .await
            .unwrap();
        writer.await.unwrap();
        assert_eq!(namespaces.personal[0].wire_prefix, "INBOX/");
        assert_eq!(namespaces.personal[0].delimiter.as_deref(), Some("/"));
    }

    #[test]
    fn modified_utf7_decoder_matches_mailso_folder_name_conversion() {
        assert_eq!(modified_utf7_to_utf8("Inbox"), "Inbox");
        assert_eq!(modified_utf7_to_utf8("R&D"), "R&D");
        assert_eq!(modified_utf7_to_utf8("R&-D"), "R&D");
        assert_eq!(modified_utf7_to_utf8("Envoy&AOk-"), "Envoyé");
        assert_eq!(modified_utf7_to_utf8("&ZeVnLIqe-"), "日本語");
        assert_eq!(modified_utf7_to_utf8("Broken&A-"), "Broken&A-");
    }

    #[test]
    fn modified_utf7_encoder_matches_imap_mailbox_wire_format() {
        for (decoded, encoded) in [
            ("Inbox", "Inbox"),
            ("R&D", "R&-D"),
            ("Envoyé", "Envoy&AOk-"),
            ("日本語", "&ZeVnLIqe-"),
            ("Emoji 😀", "Emoji &2D3eAA-"),
        ] {
            assert_eq!(modified_utf7_from_utf8(decoded), encoded);
            assert_eq!(modified_utf7_to_utf8(encoded), decoded);
        }
    }

    #[test]
    fn mailbox_decoder_preserves_utf8_mode_names_that_resemble_modified_utf7() {
        assert_eq!(imap_mailbox_to_utf8("R&-D", false), "R&D");
        assert_eq!(imap_mailbox_to_utf8("R&-D", true), "R&-D");
        assert_eq!(imap_mailbox_to_utf8("Envoy&AOk-", false), "Envoyé");
        assert_eq!(imap_mailbox_to_utf8("Envoy&AOk-", true), "Envoy&AOk-");
    }

    #[test]
    fn mailbox_wire_encoding_tracks_negotiated_utf8_mode() {
        assert_eq!(imap_mailbox_from_utf8("R&D", false), "R&-D");
        assert_eq!(imap_mailbox_from_utf8("R&D", true), "R&D");
        assert_eq!(imap_mailbox_from_utf8("Envoyé", false), "Envoy&AOk-");
        assert_eq!(imap_mailbox_from_utf8("Envoyé", true), "Envoyé");
    }

    #[test]
    fn utf8_negotiation_recognizes_accept_and_only_capabilities() {
        assert!(is_legacy_utf8_capability(&Capability::Atom(
            "utf8=accept".to_string()
        )));
        assert!(is_legacy_utf8_capability(&Capability::Atom(
            "UTF8=ONLY".to_string()
        )));
        assert!(!is_legacy_utf8_capability(&Capability::Atom(
            "ENABLE".to_string()
        )));
        assert!(!is_legacy_utf8_capability(&Capability::Imap4rev1));
    }

    #[test]
    fn extended_list_command_requests_legacy_status_and_special_use_data() {
        let command = legacy_list_command(
            "",
            false,
            &LegacyFolderListOptions {
                discover_subscriptions: true,
                list_extended: true,
                list_status: true,
                special_use: true,
                highest_modseq: true,
                append_limit: true,
                size: true,
                mailbox_id: true,
                utf8_mode: false,
            },
        )
        .unwrap();

        assert_eq!(
            command,
            "LIST \"\" \"*\" RETURN (SUBSCRIBED SPECIAL-USE STATUS (MESSAGES UNSEEN UIDNEXT UIDVALIDITY HIGHESTMODSEQ APPENDLIMIT SIZE MAILBOXID))"
        );
    }

    #[test]
    fn extended_list_responses_decode_names_status_and_optional_fields() {
        let mut input = concat!(
            "* LIST (\\Subscribed \\Archive) \"/\" \"Envoy&AOk-\"\r\n",
            "* STATUS \"Envoy&AOk-\" (MESSAGES 3 UNSEEN 1 UIDNEXT 4 UIDVALIDITY 5 ",
            "HIGHESTMODSEQ 7 APPENDLIMIT 100 SIZE 2048 MAILBOXID (folder-id))\r\n",
        )
        .as_bytes();
        let mut collected = LegacyListCommandResponses::default();
        while !input.is_empty() {
            let (remaining, response) = Response::from_bytes(input).unwrap();
            collect_legacy_list_response(&response, &mut collected, false);
            input = remaining;
        }
        for folder in &mut collected.folders {
            folder.status = collected.statuses.remove(&folder.full_name);
        }

        let folder = collected
            .folders
            .pop()
            .unwrap()
            .into_legacy_folder(HashMap::new(), "client-hash");
        assert_eq!(folder.full_name, "Envoyé");
        assert_eq!(folder.attributes, vec!["\\subscribed", "\\archive"]);
        assert_eq!(folder.total_emails, Some(3));
        assert_eq!(folder.unread_emails, Some(1));
        assert_eq!(folder.uid_next, Some(4));
        assert_eq!(folder.size, Some(2048));
        assert_eq!(folder.id.as_deref(), Some("Zm9sZGVyLWlk"));
        assert_eq!(folder.role.as_deref(), Some("archive"));
        assert!(folder.etag.is_some());
    }

    #[test]
    fn extended_list_status_accepts_append_limit_nil() {
        let (_, response) =
            Response::from_bytes(b"* STATUS \"INBOX\" (MESSAGES 1 APPENDLIMIT NIL)\r\n").unwrap();
        let mut collected = LegacyListCommandResponses::default();
        collect_legacy_list_response(&response, &mut collected, false);

        assert_eq!(
            collected
                .statuses
                .get("INBOX")
                .and_then(|status| status.total_emails),
            Some(1)
        );
    }

    #[test]
    fn extended_folder_status_command_is_capability_gated_and_safely_quoted() {
        let command = legacy_folder_status_command(
            "Work \"shared\"",
            &LegacyFolderStatusOptions {
                highest_modseq: true,
                append_limit: true,
                size: true,
                mailbox_id: true,
            },
        )
        .unwrap();
        assert_eq!(
            command,
            "STATUS \"Work \\\"shared\\\"\" (MESSAGES UNSEEN UIDNEXT UIDVALIDITY HIGHESTMODSEQ APPENDLIMIT SIZE MAILBOXID)"
        );

        assert_eq!(
            legacy_folder_status_command("INBOX", &LegacyFolderStatusOptions::default()).unwrap(),
            "STATUS \"INBOX\" (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)"
        );
        assert!(legacy_folder_status_command(
            "INBOX\r\nA1 LOGOUT",
            &LegacyFolderStatusOptions::default()
        )
        .is_err());
    }

    #[test]
    fn extended_folder_status_collects_optional_values_and_nil_append_limit() {
        let (_, response) = Response::from_bytes(
            concat!(
                "* STATUS \"Archive\" (MESSAGES 3 UNSEEN 1 UIDNEXT 4 UIDVALIDITY 5 ",
                "HIGHESTMODSEQ 7 APPENDLIMIT NIL SIZE 2048 MAILBOXID (folder-id))\r\n",
            )
            .as_bytes(),
        )
        .unwrap();
        let Response::MailboxData(MailboxDatum::Status { status, .. }) = response else {
            panic!("expected STATUS response");
        };
        let mut collected = ListedLegacyFolderStatus::default();
        collect_legacy_status_attributes(&status, &mut collected);

        assert_eq!(collected.total_emails, Some(3));
        assert_eq!(collected.unread_emails, Some(1));
        assert_eq!(collected.uid_next, Some(4));
        assert_eq!(collected.uid_validity, Some(5));
        assert_eq!(collected.highest_modseq, Some(7));
        assert_eq!(collected.append_limit, Some(0));
        assert_eq!(collected.size, Some(2048));
        assert_eq!(collected.mailbox_id.as_deref(), Some("Zm9sZGVyLWlk"));
    }

    #[test]
    fn folder_information_prefers_status_counts_and_emits_extended_values() {
        let status = ListedLegacyFolderStatus {
            total_emails: Some(3),
            uid_next: Some(4),
            uid_validity: Some(5),
            unread_emails: Some(1),
            highest_modseq: Some(7),
            append_limit: Some(10_485_760),
            size: Some(2048),
            mailbox_id: Some("Zm9sZGVyLWlk".to_string()),
        };
        let examined = async_imap::types::Mailbox {
            exists: 99,
            unseen: Some(42),
            ..Default::default()
        };

        let info =
            legacy_folder_information_from_mailboxes("Archive", &status, &examined, None, "client");

        assert_eq!(info.id.as_deref(), Some("Zm9sZGVyLWlk"));
        assert_eq!(info.total_emails, Some(3));
        assert_eq!(info.unread_emails, Some(1));
        assert_eq!(info.highest_modseq, Some(7));
        assert_eq!(info.append_limit, Some(10_485_760));
        assert_eq!(info.size, Some(2048));
    }

    #[test]
    fn generic_imap_completion_rejects_matching_list_and_quota_failures() {
        let request_id = RequestId("A1".to_string());
        let (_, list_no) = Response::from_bytes(b"A1 NO list rejected\r\n").unwrap();
        assert!(imap_command_completion(&list_no, &request_id, "list mailboxes").is_err());
        let (_, quota_bad) = Response::from_bytes(b"A1 BAD quota unsupported\r\n").unwrap();
        assert!(imap_command_completion(&quota_bad, &request_id, "read quota").is_err());
    }

    #[test]
    fn folder_metadata_special_use_takes_role_precedence() {
        assert_eq!(
            legacy_folder_role_with_metadata(
                "Archive",
                &["\\archive".to_string()],
                &HashMap::from([("/private/specialuse".to_string(), "\\Sent".to_string())]),
            ),
            Some("sent".to_string())
        );
        assert_eq!(
            legacy_folder_role_with_metadata("inbox", &[], &HashMap::new()),
            Some("inbox".to_string())
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
    fn message_list_search_criteria_filters_deleted_before_paging() {
        assert_eq!(
            legacy_message_list_search_criteria("", true).unwrap(),
            "UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria("", false).unwrap(),
            "ALL"
        );
    }

    #[test]
    fn server_uid_cache_skips_flag_dependent_searches() {
        assert!(legacy_message_list_uid_cache_eligible(""));
        assert!(legacy_message_list_uid_cache_eligible("subject=report"));
        assert!(!legacy_message_list_uid_cache_eligible("unseen"));
        assert!(!legacy_message_list_uid_cache_eligible(
            "subject=report&is=flagged"
        ));
        assert!(!legacy_message_list_uid_cache_eligible("is=read"));
    }

    #[test]
    fn server_uid_cache_key_matches_php_literal_plus_unicode_contract() {
        let options = LegacyMessageListQueryOptions {
            hide_deleted: true,
            fast_simple_search: true,
            permanent_filter: "",
            sort: None,
            utf8_mode: false,
            supports_within: false,
            supports_literal_plus: false,
        };
        let literal_options = LegacyMessageListQueryOptions {
            supports_literal_plus: true,
            ..options
        };

        assert_eq!(
            legacy_message_list_uid_cache_key("INBOX", "client-hash", "subject=réport", options)
                .unwrap(),
            "GetUIDS//client-hash/INBOX/SUBJECT \"réport\" UNDELETED"
        );
        assert_eq!(
            legacy_message_list_uid_cache_key(
                "INBOX",
                "client-hash",
                "subject=réport",
                literal_options
            )
            .unwrap(),
            "GetUIDS//client-hash/INBOX/SUBJECT {7}\r\nréport UNDELETED"
        );

        let literal_permanent_filter = LegacyMessageListQueryOptions {
            permanent_filter: "SUBJECT \"réport\"",
            ..literal_options
        };
        assert_eq!(
            legacy_message_list_uid_cache_key("INBOX", "client-hash", "", literal_permanent_filter)
                .unwrap(),
            "GetUIDS//client-hash/INBOX/UNDELETED SUBJECT \"réport\""
        );
    }

    #[tokio::test]
    async fn server_uid_cache_hit_uses_legacy_key_without_imap_query() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let cache = RecordingUidCache {
            returned_uids: Some(vec![9, 4]),
            gets: Mutex::new(Vec::new()),
            sets: Mutex::new(Vec::new()),
        };

        let result = legacy_message_list_visible_uids_cached(
            &mut session,
            "INBOX",
            "folder-etag",
            "client-hash",
            "subject=report",
            LegacyMessageListQueryOptions {
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort: Some("REVERSE DATE"),
                utf8_mode: false,
                supports_within: false,
                supports_literal_plus: false,
            },
            Some(&cache),
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(result, vec![9, 4]);
        assert_eq!(
            *cache.gets.lock().unwrap(),
            vec![(
                "GetUIDS/REVERSE DATE/client-hash/INBOX/SUBJECT \"report\" UNDELETED".to_string(),
                "folder-etag".to_string()
            )]
        );
        assert!(cache.sets.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn server_uid_cache_miss_queries_imap_and_populates_cache() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();
            let search = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(search, "A0002 UID SEARCH SUBJECT \"report\" UNDELETED\r\n");
            server_stream
                .write_all(b"* SEARCH 4 9\r\nA0002 OK searched\r\n")
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let cache = RecordingUidCache {
            returned_uids: None,
            gets: Mutex::new(Vec::new()),
            sets: Mutex::new(Vec::new()),
        };

        let result = legacy_message_list_visible_uids_cached(
            &mut session,
            "INBOX",
            "folder-etag",
            "client-hash",
            "subject=report",
            LegacyMessageListQueryOptions {
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort: None,
                utf8_mode: false,
                supports_within: false,
                supports_literal_plus: false,
            },
            Some(&cache),
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(result, vec![4, 9]);
        assert_eq!(
            *cache.sets.lock().unwrap(),
            vec![(
                "GetUIDS//client-hash/INBOX/SUBJECT \"report\" UNDELETED".to_string(),
                "folder-etag".to_string(),
                vec![4, 9]
            )]
        );
    }

    #[tokio::test]
    async fn limited_message_list_sort_uses_sequence_numbers() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();
            let sort = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(sort, "A0002 SORT (REVERSE DATE) UTF-8 9,8,7 UNDELETED\r\n");
            server_stream
                .write_all(b"* SORT 8 7 9\r\nA0002 OK sorted\r\n")
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };

        let ids = legacy_message_list_ids_with_settings_bounded(
            &mut session,
            "",
            LegacyMessageListQueryOptions {
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort: Some("REVERSE DATE"),
                utf8_mode: false,
                supports_within: false,
                supports_literal_plus: false,
            },
            None,
            false,
            Some("9,8,7"),
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(ids, vec![8, 7, 9]);
    }

    #[tokio::test]
    async fn limited_message_list_cache_warm_populates_next_request_keys() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let sort = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(sort, "A0002 UID SORT (REVERSE DATE) UTF-8 UNDELETED\r\n");
            server_stream
                .write_all(b"* SORT 49 50\r\nA0002 OK sorted\r\n")
                .await
                .unwrap();

            let thread = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(thread, "A0003 UID THREAD REFERENCES UTF-8 ALL\r\n");
            server_stream
                .write_all(b"* THREAD (49 50)\r\nA0003 OK threaded\r\n")
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let cache = StatefulUidCache::default();
        let request = LegacyMessageListRequest {
            mailbox: "INBOX".to_string(),
            offset: 0,
            limit: 10,
            search: "subject=report".to_string(),
            sort: String::new(),
            prev_uid_next: None,
            hide_deleted: true,
            fast_simple_search: true,
            permanent_filter: String::new(),
            message_list_limit: 10_000,
            use_threads: true,
            thread_uid: 0,
            thread_algorithm: "REFERENCES".to_string(),
        };
        let capabilities = ImapFetchMetadataCapabilities {
            supports_gmail_id: false,
            supports_object_id: false,
            supports_preview: false,
            supports_literal_plus: false,
            uses_utf8_search: false,
            supports_within: false,
            supports_multisearch: false,
            supports_sort: true,
            supports_sort_display: false,
            thread_algorithms: vec!["REFERENCES".to_string()],
        };

        warm_legacy_message_list_cache_in_session(
            &mut session,
            &request,
            "folder-etag",
            "client-hash",
            &capabilities,
            &cache,
        )
        .await
        .unwrap();
        server.await.unwrap();

        let cached = legacy_message_list_visible_uids_from_cache(
            "INBOX",
            "folder-etag",
            "client-hash",
            "",
            LegacyMessageListQueryOptions {
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort: Some("REVERSE DATE"),
                utf8_mode: false,
                supports_within: false,
                supports_literal_plus: false,
            },
            Some(&cache),
        )
        .await
        .unwrap();
        assert_eq!(cached, Some(vec![49, 50]));
        assert_eq!(
            cache
                .get_thread_map("ThreadsMap/REFERENCES/ALL/folder-etag")
                .await,
            Some(vec![vec![49, 50]])
        );
    }

    #[tokio::test]
    async fn limited_message_list_sort_rejects_oversized_response() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();
            let sort = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(sort, "A0002 SORT (REVERSE DATE) UTF-8 9,8,7 UNDELETED\r\n");
            server_stream
                .write_all(b"* SORT 9 8 7 6\r\nA0002 OK sorted\r\n")
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };

        let error = legacy_message_list_ids_with_settings_bounded(
            &mut session,
            "",
            LegacyMessageListQueryOptions {
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort: Some("REVERSE DATE"),
                utf8_mode: false,
                supports_within: false,
                supports_literal_plus: false,
            },
            Some(3),
            false,
            Some("9,8,7"),
        )
        .await
        .unwrap_err();
        server.await.unwrap();

        assert!(error.to_string().contains("too many UIDs"));
    }

    async fn read_scripted_imap_command(stream: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncWriteExt as _;

        let mut command = Vec::new();
        let mut buffer = [0_u8; 128];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0, "IMAP client closed before sending command");
            command.extend_from_slice(&buffer[..count]);
            if command.ends_with(b"\r\n") {
                return String::from_utf8(command).unwrap();
            }
            stream.flush().await.unwrap();
        }
    }

    #[tokio::test]
    async fn detailed_message_fetch_reads_capability_gated_object_email_id() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let fetch = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(fetch, "A0002 UID FETCH 41 (UID EMAILID)\r\n");
            server_stream
                .write_all(
                    b"* 6 FETCH (UID 40 EMAILID (Mwrongmessage))\r\n\
                      * 7 FETCH (UID 41 EMAILID (M6d99ac3275bb4e))\r\n\
                      * 7 FETCH (UID 41 FLAGS (\\Seen))\r\n\
                      A0002 OK completed\r\n",
                )
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let email_id = fetch_legacy_message_email_id(
            &mut session,
            41,
            &ImapFetchMetadataCapabilities {
                supports_gmail_id: false,
                supports_object_id: true,
                supports_preview: false,
                supports_literal_plus: false,
                uses_utf8_search: false,
                supports_within: false,
                supports_multisearch: false,
                supports_sort: false,
                supports_sort_display: false,
                thread_algorithms: Vec::new(),
            },
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(email_id.as_deref(), Some("M6d99ac3275bb4e"));
    }

    #[tokio::test]
    async fn draft_append_uses_seen_and_resolves_the_newest_message_id_uid() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let raw = b"Subject: Draft\r\n\r\nBody";
        let (client_stream, mut server_stream) = tokio::io::duplex(2048);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let append = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                append,
                format!("A0002 APPEND \"Drafts\" (\\Seen) {{{}}}\r\n", raw.len())
            );
            server_stream.write_all(b"+ Ready\r\n").await.unwrap();
            let mut literal = vec![0_u8; raw.len() + 2];
            server_stream.read_exact(&mut literal).await.unwrap();
            assert_eq!(&literal[..raw.len()], raw);
            assert_eq!(&literal[raw.len()..], b"\r\n");
            server_stream
                .write_all(b"A0002 OK [APPENDUID 9 43] appended\r\n")
                .await
                .unwrap();

            let select = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(select, "A0003 SELECT \"Drafts\"\r\n");
            server_stream
                .write_all(
                    b"* 2 EXISTS\r\n* OK [UIDVALIDITY 9] valid\r\nA0003 OK [READ-WRITE] selected\r\n",
                )
                .await
                .unwrap();

            let search = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                search,
                "A0004 UID SEARCH HEADER MESSAGE-ID \"draft@example.com\"\r\n"
            );
            server_stream
                .write_all(b"* SEARCH 41 43\r\nA0004 OK searched\r\n")
                .await
                .unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let uid =
            append_draft_message_in_session(&mut session, "Drafts", raw, Some("draft@example.com"))
                .await
                .unwrap();
        server.await.unwrap();

        assert_eq!(uid, DraftAppendAttempt::Saved(Some(43)));
    }

    #[tokio::test]
    async fn draft_append_stays_successful_when_post_commit_uid_lookup_fails() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let raw = b"Subject: Draft\r\n\r\nBody";
        let (client_stream, mut server_stream) = tokio::io::duplex(2048);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let append = read_scripted_imap_command(&mut server_stream).await;
            assert!(append.starts_with("A0002 APPEND \"Drafts\" (\\Seen) {"));
            server_stream.write_all(b"+ Ready\r\n").await.unwrap();
            let mut literal = vec![0_u8; raw.len() + 2];
            server_stream.read_exact(&mut literal).await.unwrap();
            server_stream
                .write_all(b"A0002 OK appended\r\n")
                .await
                .unwrap();

            let select = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(select, "A0003 SELECT \"Drafts\"\r\n");
            server_stream
                .write_all(b"A0003 NO temporarily unavailable\r\n")
                .await
                .unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let uid =
            append_draft_message_in_session(&mut session, "Drafts", raw, Some("draft@example.com"))
                .await
                .unwrap();
        server.await.unwrap();

        assert_eq!(uid, DraftAppendAttempt::Saved(None));
    }

    #[tokio::test]
    async fn detailed_message_fetch_reads_capability_gated_uid_correlated_preview() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let fetch = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(fetch, "A0002 UID FETCH 41 (UID PREVIEW)\r\n");
            server_stream
                .write_all(
                    b"* 6 FETCH (UID 40 PREVIEW \"Wrong message\")\r\n\
                      * 7 FETCH (UID 41 PREVIEW \"Requested preview\")\r\n\
                      * 7 FETCH (UID 41 FLAGS (\\Seen))\r\n\
                      A0002 OK completed\r\n",
                )
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let preview = fetch_legacy_message_preview(
            &mut session,
            41,
            &ImapFetchMetadataCapabilities {
                supports_gmail_id: false,
                supports_object_id: false,
                supports_preview: true,
                supports_literal_plus: false,
                uses_utf8_search: false,
                supports_within: false,
                supports_multisearch: false,
                supports_sort: false,
                supports_sort_display: false,
                thread_algorithms: Vec::new(),
            },
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(preview.as_deref(), Some("Requested preview"));
    }

    #[tokio::test]
    async fn message_list_fetch_prefers_correlated_object_email_ids_over_gmail_ids() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let fetch = read_scripted_imap_command(&mut server_stream).await;
            assert!(fetch.starts_with("A0002 UID FETCH 41,42 (UID FLAGS "));
            assert!(!fetch.contains("X-GM-MSGID"));
            server_stream
                .write_all(
                    b"* 99 FETCH (UID 99)\r\n\
                      * 1 FETCH (UID 41 FLAGS (\\Answered) RFC822.SIZE 123 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 1 FETCH (UID 41 FLAGS (\\Seen))\r\n\
                      * 2 FETCH (UID 42 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      A0002 OK fetched\r\n",
                )
                .await
                .unwrap();

            let email_ids = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(email_ids, "A0003 UID FETCH 41,42 (UID EMAILID)\r\n");
            server_stream
                .write_all(
                    b"* 3 FETCH (UID 99 EMAILID (Mwrongmessage))\r\n\
                      * 1 FETCH (UID 41 EMAILID (Mmessage41))\r\n\
                      * 1 FETCH (UID 41 FLAGS (\\Seen))\r\n\
                      * 2 FETCH (UID 42 EMAILID (Mmessage42))\r\n\
                      A0003 OK fetched\r\n",
                )
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let messages = fetch_legacy_message_list_summaries(
            &mut session,
            "INBOX",
            &[42, 41],
            LegacyMessageListFetchMode::Uids,
            &ImapFetchMetadataCapabilities {
                supports_gmail_id: true,
                supports_object_id: true,
                supports_preview: false,
                supports_literal_plus: false,
                uses_utf8_search: false,
                supports_within: false,
                supports_multisearch: false,
                supports_sort: false,
                supports_sort_display: false,
                thread_algorithms: Vec::new(),
            },
            &[],
            &[],
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(
            messages
                .iter()
                .map(|message| (message.uid, message.email_id.as_deref()))
                .collect::<Vec<_>>(),
            vec![(42, Some("Mmessage42")), (41, Some("Mmessage41"))]
        );
        assert_eq!(messages[1].size, 123);
        assert_eq!(messages[1].flags, vec!["\\answered"]);
    }

    #[tokio::test]
    async fn limited_sequence_message_list_maps_object_email_ids_by_uid() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let fetch = read_scripted_imap_command(&mut server_stream).await;
            assert!(fetch.starts_with("A0002 FETCH 2,1 (UID FLAGS "));
            server_stream
                .write_all(
                    b"* 99 FETCH (UID 99)\r\n\
                      * 1 FETCH (UID 41 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 1 FETCH (UID 41 FLAGS (\\Seen))\r\n\
                      * 2 FETCH (UID 42 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      A0002 OK fetched\r\n",
                )
                .await
                .unwrap();

            let email_ids = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(email_ids, "A0003 UID FETCH 41,42 (UID EMAILID)\r\n");
            server_stream
                .write_all(
                    b"* 1 FETCH (UID 41 EMAILID (Mmessage41))\r\n\
                      * 2 FETCH (UID 42 EMAILID (Mmessage42))\r\n\
                      A0003 OK fetched\r\n",
                )
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let messages = fetch_legacy_message_list_summaries(
            &mut session,
            "INBOX",
            &[2, 1],
            LegacyMessageListFetchMode::Sequences,
            &ImapFetchMetadataCapabilities {
                supports_gmail_id: false,
                supports_object_id: true,
                supports_preview: false,
                supports_literal_plus: false,
                uses_utf8_search: false,
                supports_within: false,
                supports_multisearch: false,
                supports_sort: false,
                supports_sort_display: false,
                thread_algorithms: Vec::new(),
            },
            &[],
            &[],
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(
            messages
                .iter()
                .map(|message| (message.uid, message.email_id.as_deref()))
                .collect::<Vec<_>>(),
            vec![(42, Some("Mmessage42")), (41, Some("Mmessage41"))]
        );
    }

    async fn run_scripted_visible_uid_search(
        search_value: &'static str,
        hide_deleted: bool,
        expected_criteria: &'static str,
        response: &'static str,
    ) -> Result<Vec<u32>> {
        run_scripted_visible_uid_search_with_capabilities(
            search_value,
            hide_deleted,
            false,
            expected_criteria,
            response,
        )
        .await
    }

    async fn run_scripted_visible_uid_search_with_capabilities(
        search_value: &'static str,
        hide_deleted: bool,
        supports_within: bool,
        expected_criteria: &'static str,
        response: &'static str,
    ) -> Result<Vec<u32>> {
        run_scripted_visible_uid_search_with_settings(
            search_value,
            hide_deleted,
            true,
            "",
            supports_within,
            expected_criteria,
            response,
        )
        .await
    }

    async fn run_scripted_visible_uid_search_with_settings(
        search_value: &'static str,
        hide_deleted: bool,
        fast_simple_search: bool,
        permanent_filter: &'static str,
        supports_within: bool,
        expected_criteria: &'static str,
        response: &'static str,
    ) -> Result<Vec<u32>> {
        run_scripted_message_list_uid_query(ScriptedMessageListUidQuery {
            search_value,
            hide_deleted,
            fast_simple_search,
            permanent_filter,
            sort: None,
            supports_within,
            expected_criteria,
            response,
        })
        .await
    }

    struct ScriptedMessageListUidQuery {
        search_value: &'static str,
        hide_deleted: bool,
        fast_simple_search: bool,
        permanent_filter: &'static str,
        sort: Option<&'static str>,
        supports_within: bool,
        expected_criteria: &'static str,
        response: &'static str,
    }

    async fn run_scripted_message_list_uid_query(
        query: ScriptedMessageListUidQuery,
    ) -> Result<Vec<u32>> {
        use tokio::io::AsyncWriteExt as _;

        let ScriptedMessageListUidQuery {
            search_value,
            hide_deleted,
            fast_simple_search,
            permanent_filter,
            sort,
            supports_within,
            expected_criteria,
            response,
        } = query;
        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let query = read_scripted_imap_command(&mut server_stream).await;
            let expected = match sort {
                Some(sort) => {
                    format!("A0002 UID SORT ({sort}) UTF-8 {expected_criteria}\r\n")
                }
                None => format!("A0002 UID SEARCH {expected_criteria}\r\n"),
            };
            assert_eq!(query, expected);
            server_stream.write_all(response.as_bytes()).await.unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let result = legacy_message_list_visible_uids_with_settings_bounded(
            &mut session,
            search_value,
            LegacyMessageListQueryOptions {
                hide_deleted,
                fast_simple_search,
                permanent_filter,
                sort,
                utf8_mode: true,
                supports_within,
                supports_literal_plus: false,
            },
            None,
        )
        .await;
        server.await.unwrap();
        result
    }

    async fn run_scripted_message_list_multisearch(
        search_value: &'static str,
        utf8_mode: bool,
        expected_command: &'static str,
        expected_literal: Option<&'static str>,
        response: &'static str,
    ) -> Result<Option<Vec<LegacyMessageListMailboxMatches>>> {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let query = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(query, expected_command);
            if let Some(expected_literal) = expected_literal {
                server_stream.write_all(b"+ continue\r\n").await.unwrap();
                let literal = read_scripted_imap_command(&mut server_stream).await;
                assert_eq!(literal, expected_literal);
            }
            server_stream.write_all(response.as_bytes()).await.unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let result = legacy_message_list_multisearch_matches(
            &mut session,
            "INBOX",
            search_value,
            LegacyMessageListQueryOptions {
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort: None,
                utf8_mode,
                supports_within: false,
                supports_literal_plus: false,
            },
            true,
        )
        .await;
        server.await.unwrap();
        result
    }

    #[tokio::test]
    async fn message_list_uid_search_collects_ids_and_validates_success_completion() {
        assert_eq!(
            run_scripted_visible_uid_search(
                "",
                true,
                "UNDELETED",
                "* SEARCH 105 74 99\r\nA0002 OK searched\r\n",
            )
            .await
            .unwrap(),
            vec![105, 74, 99]
        );
    }

    #[tokio::test]
    async fn message_list_multisearch_collects_mailbox_correlated_counts() {
        let matches = run_scripted_message_list_multisearch(
            "in=subtree&subject=quarterly",
            true,
            "A0002 ESEARCH IN (subtree \"INBOX\") RETURN (COUNT) \
             SUBJECT \"quarterly\" UNDELETED\r\n",
            None,
            "* ESEARCH UID ALL 99 COUNT 1\r\n\
             * ESEARCH (TAG \"OTHER\" MAILBOX \"Ignored\" UIDVALIDITY 1) \
             UID COUNT 1\r\n\
             * ESEARCH (TAG \"A0002\" MAILBOX \"Projects \\\"Red\\\"\" UIDVALIDITY 42) \
             UID COUNT 3\r\n\
             * ESEARCH (TAG \"A0002\" MAILBOX Archive UIDVALIDITY 88) \
             UID COUNT 2\r\n\
             A0002 OK searched\r\n",
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].mailbox, "Projects \"Red\"");
        assert_eq!(matches[0].uid_validity, 42);
        assert_eq!(matches[0].count, 3);
        assert_eq!(matches[1].mailbox, "Archive");
        assert_eq!(matches[1].count, 2);
    }

    #[tokio::test]
    async fn message_list_multisearch_frames_unicode_literals_and_allows_no_matches() {
        let matches = run_scripted_message_list_multisearch(
            "in=subtree-one&subject=café",
            false,
            "A0002 ESEARCH IN (subtree-one \"INBOX\") RETURN (COUNT) \
             CHARSET UTF-8 SUBJECT {5}\r\n",
            Some("café UNDELETED\r\n"),
            "A0002 OK searched\r\n",
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn message_list_multisearch_is_capability_gated() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let matches = legacy_message_list_multisearch_matches(
            &mut session,
            "INBOX",
            "in=subtree&subject=test",
            LegacyMessageListQueryOptions {
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort: None,
                utf8_mode: true,
                supports_within: false,
                supports_literal_plus: false,
            },
            false,
        )
        .await
        .unwrap();
        assert_eq!(matches, None);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn message_list_multisearch_rejects_missing_and_duplicate_correlators() {
        let missing = run_scripted_message_list_multisearch(
            "in=mailboxes",
            true,
            "A0002 ESEARCH IN (mailboxes \"INBOX\") RETURN (COUNT) UNDELETED\r\n",
            None,
            "* ESEARCH (TAG \"A0002\" UIDVALIDITY 1) UID COUNT 1\r\n\
             A0002 OK searched\r\n",
        )
        .await
        .unwrap_err();
        assert!(missing.to_string().contains("without MAILBOX"));

        let duplicate = run_scripted_message_list_multisearch(
            "in=mailboxes",
            true,
            "A0002 ESEARCH IN (mailboxes \"INBOX\") RETURN (COUNT) UNDELETED\r\n",
            None,
            "* ESEARCH (TAG \"A0002\" MAILBOX INBOX UIDVALIDITY 1) UID COUNT 1\r\n\
             * ESEARCH (TAG \"A0002\" MAILBOX INBOX UIDVALIDITY 1) UID COUNT 1\r\n\
             A0002 OK searched\r\n",
        )
        .await
        .unwrap_err();
        assert!(duplicate.to_string().contains("duplicate mailbox"));
    }

    #[tokio::test]
    async fn message_list_uid_search_sends_compiled_search_criteria() {
        assert_eq!(
            run_scripted_visible_uid_search(
                "from:alice is:unseen",
                true,
                "FROM \"alice\" UNSEEN UNDELETED",
                "* SEARCH 9 3\r\nA0002 OK searched\r\n",
            )
            .await
            .unwrap(),
            vec![9, 3]
        );
    }

    #[tokio::test]
    async fn message_list_uid_search_sends_within_capability_criteria() {
        assert_eq!(
            run_scripted_visible_uid_search_with_capabilities(
                "older=3600",
                true,
                true,
                "OLDER 3600 UNDELETED",
                "* SEARCH 11\r\nA0002 OK searched\r\n",
            )
            .await
            .unwrap(),
            vec![11]
        );
    }

    #[tokio::test]
    async fn message_list_uid_search_uses_configured_search_settings() {
        assert_eq!(
            run_scripted_visible_uid_search_with_settings(
                "needle",
                true,
                false,
                "NOT FLAGGED",
                false,
                "TEXT \"needle\" UNDELETED NOT FLAGGED",
                "* SEARCH 13\r\nA0002 OK searched\r\n",
            )
            .await
            .unwrap(),
            vec![13]
        );
    }

    #[tokio::test]
    async fn message_list_uid_sort_preserves_server_order() {
        assert_eq!(
            run_scripted_message_list_uid_query(ScriptedMessageListUidQuery {
                search_value: "from:alice",
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort: Some("FROM REVERSE DATE"),
                supports_within: false,
                expected_criteria: "FROM \"alice\" UNDELETED",
                response: "* UID SORT 74 105 99\r\nA0002 OK sorted\r\n",
            })
            .await
            .unwrap(),
            vec![74, 105, 99]
        );
    }

    #[tokio::test]
    async fn message_list_preview_fetch_collects_utf8_and_skips_nil() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let query = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(query, "A0002 UID FETCH 9,11 (UID PREVIEW)\r\n");
            server_stream
                .write_all(
                    "* 1 FETCH (UID 8 PREVIEW \"Unsolicited preview\")\r\n\
                     * 2 FETCH (UID 9 PREVIEW \"Café preview\")\r\n\
                     * 3 FETCH (UID 11 PREVIEW NIL)\r\n\
                     A0002 OK fetched\r\n"
                        .as_bytes(),
                )
                .await
                .unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let (_, previews) = fetch_legacy_message_email_ids_and_previews(
            &mut session,
            &[9, 11],
            false,
            true,
            "fetch legacy message-list previews",
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(previews.get(&9).map(String::as_str), Some("Café preview"));
        assert!(!previews.contains_key(&11));
        assert!(!previews.contains_key(&8));
    }

    #[tokio::test]
    async fn message_list_thread_fetch_flattens_top_level_threads() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let query = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(query, "A0002 UID THREAD REFERENCES UTF-8 ALL\r\n");
            server_stream
                .write_all(
                    b"* THREAD (2)(3 6 (4 23)(44 7 96))\r\n\
                      A0002 OK threaded\r\n",
                )
                .await
                .unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let threads = fetch_legacy_message_threads(&mut session, "REFERENCES")
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(threads, vec![vec![2], vec![3, 6, 4, 23, 44, 7, 96]]);
    }

    #[tokio::test]
    async fn message_list_thread_failure_degrades_to_empty_map_and_keeps_session_aligned() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let thread = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(thread, "A0002 UID THREAD REFERENCES UTF-8 ALL\r\n");
            server_stream
                .write_all(b"A0002 NO threading unavailable\r\n")
                .await
                .unwrap();

            let noop = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(noop, "A0003 NOOP\r\n");
            server_stream.write_all(b"A0003 OK noop\r\n").await.unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let threads = fetch_legacy_message_threads_compat(&mut session, "REFERENCES").await;
        assert!(threads.is_empty());
        session.noop().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn conditional_message_list_stops_after_matching_folder_etag() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let capability = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(capability, "A0002 CAPABILITY\r\n");
            server_stream
                .write_all(b"* CAPABILITY IMAP4rev1\r\nA0002 OK capability\r\n")
                .await
                .unwrap();

            let status = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                status,
                "A0003 STATUS \"INBOX\" (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)\r\n"
            );
            server_stream
                .write_all(
                    b"* STATUS \"INBOX\" (MESSAGES 6 UNSEEN 3 UIDNEXT 13 UIDVALIDITY 1)\r\n\
                      A0003 OK status\r\n",
                )
                .await
                .unwrap();

            let examine = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(examine, "A0004 EXAMINE \"INBOX\"\r\n");
            server_stream
                .write_all(
                    b"* FLAGS (\\Seen \\Deleted)\r\n\
                      * 6 EXISTS\r\n\
                      * 0 RECENT\r\n\
                      * OK [UIDVALIDITY 1] valid\r\n\
                      * OK [UIDNEXT 13] next\r\n\
                      * OK [PERMANENTFLAGS (\\Seen \\Deleted)] flags\r\n\
                      A0004 OK [READ-ONLY] examined\r\n",
                )
                .await
                .unwrap();

            let logout = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(logout, "A0005 LOGOUT\r\n");
            server_stream
                .write_all(b"* BYE logout\r\nA0005 OK logout\r\n")
                .await
                .unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let folder_etag =
            legacy_folder_etag("INBOX", 6, Some(13), Some(1), Some(3), None, "client-hash");
        let result = legacy_message_list_in_session_if_changed(
            &mut session,
            LegacyMessageListRequest {
                mailbox: "INBOX".to_string(),
                offset: 0,
                limit: 50,
                search: String::new(),
                sort: String::new(),
                prev_uid_next: Some(10),
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: String::new(),
                message_list_limit: 10_000,
                use_threads: false,
                thread_uid: 0,
                thread_algorithm: String::new(),
            },
            "client-hash",
            ImapFetchMetadataCapabilities {
                supports_gmail_id: false,
                supports_object_id: false,
                supports_preview: false,
                supports_literal_plus: false,
                uses_utf8_search: false,
                supports_within: false,
                supports_multisearch: false,
                supports_sort: false,
                supports_sort_display: false,
                thread_algorithms: Vec::new(),
            },
            None,
            Some(&folder_etag),
        )
        .await
        .unwrap();

        assert_eq!(result, None);
        session.logout().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn message_list_multisearch_fetches_a_stable_page_across_mailboxes() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            for tag in ["A0002", "A0003"] {
                let capability = read_scripted_imap_command(&mut server_stream).await;
                assert_eq!(capability, format!("{tag} CAPABILITY\r\n"));
                server_stream
                    .write_all(
                        format!(
                            "* CAPABILITY IMAP4rev1 MULTISEARCH OBJECTID SORT THREAD=REFERENCES\r\n\
                             {tag} OK capability\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }

            let status = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                status,
                "A0004 STATUS \"INBOX\" (MESSAGES UNSEEN UIDNEXT UIDVALIDITY MAILBOXID)\r\n"
            );
            server_stream
                .write_all(
                    b"* STATUS \"INBOX\" (MESSAGES 0 UNSEEN 0 UIDNEXT 1 UIDVALIDITY 1 MAILBOXID (Minbox))\r\n\
                      A0004 OK status\r\n",
                )
                .await
                .unwrap();

            let examine = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(examine, "A0005 EXAMINE \"INBOX\"\r\n");
            server_stream
                .write_all(
                    b"* FLAGS (\\Seen \\Deleted)\r\n\
                      * 0 EXISTS\r\n\
                      * 0 RECENT\r\n\
                      * OK [UIDVALIDITY 1] valid\r\n\
                      * OK [UIDNEXT 1] next\r\n\
                      * OK [PERMANENTFLAGS (\\Seen \\Deleted)] flags\r\n\
                      A0005 OK [READ-ONLY] examined\r\n",
                )
                .await
                .unwrap();

            let multisearch = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                multisearch,
                "A0006 ESEARCH IN (subtree \"INBOX\") RETURN (COUNT) \
                 SUBJECT \"report\" UNDELETED\r\n"
            );
            server_stream
                .write_all(
                    b"* ESEARCH (TAG \"A0006\" MAILBOX Projects UIDVALIDITY 42) \
                      UID COUNT 9\r\n\
                      * ESEARCH (TAG \"A0006\" MAILBOX Archive UIDVALIDITY 88) \
                      UID COUNT 2\r\n\
                      A0006 OK searched\r\n",
                )
                .await
                .unwrap();

            let examine_archive = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(examine_archive, "A0007 EXAMINE \"Archive\"\r\n");
            server_stream
                .write_all(
                    b"* 3 EXISTS\r\n\
                      * 0 RECENT\r\n\
                      * OK [UIDVALIDITY 88] valid\r\n\
                      A0007 OK [READ-ONLY] examined\r\n",
                )
                .await
                .unwrap();

            let search_archive = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                search_archive,
                "A0008 UID SEARCH SUBJECT \"report\" UNDELETED\r\n"
            );
            server_stream
                .write_all(b"* SEARCH 2 4\r\nA0008 OK searched\r\n")
                .await
                .unwrap();

            let fetch_archive = read_scripted_imap_command(&mut server_stream).await;
            assert!(fetch_archive.starts_with("A0009 UID FETCH 2 ("));
            server_stream
                .write_all(
                    b"* 99 FETCH (UID 99 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 1 FETCH (UID 2 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      A0009 OK fetched\r\n",
                )
                .await
                .unwrap();

            let archive_email_ids = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(archive_email_ids, "A0010 UID FETCH 2 (UID EMAILID)\r\n");
            server_stream
                .write_all(
                    b"* 1 FETCH (UID 2 EMAILID (Marchive2))\r\n\
                      A0010 OK fetched\r\n",
                )
                .await
                .unwrap();

            let examine_projects = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(examine_projects, "A0011 EXAMINE \"Projects\"\r\n");
            server_stream
                .write_all(
                    b"* 9 EXISTS\r\n\
                      * 0 RECENT\r\n\
                      * OK [UIDVALIDITY 42] valid\r\n\
                      A0011 OK [READ-ONLY] examined\r\n",
                )
                .await
                .unwrap();

            let search_projects = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                search_projects,
                "A0012 UID SEARCH SUBJECT \"report\" UNDELETED\r\n"
            );
            server_stream
                .write_all(
                    b"* SEARCH 10 11 12 13 14 15 16 17 18\r\n\
                      A0012 OK searched\r\n",
                )
                .await
                .unwrap();

            let fetch_projects = read_scripted_imap_command(&mut server_stream).await;
            assert!(fetch_projects.starts_with("A0013 UID FETCH 10,11,12,13,14,15,16,17,18 ("));
            server_stream
                .write_all(
                    b"* 1 FETCH (UID 10 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 2 FETCH (UID 11 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 3 FETCH (UID 12 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 4 FETCH (UID 13 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 5 FETCH (UID 14 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 6 FETCH (UID 15 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 7 FETCH (UID 16 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 8 FETCH (UID 17 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 9 FETCH (UID 18 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      A0013 OK fetched\r\n",
                )
                .await
                .unwrap();

            let project_email_ids = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                project_email_ids,
                "A0014 UID FETCH 10,11,12,13,14,15,16,17,18 (UID EMAILID)\r\n"
            );
            server_stream
                .write_all(
                    b"* 1 FETCH (UID 10 EMAILID (Mproject10))\r\n\
                      * 2 FETCH (UID 11 EMAILID (Mproject11))\r\n\
                      * 3 FETCH (UID 12 EMAILID (Mproject12))\r\n\
                      * 4 FETCH (UID 13 EMAILID (Mproject13))\r\n\
                      * 5 FETCH (UID 14 EMAILID (Mproject14))\r\n\
                      * 6 FETCH (UID 15 EMAILID (Mproject15))\r\n\
                      * 7 FETCH (UID 16 EMAILID (Mproject16))\r\n\
                      * 8 FETCH (UID 17 EMAILID (Mproject17))\r\n\
                      * 9 FETCH (UID 18 EMAILID (Mproject18))\r\n\
                      A0014 OK fetched\r\n",
                )
                .await
                .unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let capabilities = imap_fetch_metadata_capabilities(&mut session)
            .await
            .unwrap();
        let result = legacy_message_list_in_session(
            &mut session,
            LegacyMessageListRequest {
                mailbox: "INBOX".to_string(),
                offset: 1,
                limit: 10,
                search: "in=subtree&subject=report".to_string(),
                sort: "FROM".to_string(),
                prev_uid_next: None,
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: String::new(),
                message_list_limit: 10_000,
                use_threads: true,
                thread_uid: 0,
                thread_algorithm: "REFERENCES".to_string(),
            },
            "client-hash",
            capabilities,
            None,
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(result.total_emails, 11);
        assert_eq!(result.total_threads, None);
        assert_eq!(result.sort, "");
        assert_eq!(
            result
                .messages
                .iter()
                .map(|message| {
                    (
                        message.folder.as_str(),
                        message.uid,
                        message.email_id.as_deref(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                ("Archive", 2, Some("Marchive2")),
                ("Projects", 18, Some("Mproject18")),
                ("Projects", 17, Some("Mproject17")),
                ("Projects", 16, Some("Mproject16")),
                ("Projects", 15, Some("Mproject15")),
                ("Projects", 14, Some("Mproject14")),
                ("Projects", 13, Some("Mproject13")),
                ("Projects", 12, Some("Mproject12")),
                ("Projects", 11, Some("Mproject11")),
                ("Projects", 10, Some("Mproject10")),
            ]
        );
    }

    #[tokio::test]
    async fn message_list_multisearch_rejects_missing_requested_fetch_uid() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(2048);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let examine = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(examine, "A0002 EXAMINE \"Archive\"\r\n");
            server_stream
                .write_all(
                    b"* 2 EXISTS\r\n\
                      * 0 RECENT\r\n\
                      * OK [UIDVALIDITY 88] valid\r\n\
                      A0002 OK [READ-ONLY] examined\r\n",
                )
                .await
                .unwrap();

            let search = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(search, "A0003 UID SEARCH SUBJECT \"report\" UNDELETED\r\n");
            server_stream
                .write_all(b"* SEARCH 2 4\r\nA0003 OK searched\r\n")
                .await
                .unwrap();

            let fetch = read_scripted_imap_command(&mut server_stream).await;
            assert!(fetch.starts_with("A0004 UID FETCH 2,4 ("));
            server_stream
                .write_all(
                    b"* 1 FETCH (UID 2)\r\n\
                      A0004 OK fetched\r\n",
                )
                .await
                .unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let result = fetch_legacy_message_list_multisearch_page(
            &mut session,
            &[LegacyMessageListMailboxPage {
                mailbox: "Archive".to_string(),
                uid_validity: 88,
                expected_count: 2,
                offset: 0,
                limit: 2,
            }],
            "in=subtree&subject=report",
            LegacyMessageListQueryOptions {
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort: None,
                utf8_mode: false,
                supports_within: false,
                supports_literal_plus: false,
            },
            &ImapFetchMetadataCapabilities {
                supports_gmail_id: false,
                supports_object_id: false,
                supports_preview: false,
                supports_literal_plus: false,
                uses_utf8_search: false,
                supports_within: false,
                supports_multisearch: true,
                supports_sort: false,
                supports_sort_display: false,
                thread_algorithms: Vec::new(),
            },
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert!(result
            .to_string()
            .contains("changed while fetching Archive"));
    }

    #[tokio::test]
    async fn message_list_multisearch_rejects_large_uid_enumeration_before_imap_work() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();
        });
        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let result = fetch_legacy_message_list_multisearch_page(
            &mut session,
            &[LegacyMessageListMailboxPage {
                mailbox: "Archive".to_string(),
                uid_validity: 88,
                expected_count: MULTISEARCH_UID_ENUMERATION_LIMIT + 1,
                offset: 0,
                limit: 1,
            }],
            "in=subtree&subject=report",
            LegacyMessageListQueryOptions {
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort: None,
                utf8_mode: false,
                supports_within: false,
                supports_literal_plus: false,
            },
            &ImapFetchMetadataCapabilities {
                supports_gmail_id: false,
                supports_object_id: false,
                supports_preview: false,
                supports_literal_plus: false,
                uses_utf8_search: false,
                supports_within: false,
                supports_multisearch: true,
                supports_sort: false,
                supports_sort_display: false,
                thread_algorithms: Vec::new(),
            },
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert!(result.to_string().contains("too many matching UIDs"));
    }

    #[tokio::test]
    async fn message_list_threading_selects_representatives_and_populates_metadata() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            for tag in ["A0002", "A0003"] {
                let capability = read_scripted_imap_command(&mut server_stream).await;
                assert_eq!(capability, format!("{tag} CAPABILITY\r\n"));
                server_stream
                    .write_all(
                        format!(
                            "* CAPABILITY IMAP4rev1 THREAD=REFERENCES\r\n\
                             {tag} OK capability\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }

            let status = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                status,
                "A0004 STATUS \"INBOX\" (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)\r\n"
            );
            server_stream
                .write_all(
                    b"* STATUS \"INBOX\" (MESSAGES 6 UNSEEN 3 UIDNEXT 13 UIDVALIDITY 1)\r\n\
                      A0004 OK status\r\n",
                )
                .await
                .unwrap();

            let examine = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(examine, "A0005 EXAMINE \"INBOX\"\r\n");
            server_stream
                .write_all(
                    b"* FLAGS (\\Seen \\Deleted)\r\n\
                      * 6 EXISTS\r\n\
                      * 0 RECENT\r\n\
                      * OK [UIDVALIDITY 1] valid\r\n\
                      * OK [UIDNEXT 13] next\r\n\
                      * OK [PERMANENTFLAGS (\\Seen \\Deleted)] flags\r\n\
                      A0005 OK [READ-ONLY] examined\r\n",
                )
                .await
                .unwrap();

            let initial_search = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(initial_search, "A0006 UID SEARCH UNDELETED\r\n");
            server_stream
                .write_all(b"* SEARCH 7 8 9 10 11 12\r\nA0006 OK searched\r\n")
                .await
                .unwrap();

            let thread = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(thread, "A0007 UID THREAD REFERENCES UTF-8 ALL\r\n");
            server_stream
                .write_all(
                    b"* THREAD (7 8 9)(10 12)(11)\r\n\
                      A0007 OK threaded\r\n",
                )
                .await
                .unwrap();

            let unseen = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(unseen, "A0008 UID SEARCH UNSEEN UNDELETED\r\n");
            server_stream
                .write_all(b"* SEARCH 8 11 12\r\nA0008 OK searched\r\n")
                .await
                .unwrap();

            let fetch = read_scripted_imap_command(&mut server_stream).await;
            assert!(fetch.starts_with("A0009 UID FETCH 9,11,12 ("));
            server_stream
                .write_all(
                    b"* 1 FETCH (UID 9 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 2 FETCH (UID 11 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 3 FETCH (UID 12 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      A0009 OK fetched\r\n",
                )
                .await
                .unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let capabilities = imap_fetch_metadata_capabilities(&mut session)
            .await
            .unwrap();
        let result = legacy_message_list_in_session(
            &mut session,
            LegacyMessageListRequest {
                mailbox: "INBOX".to_string(),
                offset: 0,
                limit: 10,
                search: String::new(),
                sort: String::new(),
                prev_uid_next: None,
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: String::new(),
                message_list_limit: 10_000,
                use_threads: true,
                thread_uid: 0,
                thread_algorithm: "REFERENCES".to_string(),
            },
            "client-hash",
            capabilities,
            None,
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(result.total_emails, 3);
        assert_eq!(result.total_threads, Some(3));
        assert_eq!(
            result
                .messages
                .iter()
                .map(|message| message.uid)
                .collect::<Vec<_>>(),
            vec![12, 11, 9]
        );
        assert_eq!(result.messages[0].threads, vec![10, 12]);
        assert_eq!(result.messages[0].thread_unseen, vec![12]);
        assert_eq!(result.messages[1].threads, vec![11]);
        assert_eq!(result.messages[1].thread_unseen, vec![11]);
        assert_eq!(result.messages[2].threads, vec![7, 8, 9]);
        assert_eq!(result.messages[2].thread_unseen, vec![8]);
    }

    #[tokio::test]
    async fn large_message_list_uses_limited_sequence_sort_and_skips_threads() {
        use tokio::io::AsyncWriteExt as _;

        let candidates = legacy_message_list_optimized_sequence_ids(10_000, 0, 10, true);
        let candidate_set = legacy_sequence_set_preserving_order(&candidates).unwrap();
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            for tag in ["A0002", "A0003"] {
                let capability = read_scripted_imap_command(&mut server_stream).await;
                assert_eq!(capability, format!("{tag} CAPABILITY\r\n"));
                server_stream
                    .write_all(
                        format!(
                            "* CAPABILITY IMAP4rev1 SORT THREAD=REFERENCES\r\n\
                             {tag} OK capability\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }

            let status = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                status,
                "A0004 STATUS \"INBOX\" (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)\r\n"
            );
            server_stream
                .write_all(
                    b"* STATUS \"INBOX\" (MESSAGES 10000 UNSEEN 3 UIDNEXT 50001 UIDVALIDITY 1)\r\n\
                      A0004 OK status\r\n",
                )
                .await
                .unwrap();

            let examine = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(examine, "A0005 EXAMINE \"INBOX\"\r\n");
            server_stream
                .write_all(
                    b"* FLAGS (\\Seen \\Deleted)\r\n\
                      * 10000 EXISTS\r\n\
                      * 0 RECENT\r\n\
                      * OK [UIDVALIDITY 1] valid\r\n\
                      * OK [UIDNEXT 50001] next\r\n\
                      * OK [PERMANENTFLAGS (\\Seen \\Deleted)] flags\r\n\
                      A0005 OK [READ-ONLY] examined\r\n",
                )
                .await
                .unwrap();

            let sort = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                sort,
                format!("A0006 SORT (REVERSE DATE) UTF-8 {candidate_set} UNDELETED\r\n")
            );
            server_stream
                .write_all(b"* SORT 9998 10000 9999\r\nA0006 OK sorted\r\n")
                .await
                .unwrap();

            let fetch = read_scripted_imap_command(&mut server_stream).await;
            assert!(fetch.starts_with("A0007 FETCH 9998,10000,9999 ("));
            server_stream
                .write_all(
                    b"* 10000 FETCH (UID 50000 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 9999 FETCH (UID 49999 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 9998 FETCH (UID 49998 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      A0007 OK fetched\r\n",
                )
                .await
                .unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let capabilities = imap_fetch_metadata_capabilities(&mut session)
            .await
            .unwrap();
        let result = legacy_message_list_in_session(
            &mut session,
            LegacyMessageListRequest {
                mailbox: "INBOX".to_string(),
                offset: 0,
                limit: 10,
                search: String::new(),
                sort: String::new(),
                prev_uid_next: None,
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: String::new(),
                message_list_limit: 10_000,
                use_threads: true,
                thread_uid: 0,
                thread_algorithm: "REFERENCES".to_string(),
            },
            "client-hash",
            capabilities,
            None,
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(result.total_emails, 10_000);
        assert_eq!(result.total_threads, None);
        assert_eq!(result.sort, "REVERSE DATE");
        assert!(result.limited);
        assert_eq!(
            result
                .messages
                .iter()
                .map(|message| message.uid)
                .collect::<Vec<_>>(),
            vec![49_998, 50_000, 49_999]
        );
        assert!(result
            .messages
            .iter()
            .all(|message| message.threads.is_empty()));
    }

    #[tokio::test]
    async fn large_message_list_full_uid_cache_hit_bypasses_limiting() {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            for tag in ["A0002", "A0003"] {
                let capability = read_scripted_imap_command(&mut server_stream).await;
                assert_eq!(capability, format!("{tag} CAPABILITY\r\n"));
                server_stream
                    .write_all(
                        format!(
                            "* CAPABILITY IMAP4rev1 SORT\r\n\
                             {tag} OK capability\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }

            let status = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(
                status,
                "A0004 STATUS \"INBOX\" (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)\r\n"
            );
            server_stream
                .write_all(
                    b"* STATUS \"INBOX\" (MESSAGES 10000 UNSEEN 3 UIDNEXT 50001 UIDVALIDITY 1)\r\n\
                      A0004 OK status\r\n",
                )
                .await
                .unwrap();

            let examine = read_scripted_imap_command(&mut server_stream).await;
            assert_eq!(examine, "A0005 EXAMINE \"INBOX\"\r\n");
            server_stream
                .write_all(
                    b"* FLAGS (\\Seen \\Deleted)\r\n\
                      * 10000 EXISTS\r\n\
                      * 0 RECENT\r\n\
                      * OK [UIDVALIDITY 1] valid\r\n\
                      * OK [UIDNEXT 50001] next\r\n\
                      * OK [PERMANENTFLAGS (\\Seen \\Deleted)] flags\r\n\
                      A0005 OK [READ-ONLY] examined\r\n",
                )
                .await
                .unwrap();

            let fetch = read_scripted_imap_command(&mut server_stream).await;
            assert!(fetch.starts_with("A0006 UID FETCH 49999,50000 ("));
            server_stream
                .write_all(
                    b"* 9999 FETCH (UID 49999 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      * 10000 FETCH (UID 50000 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0))\r\n\
                      A0006 OK fetched\r\n",
                )
                .await
                .unwrap();
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let capabilities = imap_fetch_metadata_capabilities(&mut session)
            .await
            .unwrap();
        let cache = RecordingUidCache {
            returned_uids: Some(vec![50_000, 49_999]),
            gets: Mutex::new(Vec::new()),
            sets: Mutex::new(Vec::new()),
        };
        let result = legacy_message_list_in_session(
            &mut session,
            LegacyMessageListRequest {
                mailbox: "INBOX".to_string(),
                offset: 0,
                limit: 10,
                search: String::new(),
                sort: String::new(),
                prev_uid_next: None,
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: String::new(),
                message_list_limit: 10_000,
                use_threads: false,
                thread_uid: 0,
                thread_algorithm: String::new(),
            },
            "client-hash",
            capabilities,
            Some(&cache),
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert!(!result.limited);
        assert_eq!(result.total_emails, 2);
        assert_eq!(result.sort, "REVERSE DATE");
        assert_eq!(
            result
                .messages
                .iter()
                .map(|message| message.uid)
                .collect::<Vec<_>>(),
            vec![50_000, 49_999]
        );
        assert_eq!(cache.gets.lock().unwrap().len(), 1);
        assert!(cache.sets.lock().unwrap().is_empty());
    }

    async fn run_scripted_unicode_uid_search(
        utf8_mode: bool,
        continuation_response: &'static str,
    ) -> Result<Vec<u32>> {
        run_scripted_unicode_uid_query(utf8_mode, None, continuation_response).await
    }

    async fn run_scripted_unicode_uid_query(
        utf8_mode: bool,
        sort: Option<&'static str>,
        continuation_response: &'static str,
    ) -> Result<Vec<u32>> {
        use tokio::io::AsyncWriteExt as _;

        let (client_stream, mut server_stream) = tokio::io::duplex(512);
        let server = tokio::spawn(async move {
            let login = read_scripted_imap_command(&mut server_stream).await;
            assert!(login.starts_with("A0001 LOGIN "));
            server_stream
                .write_all(b"A0001 OK logged in\r\n")
                .await
                .unwrap();

            let query = read_scripted_imap_command(&mut server_stream).await;
            if utf8_mode {
                let expected = match sort {
                    Some(sort) => {
                        format!("A0002 UID SORT ({sort}) UTF-8 SUBJECT \"café\" UNDELETED\r\n")
                    }
                    None => "A0002 UID SEARCH SUBJECT \"café\" UNDELETED\r\n".to_string(),
                };
                assert_eq!(query, expected);
                let response = if sort.is_some() {
                    b"* SORT 8\r\nA0002 OK sorted\r\n".as_slice()
                } else {
                    b"* SEARCH 8\r\nA0002 OK searched\r\n".as_slice()
                };
                server_stream.write_all(response).await.unwrap();
            } else {
                let expected = match sort {
                    Some(sort) => {
                        format!("A0002 UID SORT ({sort}) UTF-8 SUBJECT {{5}}\r\n")
                    }
                    None => "A0002 UID SEARCH CHARSET UTF-8 SUBJECT {5}\r\n".to_string(),
                };
                assert_eq!(query, expected);
                server_stream
                    .write_all(continuation_response.as_bytes())
                    .await
                    .unwrap();
                if continuation_response.starts_with('+') {
                    let literal = read_scripted_imap_command(&mut server_stream).await;
                    assert_eq!(literal, "café UNDELETED\r\n");
                    let response = if sort.is_some() {
                        b"* SORT 8\r\nA0002 OK sorted\r\n".as_slice()
                    } else {
                        b"* SEARCH 8\r\nA0002 OK searched\r\n".as_slice()
                    };
                    server_stream.write_all(response).await.unwrap();
                }
            }
        });

        let stream: BoxedImapIo = Box::new(client_stream);
        let client: BoxedClient = Client::new(stream);
        let mut session = match client.login("user", "password").await {
            Ok(session) => session,
            Err((error, _client)) => panic!("scripted login failed: {error}"),
        };
        let result = legacy_message_list_visible_uids_with_settings_bounded(
            &mut session,
            "subject:café",
            LegacyMessageListQueryOptions {
                hide_deleted: true,
                fast_simple_search: true,
                permanent_filter: "",
                sort,
                utf8_mode,
                supports_within: false,
                supports_literal_plus: false,
            },
            None,
        )
        .await;
        server.await.unwrap();
        result
    }

    #[tokio::test]
    async fn message_list_unicode_search_uses_negotiated_utf8_or_classic_literal() {
        assert_eq!(
            run_scripted_unicode_uid_search(true, "").await.unwrap(),
            vec![8]
        );
        assert_eq!(
            run_scripted_unicode_uid_search(false, "+ continue\r\n")
                .await
                .unwrap(),
            vec![8]
        );
    }

    #[tokio::test]
    async fn message_list_unicode_sort_uses_utf8_charset_and_classic_literal() {
        assert_eq!(
            run_scripted_unicode_uid_query(false, Some("REVERSE DATE"), "+ continue\r\n")
                .await
                .unwrap(),
            vec![8]
        );
    }

    #[tokio::test]
    async fn message_list_unicode_search_rejects_failure_before_literal_continuation() {
        let error = run_scripted_unicode_uid_search(false, "A0002 NO charset rejected\r\n")
            .await
            .unwrap_err();
        assert!(error
            .public_message()
            .contains("search legacy message list"));
        assert!(error.public_message().contains("failed"));
    }

    #[tokio::test]
    async fn message_list_uid_search_rejects_no_bad_and_bye_responses() {
        for response in [
            "A0002 NO search rejected\r\n",
            "A0002 BAD invalid search\r\n",
            "* BYE server shutting down\r\n",
        ] {
            let error = run_scripted_visible_uid_search("", true, "UNDELETED", response)
                .await
                .unwrap_err();
            assert!(error
                .public_message()
                .contains("search legacy message list"));
            assert!(error.public_message().contains("failed"));
        }
    }

    #[test]
    fn message_list_multisearch_scope_accepts_only_legacy_selectors() {
        assert_eq!(
            legacy_message_list_multisearch_scope("in=subtree"),
            Some(LegacyMessageListMultiSearchScope::Subtree)
        );
        assert_eq!(
            legacy_message_list_multisearch_scope("in:SUBTREE-ONE subject:test"),
            Some(LegacyMessageListMultiSearchScope::SubtreeOne)
        );
        assert_eq!(
            legacy_message_list_multisearch_scope("subject=test&in=mailboxes"),
            Some(LegacyMessageListMultiSearchScope::Mailboxes)
        );
        assert_eq!(legacy_message_list_multisearch_scope("in=personal"), None);
        assert_eq!(legacy_message_list_multisearch_scope("subject=test"), None);
    }

    #[test]
    fn message_list_multisearch_page_plan_is_bounded_and_stable() {
        let matches = vec![
            LegacyMessageListMailboxMatches {
                mailbox: "Projects".to_string(),
                uid_validity: 42,
                count: 3,
            },
            LegacyMessageListMailboxMatches {
                mailbox: "Archive".to_string(),
                uid_validity: 88,
                count: 6,
            },
        ];

        let (total, page) = legacy_message_list_multisearch_page_plan(&matches, 2, 5).unwrap();
        assert_eq!(total, 9);
        assert_eq!(
            page.iter()
                .map(|item| (
                    item.mailbox.as_str(),
                    item.uid_validity,
                    item.expected_count,
                    item.offset,
                    item.limit
                ))
                .collect::<Vec<_>>(),
            vec![("Archive", 88, 6, 2, 4), ("Projects", 42, 3, 0, 1),]
        );
    }

    #[test]
    fn message_list_multisearch_page_plan_caps_distinct_mailboxes() {
        let matches = (0..=MULTISEARCH_PAGE_MAILBOX_LIMIT)
            .map(|index| LegacyMessageListMailboxMatches {
                mailbox: format!("Mailbox-{index:02}"),
                uid_validity: 88,
                count: 1,
            })
            .collect::<Vec<_>>();
        assert!(legacy_message_list_multisearch_page_plan(
            &matches,
            0,
            u32::try_from(matches.len()).unwrap()
        )
        .unwrap_err()
        .to_string()
        .contains("spans too many mailboxes"));
    }

    #[test]
    fn message_list_uid_collection_enforces_enumeration_limit_before_extend() {
        let mut uids = vec![1];
        let response = Response::MailboxData(MailboxDatum::Search(vec![2, 3]));
        assert!(
            collect_legacy_message_list_uids(&response, false, &mut uids, Some(2))
                .unwrap_err()
                .to_string()
                .contains("too many UIDs")
        );
        assert_eq!(uids, vec![1]);
    }

    #[test]
    fn message_list_search_criteria_compiles_text_address_and_state_filters() {
        assert_eq!(
            legacy_message_list_search_criteria("hello \"world\"", true).unwrap(),
            "OR OR OR FROM \"hello \\\"world\\\"\" TO \"hello \\\"world\\\"\" \
             CC \"hello \\\"world\\\"\" SUBJECT \"hello \\\"world\\\"\" UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria_with_fast_simple_search(
                "hello \"world\"",
                true,
                false,
            )
            .unwrap(),
            "TEXT \"hello \\\"world\\\"\" UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria(
                "from:\"Alice Example\" to:bob@example.test subject:report is:unseen,flagged",
                true,
            )
            .unwrap(),
            "FROM \"Alice Example\" OR TO \"bob@example.test\" CC \"bob@example.test\" \
             SUBJECT \"report\" UNSEEN FLAGGED UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria(
                "mail=alice%40example.test&is%5B%5D=read&is%5B%5D=answered",
                false,
            )
            .unwrap(),
            "OR OR FROM \"alice@example.test\" TO \"alice@example.test\" \
             CC \"alice@example.test\" SEEN ANSWERED"
        );
        assert_eq!(
            legacy_message_list_search_criteria("has:attachment", true).unwrap(),
            "OR OR OR HEADER Content-Type \"application/\" HEADER Content-Type \"multipart/m\" \
             HEADER Content-Type \"multipart/signed\" HEADER Content-Type \"multipart/report\" \
             UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria("unknown=value", true).unwrap(),
            "OR OR OR FROM \"unknown=value\" TO \"unknown=value\" CC \"unknown=value\" \
             SUBJECT \"unknown=value\" UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria("subject:first subject:second", true).unwrap(),
            "SUBJECT \"second\" UNDELETED"
        );
    }

    #[test]
    fn message_list_search_criteria_compiles_header_keyword_and_size_filters() {
        assert_eq!(
            legacy_message_list_search_criteria(
                "header:\"X-Spam-Status Yes, score=5\" keyword:Français larger:\"2 MB\" \
                 maxsize:512K",
                true,
            )
            .unwrap(),
            "HEADER \"X-Spam-Status\" \"Yes, score=5\" KEYWORD Fran&AOc-ais \
             LARGER 2097152 SMALLER 524288 UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria(
                "header=List-Id+news.example&keyword=%E6%97%A5%E6%9C%AC%E8%AA%9E&size=3K",
                false,
            )
            .unwrap(),
            "HEADER \"List-Id\" \"news.example\" KEYWORD &ZeVnLIqe- LARGER 3072"
        );
        assert_eq!(
            legacy_message_list_search_criteria("larger:nonsense smaller:10bytes", false).unwrap(),
            "LARGER 0 SMALLER 10"
        );
        assert_eq!(
            legacy_message_list_search_criteria("header=Subject+", false).unwrap(),
            "HEADER \"Subject\" \"\""
        );
        assert_eq!(
            legacy_message_list_search_criteria("header:\"Subject   exact spacing\"", false)
                .unwrap(),
            "HEADER \"Subject\" \"  exact spacing\""
        );
        for search in [
            "keyword:\"bad label\"",
            "keyword:bad*label",
            "larger:18446744073709551616",
            "larger:4294967296",
            "larger:4194304K",
        ] {
            assert!(
                legacy_message_list_search_criteria(search, false).is_err(),
                "{search} must not produce invalid or broadened IMAP criteria"
            );
        }
    }

    #[test]
    fn message_list_search_criteria_compiles_absolute_date_filters() {
        assert_eq!(
            legacy_message_list_search_criteria(
                "on:2026-07-24 senton:2026-07-23 sentsince:2026-07-01 \
                 sentbefore:2026-08-01 before:2026-09-01 since:2026-06-01",
                true,
            )
            .unwrap(),
            "ON 24-Jul-2026 SENTON 23-Jul-2026 SENTSINCE 1-Jul-2026 \
             SENTBEFORE 1-Aug-2026 BEFORE 1-Sep-2026 SINCE 1-Jun-2026 UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria("date:2026.07.24", true).unwrap(),
            "BEFORE 25-Jul-2026 SINCE 24-Jul-2026 UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria(
                "date:2026-07-01/2026-07-24 since:2026-07-10",
                false,
            )
            .unwrap(),
            "BEFORE 25-Jul-2026 SINCE 10-Jul-2026"
        );
        assert_eq!(
            legacy_message_list_search_criteria("date=2026-07-24", true).unwrap(),
            "SINCE 24-Jul-2026 UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria("date=2026-07-01%2F2026-07-24", true,).unwrap(),
            "UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria("on:not-a-date", true).unwrap(),
            "UNDELETED"
        );
    }

    #[test]
    fn message_list_search_criteria_gates_within_intervals() {
        assert_eq!(
            legacy_message_list_search_criteria_with_capabilities(
                "older=3600seconds&younger=7200",
                true,
                true,
                true,
            )
            .unwrap(),
            "OLDER 3600 YOUNGER 7200 UNDELETED"
        );
        for (search, expected) in [
            ("older=1e3", "OLDER 1000 UNDELETED"),
            ("older=1.5e3", "OLDER 1500 UNDELETED"),
            ("older=.5e3", "OLDER 500 UNDELETED"),
            ("older%5B%5D=3600&older%5B%5D=7200", "OLDER 3600 UNDELETED"),
        ] {
            assert_eq!(
                legacy_message_list_search_criteria_with_capabilities(search, true, true, true,)
                    .unwrap(),
                expected
            );
        }
        for search in ["older=0", "older=-1", "older=none", "older=1e-3"] {
            assert_eq!(
                legacy_message_list_search_criteria_with_capabilities(search, true, true, true,)
                    .unwrap(),
                "UNDELETED"
            );
        }
        assert_eq!(
            legacy_message_list_search_criteria_with_capabilities(
                "older=3600",
                false,
                true,
                false,
            )
            .unwrap(),
            "ALL"
        );
        assert!(legacy_message_list_search_criteria_with_capabilities(
            "older=4294967296",
            true,
            true,
            true,
        )
        .is_err());
    }

    #[test]
    fn message_list_search_criteria_applies_configured_search_settings() {
        assert_eq!(
            legacy_message_list_search_criteria_with_settings(
                "needle",
                true,
                false,
                false,
                "NOT FLAGGED",
            )
            .unwrap(),
            "TEXT \"needle\" UNDELETED NOT FLAGGED"
        );
        assert_eq!(
            legacy_message_list_search_criteria_with_settings(
                "is:deleted",
                true,
                true,
                false,
                "UNSEEN",
            )
            .unwrap(),
            "DELETED UNSEEN"
        );
        assert_eq!(
            legacy_message_list_search_criteria_with_settings("", false, true, false, "0",)
                .unwrap(),
            "ALL"
        );
        for filter in ["UNSEEN\r\nDELETED", "UNSEEN\0DELETED"] {
            assert!(
                legacy_message_list_search_criteria_with_settings("", true, true, false, filter,)
                    .is_err(),
                "{filter:?} must not cross the IMAP command boundary"
            );
        }
    }

    #[test]
    fn message_list_search_wire_frames_non_ascii_permanent_filter() {
        assert_eq!(
            legacy_message_list_search_wire_with_settings(
                "",
                true,
                true,
                r#"HEADER "X-Tag" "café""#,
                false,
                false,
            )
            .unwrap(),
            LegacyMessageListSearchWire {
                chunks: vec![
                    r#"UNDELETED HEADER "X-Tag" {5}"#.to_string(),
                    "café".to_string(),
                ],
                needs_utf8_charset: true,
            }
        );
    }

    #[test]
    fn message_list_search_criteria_compiles_calendar_relative_filters() {
        let now = DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2026, 3, 31)
                .unwrap()
                .and_hms_opt(12, 34, 56)
                .unwrap(),
            Utc,
        );
        assert_eq!(
            legacy_message_list_search_criteria_at(
                "older_than:1M newer_than:2D",
                true,
                true,
                false,
                now,
            )
            .unwrap(),
            "BEFORE 3-Mar-2026 SINCE 29-Mar-2026 UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria_at(
                "older_than:1M newer_than:2D",
                true,
                true,
                true,
                now,
            )
            .unwrap(),
            "OLDER 2419200 YOUNGER 172800 UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria_at(
                "older_than:1Y2M3W4DT5H6M7S",
                true,
                true,
                true,
                now,
            )
            .unwrap(),
            "OLDER 38811967 UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria_at(
                "newer_than:0001-02-03T04:05:06",
                true,
                true,
                true,
                now,
            )
            .unwrap(),
            "YOUNGER 36907506 UNDELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria_at(
                "older_than:T4294967296S",
                true,
                true,
                false,
                now,
            )
            .unwrap(),
            "BEFORE 22-Feb-1890 UNDELETED"
        );
        assert_eq!(
            legacy_message_list_interval("0001-12-31T24:59:59").unwrap(),
            LegacyMessageListInterval {
                years: 1,
                months: 12,
                days: 31,
                hours: 24,
                minutes: 59,
                seconds: 59,
            }
        );
    }

    #[test]
    fn message_list_search_criteria_rejects_invalid_calendar_relative_filters() {
        let now = DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2026, 3, 31)
                .unwrap()
                .and_hms_opt(12, 34, 56)
                .unwrap(),
            Utc,
        );
        for search in [
            "older_than:bad",
            "older_than:P1D",
            "older_than:1DT",
            "older_than:1D2Y",
            "older_than:1D2D",
            "older_than:0001-02-03T04:05",
            "older_than:0001-13-00T00:00:00",
            "older_than:0001-00-32T00:00:00",
            "older_than:0001-00-00T25:00:00",
            "older_than:0001-00-00T00:60:00",
            "older_than:0001-00-00T00:00:60",
        ] {
            assert!(
                legacy_message_list_search_criteria_at(search, true, true, false, now).is_err(),
                "{search} must not produce invalid or broadened IMAP criteria"
            );
        }
        assert!(
            legacy_message_list_search_criteria_at("older_than:0D", true, true, true, now,)
                .is_err()
        );
        assert!(
            legacy_message_list_search_criteria_at("older_than:200Y", true, true, true, now,)
                .is_err()
        );
        assert!(legacy_message_list_search_criteria_at(
            "older_than:T4294967296S",
            true,
            true,
            true,
            now,
        )
        .is_err());
        assert_eq!(
            legacy_message_list_search_criteria_at(
                "older_than=1D",
                true,
                true,
                false,
                now,
            )
            .unwrap(),
            "OR OR OR FROM \"older_than=1D\" TO \"older_than=1D\" CC \"older_than=1D\" SUBJECT \"older_than=1D\" UNDELETED"
        );
    }

    #[test]
    fn message_list_search_wire_frames_non_ascii_for_legacy_imap() {
        assert_eq!(
            legacy_message_list_search_wire("subject:café", true, true, true, false).unwrap(),
            LegacyMessageListSearchWire {
                chunks: vec!["SUBJECT \"café\" UNDELETED".to_string()],
                needs_utf8_charset: false,
            }
        );
        assert_eq!(
            legacy_message_list_search_wire("subject:café", true, true, false, false).unwrap(),
            LegacyMessageListSearchWire {
                chunks: vec!["SUBJECT {5}".to_string(), "café UNDELETED".to_string(),],
                needs_utf8_charset: true,
            }
        );
    }

    #[test]
    fn message_list_search_criteria_honors_explicit_deleted_state() {
        assert_eq!(
            legacy_message_list_search_criteria("is:deleted", true).unwrap(),
            "DELETED"
        );
        assert_eq!(
            legacy_message_list_search_criteria("is:undeleted", true).unwrap(),
            "UNDELETED"
        );
    }

    #[test]
    fn message_list_search_criteria_rejects_injection_and_malformed_header_filters() {
        for search in ["from:\"a\r\nBAD\"", "subject:a\0b"] {
            assert!(legacy_message_list_search_criteria(search, true).is_err());
        }
        let error = legacy_message_list_search_criteria("header:Subject", true).unwrap_err();
        assert!(error.public_message().contains("field name and value"));
    }

    #[test]
    fn message_list_uid_pages_preserve_selected_order_and_bounds() {
        let uids = [105, 99, 74, 51, 12];
        assert_eq!(legacy_message_list_page_uids(&uids, 0, 2), vec![105, 99]);
        assert_eq!(legacy_message_list_page_uids(&uids, 2, 2), vec![74, 51]);
        assert_eq!(legacy_message_list_page_uids(&uids, 4, 10), vec![12]);
        assert!(legacy_message_list_page_uids(&uids, 5, 10).is_empty());
        assert!(legacy_message_list_page_uids(&uids, 0, 0).is_empty());
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
    fn message_list_optimization_threshold_matches_mailso() {
        assert!(!legacy_message_list_optimization_enabled(0, 20_000));
        assert!(!legacy_message_list_optimization_enabled(99, 20_000));
        assert!(legacy_message_list_optimization_enabled(100, 20_000));
        assert!(legacy_message_list_optimization_enabled(10_000, 10_000));
        assert!(!legacy_message_list_optimization_enabled(10_000, 9_999));
    }

    #[test]
    fn message_list_cache_warm_requires_cacheable_folder_cardinality() {
        assert!(legacy_message_list_cache_warm_cacheable(
            Some(100_000),
            100_000
        ));
        assert!(!legacy_message_list_cache_warm_cacheable(
            Some(100_001),
            100_000
        ));
        assert!(!legacy_message_list_cache_warm_cacheable(None, 100_000));
    }

    #[test]
    fn message_list_cache_warm_is_single_flight_per_key() {
        let key = "single-flight-test-key".to_string();
        let first =
            try_start_legacy_message_list_cache_warm(key.clone()).expect("first warm should start");
        assert!(try_start_legacy_message_list_cache_warm(key.clone()).is_none());
        drop(first);
        let restarted =
            try_start_legacy_message_list_cache_warm(key).expect("completed warm should restart");
        drop(restarted);
    }

    #[test]
    fn message_list_cache_warm_identity_ignores_folder_generation_and_thread_knobs() {
        let cache = StatefulUidCache::default();
        let capabilities = ImapFetchMetadataCapabilities {
            supports_gmail_id: false,
            supports_object_id: false,
            supports_preview: false,
            supports_literal_plus: false,
            uses_utf8_search: false,
            supports_within: false,
            supports_multisearch: false,
            supports_sort: true,
            supports_sort_display: false,
            thread_algorithms: vec!["REFERENCES".to_string()],
        };
        let mut request = LegacyMessageListRequest {
            mailbox: "INBOX".to_string(),
            offset: 0,
            limit: 50,
            search: String::new(),
            sort: String::new(),
            prev_uid_next: None,
            hide_deleted: true,
            fast_simple_search: true,
            permanent_filter: String::new(),
            message_list_limit: 10_000,
            use_threads: false,
            thread_uid: 0,
            thread_algorithm: String::new(),
        };
        let older_generation_key =
            legacy_message_list_cache_warm_key(&request, "client-hash", &capabilities, &cache)
                .unwrap();

        request.sort = "REVERSE DATE".to_string();
        request.use_threads = true;
        request.thread_algorithm = "REFERENCES".to_string();
        let newer_generation_key =
            legacy_message_list_cache_warm_key(&request, "client-hash", &capabilities, &cache)
                .unwrap();

        assert_eq!(older_generation_key, newer_generation_key);
        let older = try_start_legacy_message_list_cache_warm(older_generation_key)
            .expect("older folder generation should acquire the UID cache key");
        assert!(
            try_start_legacy_message_list_cache_warm(newer_generation_key).is_none(),
            "newer folder generation must not race a writer for the same UID cache key"
        );
        drop(older);
    }

    #[test]
    fn message_list_optimized_sequence_windows_match_mailso() {
        let first_sorted = legacy_message_list_optimized_sequence_ids(20_000, 0, 50, true);
        assert_eq!(first_sorted.len(), 150);
        assert_eq!(first_sorted.first(), Some(&20_000));
        assert_eq!(first_sorted.last(), Some(&19_851));

        let later_sorted = legacy_message_list_optimized_sequence_ids(20_000, 100, 50, true);
        assert_eq!(later_sorted.first(), Some(&19_950));
        assert_eq!(later_sorted.last(), Some(&19_801));
        assert_eq!(
            legacy_message_list_optimized_sorted_page(&later_sorted, 100, 50),
            (19_851..=19_900).rev().collect::<Vec<_>>()
        );

        assert_eq!(
            legacy_message_list_optimized_sequence_ids(20_000, 50, 50, false),
            (19_901..=19_950).rev().collect::<Vec<_>>()
        );
        assert_eq!(
            legacy_message_list_optimized_sequence_ids(20_000, 20_000, 50, false),
            vec![1]
        );
        assert_eq!(
            legacy_sequence_set_preserving_order(&[9, 7, 8]),
            Some("9,7,8".to_string())
        );
    }

    #[test]
    fn legacy_message_list_fetches_new_messages_only_outside_threads() {
        assert!(legacy_message_list_fetches_new_messages(0));
        assert!(!legacy_message_list_fetches_new_messages(1));
        assert!(!legacy_message_list_fetches_new_messages(u32::MAX));
    }

    #[test]
    fn message_list_thread_algorithm_matches_mailso_preference_and_fallback() {
        let advertised = vec![
            "ORDEREDSUBJECT".to_string(),
            "REFERENCES".to_string(),
            "REFS".to_string(),
            "X-TEST".to_string(),
        ];

        assert_eq!(
            legacy_message_list_thread_algorithm(&advertised, ""),
            Some("REFS".to_string())
        );
        assert_eq!(
            legacy_message_list_thread_algorithm(&advertised, "references"),
            Some("REFERENCES".to_string())
        );
        assert_eq!(
            legacy_message_list_thread_algorithm(&advertised, "x-test"),
            Some("X-TEST".to_string())
        );
        assert_eq!(
            legacy_message_list_thread_algorithm(&advertised, "unsupported"),
            Some("REFS".to_string())
        );
        assert_eq!(
            legacy_message_list_thread_algorithm(&[], "REFERENCES"),
            None
        );
    }

    #[test]
    fn message_list_thread_representatives_use_highest_uid_like_mailso() {
        let mut uids = vec![12, 11, 10, 9, 8, 7];
        let threads = [vec![7, 9, 8], vec![10, 12], vec![11]];
        let old_uids = legacy_thread_old_uids(&threads);
        legacy_thread_representatives(&mut uids, &old_uids);
        assert_eq!(uids, vec![12, 11, 9]);
        assert_eq!(old_uids, vec![7, 8, 10]);
    }

    #[test]
    fn message_list_thread_cache_keys_match_mailso() {
        assert_eq!(
            legacy_message_list_thread_map_cache_key("REFERENCES", "etag"),
            "ThreadsMap/REFERENCES/ALL/etag"
        );
        assert_eq!(
            legacy_message_list_thread_uids_cache_key("etag"),
            "ThreadsOldUids/etag/N"
        );
    }

    #[test]
    fn message_list_selected_thread_uses_map_or_requested_uid_fallback() {
        let threads = vec![vec![7, 9, 8], vec![10, 12]];
        assert_eq!(legacy_selected_thread_uids(9, &threads), vec![7, 9, 8]);
        assert_eq!(legacy_selected_thread_uids(11, &threads), vec![11]);
    }

    #[test]
    fn message_list_thread_search_keeps_threads_with_any_matching_member() {
        let mut uids = vec![12, 11, 9, 6];
        let threads = vec![vec![7, 9, 8], vec![10, 12], vec![11], vec![5, 6]];
        legacy_filter_thread_search_results(&mut uids, &[8, 11], &threads);
        assert_eq!(uids, vec![11, 9]);
    }

    #[test]
    fn message_list_thread_metadata_preserves_map_and_unseen_order() {
        let threads = vec![vec![7, 9, 8], vec![10, 12]];
        assert_eq!(
            legacy_message_thread_metadata(9, &threads, &[12, 8, 7]),
            (vec![7, 9, 8], vec![8, 7])
        );
        assert_eq!(
            legacy_message_thread_metadata(11, &threads, &[12, 8, 7]),
            (Vec::new(), Vec::new())
        );
    }

    #[test]
    fn legacy_new_messages_mailbox_match_is_exact_inbox() {
        assert!(legacy_new_messages_mailbox_matches("INBOX"));
        assert!(!legacy_new_messages_mailbox_matches("Inbox"));
        assert!(!legacy_new_messages_mailbox_matches("inbox"));
        assert!(!legacy_new_messages_mailbox_matches(" INBOX "));
    }

    #[test]
    fn legacy_new_message_subject_applies_mailso_header_charset_fallbacks() {
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: \x93New mail\x94\r\nContent-Type: text/plain; charset=windows-1252\r\n\r\n"
            ),
            "\u{201c}New mail\u{201d}"
        );
        assert_eq!(
            legacy_new_message_subject(b"Subject: Andr\xe9\r\n\r\n"),
            "Andr\u{e9}"
        );
        assert_eq!(
            legacy_new_message_subject(
                "Subject: Già UTF-8\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\n"
                    .as_bytes()
            ),
            "Già UTF-8"
        );
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: =?ISO-8859-1?Q?Ol=E1?=\r\nContent-Type: text/plain; charset=windows-1252\r\n\r\n"
            ),
            "Ol\u{e1}"
        );
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: A\x93B\r\nContent-Type: text/plain; charset=windows-1252\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\n"
            ),
            "A\u{201c}B"
        );
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: A\x93B\r\nContent-Type: text/plain; charset=iso-8859-1; charset=windows-1252\r\n\r\n"
            ),
            "A\u{201c}B"
        );
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: A\x93B\r\nContent-Type: text/plain; charset=0\r\n\r\n"
            ),
            "A\u{93}B"
        );
        assert_eq!(
            legacy_new_message_subject(b"Subject:\r\nSubject: second\r\n\r\n"),
            ""
        );
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: A\x93B\r\nContent-Type:\r\nContent-Type: text/plain; charset=windows-1252\r\n\r\n"
            ),
            "A\u{93}B"
        );
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: A\x93B\r\nContent-Type: text/plain; charset=iso-8859-1; charset*=utf-8''windows-1252\r\n\r\n"
            ),
            "A\u{201c}B"
        );
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: A\x93B\r\nContent-Type: text/plain; charset*0*=utf-8''windows-; charset*1*=1252\r\n\r\n"
            ),
            "A\u{201c}B"
        );
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: A\x93B\r\nContent-Type: text/plain; charset==?US-ASCII?Q?windows-1252?=\r\n\r\n"
            ),
            "A\u{201c}B"
        );
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: A\x93B\r\nContent-Type: text/plain; CHARSET*0*=utf-8''windows-; charset*1*=1252\r\n\r\n"
            ),
            "A\u{fffd}B"
        );
        assert_eq!(
            legacy_new_message_subject(
                b"Subject: A\x93B\r\nContent-Type: text/plain; foo*charset*0*=utf-8''windows-1252\r\n\r\n"
            ),
            "A\u{201c}B"
        );
    }

    #[test]
    fn legacy_new_message_subject_handles_many_parameters_in_linear_maps() {
        let mut header = b"Subject: A\x93B\r\nContent-Type: text/plain".to_vec();
        for index in 0..4_096 {
            header.extend_from_slice(format!("; x{index}=value").as_bytes());
        }
        header.extend_from_slice(b"; charset=windows-1252\r\n\r\n");

        assert_eq!(legacy_new_message_subject(&header), "A\u{201c}B");
    }

    #[test]
    fn legacy_new_message_subject_matches_mailso_folding_rules() {
        assert_eq!(
            legacy_new_message_subject(b"Subject: hello\r\n world\r\n\r\n"),
            "hello  world"
        );
        assert_eq!(
            legacy_new_message_subject(b"Subject: hello\r\n =?UTF-8?Q?world?=   \r\n\r\n"),
            "helloworld"
        );
        assert_eq!(
            legacy_new_message_subject(b"Subject: hello\r\n =?UTF-8?Q?_world?=\r\n\r\n"),
            "hello world"
        );
        assert_eq!(
            legacy_new_message_subject(b": ignored\r\n Subject: spoof\r\nSubject: real\r\n\r\n"),
            "real"
        );
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
        assert_eq!(
            legacy_message_list_sort_for_command("REVERSE FROM SIZE", false).unwrap(),
            "REVERSE FROM SIZE REVERSE DATE"
        );
        assert_eq!(
            legacy_message_list_sort_for_command("DISPLAYFROM", true).unwrap(),
            "DISPLAYFROM REVERSE DATE"
        );
        for sort in [
            "REVERSE",
            "DISPLAYFROM",
            "FROM\r\nDATE",
            "FROM\r\nUID SEARCH ALL",
            "NOT-A-SORT",
        ] {
            assert!(
                legacy_message_list_sort_for_command(sort, false).is_err(),
                "{sort:?} must not produce an IMAP SORT command"
            );
        }
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
    fn legacy_message_summary_removes_preview_prefix_like_mailso() {
        assert_eq!(
            legacy_message_subject("[Preview] Preview subject"),
            "Preview subject"
        );
        assert_eq!(legacy_message_subject("[Preview]Xsubject"), "subject");
        assert_eq!(legacy_message_subject("[Preview]🦀subject"), "subject");
        assert_eq!(legacy_message_subject("[Preview]"), "");
        assert_eq!(
            legacy_message_subject(" [Preview] untouched "),
            "[Preview] untouched"
        );
        assert_eq!(
            legacy_header_subject("[Preview] notification subject"),
            "[Preview] notification subject"
        );

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            45,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            b"Subject: [Preview] Preview subject\r\n\r\n",
        );
        assert_eq!(summary.subject, "Preview subject");
    }

    #[test]
    fn legacy_message_summary_decodes_rfc2047_subject_and_receipt_like_mailso() {
        let header = b"Subject: =?UTF-8?Q?[Preview]_Ol=C3=A1?=\r\nFrom: =?UTF-8?Q?Jos=C3=A9?= <jose@example.com>\r\nReply-To: =?UTF-8?B?Sm9zw6k=?= <reply@example.com>\r\nTo: =?UTF-8?Q?Mar=C3=ADa?= <maria@example.com>\r\nCc: =?UTF-8?Q?Andr=C3=A9?= <andre@example.com>\r\nBcc: =?UTF-8?Q?Zo=C3=AB?= <zoe@example.com>\r\nSender: =?UTF-8?Q?Ren=C3=A9?= <rene@example.com>\r\nDelivered-To: =?UTF-8?Q?Bj=C3=B6rn?= <bjorn@example.com>\r\nDisposition-Notification-To: =?UTF-8?Q?L=C3=A9a?= <lea@example.com>\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            46,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.subject, "Olá");
        assert_eq!(summary.from, "=?UTF-8?Q?Jos=C3=A9?= <jose@example.com>");
        assert_eq!(summary.read_receipt, "Léa <lea@example.com>");
    }

    #[test]
    fn legacy_new_message_headers_decode_rfc2047_without_preview_normalization() {
        let header = b"Subject: =?UTF-8?Q?[Preview]_Ol=C3=A1?=\r\nFrom: =?UTF-8?Q?Jos=C3=A9?= <jose@example.com>\r\n\r\n";

        assert_eq!(
            legacy_header_subject(&legacy_decoded_header_value(header, "Subject")),
            "[Preview] Olá"
        );
        assert_eq!(
            header_value(header, "From").as_deref(),
            Some("=?UTF-8?Q?Jos=C3=A9?= <jose@example.com>")
        );
    }

    #[test]
    fn legacy_rfc2047_decoder_matches_mailso_edge_cases() {
        assert_eq!(
            legacy_decode_rfc2047_header_value("=?UTF-8?Q?one?=      =?UTF-8?Q?two?="),
            "one      two"
        );
        assert_eq!(
            legacy_decode_rfc2047_header_value("=?UTF-8?Q?one?=     =?UTF-8?Q?two?="),
            "onetwo"
        );
        assert_eq!(
            legacy_decode_rfc2047_header_value("=?UTF-8?Q?bad=ZZ?="),
            "bad=ZZ"
        );
        assert_eq!(legacy_decode_rfc2047_header_value("=?UTF-8?B?%%%?="), "");
        assert_eq!(
            legacy_decode_rfc2047_header_value("\u{a0} plain \u{a0}"),
            "\u{a0} plain \u{a0}"
        );
        assert_eq!(
            legacy_decode_rfc2047_header_value("=?ISO-8859-1?Q?Andr=E9?="),
            "André"
        );
        assert_eq!(
            legacy_decode_rfc2047_header_value("=?ISO8859-1?B?QW5kcuk=?="),
            "André"
        );
        assert_eq!(
            legacy_decode_rfc2047_header_value("=?CP1252?Q?=93quoted=94?="),
            "“quoted”"
        );
        assert_eq!(
            legacy_decode_rfc2047_header_value("=?windows1252?B?k3F1b3RlZJQ=?="),
            "“quoted”"
        );
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
    fn legacy_message_summary_checks_spam_before_removing_preview_prefix() {
        let header = b"Subject: [Preview]*** SPAM ***\r\nX-Spamd-Result: default: False [1.00 / 9.00]; BAYES_SPAM\r\n\r\n";

        let summary = legacy_message_summary_from_fetch(
            "INBOX",
            44,
            None,
            1,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            header,
        );

        assert_eq!(summary.subject, "** SPAM ***");
        assert_eq!(summary.spam_score, 100);
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

        let encrypted = crypto.pgp_encrypted.unwrap();
        assert_eq!(encrypted.part_id, "2");
        assert!(encrypted.key_ids.is_none());
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
        assert_eq!(signed.sig_part_id.as_deref(), Some("2"));
        assert_eq!(signed.mic_alg.as_deref(), Some("pgp-sha256"));
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
        assert_eq!(signed.sig_part_id.as_deref(), Some("1.2"));
        assert_eq!(signed.mic_alg.as_deref(), Some(""));
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
        assert!(!opaque.detached);
        assert_eq!(detached.part_id, "TEXT");
        assert_eq!(detached.sig_part_id.as_deref(), Some("2"));
        assert_eq!(detached.mic_alg, "sha-256");
        assert!(detached.detached);
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
    fn split_fetch_merge_preserves_internal_date_fallback_and_header_fields() {
        let internal = legacy_message_summary_from_fetch(
            "INBOX",
            51,
            Some(1_700_000_000),
            2048,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            b"",
        );
        let header = legacy_message_summary_from_fetch(
            "INBOX",
            51,
            None,
            0,
            Vec::<Flag<'_>>::new().into_iter(),
            None,
            b"Subject: Arrived later\r\nMessage-ID: <split@example.com>\r\n\r\n",
        );
        let mut merged = LegacyMessageSummaryAccumulator::new(
            internal,
            LegacyMessageSummaryFragment {
                header: false,
                bodystructure: false,
                internal_date: true,
                size: true,
                flags: false,
                email_id: false,
            },
        );
        merged.merge(
            header,
            LegacyMessageSummaryFragment {
                header: true,
                bodystructure: false,
                internal_date: false,
                size: false,
                flags: false,
                email_id: false,
            },
        );

        assert_eq!(merged.summary.subject, "Arrived later");
        assert_eq!(merged.summary.message_id, "<split@example.com>");
        assert_eq!(merged.summary.date_timestamp, 1_700_000_000);
        assert_eq!(merged.summary.date_timestamp_source, "internal");
        assert_eq!(merged.summary.size, 2048);
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
            fast_simple_search: true,
            permanent_filter: String::new(),
            message_list_limit: 10_000,
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
    fn header_value_uses_first_duplicate_like_mailso() {
        let raw = b"Subject: first\r\n\tcontinued\r\nsUbJeCt: second\r\n\tignored\r\n\r\n";
        assert_eq!(
            header_value(raw, "subject"),
            Some("first continued".to_string())
        );

        let empty_first = b"Subject:\r\nSubject: second\r\n\r\n";
        assert_eq!(header_value(empty_first, "subject"), None);
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

    #[test]
    fn is_valid_mime_index_accepts_only_digits_and_dots() {
        assert!(is_valid_mime_index("1"));
        assert!(is_valid_mime_index("1.2"));
        assert!(is_valid_mime_index("1.2.3"));
        assert!(!is_valid_mime_index(""));
        assert!(!is_valid_mime_index("1]"));
        assert!(!is_valid_mime_index("1\r\n"));
        assert!(!is_valid_mime_index("../etc"));
        assert!(!is_valid_mime_index("a.b"));
        assert!(!is_valid_mime_index("1; RENAME"));
        // An all-dot index (no digits at all) is rejected — it would
        // produce a malformed BODY.PEEK[.] IMAP command.
        assert!(!is_valid_mime_index("."));
        assert!(!is_valid_mime_index(".."));
    }
}
