use std::{fmt, sync::Arc, time::Duration};

use async_imap::{Client, Session};
use fm_core::{FrickmailError, Result};
use futures::TryStreamExt;
use imap_proto::{
    builders::command::{Command, CommandBuilder},
    AttributeValue, BodyStructure, MessageSection, Response, SectionPath, Status,
};
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
