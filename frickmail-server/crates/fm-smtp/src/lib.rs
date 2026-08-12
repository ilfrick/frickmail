use fm_core::{config::TransactionalSmtpConfig, FrickmailError, Result};
use lettre::{
    address::{Address, Envelope},
    message::{header::ContentType, Mailbox},
    transport::smtp::{
        authentication::{Credentials, Mechanism, DEFAULT_MECHANISMS},
        client::{AsyncSmtpConnection, Tls, TlsParameters},
        commands::{Data, Ehlo, Mail, Rcpt},
        extension::{ClientId, MailBodyParameter, MailParameter, RcptParameter},
        response::Response,
    },
    AsyncSmtpTransport, AsyncTransport, Message, SmtpTransport, Tokio1Executor, Transport,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmtpEndpoint {
    pub host: String,
    pub port: u16,
    pub login: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetEmail {
    pub to: String,
    pub username: String,
    pub reset_url: String,
}

pub fn transport_label(endpoint: &SmtpEndpoint) -> String {
    format!("{}:{} as {}", endpoint.host, endpoint.port, endpoint.login)
}

pub fn password_reset_subject() -> &'static str {
    "Frickmail - password reset"
}

pub fn password_reset_body(email: &PasswordResetEmail) -> String {
    format!(
        "Hello {username},\n\n\
         You requested a Frickmail password reset. Open this link within 30 minutes:\n\n\
         {reset_url}\n\n\
         If you did not request this, ignore this email.\n\n\
         NOTE: after the reset, IMAP passwords and OAuth refresh tokens stored in your \
         Frickmail account will need to be re-entered from Settings > Mail Accounts \
         (they are encrypted with a key derived from your password and cannot be recovered).\n\n\
         - Frickmail",
        username = email.username,
        reset_url = email.reset_url
    )
}

pub fn send_password_reset_email(
    config: &TransactionalSmtpConfig,
    email: &PasswordResetEmail,
) -> Result<bool> {
    if !config.is_configured() {
        return Ok(false);
    }

    let from = config
        .from
        .parse::<Mailbox>()
        .map_err(|err| FrickmailError::Upstream(format!("invalid SMTP sender: {err}")))?;
    let to = email.to.parse::<Mailbox>().map_err(|err| {
        FrickmailError::Upstream(format!("invalid password-reset recipient: {err}"))
    })?;

    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(password_reset_subject())
        .header(ContentType::TEXT_PLAIN)
        .body(password_reset_body(email))
        .map_err(|err| {
            FrickmailError::Upstream(format!("password-reset email build failed: {err}"))
        })?;

    let mut builder = match config.secure.trim().to_ascii_lowercase().as_str() {
        "none" | "" => SmtpTransport::builder_dangerous(config.host.trim()),
        "starttls" => SmtpTransport::starttls_relay(config.host.trim()).map_err(|err| {
            FrickmailError::Upstream(format!("SMTP transport setup failed: {err}"))
        })?,
        "ssl" | "tls" => SmtpTransport::relay(config.host.trim()).map_err(|err| {
            FrickmailError::Upstream(format!("SMTP transport setup failed: {err}"))
        })?,
        other => {
            return Err(FrickmailError::Upstream(format!(
                "unsupported SMTP security mode: {other}"
            )));
        }
    }
    .port(config.port);

    if !config.user.is_empty() {
        builder = builder.credentials(Credentials::new(
            config.user.clone(),
            config.password.clone(),
        ));
    }

    builder
        .build()
        .send(&message)
        .map(|_| true)
        .map_err(|err| FrickmailError::Upstream(format!("password-reset email send failed: {err}")))
}

/// SMTP endpoint plus credentials used to deliver a composed message.
///
/// `Debug` is implemented manually so the password is never written to logs.
#[derive(Clone, PartialEq, Eq)]
pub struct SmtpSendSettings {
    /// Original validated hostname, retained for TLS certificate verification.
    pub host: String,
    /// Public IP resolved and pinned immediately before the SMTP connection.
    pub connect_host: String,
    pub port: u16,
    pub secure: String,
    pub login: String,
    pub password: String,
    /// Optional OAuth access token for XOAUTH2 authentication.
    /// When present, takes precedence over password-based authentication.
    pub access_token: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SmtpDeliveryOptions {
    pub dsn: bool,
    pub require_tls: bool,
}

impl std::fmt::Debug for SmtpSendSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpSendSettings")
            .field("host", &self.host)
            .field("connect_host", &self.connect_host)
            .field("port", &self.port)
            .field("secure", &self.secure)
            .field("login", &self.login)
            .field("password", &"<redacted>")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

fn smtp_transport(settings: &SmtpSendSettings) -> Result<SmtpTransport> {
    let host = settings.host.trim();
    let connect_host = settings.connect_host.trim();
    if host.is_empty() || connect_host.is_empty() {
        return Err(FrickmailError::Upstream(
            "SMTP host is not configured".to_string(),
        ));
    }

    let tls_parameters = || {
        TlsParameters::new(host.to_string())
            .map_err(|err| FrickmailError::Upstream(format!("SMTP TLS setup failed: {err}")))
    };
    let mut builder = match settings.secure.trim().to_ascii_lowercase().as_str() {
        "none" | "" => SmtpTransport::builder_dangerous(connect_host).tls(Tls::None),
        "starttls" => {
            SmtpTransport::builder_dangerous(connect_host).tls(Tls::Required(tls_parameters()?))
        }
        "ssl" | "tls" => {
            SmtpTransport::builder_dangerous(connect_host).tls(Tls::Wrapper(tls_parameters()?))
        }
        other => {
            return Err(FrickmailError::Upstream(format!(
                "unsupported SMTP security mode: {other}"
            )));
        }
    }
    .port(settings.port)
    .timeout(Some(Duration::from_secs(30)));

    if !settings.login.is_empty() {
        let credentials = if let Some(access_token) = &settings.access_token {
            if !access_token.is_empty() {
                Credentials::new(settings.login.clone(), access_token.clone())
            } else {
                Credentials::new(settings.login.clone(), settings.password.clone())
            }
        } else {
            Credentials::new(settings.login.clone(), settings.password.clone())
        };
        builder = builder.credentials(credentials);

        // Set XOAUTH2 mechanism if access token is available
        if let Some(access_token) = &settings.access_token {
            if !access_token.is_empty() {
                builder = builder.authentication(vec![Mechanism::Xoauth2]);
            }
        }
    }

    Ok(builder.build())
}

fn async_smtp_transport(settings: &SmtpSendSettings) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
    let host = settings.host.trim();
    let connect_host = settings.connect_host.trim();
    if host.is_empty() || connect_host.is_empty() {
        return Err(FrickmailError::Upstream(
            "SMTP host is not configured".to_string(),
        ));
    }

    let tls_parameters = || {
        TlsParameters::new(host.to_string())
            .map_err(|err| FrickmailError::Upstream(format!("SMTP TLS setup failed: {err}")))
    };
    let mut builder = match settings.secure.trim().to_ascii_lowercase().as_str() {
        "none" | "" => {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(connect_host).tls(Tls::None)
        }
        "starttls" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(connect_host)
            .tls(Tls::Required(tls_parameters()?)),
        "ssl" | "tls" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(connect_host)
            .tls(Tls::Wrapper(tls_parameters()?)),
        other => {
            return Err(FrickmailError::Upstream(format!(
                "unsupported SMTP security mode: {other}"
            )));
        }
    }
    .port(settings.port)
    .timeout(Some(Duration::from_secs(30)));

    if !settings.login.is_empty() {
        let credentials = if let Some(access_token) = &settings.access_token {
            if !access_token.is_empty() {
                Credentials::new(settings.login.clone(), access_token.clone())
            } else {
                Credentials::new(settings.login.clone(), settings.password.clone())
            }
        } else {
            Credentials::new(settings.login.clone(), settings.password.clone())
        };
        builder = builder.credentials(credentials);

        // Set XOAUTH2 mechanism if access token is available
        if let Some(access_token) = &settings.access_token {
            if !access_token.is_empty() {
                builder = builder.authentication(vec![Mechanism::Xoauth2]);
            }
        }
    }

    Ok(builder.build())
}

/// Build the SMTP envelope for a composed message.
///
/// The envelope drives actual delivery, so BCC recipients must be included here
/// even though they are stripped from the serialized headers.
pub fn build_envelope(from: &str, recipients: &[String]) -> Result<Envelope> {
    let from_address: Address = from.trim().parse().map_err(|err| {
        FrickmailError::BadRequest(format!("invalid envelope sender '{from}': {err}"))
    })?;

    let mut to_addresses = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let trimmed = recipient.trim();
        if trimmed.is_empty() {
            continue;
        }
        let address: Address = trimmed.parse().map_err(|err| {
            FrickmailError::BadRequest(format!("invalid recipient '{trimmed}': {err}"))
        })?;
        if !to_addresses.contains(&address) {
            to_addresses.push(address);
        }
    }

    if to_addresses.is_empty() {
        return Err(FrickmailError::BadRequest(
            "no valid recipients".to_string(),
        ));
    }

    Envelope::new(Some(from_address), to_addresses)
        .map_err(|err| FrickmailError::BadRequest(format!("SMTP envelope build failed: {err}")))
}

/// Send a raw RFC 5322 message via SMTP using an explicit envelope.
pub fn send_raw_message(
    settings: &SmtpSendSettings,
    envelope: &Envelope,
    message: &[u8],
) -> Result<bool> {
    smtp_transport(settings)?
        .send_raw(envelope, message)
        .map(|_| true)
        .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))
}

/// Send a raw RFC 5322 message without blocking a Tokio worker. The caller may
/// apply a transaction-level timeout; dropping this future cancels active I/O
/// instead of leaving an uncancellable blocking SMTP task behind.
pub async fn send_raw_message_async(
    settings: &SmtpSendSettings,
    envelope: &Envelope,
    message: &[u8],
    options: SmtpDeliveryOptions,
) -> Result<bool> {
    if options.dsn || options.require_tls {
        return send_raw_message_with_extensions_async(settings, envelope, message, options).await;
    }
    async_smtp_transport(settings)?
        .send_raw(envelope, message)
        .await
        .map(|_| true)
        .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))
}

fn smtp_response_has_capability(response: &Response, capability: &str) -> bool {
    response.message().any(|line| {
        line.split_whitespace()
            .next()
            .is_some_and(|keyword| keyword.eq_ignore_ascii_case(capability))
    })
}

async fn send_raw_message_with_extensions_async(
    settings: &SmtpSendSettings,
    envelope: &Envelope,
    message: &[u8],
    options: SmtpDeliveryOptions,
) -> Result<bool> {
    let host = settings.host.trim();
    let connect_host = settings.connect_host.trim();
    if host.is_empty() || connect_host.is_empty() {
        return Err(FrickmailError::Upstream(
            "SMTP host is not configured".to_string(),
        ));
    }
    let tls_parameters = || {
        TlsParameters::new(host.to_string())
            .map_err(|err| FrickmailError::Upstream(format!("SMTP TLS setup failed: {err}")))
    };
    let security = settings.secure.trim().to_ascii_lowercase();
    let wrapper_tls = matches!(security.as_str(), "ssl" | "tls")
        .then(tls_parameters)
        .transpose()?;
    if !matches!(security.as_str(), "" | "none" | "starttls" | "ssl" | "tls") {
        return Err(FrickmailError::Upstream(format!(
            "unsupported SMTP security mode: {security}"
        )));
    }

    let hello = ClientId::default();
    let mut connection = AsyncSmtpConnection::connect_tokio1(
        (connect_host, settings.port),
        Some(Duration::from_secs(30)),
        &hello,
        wrapper_tls,
        None,
    )
    .await
    .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))?;
    if security == "starttls" {
        connection
            .starttls(tls_parameters()?, &hello)
            .await
            .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))?;
    }
    // Lettre intentionally tracks only extensions it implements. A fresh EHLO
    // after final TLS negotiation and before AUTH retains one raw capability
    // snapshot for all delivery extensions. Authentication still uses Lettre's
    // parsed EHLO state from the same post-TLS stage.
    let capabilities = connection
        .command(Ehlo::new(hello))
        .await
        .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))?;
    let dsn_supported = smtp_response_has_capability(&capabilities, "DSN");
    let require_tls_supported = smtp_response_has_capability(&capabilities, "REQUIRETLS");
    let smtp_utf8_supported = smtp_response_has_capability(&capabilities, "SMTPUTF8");
    let eight_bit_mime_supported = smtp_response_has_capability(&capabilities, "8BITMIME");

    if !settings.login.is_empty() {
        // Use XOAUTH2 if access token is available, otherwise fall back to password auth
        let mechanisms = if let Some(access_token) = &settings.access_token {
            if !access_token.is_empty() {
                vec![Mechanism::Xoauth2]
            } else {
                DEFAULT_MECHANISMS.to_vec()
            }
        } else {
            DEFAULT_MECHANISMS.to_vec()
        };

        let credentials = if let Some(access_token) = &settings.access_token {
            if !access_token.is_empty() {
                // For XOAUTH2, the secret field contains the access token
                Credentials::new(settings.login.clone(), access_token.clone())
            } else {
                Credentials::new(settings.login.clone(), settings.password.clone())
            }
        } else {
            Credentials::new(settings.login.clone(), settings.password.clone())
        };

        connection
            .auth(&mechanisms, &credentials)
            .await
            .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))?;
    }

    let mut mail_parameters = Vec::new();
    let has_non_ascii_addresses = envelope
        .from()
        .is_some_and(|address| !address.user().is_ascii() || !address.domain().is_ascii())
        || envelope
            .to()
            .iter()
            .any(|address| !address.user().is_ascii() || !address.domain().is_ascii());
    if has_non_ascii_addresses {
        if !smtp_utf8_supported {
            return Err(FrickmailError::Upstream(
                "SMTP send failed: envelope requires SMTPUTF8".to_string(),
            ));
        }
        mail_parameters.push(MailParameter::SmtpUtfEight);
    }
    if !message.is_ascii() {
        if !eight_bit_mime_supported {
            return Err(FrickmailError::Upstream(
                "SMTP send failed: message requires 8BITMIME".to_string(),
            ));
        }
        mail_parameters.push(MailParameter::Body(MailBodyParameter::EightBitMime));
    }
    if options.dsn && dsn_supported {
        mail_parameters.push(MailParameter::Other {
            keyword: "RET".to_string(),
            value: Some("HDRS".to_string()),
        });
    }
    if options.require_tls && require_tls_supported {
        mail_parameters.push(MailParameter::Other {
            keyword: "REQUIRETLS".to_string(),
            value: None,
        });
    }
    connection
        .command(Mail::new(envelope.from().cloned(), mail_parameters))
        .await
        .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))?;

    for recipient in envelope.to() {
        let parameters = if options.dsn && dsn_supported {
            vec![RcptParameter::Other {
                keyword: "NOTIFY".to_string(),
                value: Some("SUCCESS,FAILURE".to_string()),
            }]
        } else {
            Vec::new()
        };
        connection
            .command(Rcpt::new(recipient.clone(), parameters))
            .await
            .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))?;
    }
    connection
        .command(Data)
        .await
        .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))?;
    connection
        .message(message)
        .await
        .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))?;

    // Delivery is committed once DATA receives success. Drop the connection
    // immediately: waiting for QUIT could turn a confirmed delivery into the
    // caller's unknown-outcome timeout and invite a duplicate retry.
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
    };

    async fn capture_extended_smtp_transaction(advertise_extensions: bool) -> Vec<String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();
            let mut captured = Vec::new();
            writer.write_all(b"220 localhost ESMTP\r\n").await.unwrap();
            while let Some(line) = lines.next_line().await.unwrap() {
                captured.push(line.clone());
                let upper = line.to_ascii_uppercase();
                if upper.starts_with("EHLO ") {
                    if advertise_extensions {
                        writer
                            .write_all(b"250-localhost\r\n250-AUTH PLAIN\r\n250-DSN\r\n250-REQUIRETLS\r\n250 OK\r\n")
                            .await
                            .unwrap();
                    } else {
                        writer
                            .write_all(b"250-localhost\r\n250 AUTH PLAIN\r\n")
                            .await
                            .unwrap();
                    }
                } else if upper.starts_with("AUTH PLAIN") {
                    writer.write_all(b"235 authenticated\r\n").await.unwrap();
                } else if upper.starts_with("MAIL FROM:") || upper.starts_with("RCPT TO:") {
                    writer.write_all(b"250 OK\r\n").await.unwrap();
                } else if upper == "DATA" {
                    writer.write_all(b"354 continue\r\n").await.unwrap();
                } else if line == "." {
                    writer.write_all(b"250 queued\r\n").await.unwrap();
                } else if upper == "QUIT" {
                    // Intentionally no reply: confirmed DATA must not wait on QUIT.
                }
            }
            captured
        });

        let settings = SmtpSendSettings {
            host: "127.0.0.1".to_string(),
            connect_host: "127.0.0.1".to_string(),
            port,
            secure: "none".to_string(),
            login: "sender".to_string(),
            password: "secret".to_string(),
            access_token: None,
        };
        let envelope =
            build_envelope("sender@example.com", &["recipient@example.com".to_string()]).unwrap();
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            send_raw_message_async(
                &settings,
                &envelope,
                b"Subject: test\r\n\r\nbody",
                SmtpDeliveryOptions {
                    dsn: true,
                    require_tls: true,
                },
            ),
        )
        .await
        .expect("confirmed DATA must not wait for QUIT")
        .unwrap());
        server.await.unwrap()
    }

    #[test]
    fn password_reset_body_contains_link_and_warning() {
        let email = PasswordResetEmail {
            to: "alice@example.com".to_string(),
            username: "alice".to_string(),
            reset_url: "https://mail.example/?reset_token=token".to_string(),
        };

        let body = password_reset_body(&email);
        assert!(body.contains("Hello alice"));
        assert!(body.contains("https://mail.example/?reset_token=token"));
        assert!(body.contains("need to be re-entered"));
    }

    #[test]
    fn unconfigured_smtp_skips_send() {
        let config = TransactionalSmtpConfig::default();
        let email = PasswordResetEmail {
            to: "alice@example.com".to_string(),
            username: "alice".to_string(),
            reset_url: "https://mail.example/?reset_token=token".to_string(),
        };

        assert!(!send_password_reset_email(&config, &email).unwrap());
    }

    #[tokio::test]
    async fn extended_delivery_options_are_capability_gated_like_mailso() {
        let supported = capture_extended_smtp_transaction(true).await;
        let mail = supported
            .iter()
            .find(|line| line.starts_with("MAIL FROM:"))
            .unwrap();
        let recipient = supported
            .iter()
            .find(|line| line.starts_with("RCPT TO:"))
            .unwrap();
        assert!(mail.contains("RET=HDRS"));
        assert!(mail.contains("REQUIRETLS"));
        assert!(recipient.contains("NOTIFY=SUCCESS,FAILURE"));
        let second_ehlo = supported
            .iter()
            .enumerate()
            .filter(|(_, line)| line.starts_with("EHLO "))
            .nth(1)
            .map(|(index, _)| index)
            .unwrap();
        let auth = supported
            .iter()
            .position(|line| line.starts_with("AUTH PLAIN"))
            .unwrap();
        let mail_index = supported
            .iter()
            .position(|line| line.starts_with("MAIL FROM:"))
            .unwrap();
        assert!(second_ehlo < auth && auth < mail_index);
        assert!(!supported.iter().any(|line| line == "QUIT"));

        let unsupported = capture_extended_smtp_transaction(false).await;
        let mail = unsupported
            .iter()
            .find(|line| line.starts_with("MAIL FROM:"))
            .unwrap();
        let recipient = unsupported
            .iter()
            .find(|line| line.starts_with("RCPT TO:"))
            .unwrap();
        assert!(!mail.contains("RET="));
        assert!(!mail.contains("REQUIRETLS"));
        assert!(!recipient.contains("NOTIFY="));
    }
}
