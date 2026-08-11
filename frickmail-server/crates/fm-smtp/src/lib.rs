use fm_core::{config::TransactionalSmtpConfig, FrickmailError, Result};
use lettre::{
    address::{Address, Envelope},
    message::{header::ContentType, Mailbox},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
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
        builder = builder.credentials(Credentials::new(
            settings.login.clone(),
            settings.password.clone(),
        ));
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
        builder = builder.credentials(Credentials::new(
            settings.login.clone(),
            settings.password.clone(),
        ));
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
) -> Result<bool> {
    async_smtp_transport(settings)?
        .send_raw(envelope, message)
        .await
        .map(|_| true)
        .map_err(|err| FrickmailError::Upstream(format!("SMTP send failed: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
