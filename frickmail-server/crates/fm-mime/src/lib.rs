use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedMessageSummary {
    pub subject: Option<String>,
    pub from: Vec<String>,
    pub has_attachments: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedMessageBody {
    pub html: String,
    pub plain: String,
    pub subject: Option<String>,
}

pub fn parse_summary(raw: &[u8]) -> ParsedMessageSummary {
    let Some(message) = mail_parser::MessageParser::default().parse(raw) else {
        return ParsedMessageSummary {
            subject: None,
            from: Vec::new(),
            has_attachments: false,
        };
    };

    ParsedMessageSummary {
        subject: message.subject().map(ToOwned::to_owned),
        from: message
            .from()
            .map(|from| from.iter().map(format_addr).collect())
            .unwrap_or_default(),
        has_attachments: message.attachment_count() > 0,
    }
}

pub fn parse_body(raw: &[u8]) -> Option<ParsedMessageBody> {
    let message = mail_parser::MessageParser::default().parse(raw)?;
    let html = message
        .body_html(0)
        .map(|body| body.into_owned())
        .map(|body| sanitize_html(&body))
        .unwrap_or_default();
    let plain = message
        .body_text(0)
        .map(|body| body.into_owned())
        .unwrap_or_default();
    let subject = message.subject().map(ToOwned::to_owned);

    if html.is_empty() && plain.is_empty() && subject.is_none() {
        return None;
    }

    Some(ParsedMessageBody {
        html,
        plain,
        subject,
    })
}

fn format_addr(addr: &mail_parser::Addr<'_>) -> String {
    match (addr.name(), addr.address()) {
        (Some(name), Some(address)) if !name.is_empty() => format!("{name} <{address}>"),
        (_, Some(address)) => address.to_string(),
        (Some(name), None) => name.to_string(),
        (None, None) => String::new(),
    }
}

fn sanitize_html(html: &str) -> String {
    ammonia::Builder::default().clean(html).to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse_body, parse_summary};

    #[test]
    fn parses_summary_headers_and_attachment_presence() {
        let raw = br#"From: Sender <sender@example.com>
Subject: Test message
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain; charset=utf-8

Hello body.
--b
Content-Type: text/plain; name="notes.txt"
Content-Disposition: attachment; filename="notes.txt"

Attachment text.
--b--
"#;

        let summary = parse_summary(raw);

        assert_eq!(summary.subject.as_deref(), Some("Test message"));
        assert_eq!(summary.from, vec!["Sender <sender@example.com>"]);
        assert!(summary.has_attachments);
    }

    #[test]
    fn parses_html_and_plain_body_variants() {
        let raw = br#"From: sender@example.com
Subject: Body message
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b"

--b
Content-Type: text/plain; charset=utf-8

Plain body.
--b
Content-Type: text/html; charset=utf-8

<p onclick="alert(1)">HTML body.</p><script>alert(2)</script>
--b--
"#;

        let body = parse_body(raw).unwrap();

        assert_eq!(body.subject.as_deref(), Some("Body message"));
        assert_eq!(body.plain.trim(), "Plain body.");
        assert_eq!(body.html.trim(), "<p>HTML body.</p>");
        assert!(!body.html.contains("script"));
        assert!(!body.html.contains("onclick"));
    }

    #[test]
    fn invalid_message_returns_empty_summary_and_no_body() {
        let raw = b"\x00\x01\x02";

        let summary = parse_summary(raw);

        assert_eq!(summary.subject, None);
        assert!(summary.from.is_empty());
        assert!(!summary.has_attachments);
        assert_eq!(parse_body(raw), None);
    }
}
