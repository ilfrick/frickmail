use mail_parser::{Address, HeaderForm, HeaderValue};
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
    pub message_id: String,
    pub in_reply_to: String,
    pub references: String,
    pub read_receipt: String,
    pub header_timestamp: Option<i64>,
    pub date_header_present: bool,
    pub from: Vec<String>,
    pub reply_to: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub sender: Vec<String>,
    pub delivered_to: Vec<String>,
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
        from: format_address_list(message.from()),
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
    let message_id = format_legacy_header_value(&message, "Message-ID");
    let in_reply_to = format_legacy_header_value(&message, "In-Reply-To");
    let references =
        collapse_header_whitespace(&format_legacy_header_value(&message, "References"));
    let read_receipt = format_read_receipt(&message);
    let date_header_present = message
        .headers()
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case("Date"));
    let header_timestamp =
        fm_core::legacy_rfc2822_timestamp(&format_legacy_header_value(&message, "Date"));
    let from = format_header_addresses(&message, "From");
    let reply_to = format_header_addresses(&message, "Reply-To");
    let to = format_header_addresses(&message, "To");
    let cc = format_header_addresses(&message, "Cc");
    let bcc = format_header_addresses(&message, "Bcc");
    let sender = format_header_addresses(&message, "Sender");
    let delivered_to = format_header_addresses(&message, "Delivered-To");

    if html.is_empty()
        && plain.is_empty()
        && subject.is_none()
        && message_id.is_empty()
        && in_reply_to.is_empty()
        && references.is_empty()
        && read_receipt.is_empty()
        && !date_header_present
        && from.is_empty()
        && reply_to.is_empty()
        && to.is_empty()
        && cc.is_empty()
        && bcc.is_empty()
        && sender.is_empty()
        && delivered_to.is_empty()
    {
        return None;
    }

    Some(ParsedMessageBody {
        html,
        plain,
        subject,
        message_id,
        in_reply_to,
        references,
        read_receipt,
        header_timestamp,
        date_header_present,
        from,
        reply_to,
        to,
        cc,
        bcc,
        sender,
        delivered_to,
    })
}

fn format_address_list(addresses: Option<&Address<'_>>) -> Vec<String> {
    addresses.map(format_address_value).unwrap_or_default()
}

fn format_header_addresses(message: &mail_parser::Message<'_>, header: &str) -> Vec<String> {
    message
        .header_as(header, HeaderForm::Addresses)
        .into_iter()
        .next()
        .map(format_header_address_value)
        .unwrap_or_default()
}

fn format_legacy_header_value(message: &mail_parser::Message<'_>, header: &str) -> String {
    let raw = message
        .header_as(header, HeaderForm::Raw)
        .into_iter()
        .next()
        .and_then(|value| match value {
            HeaderValue::Text(value) => Some(unfold_identity_header(&value)),
            _ => None,
        })
        .unwrap_or_default();
    if raw.contains("=?") {
        message
            .header_as(header, HeaderForm::Text)
            .into_iter()
            .next()
            .and_then(|value| match value {
                HeaderValue::Text(value) => Some(value.into_owned()),
                _ => None,
            })
            .unwrap_or(raw)
    } else {
        raw
    }
}

fn format_read_receipt(message: &mail_parser::Message<'_>) -> String {
    let primary = format_legacy_header_value(message, "Disposition-Notification-To");
    let (header, selected) = if primary.is_empty() {
        (
            "X-Confirm-Reading-To",
            format_legacy_header_value(message, "X-Confirm-Reading-To"),
        )
    } else {
        ("Disposition-Notification-To", primary)
    };
    if selected.is_empty()
        || !has_non_comment_email_content(&selected)
        || format_header_addresses(message, header).is_empty()
    {
        String::new()
    } else {
        selected
    }
}

fn has_non_comment_email_content(value: &str) -> bool {
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

    !output.trim().is_empty()
}

fn unfold_identity_header(value: &str) -> String {
    let mut unfolded = String::with_capacity(value.len());
    let mut in_line_break = false;
    for ch in value.chars() {
        if matches!(ch, '\r' | '\n' | '\t') {
            if !in_line_break {
                unfolded.push(' ');
                in_line_break = true;
            }
        } else {
            unfolded.push(ch);
            in_line_break = false;
        }
    }
    unfolded.trim().to_string()
}

fn collapse_header_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn format_header_address_value(value: HeaderValue<'_>) -> Vec<String> {
    match value {
        HeaderValue::Address(address) => format_address_value(&address),
        _ => Vec::new(),
    }
}

fn format_address_value(addresses: &Address<'_>) -> Vec<String> {
    match addresses {
        Address::List(list) => list.iter().map(format_addr).collect(),
        Address::Group(groups) => groups
            .iter()
            .flat_map(|group| group.addresses.iter())
            .map(format_addr)
            .collect(),
    }
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
        assert_eq!(body.from, vec!["sender@example.com"]);
        assert_eq!(body.plain.trim(), "Plain body.");
        assert_eq!(body.html.trim(), "<p>HTML body.</p>");
        assert!(!body.html.contains("script"));
        assert!(!body.html.contains("onclick"));
    }

    #[test]
    fn parses_body_address_headers() {
        let raw = br#"From: Sender <sender@example.com>
Reply-To: Reply <reply@example.com>
To: Recipient <recipient@example.com>
Cc: CC <cc@example.com>
Bcc: Hidden <hidden@example.com>
Sender: Actual Sender <actual@example.com>
Delivered-To: delivered@example.com
Delivered-To: ignored-delivery@example.com
Message-ID: <message@example.com>
In-Reply-To: <parent@example.com>
References: <root@example.com>
 <parent@example.com>
Disposition-Notification-To: primary@example.com
X-Confirm-Reading-To: fallback@example.com
Date: Tue, 1 Jul 2003 10:52:37 CEST
Subject: Address body

Hello.
"#;

        let body = parse_body(raw).unwrap();

        assert_eq!(body.subject.as_deref(), Some("Address body"));
        assert_eq!(body.message_id, "<message@example.com>");
        assert_eq!(body.in_reply_to, "<parent@example.com>");
        assert_eq!(body.references, "<root@example.com> <parent@example.com>");
        assert_eq!(body.read_receipt, "primary@example.com");
        assert_eq!(body.header_timestamp, Some(1_057_049_557));
        assert!(body.date_header_present);
        assert_eq!(body.from, vec!["Sender <sender@example.com>"]);
        assert_eq!(body.reply_to, vec!["Reply <reply@example.com>"]);
        assert_eq!(body.to, vec!["Recipient <recipient@example.com>"]);
        assert_eq!(body.cc, vec!["CC <cc@example.com>"]);
        assert_eq!(body.bcc, vec!["Hidden <hidden@example.com>"]);
        assert_eq!(body.sender, vec!["Actual Sender <actual@example.com>"]);
        assert_eq!(body.delivered_to, vec!["delivered@example.com"]);
    }

    #[test]
    fn parses_header_only_identity_metadata() {
        let raw = b"Message-ID: =?UTF-8?Q?<m=C3=A9ssage@example.com>?=\r\n\
In-Reply-To: <first@example.com>\r\n  <second@example.com>\r\n\
References: <root@example.com>\r\n\t<first@example.com>\r\n\
Disposition-Notification-To:   \r\n\
X-Confirm-Reading-To: fallback@example.com\r\n\r\n";

        let body = parse_body(raw).unwrap();

        assert!(body.html.is_empty());
        assert!(body.plain.is_empty());
        assert!(body.subject.is_none());
        assert_eq!(body.message_id, "<m\u{e9}ssage@example.com>");
        assert_eq!(
            body.in_reply_to,
            "<first@example.com>   <second@example.com>"
        );
        assert_eq!(body.references, "<root@example.com> <first@example.com>");
        assert_eq!(body.read_receipt, "fallback@example.com");
        assert_eq!(body.header_timestamp, None);
        assert!(!body.date_header_present);
    }

    #[test]
    fn invalid_primary_read_receipt_does_not_use_fallback() {
        let raw = b"Disposition-Notification-To: <>\r\n\
X-Confirm-Reading-To: fallback@example.com\r\n\
Subject: Invalid receipt\r\n\r\n";

        let body = parse_body(raw).unwrap();

        assert!(body.read_receipt.is_empty());

        let comment_only = b"Disposition-Notification-To: (comment)\r\n\
X-Confirm-Reading-To: fallback@example.com\r\n\
Subject: Comment-only receipt\r\n\r\n";
        let body = parse_body(comment_only).unwrap();

        assert!(body.read_receipt.is_empty());
    }

    #[test]
    fn body_address_headers_use_first_duplicate_like_php() {
        let raw = br#"From: First <first@example.com>
From: Second <second@example.com>
Message-ID: <first@example.com>
Message-ID: <second@example.com>
Date: definitely not a date
Date: Wed, 2 Jul 2003 10:52:37 +0200
Subject: Duplicate address

Hello.
"#;

        let body = parse_body(raw).unwrap();

        assert_eq!(body.from, vec!["First <first@example.com>"]);
        assert_eq!(body.message_id, "<first@example.com>");
        assert_eq!(body.header_timestamp, None);
        assert!(body.date_header_present);
    }

    #[test]
    fn parses_malformed_date_only_as_available_metadata() {
        let body = parse_body(b"Date: definitely not a date\r\n\r\n").unwrap();

        assert_eq!(body.header_timestamp, None);
        assert!(body.date_header_present);
        assert!(body.html.is_empty());
        assert!(body.plain.is_empty());
        assert!(body.subject.is_none());
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
