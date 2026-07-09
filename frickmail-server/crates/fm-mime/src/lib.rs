use std::collections::HashMap;

use mail_parser::{Address, Encoding, HeaderForm, HeaderValue, MessagePart, MimeHeaders, PartType};
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
    pub attachments: Vec<ParsedMessageAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedMessageAttachment {
    pub mime_index: String,
    pub mime_type: String,
    pub file_name: String,
    pub estimated_size: u32,
    pub c_id: String,
    pub content_location: String,
    pub is_inline: bool,
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
    let attachments = format_attachments(&message);

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
        && attachments.is_empty()
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
        attachments,
    })
}

fn format_attachments(message: &mail_parser::Message<'_>) -> Vec<ParsedMessageAttachment> {
    let mime_indexes = legacy_mime_part_indexes(message);
    message
        .attachments
        .iter()
        .filter_map(|part_id| {
            let part = message.part(*part_id)?;
            let mime_index = mime_indexes
                .get(part_id)
                .cloned()
                .unwrap_or_else(|| part_id.to_string());
            Some(format_attachment(message, part, &mime_index))
        })
        .collect()
}

fn legacy_mime_part_indexes(message: &mail_parser::Message<'_>) -> HashMap<usize, String> {
    let mut indexes = HashMap::new();
    if !message.parts.is_empty() {
        collect_legacy_mime_part_indexes(message, 0, "", &mut indexes);
    }
    indexes
}

fn collect_legacy_mime_part_indexes(
    message: &mail_parser::Message<'_>,
    part_index: usize,
    part_id: &str,
    indexes: &mut HashMap<usize, String>,
) {
    let Some(part) = message.part(part_index) else {
        return;
    };
    let current_part_id = if !part_id.is_empty() {
        part_id.to_string()
    } else if matches!(part.body, PartType::Multipart(_)) {
        "TEXT".to_string()
    } else {
        "1".to_string()
    };
    indexes.insert(part_index, current_part_id);

    if let PartType::Multipart(children) = &part.body {
        let child_prefix = if part_id.is_empty() {
            String::new()
        } else {
            format!("{part_id}.")
        };
        for (index, child) in children.iter().enumerate() {
            collect_legacy_mime_part_indexes(
                message,
                *child,
                &format!("{}{index}", child_prefix, index = index + 1),
                indexes,
            );
        }
    }
}

fn format_attachment(
    message: &mail_parser::Message<'_>,
    part: &MessagePart<'_>,
    mime_index: &str,
) -> ParsedMessageAttachment {
    let mime_type = attachment_mime_type(part);
    let is_inline = attachment_is_inline(part);
    let file_name = part
        .attachment_name()
        .map(legacy_php_trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default_attachment_file_name(&mime_type, mime_index, is_inline));

    ParsedMessageAttachment {
        mime_index: mime_index.to_string(),
        mime_type,
        file_name: secure_attachment_file_name(&file_name),
        estimated_size: estimated_attachment_size(message, part),
        c_id: legacy_attachment_content_id(part),
        content_location: part.content_location().unwrap_or_default().to_string(),
        is_inline,
    }
}

fn legacy_attachment_content_id(part: &MessagePart<'_>) -> String {
    part.content_id().unwrap_or_default().trim().to_string()
}

fn estimated_attachment_size(message: &mail_parser::Message<'_>, part: &MessagePart<'_>) -> u32 {
    let raw_len = message
        .raw_message
        .get(part.offset_body..part.offset_end)
        .map(trim_ascii_whitespace)
        .map_or_else(|| part.body.len(), <[u8]>::len);
    let coefficient = match part.encoding {
        Encoding::Base64 => 0.75,
        Encoding::QuotedPrintable => 0.44,
        _ => 1.0,
    };

    ((raw_len as f64) * coefficient) as u32
}

fn trim_ascii_whitespace(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();
    while start < end && value[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && value[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &value[start..end]
}

fn attachment_mime_type(part: &MessagePart<'_>) -> String {
    if let Some(content_type) = part.content_type() {
        return format!(
            "{}/{}",
            content_type.ctype(),
            content_type.subtype().unwrap_or_default()
        )
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase();
    }

    match &part.body {
        PartType::Text(_) => "text/plain",
        PartType::Html(_) => "text/html",
        PartType::Message(_) => "message/rfc822",
        PartType::Multipart(_) => "multipart/mixed",
        PartType::Binary(_) | PartType::InlineBinary(_) => "application/octet-stream",
    }
    .to_string()
}

fn attachment_is_inline(part: &MessagePart<'_>) -> bool {
    part.content_disposition()
        .is_some_and(|disposition| disposition.ctype().eq_ignore_ascii_case("inline"))
        || matches!(part.body, PartType::InlineBinary(_))
        || part
            .content_id()
            .is_some_and(|content_id| !content_id.trim().is_empty())
}

fn default_attachment_file_name(mime_type: &str, mime_index: &str, is_inline: bool) -> String {
    let suffix = format!("-{mime_index}");
    match mime_type {
        "message/rfc822" => format!("message{suffix}.eml"),
        "text/calendar" => format!("calendar{suffix}.ics"),
        "text/plain" => format!("part{suffix}.txt"),
        "text/vcard" | "text/html" | "text/csv" | "text/xml" | "text/css" | "text/asp" => {
            format!("part{suffix}.{}", mime_type.trim_start_matches("text/"))
        }
        "image/png" | "image/jpeg" | "image/gif" | "image/bmp" | "image/cgm" | "image/ief"
        | "image/tiff" | "image/webp" => {
            format!("part{suffix}.{}", mime_type.trim_start_matches("image/"))
        }
        _ if !mime_type.is_empty() => mime_type.replace('/', &format!("{suffix}.")),
        _ if is_inline => format!("inline{suffix}"),
        _ => format!("part{suffix}"),
    }
}

fn secure_attachment_file_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_control()
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

fn legacy_php_trim(value: &str) -> &str {
    value.trim_matches(|ch| matches!(ch, ' ' | '\t' | '\n' | '\r' | '\0' | '\x0b'))
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
    fn parses_raw_message_attachment_metadata() {
        let raw = br#"Subject: Attachment message
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: multipart/alternative; boundary="alt"

--alt
Content-Type: text/plain; charset=utf-8

Body.
--alt
Content-Type: text/html; charset=utf-8

<p>Body.</p>
--alt--
--b
Content-Type: application/pdf; name="report.pdf"
Content-Disposition: attachment; filename="../report?.pdf"
Content-ID: <part@example.com>
Content-Location: cid:report
Content-Transfer-Encoding: base64

UERGREFUQQ==
--b--
"#;

        let body = parse_body(raw).unwrap();
        let attachment = &body.attachments[0];

        assert_eq!(body.attachments.len(), 1);
        assert_eq!(attachment.mime_index, "2");
        assert_eq!(attachment.mime_type, "application/pdf");
        assert_eq!(attachment.file_name, "..-report-.pdf");
        assert_eq!(attachment.estimated_size, 9);
        assert_eq!(attachment.c_id, "part@example.com");
        assert_eq!(attachment.content_location, "cid:report");
        assert!(attachment.is_inline);
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
