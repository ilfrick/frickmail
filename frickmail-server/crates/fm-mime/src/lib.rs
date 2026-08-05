use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mail_parser::{
    parsers::MessageStream, Address, Encoding, Header, HeaderForm, HeaderValue, MessagePart,
    MimeHeaders, PartType,
};
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
    pub encrypted: bool,
    pub draft_info: Option<ParsedDraftInfo>,
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
    pub headers: Vec<ParsedMessageHeader>,
    pub auth_statuses: ParsedAuthStatuses,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedMessageHeader {
    pub name: String,
    pub value: String,
    pub parameters: Vec<ParsedMessageHeaderParameter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedMessageHeaderParameter {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedAuthStatuses {
    pub dkim: Vec<[String; 3]>,
    pub dmarc: Vec<[String; 3]>,
    pub spf: Vec<[String; 3]>,
}

impl ParsedAuthStatuses {
    pub fn is_empty(&self) -> bool {
        self.dkim.is_empty() && self.dmarc.is_empty() && self.spf.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedDraftInfo {
    pub info_type: String,
    pub uid: i64,
    pub folder: String,
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
    let encrypted = legacy_message_encrypted(&message);
    let draft_info = format_draft_info(&message);
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
    let headers = format_headers(&message);
    let auth_statuses = legacy_auth_statuses(raw);

    if html.is_empty()
        && plain.is_empty()
        && subject.is_none()
        && !encrypted
        && draft_info.is_none()
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
        && headers.is_empty()
        && auth_statuses.is_empty()
    {
        return None;
    }

    Some(ParsedMessageBody {
        html,
        plain,
        subject,
        encrypted,
        draft_info,
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
        headers,
        auth_statuses,
    })
}

pub fn parse_body_part_text(raw: &[u8]) -> Option<String> {
    let message = mail_parser::MessageParser::default().parse(raw)?;
    match &message.parts.first()?.body {
        PartType::Text(text) => Some(text.to_string()),
        PartType::Html(html) => Some(sanitize_html(html)),
        PartType::Binary(bytes) | PartType::InlineBinary(bytes) => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        PartType::Message(_) | PartType::Multipart(_) => None,
    }
}

fn legacy_auth_statuses(raw: &[u8]) -> ParsedAuthStatuses {
    let mut result = ParsedAuthStatuses::default();
    let authentication_results = raw_header_values(raw, "Authentication-Results");

    if !authentication_results.is_empty() {
        let value = collapse_ascii_whitespace(&authentication_results.join(";"))
            .replace("-bit key;", "-bit key,");
        for line in value.split(';') {
            if let (Some((kind, status)), Some(identity)) =
                (auth_result_status(line), auth_result_identity(line))
            {
                let item = [
                    status.to_ascii_lowercase(),
                    identity,
                    line.trim().to_string(),
                ];
                match kind.as_str() {
                    "dkim" => result.dkim.push(item),
                    "dmarc" => result.dmarc.push(item),
                    "spf" => result.spf.push(item),
                    _ => {}
                }
            }
        }
    }

    if result.dkim.is_empty() {
        for value in raw_header_values(raw, "X-DKIM-Authentication-Results") {
            let value = collapse_ascii_whitespace(&value);
            if let (Some(status), Some(signer)) = (
                quoted_auth_parameter(&value, "status", true),
                quoted_auth_parameter(&value, "signer", false),
            ) {
                result.dkim.push([status, signer.trim().to_string(), value]);
            }
        }
    }

    result
}

fn raw_header_values(raw: &[u8], name: &str) -> Vec<String> {
    let raw = String::from_utf8_lossy(raw).replace('\r', "");
    let mut values = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_value = String::new();

    for line in raw.lines() {
        if line.is_empty() {
            break;
        }

        let first = line.chars().next();
        if matches!(first, Some(' ' | '\t')) && current_name.is_some() {
            current_value.push('\n');
            current_value.push_str(line);
            continue;
        }

        if let Some(header_name) = current_name.take() {
            if header_name.eq_ignore_ascii_case(name) {
                values.push(current_value.trim().to_string());
            }
            current_value.clear();
        }

        let Some((header_name, header_value)) = line.split_once(':') else {
            continue;
        };
        current_name = Some(header_name.trim().to_string());
        current_value.push_str(header_value);
    }

    if let Some(header_name) = current_name {
        if header_name.eq_ignore_ascii_case(name) {
            values.push(current_value.trim().to_string());
        }
    }

    values
}

fn collapse_ascii_whitespace(value: &str) -> String {
    let mut collapsed = String::with_capacity(value.len());
    let mut pending_space = false;
    for ch in value.chars() {
        if ch.is_whitespace() {
            pending_space = true;
        } else {
            if pending_space && !collapsed.is_empty() {
                collapsed.push(' ');
            }
            collapsed.push(ch);
            pending_space = false;
        }
    }
    collapsed
}

fn auth_result_status(line: &str) -> Option<(String, String)> {
    let lower = line.to_ascii_lowercase();
    let mut best: Option<(usize, &str)> = None;
    for kind in ["dkim", "dmarc", "spf"] {
        let needle = format!("{kind}=");
        if let Some(index) = lower.find(&needle) {
            if best.is_none_or(|(best_index, _)| index < best_index) {
                best = Some((index, kind));
            }
        }
    }

    let (index, kind) = best?;
    let start = index + kind.len() + 1;
    let status: String = line[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric())
        .collect();
    (!status.is_empty()).then(|| (kind.to_string(), status))
}

fn auth_result_identity(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let mut best: Option<(usize, &'static str)> = None;
    for key in ["header.d=", "header.i=", "header.from=", "smtp.mailfrom="] {
        if let Some(index) = lower.find(key) {
            if best.is_none_or(|(best_index, _)| index < best_index) {
                best = Some((index, key));
            }
        }
    }

    let (index, key) = best?;
    let value = &line[index + key.len()..];
    let value = value.strip_prefix('"').unwrap_or(value);
    let identity: String = value
        .chars()
        .take_while(|ch| !ch.is_whitespace() && *ch != ';' && *ch != '"')
        .collect();
    (!identity.is_empty()).then_some(identity)
}

fn quoted_auth_parameter(value: &str, key: &str, alphanumeric_only: bool) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let needle = key.to_ascii_lowercase();
    let index = lower.find(&needle)?;
    let rest = &value[index + needle.len()..];
    let rest = rest.strip_prefix(char::is_whitespace).unwrap_or(rest);
    let rest = rest.strip_prefix('=')?;
    let rest = rest.strip_prefix(char::is_whitespace).unwrap_or(rest);
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    let result = &rest[..end];
    if result.is_empty()
        || (alphanumeric_only && !result.chars().all(|ch| ch.is_ascii_alphanumeric()))
    {
        return None;
    }
    Some(result.to_string())
}

fn format_headers(message: &mail_parser::Message<'_>) -> Vec<ParsedMessageHeader> {
    message
        .headers()
        .iter()
        .map(|header| ParsedMessageHeader {
            name: header.name.as_str().to_string(),
            value: legacy_header_collection_value(message, header),
            parameters: legacy_header_collection_parameters(header),
        })
        .filter(|header| !header.name.is_empty() && !header.value.is_empty())
        .collect()
}

fn legacy_header_collection_value(
    message: &mail_parser::Message<'_>,
    header: &Header<'_>,
) -> String {
    match &header.value {
        HeaderValue::Text(_) | HeaderValue::Address(_) | HeaderValue::TextList(_) => {
            legacy_decode_raw_header_value(&legacy_raw_header_value(message, header))
        }
        HeaderValue::ContentType(content_type) => legacy_content_type_value(content_type),
        HeaderValue::Empty => String::new(),
        _ => legacy_raw_header_value(message, header),
    }
}

fn legacy_raw_header_value(message: &mail_parser::Message<'_>, header: &Header<'_>) -> String {
    message
        .raw_message
        .get(header.offset_start..header.offset_end)
        .map(|value| String::from_utf8_lossy(value).replace('\r', ""))
        .map(|value| legacy_php_trim(&value).to_string())
        .unwrap_or_default()
}

fn legacy_decode_raw_header_value(value: &str) -> String {
    let value = legacy_unfold_encoded_header_value(value);
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
            if whitespace_len > 0 && value[index + whitespace_len..].starts_with("=?") {
                index += whitespace_len;
            }
        } else {
            decoded.push('=');
            index = start + 1;
        }
    }

    decoded.push_str(&value[index..]);
    legacy_php_trim(&decoded).to_string()
}

fn legacy_unfold_encoded_header_value(value: &str) -> String {
    let mut unfolded = String::with_capacity(value.len());
    let mut in_fold = false;

    for ch in value.chars() {
        if matches!(ch, '\r' | '\n' | '\t') {
            if !in_fold {
                unfolded.push(' ');
                in_fold = true;
            }
        } else {
            unfolded.push(ch);
            in_fold = false;
        }
    }

    unfolded
}

fn legacy_header_collection_parameters(header: &Header<'_>) -> Vec<ParsedMessageHeaderParameter> {
    let HeaderValue::ContentType(content_type) = &header.value else {
        return Vec::new();
    };
    let Some(attributes) = &content_type.attributes else {
        return Vec::new();
    };

    attributes
        .iter()
        .map(|(name, value)| ParsedMessageHeaderParameter {
            name: legacy_php_trim(name).trim_matches(['"', '\'']).to_string(),
            value: legacy_php_trim(value).trim_matches(['"', '\'']).to_string(),
        })
        .filter(|parameter| !parameter.name.is_empty())
        .collect()
}

fn legacy_message_encrypted(message: &mail_parser::Message<'_>) -> bool {
    message.content_type().is_some_and(|content_type| {
        legacy_content_type_value(content_type) == "multipart/encrypted"
    })
}

fn format_draft_info(message: &mail_parser::Message<'_>) -> Option<ParsedDraftInfo> {
    let raw = format_legacy_header_value(message, "X-Draft-Info");
    if raw.is_empty() {
        return None;
    }

    let mut info_type = String::new();
    let mut uid = 0;
    let mut folder = String::new();

    for (name, value) in legacy_parameter_pairs(&raw) {
        match name.to_ascii_lowercase().as_str() {
            "type" => info_type = value,
            "uid" => uid = legacy_php_int(&value),
            "folder" => folder = legacy_base64_decode(&value),
            _ => {}
        }
    }

    (!info_type.is_empty() && uid != 0 && !folder.is_empty()).then_some(ParsedDraftInfo {
        info_type,
        uid,
        folder,
    })
}

fn legacy_parameter_pairs(raw: &str) -> impl Iterator<Item = (String, String)> + '_ {
    raw.split(';').filter_map(|part| {
        let (name, value) = part.split_once('=')?;
        let name = legacy_php_trim(name).trim_matches(['"', '\'']).to_string();
        let value = legacy_php_trim(value).trim_matches(['"', '\'']).to_string();
        (!name.is_empty()).then_some((name, value))
    })
}

fn legacy_base64_decode(value: &str) -> String {
    STANDARD
        .decode(value.as_bytes())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

fn legacy_php_int(value: &str) -> i64 {
    let value = legacy_php_trim(value);
    let mut end = 0;
    let mut saw_digit = false;
    for (index, ch) in value.char_indices() {
        let allowed_sign = index == 0 && (ch == '-' || ch == '+');
        if allowed_sign || ch.is_ascii_digit() {
            if ch.is_ascii_digit() {
                saw_digit = true;
            }
            end = index + ch.len_utf8();
        } else {
            break;
        }
    }
    if !saw_digit {
        return 0;
    }
    value[..end].parse::<i64>().unwrap_or_default()
}

fn legacy_content_type_value(content_type: &mail_parser::ContentType<'_>) -> String {
    let mut value = legacy_php_trim(content_type.ctype()).to_string();
    if let Some(subtype) = content_type.subtype() {
        value.push('/');
        value.push_str(legacy_php_trim(subtype));
    }
    value
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
    use super::{parse_body, parse_body_part_text, parse_summary};

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
    fn parses_text_attachment_and_binary_leaf_content() {
        let text = br#"Content-Type: text/plain; charset=utf-8
Content-Disposition: attachment; filename="message.txt"

Attached text.
"#;
        assert_eq!(
            parse_body_part_text(text).as_deref(),
            Some("Attached text.\n")
        );

        let binary = br#"Content-Type: application/octet-stream
Content-Transfer-Encoding: base64

LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0t
"#;
        assert_eq!(
            parse_body_part_text(binary).as_deref(),
            Some("-----BEGIN PGP MESSAGE-----")
        );
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
    fn parses_raw_message_header_collection_metadata() {
        let raw = br#"Subject: =?UTF-8?Q?_Header?=
          =?UTF-8?Q?_message_=C3=84_?=
Content-Type: text/plain; charset=utf-8; format=flowed
X-Custom: folded
	value
References: <root@example.com>
 <parent@example.com>
Received: from mx.example
 by mail.example

Body.
"#;

        let body = parse_body(raw).unwrap();

        assert_eq!(body.headers.len(), 5);
        assert_eq!(body.headers[0].name, "Subject");
        assert_eq!(body.headers[0].value, "Header message Ä");
        assert_eq!(body.headers[1].name, "Content-Type");
        assert_eq!(body.headers[1].value, "text/plain");
        assert_eq!(body.headers[1].parameters.len(), 2);
        assert_eq!(body.headers[1].parameters[0].name, "charset");
        assert_eq!(body.headers[1].parameters[0].value, "utf-8");
        assert_eq!(body.headers[1].parameters[1].name, "format");
        assert_eq!(body.headers[1].parameters[1].value, "flowed");
        assert_eq!(body.headers[2].name, "X-Custom");
        assert_eq!(body.headers[2].value, "folded value");
        assert_eq!(body.headers[3].name, "References");
        assert_eq!(
            body.headers[3].value,
            "<root@example.com>  <parent@example.com>"
        );
        assert_eq!(body.headers[4].name, "Received");
        assert_eq!(body.headers[4].value, "from mx.example\n by mail.example");
    }

    #[test]
    fn parses_authentication_results_like_mailso() {
        let raw = br#"Authentication-Results: mx.example;
 dkim=pass header.d=example.com header.s=s1 header.b=abc;
 spf=fail (sender ip) smtp.mailfrom="bounce.example.com";
 dmarc=pass header.from=example.com (policy=reject)
Authentication-Results: mx2.example; spf=pass smtp.mailfrom=sender.example.com

Body.
"#;

        let body = parse_body(raw).unwrap();

        assert_eq!(
            body.auth_statuses.dkim,
            vec![[
                "pass".to_string(),
                "example.com".to_string(),
                "dkim=pass header.d=example.com header.s=s1 header.b=abc".to_string(),
            ]]
        );
        assert_eq!(
            body.auth_statuses.spf,
            vec![
                [
                    "fail".to_string(),
                    "bounce.example.com".to_string(),
                    "spf=fail (sender ip) smtp.mailfrom=\"bounce.example.com\"".to_string(),
                ],
                [
                    "pass".to_string(),
                    "sender.example.com".to_string(),
                    "spf=pass smtp.mailfrom=sender.example.com".to_string(),
                ],
            ]
        );
        assert_eq!(
            body.auth_statuses.dmarc,
            vec![[
                "pass".to_string(),
                "example.com".to_string(),
                "dmarc=pass header.from=example.com (policy=reject)".to_string(),
            ]]
        );
    }

    #[test]
    fn parses_x_dkim_authentication_results_only_when_primary_dkim_absent() {
        let raw = br#"X-DKIM-Authentication-Results: signer="fallback.example" status="pass"

Body.
"#;

        let body = parse_body(raw).unwrap();

        assert_eq!(
            body.auth_statuses.dkim,
            vec![[
                "pass".to_string(),
                "fallback.example".to_string(),
                "signer=\"fallback.example\" status=\"pass\"".to_string(),
            ]]
        );

        let primary = br#"Authentication-Results: mx.example; dkim=fail header.d=primary.example
X-DKIM-Authentication-Results: signer="fallback.example" status="pass"

Body.
"#;
        let body = parse_body(primary).unwrap();

        assert_eq!(
            body.auth_statuses.dkim,
            vec![[
                "fail".to_string(),
                "primary.example".to_string(),
                "dkim=fail header.d=primary.example".to_string(),
            ]]
        );
    }

    #[test]
    fn parses_x_dkim_fallback_when_primary_auth_has_no_dkim() {
        let raw = br#"Authentication-Results: mx.example; spf=pass smtp.mailfrom=sender.example.com; dmarc=pass header.from=example.com
X-DKIM-Authentication-Results: signer="fallback.example" status="pass"

Body.
"#;

        let body = parse_body(raw).unwrap();

        assert_eq!(
            body.auth_statuses.spf,
            vec![[
                "pass".to_string(),
                "sender.example.com".to_string(),
                "spf=pass smtp.mailfrom=sender.example.com".to_string(),
            ]]
        );
        assert_eq!(
            body.auth_statuses.dmarc,
            vec![[
                "pass".to_string(),
                "example.com".to_string(),
                "dmarc=pass header.from=example.com".to_string(),
            ]]
        );
        assert_eq!(
            body.auth_statuses.dkim,
            vec![[
                "pass".to_string(),
                "fallback.example".to_string(),
                "signer=\"fallback.example\" status=\"pass\"".to_string(),
            ]]
        );
    }

    #[test]
    fn parses_raw_message_decoded_address_header_values() {
        let raw = br#"From: "=?UTF-8?Q?Sender,_=C3=84?=" <sender@example.com>, "Plain, Recipient" <plain@example.com>
To: =?UTF-8?Q?Recipient_=C3=96?= <recipient@example.com>
Cc: "=?UTF-8?Q?Multi_?= =?UTF-8?Q?Part?=" <multi@example.com>

Body.
"#;

        let body = parse_body(raw).unwrap();

        assert_eq!(body.headers[0].name, "From");
        assert_eq!(
            body.headers[0].value,
            "\"Sender, Ä\" <sender@example.com>, \"Plain, Recipient\" <plain@example.com>"
        );
        assert_eq!(body.headers[1].name, "To");
        assert_eq!(body.headers[1].value, "Recipient Ö <recipient@example.com>");
        assert_eq!(body.headers[2].name, "Cc");
        assert_eq!(body.headers[2].value, "\"Multi Part\" <multi@example.com>");
    }

    #[test]
    fn parses_raw_message_top_level_encrypted_content_type() {
        let raw = br#"Subject: Encrypted message
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="b"

--b
Content-Type: application/pgp-encrypted

Version: 1
--b--
"#;

        let body = parse_body(raw).unwrap();

        assert!(body.encrypted);
        assert_eq!(body.headers[1].name, "Content-Type");
        assert_eq!(body.headers[1].value, "multipart/encrypted");
        assert_eq!(
            body.headers[1].parameters[0].value,
            "application/pgp-encrypted"
        );
    }

    #[test]
    fn parses_raw_message_draft_info() {
        let raw = br#"Subject: Draft reply
X-Draft-Info: type=reply; uid=77; folder=SU5CT1g=

Body.
"#;

        let body = parse_body(raw).unwrap();
        let draft_info = body.draft_info.unwrap();

        assert_eq!(draft_info.info_type, "reply");
        assert_eq!(draft_info.uid, 77);
        assert_eq!(draft_info.folder, "INBOX");
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
