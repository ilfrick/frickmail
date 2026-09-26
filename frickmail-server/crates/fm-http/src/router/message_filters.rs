//! Native message filter-hook pipeline.
//!
//! This mirrors the legacy PHP `filter.*-message` hooks fired by
//! `RainLoop/Actions/Messages.php` in the send, draft-save, and
//! read-receipt paths. PHP plugins mutated the message object (or
//! by-reference scalars/streams) in place; every handler return value was
//! discarded and only a thrown exception could abort the action.
//!
//! The Rust-only deployment cannot execute third-party PHP plugins, so the
//! native pipeline ports each *bundled* plugin filter behavior behind
//! configuration (off by default, matching the plugin-disabled state) and
//! invokes it at the same fire point with the same mutation semantics:
//!
//! | Legacy hook | Fire point | Native behavior |
//! |---|---|---|
//! | `filter.build-message` | after compose assembly, before MIME build (shared by send + save) | `add_x_originating_ip` stamps `X-Originating-IP` (`add-x-originating-ip-header` port) |
//! | `filter.send-message` | after send assembly, before SMTP | demo-account recipient policy (already native via `demo_account` config) |
//! | `filter.save-message` | after draft assembly, before IMAP append | no bundled behavior beyond `filter.build-message`; structural point only |
//! | `filter.send-read-receipt-message` | after receipt assembly, before SMTP | demo-account recipient policy (already native) |
//! | `filter.message-rcpt` + `filter.smtp-from` | before SMTP connect (send + receipt paths) | `from_address_account_smtp` resolves the envelope sender to the matching account's SMTP settings/credentials (`smtp-use-from-adr-account` port) |
//!
//! Out of scope by design: `filter.send-message-stream`,
//! `filter.smtp-message-stream`, and `filter.smtp-hidden-rcpt` describe PHP
//! stream plumbing subsumed by the native Sent-append and Bcc-envelope
//! handling; `filter.build-read-receipt-message`,
//! `filter.read-receipt-message-plain`, `filter.message-html`, and
//! `filter.message-plain` have no bundled (non-stub) plugin consumers.
//! Third-party PHP filters cannot run without the legacy PHP runtime and
//! are retired by architecture, like the Kolab/Nextcloud hooks.

/// Legacy hook fired after compose assembly, before MIME serialization.
pub const HOOK_BUILD_MESSAGE: &str = "filter.build-message";
/// Legacy hook fired after send assembly, before SMTP delivery.
pub const HOOK_SEND_MESSAGE: &str = "filter.send-message";
/// Legacy hook fired after draft assembly, before IMAP append.
pub const HOOK_SAVE_MESSAGE: &str = "filter.save-message";
/// Legacy hook fired after receipt assembly, before SMTP delivery.
pub const HOOK_SEND_READ_RECEIPT_MESSAGE: &str = "filter.send-read-receipt-message";
/// Legacy hook fired before SMTP connect; may narrow the envelope recipients.
pub const HOOK_MESSAGE_RCPT: &str = "filter.message-rcpt";
/// Legacy hook fired before SMTP connect; may rewrite the envelope sender path.
pub const HOOK_SMTP_FROM: &str = "filter.smtp-from";

/// Ports `RainLoop\Plugins\Helper::ValidateWildcardValues()`.
///
/// Patterns are split on whitespace/commas/semicolons after collapsing
/// consecutive `*` wildcards. A pattern without `*` must equal the value
/// exactly (case-sensitive, like PHP `===`); a pattern with `*` matches
/// when its literal parts appear in order anywhere in the value (unanchored,
/// like PHP `preg_match` without `^$`). An empty value never matches; an
/// empty pattern list matches everything — callers must apply the same
/// non-empty gate as the PHP call sites (see
/// `MailDefaults::from_address_filter_active`).
pub fn wildcard_list_matches(patterns: &str, value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    let patterns = patterns.trim();
    if patterns.is_empty() {
        return true;
    }
    if patterns == "*" {
        return true;
    }
    let mut collapsed = String::with_capacity(patterns.len());
    let mut previous_star = false;
    for ch in patterns.chars() {
        if ch == '*' {
            if previous_star {
                continue;
            }
            previous_star = true;
        } else {
            previous_star = false;
        }
        collapsed.push(ch);
    }
    for item in collapsed
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|item| !item.is_empty())
    {
        if !item.contains('*') {
            if value == item {
                return true;
            }
        } else {
            let source = item
                .split('*')
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join(".*");
            if regex::Regex::new(&source)
                .map(|expression| expression.is_match(value))
                .unwrap_or(false)
            {
                return true;
            }
        }
    }
    false
}

/// Ports the `add-x-originating-ip-header` plugin's address mapping: the
/// directly connected peer address, with loopback normalized to
/// `127.0.0.1` exactly like PHP's `IsLocalhost` branch. `None` (peer
/// unknown, e.g. Unix-socket delivery) yields no header. Proxy headers such
/// as `X-Forwarded-For` are never consulted: they are client-controlled,
/// matching the deployment's existing never-trust-XFF rule.
pub fn originating_ip_header_value(peer_ip: Option<std::net::IpAddr>) -> Option<String> {
    peer_ip.map(|ip| {
        if ip.is_loopback() {
            "127.0.0.1".to_string()
        } else {
            ip.to_string()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_names_match_legacy_php_filters() {
        assert_eq!(HOOK_BUILD_MESSAGE, "filter.build-message");
        assert_eq!(HOOK_SEND_MESSAGE, "filter.send-message");
        assert_eq!(HOOK_SAVE_MESSAGE, "filter.save-message");
        assert_eq!(
            HOOK_SEND_READ_RECEIPT_MESSAGE,
            "filter.send-read-receipt-message"
        );
        assert_eq!(HOOK_MESSAGE_RCPT, "filter.message-rcpt");
        assert_eq!(HOOK_SMTP_FROM, "filter.smtp-from");
    }

    #[test]
    fn wildcard_matching_mirrors_legacy_plugin_helper() {
        // Exact items are case-sensitive equality.
        assert!(wildcard_list_matches(
            "user@example.com",
            "user@example.com"
        ));
        assert!(!wildcard_list_matches(
            "user@example.com",
            "User@example.com"
        ));
        assert!(!wildcard_list_matches(
            "user@example.com",
            "other@example.com"
        ));
        // The plugin's documented default pattern shape.
        assert!(wildcard_list_matches(
            "user@example.com *@example2.com",
            "anyone@example2.com"
        ));
        assert!(!wildcard_list_matches(
            "user@example.com *@example2.com",
            "anyone@example3.com"
        ));
        // Bare and collapsed stars match everything (non-empty).
        assert!(wildcard_list_matches("*", "anything@example.com"));
        assert!(wildcard_list_matches("**", "anything@example.com"));
        // Comma/semicolon delimiters split like PHP's [\s,;]+.
        assert!(wildcard_list_matches(
            "a@example.com,b@example.com",
            "b@example.com"
        ));
        assert!(wildcard_list_matches(
            "a@example.com;b@example.com",
            "b@example.com"
        ));
        // Wildcard parts match unanchored, in order.
        assert!(wildcard_list_matches("*@example.com", "user@example.com"));
        assert!(!wildcard_list_matches("*@example.com", "user@example.org"));
        // Empty values never match; empty lists match (caller-gated).
        assert!(!wildcard_list_matches("*", ""));
        assert!(!wildcard_list_matches("*", "   "));
        assert!(wildcard_list_matches("", "user@example.com"));
        assert!(wildcard_list_matches("   ", "user@example.com"));
    }

    #[test]
    fn originating_ip_maps_loopback_like_legacy_plugin() {
        assert_eq!(
            originating_ip_header_value(Some("127.0.0.1".parse().unwrap())),
            Some("127.0.0.1".to_string())
        );
        assert_eq!(
            originating_ip_header_value(Some("::1".parse().unwrap())),
            Some("127.0.0.1".to_string())
        );
        assert_eq!(
            originating_ip_header_value(Some("203.0.113.7".parse().unwrap())),
            Some("203.0.113.7".to_string())
        );
        assert_eq!(originating_ip_header_value(None), None);
    }
}
