//! Sender avatar lookup (native replacement for the SnappyMail Avatars plugin).
//!
//! Resolution order mirrors the plugin: private file cache, then bundled
//! service icons (only when the caller asserts DKIM validity, like the
//! plugin's `$bBimi` gate), then opt-in remote sources (Gravatar, then
//! direct `favicon.ico` over SSRF-safe HTTPS). Deliberate deviations:
//! third-party favicon aggregators are never queried (they leak read
//! receipts), and BIMI DNS fetching is a follow-up (the `bimi` flag
//! currently gates service icons exactly like the plugin).
//!
//! Service icons are baked in from `plugins/avatars/images/services/`
//! (MIT, RainLoop Team — see `assets/avatars/ATTRIBUTION.md`) so the
//! production image needs no legacy plugin files at runtime.

use std::path::{Path, PathBuf};

use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::AppState;

/// Largest avatar image accepted into cache and served. Remote bodies beyond
/// this are treated as a miss.
pub const AVATAR_MAX_BYTES: usize = 256 * 1024;
/// Per-attempt remote fetch deadline, mirroring the plugin's 15s with margin.
pub const AVATAR_FETCH_TIMEOUT_SECS: u64 = 10;
/// Browser cache lifetime served on avatar responses, like the plugin.
pub const AVATAR_CACHE_MAX_AGE_SECS: u64 = 86_400;

/// Normalizes an email address to lowercase ASCII: trims, requires a
/// non-empty local part and a dotted domain, converts IDN via `idna`.
pub fn normalize_avatar_email(email: &str) -> Option<String> {
    let (local, domain) = email.trim().rsplit_once('@')?;
    if local.trim().is_empty() || local.contains(char::is_whitespace) {
        return None;
    }
    let ascii = idna::domain_to_ascii(domain.trim()).ok()?;
    if !ascii.contains('.') {
        return None;
    }
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(format!("{}@{ascii}", local.trim().to_ascii_lowercase()))
}

/// Stable cache key for a normalized address (SHA-1 hex, like the plugin).
pub fn avatar_cache_key(email_ascii: &str) -> String {
    hex::encode(Sha1::digest(email_ascii.as_bytes()))
}

fn avatar_cache_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("avatars")
}

/// Detects the MIME type from magic bytes. SVG is recognized textually and
/// served as `image/svg+xml`, exactly like the plugin's MIME-from-file
/// behavior (including its script caveat — SVGs only enter the cache from
/// `image/*` HTTP responses or the curated bundle).
pub fn mime_from_magic(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && bytes[8..12] == *b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"\x00\x00\x01\x00") {
        Some("image/x-icon")
    } else if bytes.starts_with(b"<svg") || is_xml_svg(bytes) {
        Some("image/svg+xml")
    } else {
        None
    }
}

/// Recognizes XML prologues that declare inline SVG within the first bytes,
/// instead of treating every `<?xml` document as an image.
fn is_xml_svg(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"<?xml") {
        return false;
    }
    bytes
        .windows(b"<svg".len())
        .take(64)
        .any(|window| window == b"<svg")
}

fn ext_for_mime(mime: &str) -> Option<&'static str> {
    match mime {
        "image/png" => Some("png"),
        "image/jpeg" => Some("jpg"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/x-icon" | "image/vnd.microsoft.icon" => Some("ico"),
        "image/svg+xml" => Some("svg"),
        _ => None,
    }
}

const AVATAR_CACHE_EXTS: &[&str] = &["png", "jpg", "gif", "webp", "ico", "svg"];

/// Reads a cached avatar, re-verifying magic bytes so hand-planted files
/// with mismatched content are never served under a trusted MIME type.
pub fn read_cached_avatar(data_dir: &Path, email_ascii: &str) -> Option<(String, Vec<u8>)> {
    let key = avatar_cache_key(email_ascii);
    let dir = avatar_cache_dir(data_dir);
    AVATAR_CACHE_EXTS.iter().find_map(|ext| {
        let bytes = std::fs::read(dir.join(format!("{key}.{ext}"))).ok()?;
        if bytes.is_empty() || bytes.len() > AVATAR_MAX_BYTES {
            return None;
        }
        mime_from_magic(&bytes).map(|mime| (mime.to_string(), bytes))
    })
}

/// Stores an avatar atomically (temp file + rename). Best-effort: cache
/// failures never fail the lookup.
pub fn write_cached_avatar(data_dir: &Path, email_ascii: &str, mime: &str, bytes: &[u8]) {
    let Some(ext) = ext_for_mime(mime) else {
        return;
    };
    if bytes.is_empty() || bytes.len() > AVATAR_MAX_BYTES {
        return;
    }
    let dir = avatar_cache_dir(data_dir);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let key = avatar_cache_key(email_ascii);
    let tmp = dir.join(format!(".{key}.{ext}.tmp"));
    let target = dir.join(format!("{key}.{ext}"));
    if std::fs::write(&tmp, bytes).is_ok() {
        let _ = std::fs::rename(&tmp, &target);
    }
}

/// Reduces a domain to its service root, mirroring the plugin's
/// `serviceDomain()`: explicit brand mappings first, otherwise the last two
/// labels (same registrable-domain approximation the plugin uses).
pub fn service_domain(domain: &str) -> String {
    let domain = domain.to_ascii_lowercase();
    for (suffix, canonical) in [
        ("paypal.com", "paypal.com"),
        ("facebookmail.com", "facebook.com"),
        ("dhlparcel.nl", "dhl.com"),
        ("amazon.nl", "amazon.com"),
    ] {
        if domain == suffix || domain == canonical || domain.ends_with(&format!(".{suffix}")) {
            return canonical.to_string();
        }
    }
    // `sub.paypal.com` ends with `.paypal.com` and is already handled above.
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() > 2 {
        labels[labels.len() - 2..].join(".")
    } else {
        domain
    }
}

const ICON_AMAZON_COM: &[u8] = include_bytes!("../../assets/avatars/services/amazon.com.png");
const ICON_APPLE_COM: &[u8] = include_bytes!("../../assets/avatars/services/apple.com.png");
const ICON_ASANA_COM: &[u8] = include_bytes!("../../assets/avatars/services/asana.com.png");
const ICON_BATTLE_NET: &[u8] = include_bytes!("../../assets/avatars/services/battle.net.png");
const ICON_BLIZZARD_COM: &[u8] = include_bytes!("../../assets/avatars/services/blizzard.com.png");
const ICON_DHL_COM: &[u8] = include_bytes!("../../assets/avatars/services/dhl.com.png");
const ICON_DISNEYPLUS_COM: &[u8] =
    include_bytes!("../../assets/avatars/services/disneyplus.com.png");
const ICON_EA_COM: &[u8] = include_bytes!("../../assets/avatars/services/ea.com.png");
const ICON_EBAY_COM: &[u8] = include_bytes!("../../assets/avatars/services/ebay.com.png");
const ICON_FACEBOOK_COM: &[u8] = include_bytes!("../../assets/avatars/services/facebook.com.png");
const ICON_GITHUB_COM: &[u8] = include_bytes!("../../assets/avatars/services/github.com.png");
const ICON_GOOGLE_COM: &[u8] = include_bytes!("../../assets/avatars/services/google.com.png");
const ICON_LINKEDIN_COM: &[u8] = include_bytes!("../../assets/avatars/services/linkedin.com.png");
const ICON_MICROSOFT_COM: &[u8] = include_bytes!("../../assets/avatars/services/microsoft.com.png");
const ICON_ONLIVE_COM: &[u8] = include_bytes!("../../assets/avatars/services/onlive.com.png");
const ICON_PAYPAL_COM: &[u8] = include_bytes!("../../assets/avatars/services/paypal.com.png");
const ICON_SKYPE_COM: &[u8] = include_bytes!("../../assets/avatars/services/skype.com.png");
const ICON_STEAMPOWERED_COM: &[u8] =
    include_bytes!("../../assets/avatars/services/steampowered.com.png");
const ICON_TED_COM: &[u8] = include_bytes!("../../assets/avatars/services/ted.com.png");
const ICON_TWITTER_COM: &[u8] = include_bytes!("../../assets/avatars/services/twitter.com.png");
const ICON_YOUTUBE_COM: &[u8] = include_bytes!("../../assets/avatars/services/youtube.com.png");

fn lookup_service_icon(name: &str) -> Option<&'static [u8]> {
    match name {
        "amazon.com" => Some(ICON_AMAZON_COM),
        "apple.com" => Some(ICON_APPLE_COM),
        "asana.com" => Some(ICON_ASANA_COM),
        "battle.net" => Some(ICON_BATTLE_NET),
        "blizzard.com" => Some(ICON_BLIZZARD_COM),
        "dhl.com" => Some(ICON_DHL_COM),
        "disneyplus.com" => Some(ICON_DISNEYPLUS_COM),
        "ea.com" => Some(ICON_EA_COM),
        "ebay.com" => Some(ICON_EBAY_COM),
        "facebook.com" => Some(ICON_FACEBOOK_COM),
        "github.com" => Some(ICON_GITHUB_COM),
        "google.com" => Some(ICON_GOOGLE_COM),
        "linkedin.com" => Some(ICON_LINKEDIN_COM),
        "microsoft.com" => Some(ICON_MICROSOFT_COM),
        "onlive.com" => Some(ICON_ONLIVE_COM),
        "paypal.com" => Some(ICON_PAYPAL_COM),
        "skype.com" => Some(ICON_SKYPE_COM),
        "steampowered.com" => Some(ICON_STEAMPOWERED_COM),
        "ted.com" => Some(ICON_TED_COM),
        "twitter.com" => Some(ICON_TWITTER_COM),
        "youtube.com" => Some(ICON_YOUTUBE_COM),
        _ => None,
    }
}

/// Bundled brand icons, gated on caller-asserted DKIM validity.
/// Exact domain first, then the service-root normalization.
pub fn service_icon(domain: &str) -> Option<(&'static str, &'static [u8])> {
    let lowered = domain.to_ascii_lowercase();
    if let Some(bytes) = lookup_service_icon(&lowered) {
        return Some(("image/png", bytes));
    }
    lookup_service_icon(&service_domain(&lowered)).map(|bytes| ("image/png", bytes))
}

/// Builds the Gravatar URL for a normalized address (SHA-256, `d=404` so
/// unknown addresses miss instead of returning a default face).
pub fn gravatar_url(email_ascii: &str) -> String {
    let digest = Sha256::digest(email_ascii.to_ascii_lowercase().as_bytes());
    format!("https://gravatar.com/avatar/{:x}?s=80&d=404", digest)
}

/// Fetches one remote image over SSRF-safe HTTPS: public-IP resolution only
/// (reusing the router's resolver), no redirects (redirect targets would
/// need re-validation; the favicon chain already covers www variants),
/// `image/*` responses within the byte budget.
pub(super) async fn fetch_remote_image(url: &str) -> Option<(String, Vec<u8>)> {
    let parsed = url::Url::parse(url.trim()).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;
    let addrs = super::public_socket_addrs(host, port).await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(AVATAR_FETCH_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addrs)
        .build()
        .ok()?;
    let response = client.get(url.trim()).send().await.ok()?;
    if response.status() != reqwest::StatusCode::OK {
        return None;
    }
    let mime = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)?
        .to_str()
        .ok()?
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase();
    if !mime.starts_with("image/") {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    if bytes.is_empty() || bytes.len() > AVATAR_MAX_BYTES {
        return None;
    }
    // Magic bytes are authoritative; otherwise trust an `image/*` claim.
    let mime = mime_from_magic(&bytes).unwrap_or(mime.as_str());
    ext_for_mime(mime)?;
    Some((mime.to_string(), bytes.to_vec()))
}

/// Resolves a sender avatar following the plugin order: cache, bundled
/// service icons when `bimi` (caller-asserted DKIM validity), then opt-in
/// remote sources. Returns `(mime, bytes)` or `None` on any miss.
pub(super) async fn resolve_avatar(
    state: &AppState,
    email: &str,
    bimi: bool,
) -> Option<(String, Vec<u8>)> {
    let normalized = normalize_avatar_email(email)?;
    let cache_ok = state.config().private_data_dir.as_deref().map(Path::new);
    if let Some(dir) = cache_ok {
        if let Some(cached) = read_cached_avatar(dir, &normalized) {
            return Some(cached);
        }
    }
    let domain = normalized.rsplit_once('@').map(|(_, domain)| domain)?;
    if bimi {
        if let Some((mime, bytes)) = service_icon(domain) {
            if let Some(dir) = cache_ok {
                write_cached_avatar(dir, &normalized, mime, bytes);
            }
            return Some((mime.to_string(), bytes.to_vec()));
        }
    }
    if !state.config().avatar.enable_remote {
        return None;
    }
    let mut candidates = Vec::new();
    if state.config().avatar.enable_gravatar {
        candidates.push(gravatar_url(&normalized));
    }
    let service = service_domain(domain);
    for host in [
        domain.to_string(),
        format!("www.{domain}"),
        service.clone(),
        format!("www.{service}"),
    ] {
        candidates.push(format!("https://{host}/favicon.ico"));
    }
    for url in candidates {
        if let Some((mime, bytes)) = fetch_remote_image(&url).await {
            if let Some(dir) = cache_ok {
                write_cached_avatar(dir, &normalized, &mime, &bytes);
            }
            return Some((mime, bytes));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_addresses_to_ascii_lowercase() {
        assert_eq!(
            normalize_avatar_email("Alice@Example.COM "),
            Some("alice@example.com".to_string())
        );
        assert!(normalize_avatar_email("no-at-sign").is_none());
        assert!(normalize_avatar_email("@example.com").is_none());
        assert!(normalize_avatar_email("a@nodot").is_none());
        assert!(normalize_avatar_email("a b@example.com").is_none());
        assert!(normalize_avatar_email("").is_none());
    }

    #[test]
    fn cache_keys_are_stable_sha1_hex() {
        let key = avatar_cache_key("alice@example.com");
        assert_eq!(key.len(), 40);
        assert_eq!(key, avatar_cache_key("alice@example.com"));
        assert_ne!(key, avatar_cache_key("bob@example.com"));
    }

    #[test]
    fn detects_common_image_magic() {
        assert_eq!(mime_from_magic(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(mime_from_magic(b"\xff\xd8\xffrest"), Some("image/jpeg"));
        assert_eq!(mime_from_magic(b"GIF89arest"), Some("image/gif"));
        assert_eq!(
            mime_from_magic(b"RIFF\x00\x00\x00\x00WEBP"),
            Some("image/webp")
        );
        assert_eq!(
            mime_from_magic(b"\x00\x00\x01\x00rest"),
            Some("image/x-icon")
        );
        assert_eq!(mime_from_magic(b"<svg xmlns"), Some("image/svg+xml"));
        assert_eq!(
            mime_from_magic(b"<?xml version=\"1.0\"?><svg width=\"1\">"),
            Some("image/svg+xml")
        );
        assert_eq!(mime_from_magic(b"<?xml version=\"1.0\"?><html>"), None);
        assert_eq!(mime_from_magic(b"not an image"), None);
        assert_eq!(mime_from_magic(b""), None);
    }

    #[test]
    fn reduces_service_domains_like_the_plugin() {
        assert_eq!(service_domain("mail.sub.paypal.com"), "paypal.com");
        assert_eq!(service_domain("facebookmail.com"), "facebook.com");
        assert_eq!(service_domain("dhlparcel.nl"), "dhl.com");
        assert_eq!(service_domain("amazon.nl"), "amazon.com");
        assert_eq!(service_domain("mail.example.com"), "example.com");
        assert_eq!(service_domain("example.com"), "example.com");
    }

    #[test]
    fn serves_bundled_brand_icons() {
        let (mime, bytes) = service_icon("github.com").expect("github icon bundled");
        assert_eq!(mime, "image/png");
        assert_eq!(mime_from_magic(bytes), Some("image/png"));
        // Normalization applies: subdomains resolve to the brand root.
        assert!(service_icon("mail.github.com").is_some());
        assert!(service_icon("unknown.example.com").is_none());
    }

    #[test]
    fn builds_gravatar_urls_with_404_default() {
        let url = gravatar_url("Alice@Example.com");
        assert!(url.starts_with("https://gravatar.com/avatar/"));
        assert!(url.ends_with("?s=80&d=404"));
        assert_eq!(url, gravatar_url("alice@example.com"));
    }

    #[test]
    fn caches_round_trip_with_magic_verification() {
        let dir = std::env::temp_dir().join(format!("fm-avatar-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let png = b"\x89PNG\r\n\x1a\nfakepng";
        write_cached_avatar(&dir, "alice@example.com", "image/png", png);
        assert_eq!(
            read_cached_avatar(&dir, "alice@example.com"),
            Some(("image/png".to_string(), png.to_vec()))
        );
        // Oversized and empty bodies are never cached.
        write_cached_avatar(
            &dir,
            "bob@example.com",
            "image/png",
            &vec![0u8; AVATAR_MAX_BYTES + 1],
        );
        assert!(read_cached_avatar(&dir, "bob@example.com").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
