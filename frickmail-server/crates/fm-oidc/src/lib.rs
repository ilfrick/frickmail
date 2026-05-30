use fm_core::{FrickmailError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcCallbackPayload {
    pub ok: bool,
    pub mode: String,
    pub email: Option<String>,
    pub error: Option<String>,
    pub reauth_required: bool,
}

pub fn render_callback(payload: &OidcCallbackPayload) -> String {
    let json = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    let json = escape_json_for_script_data(&json);
    format!(
        r#"<!doctype html><meta charset="utf-8"><title>Frickmail</title>
<script type="application/json" id="frickmail-oidc-payload">{json}</script>
<script>
const payload = document.getElementById('frickmail-oidc-payload').textContent;
window.localStorage.setItem('frickmail-oidc-result', payload);
if (window.opener) window.opener.location.reload();
setTimeout(function() {{ window.close(); }}, 200);
</script>"#
    )
}

fn escape_json_for_script_data(input: &str) -> String {
    input
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

pub async fn start_login() -> Result<()> {
    Err(FrickmailError::NotImplemented(
        "OIDC start-login endpoint; next slice wires provider discovery and PKCE",
    ))
}

#[cfg(test)]
mod tests {
    use super::{render_callback, OidcCallbackPayload};

    #[test]
    fn callback_payload_does_not_break_script_context() {
        let html = render_callback(&OidcCallbackPayload {
            ok: false,
            mode: "login".to_string(),
            email: Some("attacker@example.com</script><script>alert(1)</script>".to_string()),
            error: Some("<img src=x onerror=alert(1)>".to_string()),
            reauth_required: false,
        });

        assert!(!html.contains("</script><script>alert(1)</script>"));
        assert!(html.contains("\\u003c/script\\u003e"));
        assert!(html.contains("\\u0026") || !html.contains('&'));
        assert!(html.contains("application/json"));
    }
}
