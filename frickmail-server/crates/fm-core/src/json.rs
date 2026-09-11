use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ApiEnvelope<T>
where
    T: Serialize,
{
    #[serde(rename = "Result")]
    pub result: T,
}

impl<T> ApiEnvelope<T>
where
    T: Serialize,
{
    pub fn ok(result: T) -> Self {
        Self { result }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub service: &'static str,
    pub status: &'static str,
    pub version: &'static str,
}

/// Versioned envelope for the stable Rust-owned `/api/frickmail/v1` API
/// (Phase 9). Unlike the legacy `ApiEnvelope`, success and failure shapes
/// are distinct and travel with real HTTP status codes instead of a 200
/// envelope carrying error codes.
#[derive(Debug, Clone, Serialize)]
pub struct ApiV1Envelope<T>
where
    T: Serialize,
{
    pub version: &'static str,
    pub data: T,
}

impl<T> ApiV1Envelope<T>
where
    T: Serialize,
{
    pub fn ok(data: T) -> Self {
        Self {
            version: API_V1_VERSION,
            data,
        }
    }
}

/// Stable machine-readable error body for `/api/frickmail/v1`.
#[derive(Debug, Clone, Serialize)]
pub struct ApiV1Error {
    pub version: &'static str,
    pub error: ApiV1ErrorBody,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiV1ErrorBody {
    pub code: &'static str,
    pub message: String,
}

impl ApiV1Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            version: API_V1_VERSION,
            error: ApiV1ErrorBody {
                code,
                message: message.into(),
            },
        }
    }
}

/// API version served under `/api/frickmail/`. Bumped only for breaking
/// contract changes; additive fields never bump it.
pub const API_V1_VERSION: &str = "v1";

#[cfg(test)]
mod tests {
    use super::{ApiV1Envelope, ApiV1Error, API_V1_VERSION};
    use serde_json::json;

    #[test]
    fn api_v1_envelope_versions_success_payloads() {
        let body = serde_json::to_value(ApiV1Envelope::ok(json!({"status": "ok"}))).unwrap();

        assert_eq!(body["version"], API_V1_VERSION);
        assert_eq!(body["data"]["status"], "ok");
        assert!(body.get("error").is_none());
    }

    #[test]
    fn api_v1_error_versions_failure_payloads() {
        let body = serde_json::to_value(ApiV1Error::new("unauthenticated", "No session")).unwrap();

        assert_eq!(body["version"], API_V1_VERSION);
        assert_eq!(body["error"]["code"], "unauthenticated");
        assert_eq!(body["error"]["message"], "No session");
        assert!(body.get("data").is_none());
    }
}
