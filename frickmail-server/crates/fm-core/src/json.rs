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
