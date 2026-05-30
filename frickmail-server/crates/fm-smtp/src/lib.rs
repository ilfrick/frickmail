use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmtpEndpoint {
    pub host: String,
    pub port: u16,
    pub login: String,
}

pub fn transport_label(endpoint: &SmtpEndpoint) -> String {
    format!("{}:{} as {}", endpoint.host, endpoint.port, endpoint.login)
}
