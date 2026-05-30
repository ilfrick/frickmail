use fm_core::{FrickmailError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImapLoginProbe {
    pub host: String,
    pub port: u16,
    pub login: String,
}

pub async fn probe_login(_probe: ImapLoginProbe, _password: &str) -> Result<()> {
    Err(FrickmailError::NotImplemented(
        "IMAP login probe; next slice wires async IMAP transport",
    ))
}
