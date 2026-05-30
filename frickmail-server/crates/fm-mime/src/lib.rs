use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedMessageSummary {
    pub subject: Option<String>,
    pub from: Vec<String>,
    pub has_attachments: bool,
}

pub fn parse_summary(_raw: &[u8]) -> ParsedMessageSummary {
    ParsedMessageSummary {
        subject: None,
        from: Vec::new(),
        has_attachments: false,
    }
}
