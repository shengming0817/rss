//! Provider-neutral dead-letter identity shared by delivery lifecycle and internal operators.

/// Parsed `dead_letter.id` UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetterId(String);

impl DeadLetterId {
    pub fn parse(raw: &str) -> Result<Self, DeadLetterIdError> {
        uuid::Uuid::parse_str(raw)
            .map(|id| Self(id.to_string()))
            .map_err(|_| DeadLetterIdError)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeadLetterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A dead-letter identifier was not a UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("dead-letter id is invalid")]
pub struct DeadLetterIdError;
