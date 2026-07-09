//! Command journal vocabulary and provider seam.
//!
//! This module owns producer-side command idempotency state. It is distinct from
//! consumer-side [`crate::InboxStore`]: the journal protects command request execution and local
//! side effects, while inbox receipts protect broker delivery handling.

const COMMAND_ID_PREFIX: &str = "command:v1:sha256:";
const SHA256_PREFIX: &str = "sha256:";
const SHA256_HEX_BYTES: usize = 64;
const COMMAND_ID_BYTES: usize = COMMAND_ID_PREFIX.len() + SHA256_HEX_BYTES;
const SHA256_LABEL_BYTES: usize = SHA256_PREFIX.len() + SHA256_HEX_BYTES;
const IDEMPOTENCY_KEY_MAX_BYTES: usize = 256;

/// Stable command identity scoped by tenant + command topic at the runtime seam.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CommandId(String);

impl std::fmt::Debug for CommandId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandId(<redacted>)")
    }
}

/// Stable idempotency key supplied by the command caller or derived by the runtime.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CommandIdempotencyKey(String);

impl std::fmt::Debug for CommandIdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandIdempotencyKey(<redacted>)")
    }
}

/// Request fingerprint used to distinguish true replay from same-key conflicting payloads.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CommandRequestFingerprint(String);

impl std::fmt::Debug for CommandRequestFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandRequestFingerprint(<redacted>)")
    }
}

/// Parse error for command journal bounded identifiers.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandJournalValueError {
    /// Value is empty.
    #[error("command journal value is empty")]
    Empty,
    /// Value exceeded its storage-bound byte limit.
    #[error("command journal value exceeds max bytes")]
    TooLong,
    /// Value does not match the closed command journal format.
    #[error("command journal value has invalid format")]
    InvalidFormat,
}

impl CommandId {
    /// Parse a stable command id.
    pub fn parse(raw: impl Into<String>) -> Result<Self, CommandJournalValueError> {
        let raw = parse_bounded(raw.into(), COMMAND_ID_BYTES)?;
        if !raw
            .strip_prefix(COMMAND_ID_PREFIX)
            .is_some_and(is_lower_hex_64)
        {
            return Err(CommandJournalValueError::InvalidFormat);
        }
        Ok(Self(raw))
    }

    /// Borrow the command id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl CommandIdempotencyKey {
    /// Parse a stable command idempotency key.
    pub fn parse(raw: impl Into<String>) -> Result<Self, CommandJournalValueError> {
        parse_bounded(raw.into(), IDEMPOTENCY_KEY_MAX_BYTES).map(Self)
    }

    /// Borrow the idempotency key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl CommandRequestFingerprint {
    /// Parse a reviewed request fingerprint.
    pub fn parse(raw: impl Into<String>) -> Result<Self, CommandJournalValueError> {
        let raw = parse_bounded(raw.into(), SHA256_LABEL_BYTES)?;
        if !raw.strip_prefix(SHA256_PREFIX).is_some_and(is_lower_hex_64) {
            return Err(CommandJournalValueError::InvalidFormat);
        }
        Ok(Self(raw))
    }

    /// Borrow the request fingerprint.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_bounded(raw: String, max: usize) -> Result<String, CommandJournalValueError> {
    if raw.is_empty() {
        return Err(CommandJournalValueError::Empty);
    }
    if raw.len() > max {
        return Err(CommandJournalValueError::TooLong);
    }
    Ok(raw)
}

fn is_lower_hex_64(raw: &str) -> bool {
    raw.len() == SHA256_HEX_BYTES
        && raw
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// Command journal status. Labels are DB CHECK values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandJournalStatus {
    /// Command has been claimed and may be executing.
    InFlight,
    /// Command completed; duplicate requests may replay a stable result summary.
    Completed,
    /// Command failed with a stable safe error summary.
    Failed,
}

impl CommandJournalStatus {
    /// Stable DB/log label.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::InFlight => "in_flight",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// Monotonic command attempt count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandAttempt(u32);

impl CommandAttempt {
    /// First attempt value.
    pub const FIRST: Self = Self(1);

    /// Build from a positive count.
    pub fn new(raw: u32) -> Result<Self, CommandAttemptError> {
        if raw == 0 {
            return Err(CommandAttemptError::Zero);
        }
        Ok(Self(raw))
    }

    /// Raw attempt count.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Attempt parse error.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandAttemptError {
    /// Attempts are 1-based.
    #[error("command attempt must be positive")]
    Zero,
}

/// Stable PII-safe command result summary.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandResultSummary(&'static str);

impl std::fmt::Debug for CommandResultSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandResultSummary(<redacted>)")
    }
}

impl CommandResultSummary {
    /// Command was durably enqueued.
    pub const ENQUEUED: Self = Self("command enqueued");

    /// Rehydrate a known persisted result summary.
    pub fn parse_persisted(raw: &str) -> Option<Self> {
        match raw {
            "command enqueued" => Some(Self::ENQUEUED),
            _ => None,
        }
    }

    /// Borrow the summary label.
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

/// Stable PII-safe command error summary.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandErrorSummary(&'static str);

impl std::fmt::Debug for CommandErrorSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandErrorSummary(<redacted>)")
    }
}

impl CommandErrorSummary {
    /// Command failed.
    pub const FAILED: Self = Self("command failed");

    /// Rehydrate a known persisted error summary.
    pub fn parse_persisted(raw: &str) -> Option<Self> {
        match raw {
            "command failed" => Some(Self::FAILED),
            _ => None,
        }
    }

    /// Borrow the summary label.
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

/// Outcome when recording a command intent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandJournalOutcome {
    /// This request won the claim and should execute the side effect.
    Recorded,
    /// Same command is already executing.
    AlreadyInFlight,
    /// Same command completed earlier.
    AlreadyCompleted(CommandResultSummary),
    /// Same command failed earlier.
    AlreadyFailed(CommandErrorSummary),
    /// Same scoped command/idempotency key was reused for a different request.
    Conflict,
}

/// Terminal summary selected by reviewed command business logic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandJournalTerminalSummary {
    /// Command completed and may replay a stable result summary.
    Completed(CommandResultSummary),
    /// Command failed with a stable safe error summary.
    Failed(CommandErrorSummary),
}

/// Reviewed command journal record consumed by provider implementations.
#[derive(Debug, Clone)]
pub struct CommandJournalRecord {
    tenant: vocab::TenantId,
    command_id: CommandId,
    idempotency_key: CommandIdempotencyKey,
    request_fingerprint: CommandRequestFingerprint,
}

impl CommandJournalRecord {
    /// Build a reviewed command journal record.
    pub fn new(
        tenant: vocab::TenantId,
        command_id: CommandId,
        idempotency_key: CommandIdempotencyKey,
        request_fingerprint: CommandRequestFingerprint,
    ) -> Self {
        Self {
            tenant,
            command_id,
            idempotency_key,
            request_fingerprint,
        }
    }

    /// Command tenant.
    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// Scoped command id.
    pub fn command_id(&self) -> &CommandId {
        &self.command_id
    }

    /// Idempotency key.
    pub fn idempotency_key(&self) -> &CommandIdempotencyKey {
        &self.idempotency_key
    }

    /// Request fingerprint.
    pub fn request_fingerprint(&self) -> &CommandRequestFingerprint {
        &self.request_fingerprint
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CommandAttempt, CommandAttemptError, CommandErrorSummary, CommandId, CommandIdempotencyKey,
        CommandJournalStatus, CommandJournalValueError, CommandRequestFingerprint,
        CommandResultSummary,
    };

    #[test]
    fn bounded_values_reject_empty_and_too_long() {
        assert_eq!(CommandId::parse(""), Err(CommandJournalValueError::Empty));
        assert_eq!(
            CommandIdempotencyKey::parse("x".repeat(257)),
            Err(CommandJournalValueError::TooLong)
        );
        assert_eq!(
            CommandId::parse("cmd-1"),
            Err(CommandJournalValueError::InvalidFormat)
        );
        assert_eq!(
            CommandRequestFingerprint::parse("sha256:abc"),
            Err(CommandJournalValueError::InvalidFormat)
        );
        assert!(CommandRequestFingerprint::parse(format!("sha256:{}", "a".repeat(64))).is_ok());
    }

    #[test]
    fn summaries_are_closed_and_parseable() {
        assert_eq!(CommandResultSummary::ENQUEUED.as_str(), "command enqueued");
        assert_eq!(CommandErrorSummary::FAILED.as_str(), "command failed");
        assert_eq!(
            CommandResultSummary::parse_persisted("command enqueued")
                .as_ref()
                .map(CommandResultSummary::as_str),
            Some("command enqueued")
        );
        assert!(CommandResultSummary::parse_persisted("runtime detail").is_none());
    }

    #[test]
    fn status_labels_match_db_values() {
        assert_eq!(CommandJournalStatus::InFlight.as_label(), "in_flight");
        assert_eq!(CommandJournalStatus::Completed.as_label(), "completed");
        assert_eq!(CommandJournalStatus::Failed.as_label(), "failed");
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test exercises known-valid positive attempt.
    fn attempt_is_positive() {
        assert_eq!(CommandAttempt::FIRST.get(), 1);
        assert_eq!(CommandAttempt::new(0), Err(CommandAttemptError::Zero));
        assert_eq!(CommandAttempt::new(2).expect("attempt").get(), 2);
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: unit test uses known-valid bounded identifiers.
    fn debug_redacts_sensitive_values() {
        let id =
            CommandId::parse(format!("command:v1:sha256:{}", "a".repeat(64))).expect("command id");
        let key = CommandIdempotencyKey::parse("idem-1").expect("idempotency");
        let fingerprint = CommandRequestFingerprint::parse(format!("sha256:{}", "b".repeat(64)))
            .expect("fingerprint");
        assert_eq!(format!("{id:?}"), "CommandId(<redacted>)");
        assert_eq!(format!("{key:?}"), "CommandIdempotencyKey(<redacted>)");
        assert_eq!(
            format!("{fingerprint:?}"),
            "CommandRequestFingerprint(<redacted>)"
        );
    }
}
