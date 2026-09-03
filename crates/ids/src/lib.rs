//! ids — RSS 强类型标识 newtype（基础层，仅 std+uuid）。
//!
//! 每个 ID 字段私有（ADR-004 C7），构造只经 `new`/`parse` funnel；不 derive serde（C6）。

/// ID 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdParseError {
    #[error("invalid id format")]
    Invalid,
}

/// Canonical lowercase-hyphenated UUIDv4 carrier for security-sensitive protocol identifiers.
///
/// The parsed UUID is retained so downstream layers do not repeat string parsing after this
/// boundary has accepted the value. `Debug` is deliberately redacted because callers use this
/// carrier for session and token identifiers.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanonicalUuidV4(uuid::Uuid);

impl CanonicalUuidV4 {
    /// Parse an exact lowercase-hyphenated UUIDv4.
    pub fn parse(raw: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(raw).map_err(|_| IdParseError::Invalid)?;
        if parsed.get_version() != Some(uuid::Version::Random)
            || parsed.get_variant() != uuid::Variant::RFC4122
            || parsed.hyphenated().to_string() != raw
        {
            return Err(IdParseError::Invalid);
        }
        Ok(Self(parsed))
    }

    /// Generate a fresh UUIDv4.
    #[must_use]
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Return the parsed UUID without reopening the string trust boundary.
    #[must_use]
    pub const fn as_uuid(self) -> uuid::Uuid {
        self.0
    }
}

impl std::fmt::Display for CanonicalUuidV4 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

impl std::fmt::Debug for CanonicalUuidV4 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CanonicalUuidV4(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn canonical_uuid_v4_is_exact_and_redacted() {
        let raw = "550e8400-e29b-41d4-a716-446655440000";
        let value = CanonicalUuidV4::parse(raw).expect("canonical UUIDv4");
        assert_eq!(value.to_string(), raw);
        assert_eq!(format!("{value:?}"), "CanonicalUuidV4(<redacted>)");
        assert!(CanonicalUuidV4::parse("550e8400-e29b-11d4-a716-446655440000").is_err());
    }
}
