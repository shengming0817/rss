#![doc = include_str!("../README.md")]

mod data_class;
mod safe_error;

pub use data_class::DataClass;
pub use safe_error::{SafeError, SafeErrorCategory, SafeErrorCode};

use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime};

/// Conversion failure for an absolute Unix timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimepointError {
    /// The value precedes the Unix epoch.
    BeforeEpoch,
    /// The value cannot be represented by the wire `int64` range or this platform.
    Overflow,
}

impl fmt::Display for TimepointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BeforeEpoch => "time precedes the Unix epoch",
            Self::Overflow => "time exceeds the Unix int64 range",
        })
    }
}
impl Error for TimepointError {}

/// Authority-free absolute time represented as non-negative Unix seconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timepoint(i64);

impl Timepoint {
    /// Convert a `SystemTime` to the wire range, clamping at both boundaries.
    #[must_use]
    pub fn saturating_from_system_time(value: SystemTime) -> Self {
        value
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(Self(0), Self::saturating_from_duration)
    }

    fn saturating_from_duration(duration: Duration) -> Self {
        Self(i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
    }

    /// Convert a duration since the epoch without saturating.
    pub fn try_from_duration(duration: Duration) -> Result<Self, TimepointError> {
        i64::try_from(duration.as_secs())
            .map(Self)
            .map_err(|_| TimepointError::Overflow)
    }

    /// Return the canonical Unix-seconds wire value.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.0
    }

    /// Rebuild `SystemTime`; platforms with a narrower range fail closed.
    pub fn to_system_time(self) -> Result<SystemTime, TimepointError> {
        let seconds = u64::try_from(self.0).map_err(|_| TimepointError::BeforeEpoch)?;
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or(TimepointError::Overflow)
    }
}

impl TryFrom<SystemTime> for Timepoint {
    type Error = TimepointError;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        value
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| TimepointError::BeforeEpoch)
            .and_then(Self::try_from_duration)
    }
}

impl TryFrom<i64> for Timepoint {
    type Error = TimepointError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if value < 0 {
            Err(TimepointError::BeforeEpoch)
        } else {
            Ok(Self(value))
        }
    }
}

/// Closed rejection categories for an opaque pagination token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageCursorError {
    /// The token is not canonical unpadded base64url.
    Malformed,
    /// The encoded token exceeds the fixed protocol bound.
    TooLong,
    /// The token is validly encoded but invalid for the current pagination scope.
    Stale,
}

impl fmt::Display for PageCursorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "page cursor is malformed",
            Self::TooLong => "page cursor is too long",
            Self::Stale => "page cursor is stale",
        })
    }
}
impl Error for PageCursorError {}

/// Opaque, bounded canonical base64url pagination token.
#[derive(Clone, Eq, PartialEq)]
pub struct PageCursor(Box<str>);

impl PageCursor {
    /// Parse an encoded token without interpreting provider-owned contents.
    pub fn parse(raw: &str) -> Result<Self, PageCursorError> {
        if raw.len() > 4096 {
            return Err(PageCursorError::TooLong);
        }
        if !canonical_base64url_no_pad(raw) {
            return Err(PageCursorError::Malformed);
        }
        Ok(Self(raw.into()))
    }

    /// Return the opaque wire token.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PageCursor([REDACTED])")
    }
}

fn canonical_base64url_no_pad(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return false;
    }
    if !bytes.iter().all(|byte| base64url_value(*byte).is_some()) {
        return false;
    }
    match bytes.len() % 4 {
        2 => base64url_value(bytes[bytes.len() - 1]).is_some_and(|value| value & 0x0f == 0),
        3 => base64url_value(bytes[bytes.len() - 1]).is_some_and(|value| value & 0x03 == 0),
        _ => true,
    }
}

const fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[derive(Clone)]
enum Text {
    Static(&'static str),
    Owned(Box<str>),
}

impl Text {
    const fn from_static(value: &'static str) -> Self {
        Self::Static(value)
    }

    fn owned(value: &str) -> Self {
        Self::Owned(value.into())
    }

    const fn as_str(&self) -> &str {
        match self {
            Self::Static(value) => value,
            Self::Owned(value) => value,
        }
    }
}

impl PartialEq for Text {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for Text {}
impl Hash for Text {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IdentityError {
    Empty,
    TooLong,
    InvalidFormat,
    ZeroVersion,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "contract identity is empty",
            Self::TooLong => "contract identity is too long",
            Self::InvalidFormat => "contract identity has invalid format",
            Self::ZeroVersion => "contract version is zero",
        })
    }
}
impl Error for IdentityError {}

/// Canonical dotted contract identifier.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ContractId(Text);

impl ContractId {
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        validate_contract_id(value)?;
        Ok(Self(Text::owned(value)))
    }

    #[must_use]
    pub const fn from_static(value: &'static str) -> Self {
        assert!(valid_contract_id(value), "invalid contract id");
        Self(Text::from_static(value))
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ContractId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ContractId")
            .field(&self.as_str())
            .finish()
    }
}
impl fmt::Display for ContractId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn validate_contract_id(value: &str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty);
    }
    if value.len() > 255 {
        return Err(IdentityError::TooLong);
    }
    if !valid_contract_id(value) {
        return Err(IdentityError::InvalidFormat);
    }
    Ok(())
}

const fn valid_contract_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 {
        return false;
    }
    let mut index = 0;
    let mut segment_start = true;
    while index < bytes.len() {
        let byte = bytes[index];
        if segment_start {
            if !byte.is_ascii_lowercase() {
                return false;
            }
            segment_start = false;
        } else if byte == b'.' {
            segment_start = true;
        } else if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
            return false;
        }
        index += 1;
    }
    !segment_start
}

/// Canonical manifest contract version (`v{N}`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContractVersion(u32);

impl ContractVersion {
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        let digits = value
            .strip_prefix('v')
            .ok_or(IdentityError::InvalidFormat)?;
        if digits.is_empty()
            || digits.starts_with('0')
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(IdentityError::InvalidFormat);
        }
        let major = digits.parse().map_err(|_| IdentityError::InvalidFormat)?;
        Self::from_major(major)
    }

    pub const fn from_major(major: u32) -> Result<Self, IdentityError> {
        if major == 0 {
            Err(IdentityError::ZeroVersion)
        } else {
            Ok(Self(major))
        }
    }

    #[must_use]
    pub const fn from_static_major(major: u32) -> Self {
        assert!(major != 0, "contract version must be non-zero");
        Self(major)
    }

    #[must_use]
    pub const fn major(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ContractVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v{}", self.0)
    }
}

/// Canonical SHA-256 schema bundle digest.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SchemaDigest(Text);

impl SchemaDigest {
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        if !valid_schema_digest(value) {
            return Err(IdentityError::InvalidFormat);
        }
        Ok(Self(Text::owned(value)))
    }

    #[must_use]
    pub const fn from_static(value: &'static str) -> Self {
        assert!(valid_schema_digest(value), "invalid schema digest");
        Self(Text::from_static(value))
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SchemaDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SchemaDigest")
            .field(&self.as_str())
            .finish()
    }
}
impl fmt::Display for SchemaDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

const fn valid_schema_digest(value: &str) -> bool {
    let bytes = value.as_bytes();
    let prefix = b"sha256:";
    if bytes.len() != prefix.len() + 64 {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if bytes[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')) {
            return false;
        }
        index += 1;
    }
    true
}

/// Immutable identity of one authored contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContractDescriptor {
    id: &'static str,
    version: ContractVersion,
    schema_digest: &'static str,
}

impl ContractDescriptor {
    #[must_use]
    pub const fn from_static_version(
        id: &'static str,
        version: &'static str,
        schema_digest: &'static str,
    ) -> Self {
        Self::from_static_parts(id, parse_static_version(version), schema_digest)
    }

    #[must_use]
    pub const fn from_static(
        id: &'static str,
        version_major: u32,
        schema_digest: &'static str,
    ) -> Self {
        Self::from_static_parts(
            id,
            ContractVersion::from_static_major(version_major),
            schema_digest,
        )
    }

    const fn from_static_parts(
        id: &'static str,
        version: ContractVersion,
        schema_digest: &'static str,
    ) -> Self {
        assert!(valid_contract_id(id), "invalid contract id");
        assert!(valid_schema_digest(schema_digest), "invalid schema digest");
        Self {
            id,
            version,
            schema_digest,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }
    #[must_use]
    pub const fn version(&self) -> ContractVersion {
        self.version
    }
    #[must_use]
    pub const fn schema_digest(&self) -> &'static str {
        self.schema_digest
    }
}

const fn parse_static_version(value: &str) -> ContractVersion {
    let bytes = value.as_bytes();
    assert!(
        bytes.len() >= 2 && bytes[0] == b'v',
        "invalid contract version"
    );
    assert!(
        bytes.len() == 2 || bytes[1] != b'0',
        "invalid contract version"
    );
    let mut index = 1;
    let mut major = 0_u32;
    while index < bytes.len() {
        let byte = bytes[index];
        assert!(byte.is_ascii_digit(), "invalid contract version");
        let digit = (byte - b'0') as u32;
        assert!(major <= (u32::MAX - digit) / 10, "invalid contract version");
        major = major * 10 + digit;
        index += 1;
    }
    assert!(major != 0, "invalid contract version");
    ContractVersion::from_static_major(major)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn canonical_values_round_trip() -> Result<(), IdentityError> {
        let id = ContractId::parse("runtime.inventory")?;
        let version = ContractVersion::parse("v12")?;
        let digest = SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?;
        assert_eq!(id.as_str(), "runtime.inventory");
        assert_eq!(version.to_string(), "v12");
        assert_eq!(digest.as_str().len(), 71);
        Ok(())
    }

    #[test]
    fn rejects_noncanonical_values() {
        for value in [
            "",
            "Runtime.inventory",
            "runtime..inventory",
            "runtime._inventory",
        ] {
            assert!(ContractId::parse(value).is_err(), "{value}");
        }
        for value in ["", "1", "v0", "v01", "v-1"] {
            assert!(ContractVersion::parse(value).is_err(), "{value}");
        }
        assert!(SchemaDigest::parse(&format!("sha256:{}", "A".repeat(64))).is_err());
    }

    #[test]
    fn static_versions_accept_max_and_reject_invalid_values() {
        assert_eq!(parse_static_version("v4294967295").major(), u32::MAX);
        for value in ["v0", "v01", "v12x", "v4294967296"] {
            assert!(std::panic::catch_unwind(|| parse_static_version(value)).is_err());
        }
    }

    #[test]
    fn identity_error_messages_are_stable_distinct_and_redacted() {
        let messages = [
            IdentityError::Empty,
            IdentityError::TooLong,
            IdentityError::InvalidFormat,
            IdentityError::ZeroVersion,
        ]
        .map(|error| error.to_string());
        assert_eq!(
            messages
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            4
        );
        assert!(messages.iter().all(|message| !message.contains("secret")));
    }

    #[test]
    fn exhaustive_public_value_boundaries() -> Result<(), IdentityError> {
        let max = format!("a.{}", "b".repeat(253));
        assert_eq!(ContractId::parse(&max)?.to_string(), max);
        assert_eq!(
            ContractId::parse(&"a".repeat(256)),
            Err(IdentityError::TooLong)
        );
        assert_eq!(ContractId::parse("a/b"), Err(IdentityError::InvalidFormat));
        assert_eq!(
            ContractVersion::from_major(0),
            Err(IdentityError::ZeroVersion)
        );
        assert_eq!(ContractVersion::from_major(7)?.major(), 7);
        assert!(ContractVersion::parse("v4294967296").is_err());
        let digest = format!("sha256:{}", "0".repeat(64));
        let parsed = SchemaDigest::parse(&digest)?;
        assert_eq!(parsed.to_string(), digest);
        assert!(SchemaDigest::parse("sha256:00").is_err());
        let descriptor = ContractDescriptor::from_static_version(
            "runtime.inventory",
            "v12",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert_eq!(descriptor.id(), "runtime.inventory");
        assert_eq!(descriptor.version().major(), 12);
        assert_eq!(descriptor.schema_digest().len(), 71);
        assert_eq!(
            descriptor,
            ContractDescriptor::from_static(
                "runtime.inventory",
                12,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
        );
        assert_eq!(
            ContractId::from_static("runtime.inventory"),
            ContractId::parse("runtime.inventory")?
        );
        assert_eq!(
            SchemaDigest::from_static(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            SchemaDigest::parse(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )?
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn timepoint_rejects_out_of_range_values_and_round_trips() {
        assert_eq!(Timepoint::try_from(-1), Err(TimepointError::BeforeEpoch));
        assert_eq!(
            Timepoint::try_from(SystemTime::UNIX_EPOCH - Duration::from_secs(1)),
            Err(TimepointError::BeforeEpoch)
        );
        assert_eq!(
            Timepoint::try_from_duration(Duration::from_secs(i64::MAX as u64 + 1)),
            Err(TimepointError::Overflow)
        );

        let epoch = Timepoint::try_from(0).expect("epoch is representable");
        let later = Timepoint::try_from(42).expect("timestamp is representable");
        assert!(epoch < later);
        assert_eq!(later.unix_seconds(), 42);
        assert_eq!(
            later
                .to_system_time()
                .expect("system time is representable"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(42)
        );
        assert_eq!(
            Timepoint::try_from(i64::MAX)
                .expect("wire maximum is representable")
                .unix_seconds(),
            i64::MAX
        );
    }

    #[test]
    fn timepoint_saturating_conversion_clamps_both_boundaries() {
        assert_eq!(
            Timepoint::saturating_from_system_time(SystemTime::UNIX_EPOCH - Duration::from_secs(1))
                .unix_seconds(),
            0
        );
        assert_eq!(
            Timepoint::saturating_from_duration(Duration::from_secs(i64::MAX as u64 + 1))
                .unix_seconds(),
            i64::MAX
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn page_cursor_accepts_only_bounded_canonical_base64url() {
        for raw in ["AQ", "AAE", "cGFnZTo0Mg", &"A".repeat(4096)] {
            let cursor = PageCursor::parse(raw).expect("canonical cursor");
            assert_eq!(cursor.as_str(), raw);
        }

        for raw in ["", "A", "AR", "AAF", "abc=", "abc+", "abc/", "not valid"] {
            assert_eq!(PageCursor::parse(raw), Err(PageCursorError::Malformed));
        }
        assert_eq!(
            PageCursor::parse(&"A".repeat(4097)),
            Err(PageCursorError::TooLong)
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn page_cursor_diagnostics_are_closed_and_redacted() {
        let raw = "c2VjcmV0LXRva2Vu";
        let cursor = PageCursor::parse(raw).expect("canonical cursor");
        assert!(!format!("{cursor:?}").contains(raw));

        let errors = [
            PageCursorError::Malformed,
            PageCursorError::TooLong,
            PageCursorError::Stale,
        ];
        for error in errors {
            assert!(!error.to_string().contains(raw));
        }
    }
}
