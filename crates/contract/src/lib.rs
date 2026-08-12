#![doc = include_str!("../README.md")]

use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};

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
        Self::from_static(id, parse_static_version(version), schema_digest)
    }

    #[must_use]
    pub const fn from_static(
        id: &'static str,
        version_major: u32,
        schema_digest: &'static str,
    ) -> Self {
        assert!(valid_contract_id(id), "invalid contract id");
        assert!(version_major != 0, "contract version must be non-zero");
        assert!(valid_schema_digest(schema_digest), "invalid schema digest");
        Self {
            id,
            version: ContractVersion::from_static_major(version_major),
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

const fn parse_static_version(value: &str) -> u32 {
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
        major = match major.checked_mul(10) {
            Some(value) => value,
            None => panic!("invalid contract version"),
        };
        major = match major.checked_add((byte - b'0') as u32) {
            Some(value) => value,
            None => panic!("invalid contract version"),
        };
        index += 1;
    }
    assert!(major != 0, "invalid contract version");
    major
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_values_round_trip() {
        let id = ContractId::parse("runtime.inventory").unwrap();
        let version = ContractVersion::parse("v12").unwrap();
        let digest = SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        assert_eq!(id.as_str(), "runtime.inventory");
        assert_eq!(version.to_string(), "v12");
        assert_eq!(digest.as_str().len(), 71);
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
    fn static_versions_reject_leading_zero_and_overflow() {
        for value in ["v01", "v4294967296"] {
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
    fn exhaustive_public_value_boundaries() {
        let max = format!("a.{}", "b".repeat(253));
        assert_eq!(ContractId::parse(&max).unwrap().to_string(), max);
        assert_eq!(
            ContractId::parse(&"a".repeat(256)),
            Err(IdentityError::TooLong)
        );
        assert_eq!(ContractId::parse("a/b"), Err(IdentityError::InvalidFormat));
        assert_eq!(
            ContractVersion::from_major(0),
            Err(IdentityError::ZeroVersion)
        );
        assert_eq!(ContractVersion::from_major(7).unwrap().major(), 7);
        assert!(ContractVersion::parse("v4294967296").is_err());
        let digest = format!("sha256:{}", "0".repeat(64));
        let parsed = SchemaDigest::parse(&digest).unwrap();
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
            ContractId::from_static("runtime.inventory"),
            ContractId::parse("runtime.inventory").unwrap()
        );
        assert_eq!(
            SchemaDigest::from_static(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            SchemaDigest::parse(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .unwrap()
        );
    }
}
