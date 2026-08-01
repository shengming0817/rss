//! Canonical textual SHA-256 identity.

use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::str::FromStr;

const PREFIX: &str = "sha256:";
const HEX_LEN: usize = 64;

/// A canonical textual SHA-256 digest: `sha256:` followed by 64 lowercase hex digits.
///
/// This type proves syntax only. It does not claim that a digest came from generated artifacts,
/// a trusted repository, or any other provenance-bearing source.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CanonicalSha256Digest(String);

impl CanonicalSha256Digest {
    /// Parse and validate a canonical textual SHA-256 digest.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, CanonicalSha256DigestError> {
        let value = value.as_ref();
        let Some(hex) = value.strip_prefix(PREFIX) else {
            return Err(CanonicalSha256DigestError);
        };
        if hex.len() != HEX_LEN
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CanonicalSha256DigestError);
        }
        Ok(Self(value.to_owned()))
    }

    /// Borrow the canonical wire representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CanonicalSha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CanonicalSha256Digest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for CanonicalSha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for CanonicalSha256Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for CanonicalSha256Digest {
    type Err = CanonicalSha256DigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for CanonicalSha256Digest {
    type Error = CanonicalSha256DigestError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<String> for CanonicalSha256Digest {
    type Error = CanonicalSha256DigestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for CanonicalSha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// A string is not a canonical textual SHA-256 digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("digest must use sha256: followed by 64 lowercase hexadecimal digits")]
pub struct CanonicalSha256DigestError;

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_exact_canonical_syntax() {
        let digest = CanonicalSha256Digest::parse(VALID).expect("canonical digest");
        assert_eq!(digest.as_str(), VALID);
        assert_eq!(digest.to_string(), VALID);
    }

    #[test]
    fn rejects_noncanonical_syntax() {
        for invalid in [
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "sha256:0123",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
        ] {
            assert_eq!(
                CanonicalSha256Digest::parse(invalid),
                Err(CanonicalSha256DigestError),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn serde_uses_the_canonical_string_boundary() {
        let digest: CanonicalSha256Digest =
            serde_json::from_str(&format!("\"{VALID}\"")).expect("deserialize canonical digest");
        assert_eq!(
            serde_json::to_string(&digest).expect("serialize"),
            format!("\"{VALID}\"")
        );
        assert!(serde_json::from_str::<CanonicalSha256Digest>("\"sha256:00\"").is_err());
    }
}
