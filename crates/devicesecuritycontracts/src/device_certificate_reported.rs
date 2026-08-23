//! Generated from the canonical `identity.device-certificate-reported` Draft contract. Do not edit.

/// Error types.
pub mod error {
    /// Error from a `TryFrom` or `FromStr` implementation.
    pub struct ConversionError(::std::borrow::Cow<'static, str>);
    impl ::std::error::Error for ConversionError {}
    impl ::std::fmt::Display for ConversionError {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> Result<(), ::std::fmt::Error> {
            ::std::fmt::Display::fmt(&self.0, f)
        }
    }
    impl ::std::fmt::Debug for ConversionError {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> Result<(), ::std::fmt::Error> {
            ::std::fmt::Debug::fmt(&self.0, f)
        }
    }
    impl From<&'static str> for ConversionError {
        fn from(value: &'static str) -> Self {
            Self(value.into())
        }
    }
    impl From<String> for ConversionError {
        fn from(value: String) -> Self {
            Self(value.into())
        }
    }
}
///Draft OutboxFact reported-state payload proposal. The stable event ID is carried only by the envelope.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateReportedPayload",
///  "description": "Draft OutboxFact reported-state payload proposal. The stable event ID is carried only by the envelope.",
///  "type": "object",
///  "required": [
///    "artifactDigest",
///    "deviceId",
///    "deviceSequence",
///    "fenceEpoch",
///    "observedAt",
///    "observedGeneration",
///    "stateHash"
///  ],
///  "properties": {
///    "artifactDigest": {
///      "type": "string",
///      "pattern": "^sha256:[0-9a-f]{64}$"
///    },
///    "deviceId": {
///      "type": "string",
///      "format": "uuid"
///    },
///    "deviceSequence": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 0.0
///    },
///    "expiresAt": {
///      "type": [
///        "integer",
///        "null"
///      ],
///      "format": "int64"
///    },
///    "fenceEpoch": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 1.0
///    },
///    "observedAt": {
///      "type": "integer",
///      "format": "int64"
///    },
///    "observedGeneration": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 1.0
///    },
///    "stateHash": {
///      "type": "string",
///      "pattern": "^sha256:[0-9a-f]{64}$"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificateReportedPayload {
    #[serde(rename = "artifactDigest")]
    pub artifact_digest: IdentityDeviceCertificateReportedPayloadArtifactDigest,
    #[serde(rename = "deviceId")]
    pub device_id: ::uuid::Uuid,
    #[serde(rename = "deviceSequence")]
    pub device_sequence: i64,
    #[serde(
        rename = "expiresAt",
        default,
        skip_serializing_if = "::std::option::Option::is_none"
    )]
    pub expires_at: ::std::option::Option<i64>,
    #[serde(rename = "fenceEpoch")]
    pub fence_epoch: ::std::num::NonZeroU64,
    #[serde(rename = "observedAt")]
    pub observed_at: i64,
    #[serde(rename = "observedGeneration")]
    pub observed_generation: ::std::num::NonZeroU64,
    #[serde(rename = "stateHash")]
    pub state_hash: IdentityDeviceCertificateReportedPayloadStateHash,
}
///`IdentityDeviceCertificateReportedPayloadArtifactDigest`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^sha256:[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityDeviceCertificateReportedPayloadArtifactDigest(::std::string::String);
impl ::std::ops::Deref for IdentityDeviceCertificateReportedPayloadArtifactDigest {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityDeviceCertificateReportedPayloadArtifactDigest>
    for ::std::string::String
{
    fn from(value: IdentityDeviceCertificateReportedPayloadArtifactDigest) -> Self {
        value.0
    }
}
#[allow(clippy::unwrap_used)]
impl ::std::str::FromStr for IdentityDeviceCertificateReportedPayloadArtifactDigest {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> =
            ::std::sync::LazyLock::new(|| ::regress::Regex::new("^sha256:[0-9a-f]{64}$").unwrap());
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^sha256:[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificateReportedPayloadArtifactDigest {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificateReportedPayloadArtifactDigest
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificateReportedPayloadArtifactDigest
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityDeviceCertificateReportedPayloadArtifactDigest {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`IdentityDeviceCertificateReportedPayloadStateHash`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^sha256:[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityDeviceCertificateReportedPayloadStateHash(::std::string::String);
impl ::std::ops::Deref for IdentityDeviceCertificateReportedPayloadStateHash {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityDeviceCertificateReportedPayloadStateHash>
    for ::std::string::String
{
    fn from(value: IdentityDeviceCertificateReportedPayloadStateHash) -> Self {
        value.0
    }
}
#[allow(clippy::unwrap_used)]
impl ::std::str::FromStr for IdentityDeviceCertificateReportedPayloadStateHash {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> =
            ::std::sync::LazyLock::new(|| ::regress::Regex::new("^sha256:[0-9a-f]{64}$").unwrap());
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^sha256:[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificateReportedPayloadStateHash {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificateReportedPayloadStateHash
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificateReportedPayloadStateHash
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityDeviceCertificateReportedPayloadStateHash {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}

/// Canonical contract identity and aggregate schema digest.
pub const DESCRIPTOR: ::rss_contract::ContractDescriptor =
    ::rss_contract::ContractDescriptor::from_static_version(
        "identity.device-certificate-reported",
        "v1",
        "sha256:d4c798267d837b88ab4e88094a612fb3cfd043b4ba8d29e7dc4607c5cc1ad637",
    );
/// Candidate lifecycle; this package does not activate the contract.
pub const LIFECYCLE: &str = "draft";
/// Exact authored schema artifacts embedded in this package.
pub const SCHEMAS: &[crate::SchemaArtifact] = &[crate::SchemaArtifact::new(
    "payload",
    "sha256:f1e248ec13c4fd3dbd32ef0dca37642cda1dfa53dcfa600524cbfe03a561a812",
    include_bytes!("../schema/device_certificate_reported/payload.schema.json"),
)];
