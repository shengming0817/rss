//! Generated from the canonical `identity.apply-device-certificate` Draft contract. Do not edit.

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
///Draft OutboxFact command payload proposal. It can represent only an opaque authorized public artifact reference.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityApplyDeviceCertificateRequest",
///  "description": "Draft OutboxFact command payload proposal. It can represent only an opaque authorized public artifact reference.",
///  "type": "object",
///  "required": [
///    "artifactDigest",
///    "artifactId",
///    "authorizationReceiptId",
///    "deadlineEpochSeconds",
///    "desiredGeneration",
///    "deviceId",
///    "fenceEpoch",
///    "intentDigest",
///    "policyHash"
///  ],
///  "properties": {
///    "artifactDigest": {
///      "type": "string",
///      "pattern": "^sha256:[0-9a-f]{64}$"
///    },
///    "artifactId": {
///      "type": "string",
///      "maxLength": 256,
///      "minLength": 16
///    },
///    "authorizationReceiptId": {
///      "$ref": "#/definitions/AuthorizationReceiptId",
///      "x-redaction": "internal"
///    },
///    "deadlineEpochSeconds": {
///      "type": "integer",
///      "format": "int64",
///      "maximum": 9223372036854.0,
///      "minimum": 1.0
///    },
///    "desiredGeneration": {
///      "type": "integer",
///      "format": "int64",
///      "maximum": 9.223372036854776e+18,
///      "minimum": 1.0
///    },
///    "deviceId": {
///      "type": "string",
///      "format": "uuid"
///    },
///    "fenceEpoch": {
///      "type": "integer",
///      "format": "int64",
///      "maximum": 9.223372036854776e+18,
///      "minimum": 1.0
///    },
///    "intentDigest": {
///      "type": "string",
///      "pattern": "^sha256:[0-9a-f]{64}$",
///      "x-redaction": "secret"
///    },
///    "policyHash": {
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
pub struct IdentityApplyDeviceCertificateRequest {
    #[serde(rename = "artifactDigest")]
    pub artifact_digest: IdentityApplyDeviceCertificateRequestArtifactDigest,
    #[serde(rename = "artifactId")]
    pub artifact_id: IdentityApplyDeviceCertificateRequestArtifactId,
    #[serde(rename = "authorizationReceiptId")]
    pub authorization_receipt_id: crate::AuthorizationReceiptId,
    #[serde(rename = "deadlineEpochSeconds")]
    pub deadline_epoch_seconds: ::std::num::NonZeroU64,
    #[serde(rename = "desiredGeneration")]
    pub desired_generation: ::std::num::NonZeroU64,
    #[serde(rename = "deviceId")]
    pub device_id: ::uuid::Uuid,
    #[serde(rename = "fenceEpoch")]
    pub fence_epoch: ::std::num::NonZeroU64,
    #[serde(rename = "intentDigest")]
    pub intent_digest: IdentityApplyDeviceCertificateRequestIntentDigest,
    #[serde(rename = "policyHash")]
    pub policy_hash: IdentityApplyDeviceCertificateRequestPolicyHash,
}
///`IdentityApplyDeviceCertificateRequestArtifactDigest`
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
pub struct IdentityApplyDeviceCertificateRequestArtifactDigest(::std::string::String);
impl ::std::ops::Deref for IdentityApplyDeviceCertificateRequestArtifactDigest {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityApplyDeviceCertificateRequestArtifactDigest>
    for ::std::string::String
{
    fn from(value: IdentityApplyDeviceCertificateRequestArtifactDigest) -> Self {
        value.0
    }
}
#[allow(clippy::unwrap_used)]
impl ::std::str::FromStr for IdentityApplyDeviceCertificateRequestArtifactDigest {
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
impl ::std::convert::TryFrom<&str> for IdentityApplyDeviceCertificateRequestArtifactDigest {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityApplyDeviceCertificateRequestArtifactDigest
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityApplyDeviceCertificateRequestArtifactDigest
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityApplyDeviceCertificateRequestArtifactDigest {
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
///`IdentityApplyDeviceCertificateRequestArtifactId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "maxLength": 256,
///  "minLength": 16
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityApplyDeviceCertificateRequestArtifactId(::std::string::String);
impl ::std::ops::Deref for IdentityApplyDeviceCertificateRequestArtifactId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityApplyDeviceCertificateRequestArtifactId>
    for ::std::string::String
{
    fn from(value: IdentityApplyDeviceCertificateRequestArtifactId) -> Self {
        value.0
    }
}
impl ::std::str::FromStr for IdentityApplyDeviceCertificateRequestArtifactId {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() > 256usize {
            return Err("longer than 256 characters".into());
        }
        if value.chars().count() < 16usize {
            return Err("shorter than 16 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for IdentityApplyDeviceCertificateRequestArtifactId {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityApplyDeviceCertificateRequestArtifactId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityApplyDeviceCertificateRequestArtifactId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityApplyDeviceCertificateRequestArtifactId {
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
///`IdentityApplyDeviceCertificateRequestIntentDigest`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^sha256:[0-9a-f]{64}$",
///  "x-redaction": "secret"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityApplyDeviceCertificateRequestIntentDigest(::std::string::String);
impl ::std::ops::Deref for IdentityApplyDeviceCertificateRequestIntentDigest {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityApplyDeviceCertificateRequestIntentDigest>
    for ::std::string::String
{
    fn from(value: IdentityApplyDeviceCertificateRequestIntentDigest) -> Self {
        value.0
    }
}
#[allow(clippy::unwrap_used)]
impl ::std::str::FromStr for IdentityApplyDeviceCertificateRequestIntentDigest {
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
impl ::std::convert::TryFrom<&str> for IdentityApplyDeviceCertificateRequestIntentDigest {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityApplyDeviceCertificateRequestIntentDigest
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityApplyDeviceCertificateRequestIntentDigest
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityApplyDeviceCertificateRequestIntentDigest {
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
///`IdentityApplyDeviceCertificateRequestPolicyHash`
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
pub struct IdentityApplyDeviceCertificateRequestPolicyHash(::std::string::String);
impl ::std::ops::Deref for IdentityApplyDeviceCertificateRequestPolicyHash {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityApplyDeviceCertificateRequestPolicyHash>
    for ::std::string::String
{
    fn from(value: IdentityApplyDeviceCertificateRequestPolicyHash) -> Self {
        value.0
    }
}
#[allow(clippy::unwrap_used)]
impl ::std::str::FromStr for IdentityApplyDeviceCertificateRequestPolicyHash {
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
impl ::std::convert::TryFrom<&str> for IdentityApplyDeviceCertificateRequestPolicyHash {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityApplyDeviceCertificateRequestPolicyHash
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityApplyDeviceCertificateRequestPolicyHash
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityApplyDeviceCertificateRequestPolicyHash {
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
        "identity.apply-device-certificate",
        "v1",
        "sha256:a45a6ce5b930e2921919b10d688321bb05f59117fa8b8cb9076a7c455bff213b",
    );
/// Candidate lifecycle; this package does not activate the contract.
pub const LIFECYCLE: &str = "draft";
/// Exact authored schema artifacts embedded in this package.
pub const SCHEMAS: &[crate::SchemaArtifact] = &[crate::SchemaArtifact::new(
    "request",
    "sha256:ae2bed128ede28c1a2a1f913bf394213a39cae09cb9f3f0accc5e39aba2a4501",
    include_bytes!("../schema/apply_device_certificate/request.schema.json"),
)];
