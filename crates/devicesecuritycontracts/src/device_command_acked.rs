//! Generated from the canonical `identity.device-command-acked` Draft contract. Do not edit.

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
///Draft OutboxFact payload proposal. The stable event ID is carried only by the envelope; ACK does not assert convergence.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCommandAckedPayload",
///  "description": "Draft OutboxFact payload proposal. The stable event ID is carried only by the envelope; ACK does not assert convergence.",
///  "oneOf": [
///    {
///      "$ref": "#/definitions/IdentityDeviceCommandAckedReceivedPayload"
///    },
///    {
///      "$ref": "#/definitions/IdentityDeviceCommandAckedRejectedPayload"
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(untagged)]
pub enum IdentityDeviceCommandAckedPayload {
    ReceivedPayload(IdentityDeviceCommandAckedReceivedPayload),
    RejectedPayload(IdentityDeviceCommandAckedRejectedPayload),
}
impl ::std::convert::From<IdentityDeviceCommandAckedReceivedPayload>
    for IdentityDeviceCommandAckedPayload
{
    fn from(value: IdentityDeviceCommandAckedReceivedPayload) -> Self {
        Self::ReceivedPayload(value)
    }
}
impl ::std::convert::From<IdentityDeviceCommandAckedRejectedPayload>
    for IdentityDeviceCommandAckedPayload
{
    fn from(value: IdentityDeviceCommandAckedRejectedPayload) -> Self {
        Self::RejectedPayload(value)
    }
}
///`IdentityDeviceCommandAckedReceivedPayload`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCommandAckedReceivedPayload",
///  "type": "object",
///  "required": [
///    "commandId",
///    "desiredGeneration",
///    "deviceId",
///    "deviceSequence",
///    "fenceEpoch",
///    "observedAt",
///    "reason",
///    "result"
///  ],
///  "properties": {
///    "commandId": {
///      "type": "string",
///      "maxLength": 256,
///      "minLength": 1
///    },
///    "desiredGeneration": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 1.0
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
///    "fenceEpoch": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 1.0
///    },
///    "observedAt": {
///      "type": "integer",
///      "format": "int64"
///    },
///    "reason": {
///      "type": "string",
///      "enum": [
///        "None"
///      ]
///    },
///    "result": {
///      "type": "string",
///      "enum": [
///        "received"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCommandAckedReceivedPayload {
    #[serde(rename = "commandId")]
    pub command_id: IdentityDeviceCommandAckedReceivedPayloadCommandId,
    #[serde(rename = "desiredGeneration")]
    pub desired_generation: ::std::num::NonZeroU64,
    #[serde(rename = "deviceId")]
    pub device_id: ::uuid::Uuid,
    #[serde(rename = "deviceSequence")]
    pub device_sequence: i64,
    #[serde(rename = "fenceEpoch")]
    pub fence_epoch: ::std::num::NonZeroU64,
    #[serde(rename = "observedAt")]
    pub observed_at: i64,
    pub reason: IdentityDeviceCommandAckedReceivedPayloadReason,
    pub result: IdentityDeviceCommandAckedReceivedPayloadResult,
}
///`IdentityDeviceCommandAckedReceivedPayloadCommandId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "maxLength": 256,
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityDeviceCommandAckedReceivedPayloadCommandId(::std::string::String);
impl ::std::ops::Deref for IdentityDeviceCommandAckedReceivedPayloadCommandId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityDeviceCommandAckedReceivedPayloadCommandId>
    for ::std::string::String
{
    fn from(value: IdentityDeviceCommandAckedReceivedPayloadCommandId) -> Self {
        value.0
    }
}
impl ::std::str::FromStr for IdentityDeviceCommandAckedReceivedPayloadCommandId {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() > 256usize {
            return Err("longer than 256 characters".into());
        }
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCommandAckedReceivedPayloadCommandId {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCommandAckedReceivedPayloadCommandId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCommandAckedReceivedPayloadCommandId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityDeviceCommandAckedReceivedPayloadCommandId {
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
///`IdentityDeviceCommandAckedReceivedPayloadReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "None"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCommandAckedReceivedPayloadReason {
    None,
}
impl ::std::fmt::Display for IdentityDeviceCommandAckedReceivedPayloadReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::None => f.write_str("None"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCommandAckedReceivedPayloadReason {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "None" => Ok(Self::None),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCommandAckedReceivedPayloadReason {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCommandAckedReceivedPayloadReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCommandAckedReceivedPayloadReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCommandAckedReceivedPayloadResult`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "received"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCommandAckedReceivedPayloadResult {
    #[serde(rename = "received")]
    Received,
}
impl ::std::fmt::Display for IdentityDeviceCommandAckedReceivedPayloadResult {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Received => f.write_str("received"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCommandAckedReceivedPayloadResult {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "received" => Ok(Self::Received),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCommandAckedReceivedPayloadResult {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCommandAckedReceivedPayloadResult
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCommandAckedReceivedPayloadResult
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCommandAckedRejectedPayload`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCommandAckedRejectedPayload",
///  "type": "object",
///  "required": [
///    "commandId",
///    "desiredGeneration",
///    "deviceId",
///    "deviceSequence",
///    "fenceEpoch",
///    "observedAt",
///    "reason",
///    "result"
///  ],
///  "properties": {
///    "commandId": {
///      "type": "string",
///      "maxLength": 256,
///      "minLength": 1
///    },
///    "desiredGeneration": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 1.0
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
///    "fenceEpoch": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 1.0
///    },
///    "observedAt": {
///      "type": "integer",
///      "format": "int64"
///    },
///    "reason": {
///      "type": "string",
///      "enum": [
///        "ArtifactUnavailable",
///        "ArtifactDigestMismatch",
///        "PolicyRejected",
///        "GenerationStale",
///        "FenceEpochStale",
///        "MalformedCommand",
///        "DeviceFailure"
///      ]
///    },
///    "result": {
///      "type": "string",
///      "enum": [
///        "rejected"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCommandAckedRejectedPayload {
    #[serde(rename = "commandId")]
    pub command_id: IdentityDeviceCommandAckedRejectedPayloadCommandId,
    #[serde(rename = "desiredGeneration")]
    pub desired_generation: ::std::num::NonZeroU64,
    #[serde(rename = "deviceId")]
    pub device_id: ::uuid::Uuid,
    #[serde(rename = "deviceSequence")]
    pub device_sequence: i64,
    #[serde(rename = "fenceEpoch")]
    pub fence_epoch: ::std::num::NonZeroU64,
    #[serde(rename = "observedAt")]
    pub observed_at: i64,
    pub reason: IdentityDeviceCommandAckedRejectedPayloadReason,
    pub result: IdentityDeviceCommandAckedRejectedPayloadResult,
}
///`IdentityDeviceCommandAckedRejectedPayloadCommandId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "maxLength": 256,
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityDeviceCommandAckedRejectedPayloadCommandId(::std::string::String);
impl ::std::ops::Deref for IdentityDeviceCommandAckedRejectedPayloadCommandId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityDeviceCommandAckedRejectedPayloadCommandId>
    for ::std::string::String
{
    fn from(value: IdentityDeviceCommandAckedRejectedPayloadCommandId) -> Self {
        value.0
    }
}
impl ::std::str::FromStr for IdentityDeviceCommandAckedRejectedPayloadCommandId {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() > 256usize {
            return Err("longer than 256 characters".into());
        }
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCommandAckedRejectedPayloadCommandId {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCommandAckedRejectedPayloadCommandId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCommandAckedRejectedPayloadCommandId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityDeviceCommandAckedRejectedPayloadCommandId {
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
///`IdentityDeviceCommandAckedRejectedPayloadReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "ArtifactUnavailable",
///    "ArtifactDigestMismatch",
///    "PolicyRejected",
///    "GenerationStale",
///    "FenceEpochStale",
///    "MalformedCommand",
///    "DeviceFailure"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCommandAckedRejectedPayloadReason {
    ArtifactUnavailable,
    ArtifactDigestMismatch,
    PolicyRejected,
    GenerationStale,
    FenceEpochStale,
    MalformedCommand,
    DeviceFailure,
}
impl ::std::fmt::Display for IdentityDeviceCommandAckedRejectedPayloadReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::ArtifactUnavailable => f.write_str("ArtifactUnavailable"),
            Self::ArtifactDigestMismatch => f.write_str("ArtifactDigestMismatch"),
            Self::PolicyRejected => f.write_str("PolicyRejected"),
            Self::GenerationStale => f.write_str("GenerationStale"),
            Self::FenceEpochStale => f.write_str("FenceEpochStale"),
            Self::MalformedCommand => f.write_str("MalformedCommand"),
            Self::DeviceFailure => f.write_str("DeviceFailure"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCommandAckedRejectedPayloadReason {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "ArtifactUnavailable" => Ok(Self::ArtifactUnavailable),
            "ArtifactDigestMismatch" => Ok(Self::ArtifactDigestMismatch),
            "PolicyRejected" => Ok(Self::PolicyRejected),
            "GenerationStale" => Ok(Self::GenerationStale),
            "FenceEpochStale" => Ok(Self::FenceEpochStale),
            "MalformedCommand" => Ok(Self::MalformedCommand),
            "DeviceFailure" => Ok(Self::DeviceFailure),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCommandAckedRejectedPayloadReason {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCommandAckedRejectedPayloadReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCommandAckedRejectedPayloadReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCommandAckedRejectedPayloadResult`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "rejected"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCommandAckedRejectedPayloadResult {
    #[serde(rename = "rejected")]
    Rejected,
}
impl ::std::fmt::Display for IdentityDeviceCommandAckedRejectedPayloadResult {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Rejected => f.write_str("rejected"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCommandAckedRejectedPayloadResult {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "rejected" => Ok(Self::Rejected),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCommandAckedRejectedPayloadResult {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCommandAckedRejectedPayloadResult
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCommandAckedRejectedPayloadResult
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}

/// Canonical contract identity and aggregate schema digest.
pub const DESCRIPTOR: ::rss_contract::ContractDescriptor =
    ::rss_contract::ContractDescriptor::from_static_version(
        "identity.device-command-acked",
        "v1",
        "sha256:bb05c85aa143c6cde3a66ff61c97a58b59c95e51b24090c5800535dcd24828d2",
    );
/// Candidate lifecycle; this package does not activate the contract.
pub const LIFECYCLE: &str = "draft";
/// Exact authored schema artifacts embedded in this package.
pub const SCHEMAS: &[crate::SchemaArtifact] = &[crate::SchemaArtifact::new(
    "payload",
    "sha256:609d2d7e01d9ed09e642f4af6b774d685a832788201575f20c18121938ef6223",
    include_bytes!("../schema/device_command_acked/payload.schema.json"),
)];
