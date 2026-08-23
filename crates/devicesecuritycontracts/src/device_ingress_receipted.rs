//! Generated from the canonical `identity.device-ingress-receipted` Draft contract. Do not edit.

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
///`IdentityDeviceIngressCommittedPayload`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceIngressCommittedPayload",
///  "type": "object",
///  "required": [
///    "authorizationReceiptId",
///    "committedAt",
///    "desiredGeneration",
///    "deviceId",
///    "ingressEnvelopeId",
///    "outcome",
///    "reason"
///  ],
///  "properties": {
///    "authorizationReceiptId": {
///      "$ref": "#/definitions/AuthorizationReceiptId",
///      "x-redaction": "internal"
///    },
///    "committedAt": {
///      "type": "integer",
///      "format": "int64"
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
///    "ingressEnvelopeId": {
///      "description": "Correlation to the receipted inbound envelope, not this receipt event's identity.",
///      "type": "string",
///      "maxLength": 256,
///      "minLength": 1
///    },
///    "outcome": {
///      "type": "string",
///      "enum": [
///        "committed"
///      ]
///    },
///    "reason": {
///      "type": "string",
///      "enum": [
///        "None"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceIngressCommittedPayload {
    #[serde(rename = "authorizationReceiptId")]
    pub authorization_receipt_id: crate::AuthorizationReceiptId,
    #[serde(rename = "committedAt")]
    pub committed_at: i64,
    #[serde(rename = "desiredGeneration")]
    pub desired_generation: ::std::num::NonZeroU64,
    #[serde(rename = "deviceId")]
    pub device_id: ::uuid::Uuid,
    ///Correlation to the receipted inbound envelope, not this receipt event's identity.
    #[serde(rename = "ingressEnvelopeId")]
    pub ingress_envelope_id: IdentityDeviceIngressCommittedPayloadIngressEnvelopeId,
    pub outcome: IdentityDeviceIngressCommittedPayloadOutcome,
    pub reason: IdentityDeviceIngressCommittedPayloadReason,
}
///Correlation to the receipted inbound envelope, not this receipt event's identity.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Correlation to the receipted inbound envelope, not this receipt event's identity.",
///  "type": "string",
///  "maxLength": 256,
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityDeviceIngressCommittedPayloadIngressEnvelopeId(::std::string::String);
impl ::std::ops::Deref for IdentityDeviceIngressCommittedPayloadIngressEnvelopeId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityDeviceIngressCommittedPayloadIngressEnvelopeId>
    for ::std::string::String
{
    fn from(value: IdentityDeviceIngressCommittedPayloadIngressEnvelopeId) -> Self {
        value.0
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressCommittedPayloadIngressEnvelopeId {
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
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressCommittedPayloadIngressEnvelopeId {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceIngressCommittedPayloadIngressEnvelopeId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceIngressCommittedPayloadIngressEnvelopeId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityDeviceIngressCommittedPayloadIngressEnvelopeId {
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
///`IdentityDeviceIngressCommittedPayloadOutcome`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "committed"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceIngressCommittedPayloadOutcome {
    #[serde(rename = "committed")]
    Committed,
}
impl ::std::fmt::Display for IdentityDeviceIngressCommittedPayloadOutcome {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Committed => f.write_str("committed"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressCommittedPayloadOutcome {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "committed" => Ok(Self::Committed),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressCommittedPayloadOutcome {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceIngressCommittedPayloadOutcome
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceIngressCommittedPayloadOutcome
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceIngressCommittedPayloadReason`
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
pub enum IdentityDeviceIngressCommittedPayloadReason {
    None,
}
impl ::std::fmt::Display for IdentityDeviceIngressCommittedPayloadReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::None => f.write_str("None"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressCommittedPayloadReason {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "None" => Ok(Self::None),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressCommittedPayloadReason {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceIngressCommittedPayloadReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceIngressCommittedPayloadReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceIngressDuplicatePayload`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceIngressDuplicatePayload",
///  "type": "object",
///  "required": [
///    "authorizationReceiptId",
///    "committedAt",
///    "desiredGeneration",
///    "deviceId",
///    "ingressEnvelopeId",
///    "outcome",
///    "reason"
///  ],
///  "properties": {
///    "authorizationReceiptId": {
///      "$ref": "#/definitions/AuthorizationReceiptId",
///      "x-redaction": "internal"
///    },
///    "committedAt": {
///      "type": "integer",
///      "format": "int64"
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
///    "ingressEnvelopeId": {
///      "description": "Correlation to the receipted inbound envelope, not this receipt event's identity.",
///      "type": "string",
///      "maxLength": 256,
///      "minLength": 1
///    },
///    "outcome": {
///      "type": "string",
///      "enum": [
///        "duplicate"
///      ]
///    },
///    "reason": {
///      "type": "string",
///      "enum": [
///        "AlreadyCommitted"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceIngressDuplicatePayload {
    #[serde(rename = "authorizationReceiptId")]
    pub authorization_receipt_id: crate::AuthorizationReceiptId,
    #[serde(rename = "committedAt")]
    pub committed_at: i64,
    #[serde(rename = "desiredGeneration")]
    pub desired_generation: ::std::num::NonZeroU64,
    #[serde(rename = "deviceId")]
    pub device_id: ::uuid::Uuid,
    ///Correlation to the receipted inbound envelope, not this receipt event's identity.
    #[serde(rename = "ingressEnvelopeId")]
    pub ingress_envelope_id: IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId,
    pub outcome: IdentityDeviceIngressDuplicatePayloadOutcome,
    pub reason: IdentityDeviceIngressDuplicatePayloadReason,
}
///Correlation to the receipted inbound envelope, not this receipt event's identity.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Correlation to the receipted inbound envelope, not this receipt event's identity.",
///  "type": "string",
///  "maxLength": 256,
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId(::std::string::String);
impl ::std::ops::Deref for IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId>
    for ::std::string::String
{
    fn from(value: IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId) -> Self {
        value.0
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId {
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
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId {
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
///`IdentityDeviceIngressDuplicatePayloadOutcome`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "duplicate"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceIngressDuplicatePayloadOutcome {
    #[serde(rename = "duplicate")]
    Duplicate,
}
impl ::std::fmt::Display for IdentityDeviceIngressDuplicatePayloadOutcome {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Duplicate => f.write_str("duplicate"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressDuplicatePayloadOutcome {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "duplicate" => Ok(Self::Duplicate),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressDuplicatePayloadOutcome {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceIngressDuplicatePayloadOutcome
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceIngressDuplicatePayloadOutcome
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceIngressDuplicatePayloadReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "AlreadyCommitted"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceIngressDuplicatePayloadReason {
    AlreadyCommitted,
}
impl ::std::fmt::Display for IdentityDeviceIngressDuplicatePayloadReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::AlreadyCommitted => f.write_str("AlreadyCommitted"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressDuplicatePayloadReason {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "AlreadyCommitted" => Ok(Self::AlreadyCommitted),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressDuplicatePayloadReason {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceIngressDuplicatePayloadReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceIngressDuplicatePayloadReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Draft OutboxFact application-receipt payload proposal. Its own stable event ID is carried only by the envelope.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceIngressReceiptedPayload",
///  "description": "Draft OutboxFact application-receipt payload proposal. Its own stable event ID is carried only by the envelope.",
///  "oneOf": [
///    {
///      "$ref": "#/definitions/IdentityDeviceIngressCommittedPayload"
///    },
///    {
///      "$ref": "#/definitions/IdentityDeviceIngressDuplicatePayload"
///    },
///    {
///      "$ref": "#/definitions/IdentityDeviceIngressStalePayload"
///    },
///    {
///      "$ref": "#/definitions/IdentityDeviceIngressRejectedPayload"
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(untagged)]
pub enum IdentityDeviceIngressReceiptedPayload {
    CommittedPayload(IdentityDeviceIngressCommittedPayload),
    DuplicatePayload(IdentityDeviceIngressDuplicatePayload),
    StalePayload(IdentityDeviceIngressStalePayload),
    RejectedPayload(IdentityDeviceIngressRejectedPayload),
}
impl ::std::convert::From<IdentityDeviceIngressCommittedPayload>
    for IdentityDeviceIngressReceiptedPayload
{
    fn from(value: IdentityDeviceIngressCommittedPayload) -> Self {
        Self::CommittedPayload(value)
    }
}
impl ::std::convert::From<IdentityDeviceIngressDuplicatePayload>
    for IdentityDeviceIngressReceiptedPayload
{
    fn from(value: IdentityDeviceIngressDuplicatePayload) -> Self {
        Self::DuplicatePayload(value)
    }
}
impl ::std::convert::From<IdentityDeviceIngressStalePayload>
    for IdentityDeviceIngressReceiptedPayload
{
    fn from(value: IdentityDeviceIngressStalePayload) -> Self {
        Self::StalePayload(value)
    }
}
impl ::std::convert::From<IdentityDeviceIngressRejectedPayload>
    for IdentityDeviceIngressReceiptedPayload
{
    fn from(value: IdentityDeviceIngressRejectedPayload) -> Self {
        Self::RejectedPayload(value)
    }
}
///`IdentityDeviceIngressRejectedPayload`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceIngressRejectedPayload",
///  "type": "object",
///  "required": [
///    "committedAt",
///    "deviceId",
///    "ingressEnvelopeId",
///    "outcome",
///    "reason"
///  ],
///  "properties": {
///    "committedAt": {
///      "type": "integer",
///      "format": "int64"
///    },
///    "deviceId": {
///      "type": "string",
///      "format": "uuid"
///    },
///    "ingressEnvelopeId": {
///      "description": "Correlation to the receipted inbound envelope, not this receipt event's identity.",
///      "type": "string",
///      "maxLength": 256,
///      "minLength": 1
///    },
///    "outcome": {
///      "type": "string",
///      "enum": [
///        "rejected"
///      ]
///    },
///    "reason": {
///      "type": "string",
///      "enum": [
///        "NotAccepted",
///        "SchemaRejected",
///        "ProtocolViolation"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceIngressRejectedPayload {
    #[serde(rename = "committedAt")]
    pub committed_at: i64,
    #[serde(rename = "deviceId")]
    pub device_id: ::uuid::Uuid,
    ///Correlation to the receipted inbound envelope, not this receipt event's identity.
    #[serde(rename = "ingressEnvelopeId")]
    pub ingress_envelope_id: IdentityDeviceIngressRejectedPayloadIngressEnvelopeId,
    pub outcome: IdentityDeviceIngressRejectedPayloadOutcome,
    pub reason: IdentityDeviceIngressRejectedPayloadReason,
}
///Correlation to the receipted inbound envelope, not this receipt event's identity.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Correlation to the receipted inbound envelope, not this receipt event's identity.",
///  "type": "string",
///  "maxLength": 256,
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityDeviceIngressRejectedPayloadIngressEnvelopeId(::std::string::String);
impl ::std::ops::Deref for IdentityDeviceIngressRejectedPayloadIngressEnvelopeId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityDeviceIngressRejectedPayloadIngressEnvelopeId>
    for ::std::string::String
{
    fn from(value: IdentityDeviceIngressRejectedPayloadIngressEnvelopeId) -> Self {
        value.0
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressRejectedPayloadIngressEnvelopeId {
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
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressRejectedPayloadIngressEnvelopeId {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceIngressRejectedPayloadIngressEnvelopeId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceIngressRejectedPayloadIngressEnvelopeId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityDeviceIngressRejectedPayloadIngressEnvelopeId {
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
///`IdentityDeviceIngressRejectedPayloadOutcome`
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
pub enum IdentityDeviceIngressRejectedPayloadOutcome {
    #[serde(rename = "rejected")]
    Rejected,
}
impl ::std::fmt::Display for IdentityDeviceIngressRejectedPayloadOutcome {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Rejected => f.write_str("rejected"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressRejectedPayloadOutcome {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "rejected" => Ok(Self::Rejected),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressRejectedPayloadOutcome {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceIngressRejectedPayloadOutcome
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceIngressRejectedPayloadOutcome
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceIngressRejectedPayloadReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "NotAccepted",
///    "SchemaRejected",
///    "ProtocolViolation"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceIngressRejectedPayloadReason {
    NotAccepted,
    SchemaRejected,
    ProtocolViolation,
}
impl ::std::fmt::Display for IdentityDeviceIngressRejectedPayloadReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::NotAccepted => f.write_str("NotAccepted"),
            Self::SchemaRejected => f.write_str("SchemaRejected"),
            Self::ProtocolViolation => f.write_str("ProtocolViolation"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressRejectedPayloadReason {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "NotAccepted" => Ok(Self::NotAccepted),
            "SchemaRejected" => Ok(Self::SchemaRejected),
            "ProtocolViolation" => Ok(Self::ProtocolViolation),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressRejectedPayloadReason {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceIngressRejectedPayloadReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for IdentityDeviceIngressRejectedPayloadReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceIngressStalePayload`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceIngressStalePayload",
///  "type": "object",
///  "required": [
///    "authorizationReceiptId",
///    "committedAt",
///    "desiredGeneration",
///    "deviceId",
///    "ingressEnvelopeId",
///    "outcome",
///    "reason"
///  ],
///  "properties": {
///    "authorizationReceiptId": {
///      "$ref": "#/definitions/AuthorizationReceiptId",
///      "x-redaction": "internal"
///    },
///    "committedAt": {
///      "type": "integer",
///      "format": "int64"
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
///    "ingressEnvelopeId": {
///      "description": "Correlation to the receipted inbound envelope, not this receipt event's identity.",
///      "type": "string",
///      "maxLength": 256,
///      "minLength": 1
///    },
///    "outcome": {
///      "type": "string",
///      "enum": [
///        "stale"
///      ]
///    },
///    "reason": {
///      "type": "string",
///      "enum": [
///        "GenerationStale",
///        "FenceEpochStale",
///        "DeviceSequenceStale"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceIngressStalePayload {
    #[serde(rename = "authorizationReceiptId")]
    pub authorization_receipt_id: crate::AuthorizationReceiptId,
    #[serde(rename = "committedAt")]
    pub committed_at: i64,
    #[serde(rename = "desiredGeneration")]
    pub desired_generation: ::std::num::NonZeroU64,
    #[serde(rename = "deviceId")]
    pub device_id: ::uuid::Uuid,
    ///Correlation to the receipted inbound envelope, not this receipt event's identity.
    #[serde(rename = "ingressEnvelopeId")]
    pub ingress_envelope_id: IdentityDeviceIngressStalePayloadIngressEnvelopeId,
    pub outcome: IdentityDeviceIngressStalePayloadOutcome,
    pub reason: IdentityDeviceIngressStalePayloadReason,
}
///Correlation to the receipted inbound envelope, not this receipt event's identity.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Correlation to the receipted inbound envelope, not this receipt event's identity.",
///  "type": "string",
///  "maxLength": 256,
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityDeviceIngressStalePayloadIngressEnvelopeId(::std::string::String);
impl ::std::ops::Deref for IdentityDeviceIngressStalePayloadIngressEnvelopeId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityDeviceIngressStalePayloadIngressEnvelopeId>
    for ::std::string::String
{
    fn from(value: IdentityDeviceIngressStalePayloadIngressEnvelopeId) -> Self {
        value.0
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressStalePayloadIngressEnvelopeId {
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
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressStalePayloadIngressEnvelopeId {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceIngressStalePayloadIngressEnvelopeId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceIngressStalePayloadIngressEnvelopeId
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityDeviceIngressStalePayloadIngressEnvelopeId {
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
///`IdentityDeviceIngressStalePayloadOutcome`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "stale"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceIngressStalePayloadOutcome {
    #[serde(rename = "stale")]
    Stale,
}
impl ::std::fmt::Display for IdentityDeviceIngressStalePayloadOutcome {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Stale => f.write_str("stale"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressStalePayloadOutcome {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "stale" => Ok(Self::Stale),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressStalePayloadOutcome {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for IdentityDeviceIngressStalePayloadOutcome {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for IdentityDeviceIngressStalePayloadOutcome {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceIngressStalePayloadReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "GenerationStale",
///    "FenceEpochStale",
///    "DeviceSequenceStale"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceIngressStalePayloadReason {
    GenerationStale,
    FenceEpochStale,
    DeviceSequenceStale,
}
impl ::std::fmt::Display for IdentityDeviceIngressStalePayloadReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::GenerationStale => f.write_str("GenerationStale"),
            Self::FenceEpochStale => f.write_str("FenceEpochStale"),
            Self::DeviceSequenceStale => f.write_str("DeviceSequenceStale"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceIngressStalePayloadReason {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "GenerationStale" => Ok(Self::GenerationStale),
            "FenceEpochStale" => Ok(Self::FenceEpochStale),
            "DeviceSequenceStale" => Ok(Self::DeviceSequenceStale),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceIngressStalePayloadReason {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for IdentityDeviceIngressStalePayloadReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for IdentityDeviceIngressStalePayloadReason {
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
        "identity.device-ingress-receipted",
        "v1",
        "sha256:95f384f11c6812158a3ac66c80abfbfaa3856f8c2b0a86f6d32fc25466aabc9c",
    );
/// Candidate lifecycle; this package does not activate the contract.
pub const LIFECYCLE: &str = "draft";
/// Exact authored schema artifacts embedded in this package.
pub const SCHEMAS: &[crate::SchemaArtifact] = &[crate::SchemaArtifact::new(
    "payload",
    "sha256:d4cc5f2b0584e95d12427009d3690ef3fe49bd13cd4b6c83cdb1daaecbbd924b",
    include_bytes!("../schema/device_ingress_receipted/payload.schema.json"),
)];
