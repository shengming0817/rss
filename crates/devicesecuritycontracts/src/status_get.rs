//! Generated from the canonical `identity.device-certificate-status-get` Draft contract. Do not edit.

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
///`ActiveCommand`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetActiveCommand",
///  "type": "object",
///  "required": [
///    "fenceEpoch",
///    "state"
///  ],
///  "properties": {
///    "fenceEpoch": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 1.0
///    },
///    "state": {
///      "type": "string",
///      "enum": [
///        "queued",
///        "published",
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
pub struct ActiveCommand {
    #[serde(rename = "fenceEpoch")]
    pub fence_epoch: ::std::num::NonZeroU64,
    pub state: ActiveCommandState,
}
///`ActiveCommandState`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "queued",
///    "published",
///    "received"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum ActiveCommandState {
    #[serde(rename = "queued")]
    Queued,
    #[serde(rename = "published")]
    Published,
    #[serde(rename = "received")]
    Received,
}
impl ::std::fmt::Display for ActiveCommandState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Queued => f.write_str("queued"),
            Self::Published => f.write_str("published"),
            Self::Received => f.write_str("received"),
        }
    }
}
impl ::std::str::FromStr for ActiveCommandState {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "queued" => Ok(Self::Queued),
            "published" => Ok(Self::Published),
            "received" => Ok(Self::Received),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ActiveCommandState {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ActiveCommandState {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ActiveCommandState {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`Condition`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetCondition",
///  "type": "object",
///  "required": [
///    "lastTransitionAt",
///    "observedGeneration",
///    "reason",
///    "status",
///    "type"
///  ],
///  "properties": {
///    "lastTransitionAt": {
///      "type": "integer",
///      "format": "int64"
///    },
///    "observedGeneration": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 0.0
///    },
///    "reason": {
///      "type": "string",
///      "enum": [
///        "DesiredAccepted",
///        "CommandQueued",
///        "AwaitingDevice",
///        "DeviceReported",
///        "StateMatches",
///        "StateDrift",
///        "CommandRejected",
///        "CommandTimedOut",
///        "ProtocolViolation",
///        "QuarantinedByOperator",
///        "DeletionPending",
///        "DeletionComplete",
///        "ArtifactUnavailable",
///        "TransportUnavailable"
///      ]
///    },
///    "status": {
///      "type": "string",
///      "enum": [
///        "True",
///        "False",
///        "Unknown"
///      ]
///    },
///    "type": {
///      "type": "string",
///      "enum": [
///        "Ready",
///        "Reconciling",
///        "PendingDevice",
///        "Degraded",
///        "Quarantined",
///        "Deleting"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    #[serde(rename = "lastTransitionAt")]
    pub last_transition_at: i64,
    #[serde(rename = "observedGeneration")]
    pub observed_generation: i64,
    pub reason: ConditionReason,
    pub status: ConditionStatus,
    #[serde(rename = "type")]
    pub type_: ConditionType,
}
///`ConditionReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "DesiredAccepted",
///    "CommandQueued",
///    "AwaitingDevice",
///    "DeviceReported",
///    "StateMatches",
///    "StateDrift",
///    "CommandRejected",
///    "CommandTimedOut",
///    "ProtocolViolation",
///    "QuarantinedByOperator",
///    "DeletionPending",
///    "DeletionComplete",
///    "ArtifactUnavailable",
///    "TransportUnavailable"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum ConditionReason {
    DesiredAccepted,
    CommandQueued,
    AwaitingDevice,
    DeviceReported,
    StateMatches,
    StateDrift,
    CommandRejected,
    CommandTimedOut,
    ProtocolViolation,
    QuarantinedByOperator,
    DeletionPending,
    DeletionComplete,
    ArtifactUnavailable,
    TransportUnavailable,
}
impl ::std::fmt::Display for ConditionReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::DesiredAccepted => f.write_str("DesiredAccepted"),
            Self::CommandQueued => f.write_str("CommandQueued"),
            Self::AwaitingDevice => f.write_str("AwaitingDevice"),
            Self::DeviceReported => f.write_str("DeviceReported"),
            Self::StateMatches => f.write_str("StateMatches"),
            Self::StateDrift => f.write_str("StateDrift"),
            Self::CommandRejected => f.write_str("CommandRejected"),
            Self::CommandTimedOut => f.write_str("CommandTimedOut"),
            Self::ProtocolViolation => f.write_str("ProtocolViolation"),
            Self::QuarantinedByOperator => f.write_str("QuarantinedByOperator"),
            Self::DeletionPending => f.write_str("DeletionPending"),
            Self::DeletionComplete => f.write_str("DeletionComplete"),
            Self::ArtifactUnavailable => f.write_str("ArtifactUnavailable"),
            Self::TransportUnavailable => f.write_str("TransportUnavailable"),
        }
    }
}
impl ::std::str::FromStr for ConditionReason {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "DesiredAccepted" => Ok(Self::DesiredAccepted),
            "CommandQueued" => Ok(Self::CommandQueued),
            "AwaitingDevice" => Ok(Self::AwaitingDevice),
            "DeviceReported" => Ok(Self::DeviceReported),
            "StateMatches" => Ok(Self::StateMatches),
            "StateDrift" => Ok(Self::StateDrift),
            "CommandRejected" => Ok(Self::CommandRejected),
            "CommandTimedOut" => Ok(Self::CommandTimedOut),
            "ProtocolViolation" => Ok(Self::ProtocolViolation),
            "QuarantinedByOperator" => Ok(Self::QuarantinedByOperator),
            "DeletionPending" => Ok(Self::DeletionPending),
            "DeletionComplete" => Ok(Self::DeletionComplete),
            "ArtifactUnavailable" => Ok(Self::ArtifactUnavailable),
            "TransportUnavailable" => Ok(Self::TransportUnavailable),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ConditionReason {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ConditionReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ConditionReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`ConditionStatus`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "True",
///    "False",
///    "Unknown"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}
impl ::std::fmt::Display for ConditionStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::True => f.write_str("True"),
            Self::False => f.write_str("False"),
            Self::Unknown => f.write_str("Unknown"),
        }
    }
}
impl ::std::str::FromStr for ConditionStatus {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "True" => Ok(Self::True),
            "False" => Ok(Self::False),
            "Unknown" => Ok(Self::Unknown),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ConditionStatus {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ConditionStatus {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ConditionStatus {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`ConditionType`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "Ready",
///    "Reconciling",
///    "PendingDevice",
///    "Degraded",
///    "Quarantined",
///    "Deleting"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum ConditionType {
    Ready,
    Reconciling,
    PendingDevice,
    Degraded,
    Quarantined,
    Deleting,
}
impl ::std::fmt::Display for ConditionType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Ready => f.write_str("Ready"),
            Self::Reconciling => f.write_str("Reconciling"),
            Self::PendingDevice => f.write_str("PendingDevice"),
            Self::Degraded => f.write_str("Degraded"),
            Self::Quarantined => f.write_str("Quarantined"),
            Self::Deleting => f.write_str("Deleting"),
        }
    }
}
impl ::std::str::FromStr for ConditionType {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "Ready" => Ok(Self::Ready),
            "Reconciling" => Ok(Self::Reconciling),
            "PendingDevice" => Ok(Self::PendingDevice),
            "Degraded" => Ok(Self::Degraded),
            "Quarantined" => Ok(Self::Quarantined),
            "Deleting" => Ok(Self::Deleting),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ConditionType {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ConditionType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ConditionType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`Desired`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetDesired",
///  "type": "object",
///  "required": [
///    "activeCommand",
///    "authorizationReceiptId",
///    "generation"
///  ],
///  "properties": {
///    "activeCommand": {
///      "oneOf": [
///        {
///          "type": "null"
///        },
///        {
///          "$ref": "#/definitions/activeCommand"
///        }
///      ]
///    },
///    "authorizationReceiptId": {
///      "$ref": "#/definitions/AuthorizationReceiptId",
///      "x-redaction": "internal"
///    },
///    "generation": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 1.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Desired {
    #[serde(rename = "activeCommand")]
    pub active_command: ::std::option::Option<ActiveCommand>,
    #[serde(rename = "authorizationReceiptId")]
    pub authorization_receipt_id: crate::AuthorizationReceiptId,
    pub generation: ::std::num::NonZeroU64,
}
///`IdentityDeviceCertificateStatusGetData`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetData",
///  "type": "object",
///  "required": [
///    "conditions",
///    "desired",
///    "observedGeneration"
///  ],
///  "properties": {
///    "conditions": {
///      "type": "array",
///      "items": {
///        "$ref": "#/definitions/condition"
///      }
///    },
///    "desired": {
///      "oneOf": [
///        {
///          "type": "null"
///        },
///        {
///          "$ref": "#/definitions/desired"
///        }
///      ]
///    },
///    "observedGeneration": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificateStatusGetData {
    pub conditions: ::std::vec::Vec<Condition>,
    pub desired: ::std::option::Option<Desired>,
    #[serde(rename = "observedGeneration")]
    pub observed_generation: i64,
}
///`IdentityDeviceCertificateStatusGetProviderUnavailableError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetProviderUnavailableError",
///  "type": "object",
///  "required": [
///    "code",
///    "details",
///    "message",
///    "requestId",
///    "retryable"
///  ],
///  "properties": {
///    "code": {
///      "type": "string",
///      "enum": [
///        "ERR_CORE_PROVIDER_UNAVAILABLE"
///      ]
///    },
///    "details": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "additionalProperties": {
///          "type": "string"
///        }
///      },
///      "maxItems": 0
///    },
///    "message": {
///      "type": "string",
///      "enum": [
///        "provider unavailable"
///      ]
///    },
///    "requestId": {
///      "type": "string"
///    },
///    "retryable": {
///      "type": "boolean",
///      "const": true
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificateStatusGetProviderUnavailableError {
    pub code: IdentityDeviceCertificateStatusGetProviderUnavailableErrorCode,
    pub details:
        ::std::vec::Vec<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub message: IdentityDeviceCertificateStatusGetProviderUnavailableErrorMessage,
    #[serde(rename = "requestId")]
    pub request_id: ::std::string::String,
    pub retryable: bool,
}
///`IdentityDeviceCertificateStatusGetProviderUnavailableErrorCode`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "ERR_CORE_PROVIDER_UNAVAILABLE"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificateStatusGetProviderUnavailableErrorCode {
    #[serde(rename = "ERR_CORE_PROVIDER_UNAVAILABLE")]
    ErrCoreProviderUnavailable,
}
impl ::std::fmt::Display for IdentityDeviceCertificateStatusGetProviderUnavailableErrorCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::ErrCoreProviderUnavailable => f.write_str("ERR_CORE_PROVIDER_UNAVAILABLE"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificateStatusGetProviderUnavailableErrorCode {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "ERR_CORE_PROVIDER_UNAVAILABLE" => Ok(Self::ErrCoreProviderUnavailable),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
    for IdentityDeviceCertificateStatusGetProviderUnavailableErrorCode
{
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificateStatusGetProviderUnavailableErrorCode
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificateStatusGetProviderUnavailableErrorCode
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificateStatusGetProviderUnavailableErrorMessage`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "provider unavailable"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificateStatusGetProviderUnavailableErrorMessage {
    #[serde(rename = "provider unavailable")]
    ProviderUnavailable,
}
impl ::std::fmt::Display for IdentityDeviceCertificateStatusGetProviderUnavailableErrorMessage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::ProviderUnavailable => f.write_str("provider unavailable"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificateStatusGetProviderUnavailableErrorMessage {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "provider unavailable" => Ok(Self::ProviderUnavailable),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
    for IdentityDeviceCertificateStatusGetProviderUnavailableErrorMessage
{
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificateStatusGetProviderUnavailableErrorMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificateStatusGetProviderUnavailableErrorMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificateStatusGetProviderUnavailableResponse`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetProviderUnavailableResponse",
///  "type": "object",
///  "required": [
///    "error"
///  ],
///  "properties": {
///    "error": {
///      "title": "IdentityDeviceCertificateStatusGetProviderUnavailableError",
///      "type": "object",
///      "required": [
///        "code",
///        "details",
///        "message",
///        "requestId",
///        "retryable"
///      ],
///      "properties": {
///        "code": {
///          "type": "string",
///          "enum": [
///            "ERR_CORE_PROVIDER_UNAVAILABLE"
///          ]
///        },
///        "details": {
///          "type": "array",
///          "items": {
///            "type": "object",
///            "additionalProperties": {
///              "type": "string"
///            }
///          },
///          "maxItems": 0
///        },
///        "message": {
///          "type": "string",
///          "enum": [
///            "provider unavailable"
///          ]
///        },
///        "requestId": {
///          "type": "string"
///        },
///        "retryable": {
///          "type": "boolean",
///          "const": true
///        }
///      },
///      "additionalProperties": false
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificateStatusGetProviderUnavailableResponse {
    pub error: IdentityDeviceCertificateStatusGetProviderUnavailableError,
}
///Tenant comes from authenticated scope and device identity comes from the HTTP path.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetRequest",
///  "description": "Tenant comes from authenticated scope and device identity comes from the HTTP path.",
///  "type": "object",
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificateStatusGetRequest {}
#[allow(clippy::derivable_impls)]
impl ::std::default::Default for IdentityDeviceCertificateStatusGetRequest {
    fn default() -> Self {
        Self {}
    }
}
///LocalOnly desired authorization lineage and reported certificate status.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetResponse",
///  "description": "LocalOnly desired authorization lineage and reported certificate status.",
///  "type": "object",
///  "required": [
///    "data"
///  ],
///  "properties": {
///    "data": {
///      "title": "IdentityDeviceCertificateStatusGetData",
///      "type": "object",
///      "required": [
///        "conditions",
///        "desired",
///        "observedGeneration"
///      ],
///      "properties": {
///        "conditions": {
///          "type": "array",
///          "items": {
///            "$ref": "#/definitions/condition"
///          }
///        },
///        "desired": {
///          "oneOf": [
///            {
///              "type": "null"
///            },
///            {
///              "$ref": "#/definitions/desired"
///            }
///          ]
///        },
///        "observedGeneration": {
///          "type": "integer",
///          "format": "int64",
///          "minimum": 0.0
///        }
///      },
///      "additionalProperties": false
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificateStatusGetResponse {
    pub data: IdentityDeviceCertificateStatusGetData,
}
///`IdentityDeviceCertificateStatusGetValidationDetail`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetValidationDetail",
///  "type": "object",
///  "required": [
///    "field",
///    "reason"
///  ],
///  "properties": {
///    "field": {
///      "type": "string",
///      "enum": [
///        "deviceId"
///      ]
///    },
///    "reason": {
///      "type": "string",
///      "enum": [
///        "invalidFormat"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificateStatusGetValidationDetail {
    pub field: IdentityDeviceCertificateStatusGetValidationDetailField,
    pub reason: IdentityDeviceCertificateStatusGetValidationDetailReason,
}
///`IdentityDeviceCertificateStatusGetValidationDetailField`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "deviceId"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificateStatusGetValidationDetailField {
    #[serde(rename = "deviceId")]
    DeviceId,
}
impl ::std::fmt::Display for IdentityDeviceCertificateStatusGetValidationDetailField {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::DeviceId => f.write_str("deviceId"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificateStatusGetValidationDetailField {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "deviceId" => Ok(Self::DeviceId),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificateStatusGetValidationDetailField {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificateStatusGetValidationDetailField
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificateStatusGetValidationDetailField
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificateStatusGetValidationDetailReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "invalidFormat"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificateStatusGetValidationDetailReason {
    #[serde(rename = "invalidFormat")]
    InvalidFormat,
}
impl ::std::fmt::Display for IdentityDeviceCertificateStatusGetValidationDetailReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::InvalidFormat => f.write_str("invalidFormat"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificateStatusGetValidationDetailReason {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "invalidFormat" => Ok(Self::InvalidFormat),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificateStatusGetValidationDetailReason {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificateStatusGetValidationDetailReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificateStatusGetValidationDetailReason
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificateStatusGetValidationError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetValidationError",
///  "type": "object",
///  "required": [
///    "code",
///    "details",
///    "message",
///    "requestId",
///    "retryable"
///  ],
///  "properties": {
///    "code": {
///      "type": "string",
///      "enum": [
///        "ERR_CORE_VALIDATION"
///      ]
///    },
///    "details": {
///      "type": "array",
///      "items": {
///        "title": "IdentityDeviceCertificateStatusGetValidationDetail",
///        "type": "object",
///        "required": [
///          "field",
///          "reason"
///        ],
///        "properties": {
///          "field": {
///            "type": "string",
///            "enum": [
///              "deviceId"
///            ]
///          },
///          "reason": {
///            "type": "string",
///            "enum": [
///              "invalidFormat"
///            ]
///          }
///        },
///        "additionalProperties": false
///      },
///      "maxItems": 1,
///      "minItems": 1
///    },
///    "message": {
///      "type": "string",
///      "enum": [
///        "validation failed"
///      ]
///    },
///    "requestId": {
///      "type": "string"
///    },
///    "retryable": {
///      "type": "boolean",
///      "const": false
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificateStatusGetValidationError {
    pub code: IdentityDeviceCertificateStatusGetValidationErrorCode,
    pub details: [IdentityDeviceCertificateStatusGetValidationDetail; 1usize],
    pub message: IdentityDeviceCertificateStatusGetValidationErrorMessage,
    #[serde(rename = "requestId")]
    pub request_id: ::std::string::String,
    pub retryable: bool,
}
///`IdentityDeviceCertificateStatusGetValidationErrorCode`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "ERR_CORE_VALIDATION"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificateStatusGetValidationErrorCode {
    #[serde(rename = "ERR_CORE_VALIDATION")]
    ErrCoreValidation,
}
impl ::std::fmt::Display for IdentityDeviceCertificateStatusGetValidationErrorCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::ErrCoreValidation => f.write_str("ERR_CORE_VALIDATION"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificateStatusGetValidationErrorCode {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "ERR_CORE_VALIDATION" => Ok(Self::ErrCoreValidation),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificateStatusGetValidationErrorCode {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificateStatusGetValidationErrorCode
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificateStatusGetValidationErrorCode
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificateStatusGetValidationErrorMessage`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "validation failed"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificateStatusGetValidationErrorMessage {
    #[serde(rename = "validation failed")]
    ValidationFailed,
}
impl ::std::fmt::Display for IdentityDeviceCertificateStatusGetValidationErrorMessage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::ValidationFailed => f.write_str("validation failed"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificateStatusGetValidationErrorMessage {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "validation failed" => Ok(Self::ValidationFailed),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificateStatusGetValidationErrorMessage {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificateStatusGetValidationErrorMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificateStatusGetValidationErrorMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificateStatusGetValidationResponse`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificateStatusGetValidationResponse",
///  "type": "object",
///  "required": [
///    "error"
///  ],
///  "properties": {
///    "error": {
///      "title": "IdentityDeviceCertificateStatusGetValidationError",
///      "type": "object",
///      "required": [
///        "code",
///        "details",
///        "message",
///        "requestId",
///        "retryable"
///      ],
///      "properties": {
///        "code": {
///          "type": "string",
///          "enum": [
///            "ERR_CORE_VALIDATION"
///          ]
///        },
///        "details": {
///          "type": "array",
///          "items": {
///            "title": "IdentityDeviceCertificateStatusGetValidationDetail",
///            "type": "object",
///            "required": [
///              "field",
///              "reason"
///            ],
///            "properties": {
///              "field": {
///                "type": "string",
///                "enum": [
///                  "deviceId"
///                ]
///              },
///              "reason": {
///                "type": "string",
///                "enum": [
///                  "invalidFormat"
///                ]
///              }
///            },
///            "additionalProperties": false
///          },
///          "maxItems": 1,
///          "minItems": 1
///        },
///        "message": {
///          "type": "string",
///          "enum": [
///            "validation failed"
///          ]
///        },
///        "requestId": {
///          "type": "string"
///        },
///        "retryable": {
///          "type": "boolean",
///          "const": false
///        }
///      },
///      "additionalProperties": false
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificateStatusGetValidationResponse {
    pub error: IdentityDeviceCertificateStatusGetValidationError,
}

/// Canonical contract identity and aggregate schema digest.
pub const DESCRIPTOR: ::rss_contract::ContractDescriptor =
    ::rss_contract::ContractDescriptor::from_static_version(
        "identity.device-certificate-status-get",
        "v2",
        "sha256:536b5d1d260537cac2c64942184c74e8bbfa15cc01b3267f4ffc4bca8961a8fd",
    );
/// Authority-free HTTP operation metadata generated from the canonical contract.
pub const OPERATION: crate::HttpOperationDescriptor = crate::HttpOperationDescriptor::new(
    DESCRIPTOR,
    crate::HttpMethod::Get,
    "/api/v2/identity/devices/{deviceId}/certificate-status",
);
/// Candidate lifecycle; this package does not activate the contract.
pub const LIFECYCLE: &str = "draft";
/// Exact authored schema artifacts embedded in this package.
pub const SCHEMAS: &[crate::SchemaArtifact] = &[
    crate::SchemaArtifact::new(
        "request",
        "sha256:e968d84eb3304fc5ca2727e44755b3bc94cd5d0d56dfcd11e6347ac34792c495",
        include_bytes!("../schema/status_get/request.schema.json"),
    ),
    crate::SchemaArtifact::new(
        "response:200",
        "sha256:5ea406c25fbc7505918e9506454ff04dc27699d723f7ac583367a046cc606d90",
        include_bytes!("../schema/status_get/response.schema.json"),
    ),
    crate::SchemaArtifact::new(
        "response:400",
        "sha256:477205c7302ebff12ca42dc67e612e08c8379ae250ca872522719bb2d1751c27",
        include_bytes!("../schema/status_get/validation.response.schema.json"),
    ),
    crate::SchemaArtifact::new(
        "response:503",
        "sha256:dd64323b8783edd2589e76ccb3b79efa7cfedc1dfb769591bf8f45b90b465bac",
        include_bytes!("../schema/status_get/provider-unavailable.response.schema.json"),
    ),
];
