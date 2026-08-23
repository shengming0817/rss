//! Generated from the canonical `identity.device-certificate-policy-put` Draft contract. Do not edit.

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
///`IdentityDeviceCertificatePolicyPutConflictError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutConflictError",
///  "oneOf": [
///    {
///      "title": "IdentityDeviceCertificatePolicyPutVersionConflictError",
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
///            "ERR_CORE_VERSION_CONFLICT"
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
///          "title": "IdentityDeviceCertificatePolicyPutVersionConflictMessage",
///          "type": "string",
///          "enum": [
///            "version conflict"
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
///    },
///    {
///      "title": "IdentityDeviceCertificatePolicyPutGeneralConflictError",
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
///            "ERR_CORE_CONFLICT"
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
///          "title": "IdentityDeviceCertificatePolicyPutGeneralConflictMessage",
///          "type": "string",
///          "enum": [
///            "conflict"
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
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(tag = "code", deny_unknown_fields)]
pub enum IdentityDeviceCertificatePolicyPutConflictError {
    ///IdentityDeviceCertificatePolicyPutVersionConflictError
    #[serde(rename = "ERR_CORE_VERSION_CONFLICT")]
    ErrCoreVersionConflict {
        details: ::std::vec::Vec<
            ::std::collections::HashMap<::std::string::String, ::std::string::String>,
        >,
        message: IdentityDeviceCertificatePolicyPutVersionConflictMessage,
        #[serde(rename = "requestId")]
        request_id: ::std::string::String,
        retryable: bool,
    },
    ///IdentityDeviceCertificatePolicyPutGeneralConflictError
    #[serde(rename = "ERR_CORE_CONFLICT")]
    ErrCoreConflict {
        details: ::std::vec::Vec<
            ::std::collections::HashMap<::std::string::String, ::std::string::String>,
        >,
        message: IdentityDeviceCertificatePolicyPutGeneralConflictMessage,
        #[serde(rename = "requestId")]
        request_id: ::std::string::String,
        retryable: bool,
    },
}
///A generation mismatch or idempotency-key fingerprint mismatch rejects the write.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutConflictResponse",
///  "description": "A generation mismatch or idempotency-key fingerprint mismatch rejects the write.",
///  "type": "object",
///  "required": [
///    "error"
///  ],
///  "properties": {
///    "error": {
///      "title": "IdentityDeviceCertificatePolicyPutConflictError",
///      "oneOf": [
///        {
///          "title": "IdentityDeviceCertificatePolicyPutVersionConflictError",
///          "type": "object",
///          "required": [
///            "code",
///            "details",
///            "message",
///            "requestId",
///            "retryable"
///          ],
///          "properties": {
///            "code": {
///              "type": "string",
///              "enum": [
///                "ERR_CORE_VERSION_CONFLICT"
///              ]
///            },
///            "details": {
///              "type": "array",
///              "items": {
///                "type": "object",
///                "additionalProperties": {
///                  "type": "string"
///                }
///              },
///              "maxItems": 0
///            },
///            "message": {
///              "title": "IdentityDeviceCertificatePolicyPutVersionConflictMessage",
///              "type": "string",
///              "enum": [
///                "version conflict"
///              ]
///            },
///            "requestId": {
///              "type": "string"
///            },
///            "retryable": {
///              "type": "boolean",
///              "const": true
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "title": "IdentityDeviceCertificatePolicyPutGeneralConflictError",
///          "type": "object",
///          "required": [
///            "code",
///            "details",
///            "message",
///            "requestId",
///            "retryable"
///          ],
///          "properties": {
///            "code": {
///              "type": "string",
///              "enum": [
///                "ERR_CORE_CONFLICT"
///              ]
///            },
///            "details": {
///              "type": "array",
///              "items": {
///                "type": "object",
///                "additionalProperties": {
///                  "type": "string"
///                }
///              },
///              "maxItems": 0
///            },
///            "message": {
///              "title": "IdentityDeviceCertificatePolicyPutGeneralConflictMessage",
///              "type": "string",
///              "enum": [
///                "conflict"
///              ]
///            },
///            "requestId": {
///              "type": "string"
///            },
///            "retryable": {
///              "type": "boolean",
///              "const": false
///            }
///          },
///          "additionalProperties": false
///        }
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificatePolicyPutConflictResponse {
    pub error: IdentityDeviceCertificatePolicyPutConflictError,
}
///`IdentityDeviceCertificatePolicyPutData`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutData",
///  "type": "object",
///  "required": [
///    "acceptedGeneration",
///    "authorizationReceiptId",
///    "condition"
///  ],
///  "properties": {
///    "acceptedGeneration": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 1.0
///    },
///    "authorizationReceiptId": {
///      "$ref": "#/definitions/AuthorizationReceiptId",
///      "x-redaction": "internal"
///    },
///    "condition": {
///      "type": "string",
///      "enum": [
///        "Reconciling",
///        "PendingDevice"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificatePolicyPutData {
    #[serde(rename = "acceptedGeneration")]
    pub accepted_generation: ::std::num::NonZeroU64,
    #[serde(rename = "authorizationReceiptId")]
    pub authorization_receipt_id: crate::AuthorizationReceiptId,
    pub condition: IdentityDeviceCertificatePolicyPutDataCondition,
}
///`IdentityDeviceCertificatePolicyPutDataCondition`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "Reconciling",
///    "PendingDevice"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificatePolicyPutDataCondition {
    Reconciling,
    PendingDevice,
}
impl ::std::fmt::Display for IdentityDeviceCertificatePolicyPutDataCondition {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Reconciling => f.write_str("Reconciling"),
            Self::PendingDevice => f.write_str("PendingDevice"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificatePolicyPutDataCondition {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "Reconciling" => Ok(Self::Reconciling),
            "PendingDevice" => Ok(Self::PendingDevice),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificatePolicyPutDataCondition {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificatePolicyPutDataCondition
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificatePolicyPutDataCondition
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificatePolicyPutGeneralConflictMessage`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutGeneralConflictMessage",
///  "type": "string",
///  "enum": [
///    "conflict"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificatePolicyPutGeneralConflictMessage {
    #[serde(rename = "conflict")]
    Conflict,
}
impl ::std::fmt::Display for IdentityDeviceCertificatePolicyPutGeneralConflictMessage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Conflict => f.write_str("conflict"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificatePolicyPutGeneralConflictMessage {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "conflict" => Ok(Self::Conflict),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificatePolicyPutGeneralConflictMessage {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificatePolicyPutGeneralConflictMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificatePolicyPutGeneralConflictMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificatePolicyPutNotFoundError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutNotFoundError",
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
///        "ERR_CORE_NOT_FOUND"
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
///        "not found"
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
pub struct IdentityDeviceCertificatePolicyPutNotFoundError {
    pub code: IdentityDeviceCertificatePolicyPutNotFoundErrorCode,
    pub details:
        ::std::vec::Vec<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub message: IdentityDeviceCertificatePolicyPutNotFoundErrorMessage,
    #[serde(rename = "requestId")]
    pub request_id: ::std::string::String,
    pub retryable: bool,
}
///`IdentityDeviceCertificatePolicyPutNotFoundErrorCode`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "ERR_CORE_NOT_FOUND"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificatePolicyPutNotFoundErrorCode {
    #[serde(rename = "ERR_CORE_NOT_FOUND")]
    ErrCoreNotFound,
}
impl ::std::fmt::Display for IdentityDeviceCertificatePolicyPutNotFoundErrorCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::ErrCoreNotFound => f.write_str("ERR_CORE_NOT_FOUND"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificatePolicyPutNotFoundErrorCode {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "ERR_CORE_NOT_FOUND" => Ok(Self::ErrCoreNotFound),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificatePolicyPutNotFoundErrorCode {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificatePolicyPutNotFoundErrorCode
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificatePolicyPutNotFoundErrorCode
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificatePolicyPutNotFoundErrorMessage`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "not found"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificatePolicyPutNotFoundErrorMessage {
    #[serde(rename = "not found")]
    NotFound,
}
impl ::std::fmt::Display for IdentityDeviceCertificatePolicyPutNotFoundErrorMessage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::NotFound => f.write_str("not found"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificatePolicyPutNotFoundErrorMessage {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "not found" => Ok(Self::NotFound),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificatePolicyPutNotFoundErrorMessage {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificatePolicyPutNotFoundErrorMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificatePolicyPutNotFoundErrorMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///A hidden or absent device uses the same public response surface.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutNotFoundResponse",
///  "description": "A hidden or absent device uses the same public response surface.",
///  "type": "object",
///  "required": [
///    "error"
///  ],
///  "properties": {
///    "error": {
///      "title": "IdentityDeviceCertificatePolicyPutNotFoundError",
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
///            "ERR_CORE_NOT_FOUND"
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
///            "not found"
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
pub struct IdentityDeviceCertificatePolicyPutNotFoundResponse {
    pub error: IdentityDeviceCertificatePolicyPutNotFoundError,
}
///`IdentityDeviceCertificatePolicyPutPolicy`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutPolicy",
///  "type": "object",
///  "required": [
///    "keyUsages",
///    "renewBeforeSeconds",
///    "validitySeconds"
///  ],
///  "properties": {
///    "keyUsages": {
///      "type": "array",
///      "items": {
///        "type": "string",
///        "enum": [
///          "clientAuth",
///          "serverAuth"
///        ]
///      },
///      "minItems": 1,
///      "uniqueItems": true,
///      "x-redaction": "internal"
///    },
///    "renewBeforeSeconds": {
///      "type": "integer",
///      "format": "int64",
///      "maximum": 31535999.0,
///      "minimum": 60.0
///    },
///    "sans": {
///      "type": "array",
///      "items": {
///        "type": "string",
///        "maxLength": 253,
///        "minLength": 1
///      },
///      "maxItems": 32,
///      "uniqueItems": true,
///      "x-pii": "generic",
///      "x-redaction": "drop"
///    },
///    "validitySeconds": {
///      "type": "integer",
///      "format": "int64",
///      "maximum": 31536000.0,
///      "minimum": 300.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificatePolicyPutPolicy {
    #[serde(rename = "keyUsages")]
    key_usages: Vec<IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem>,
    #[serde(rename = "renewBeforeSeconds")]
    renew_before_seconds: i64,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    sans: ::std::option::Option<Vec<IdentityDeviceCertificatePolicyPutPolicySansItem>>,
    #[serde(rename = "validitySeconds")]
    validity_seconds: i64,
}
///`IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "clientAuth",
///    "serverAuth"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem {
    #[serde(rename = "clientAuth")]
    ClientAuth,
    #[serde(rename = "serverAuth")]
    ServerAuth,
}
impl ::std::fmt::Display for IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::ClientAuth => f.write_str("clientAuth"),
            Self::ServerAuth => f.write_str("serverAuth"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "clientAuth" => Ok(Self::ClientAuth),
            "serverAuth" => Ok(Self::ServerAuth),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificatePolicyPutPolicySansItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "maxLength": 253,
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct IdentityDeviceCertificatePolicyPutPolicySansItem(::std::string::String);
impl ::std::ops::Deref for IdentityDeviceCertificatePolicyPutPolicySansItem {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<IdentityDeviceCertificatePolicyPutPolicySansItem>
    for ::std::string::String
{
    fn from(value: IdentityDeviceCertificatePolicyPutPolicySansItem) -> Self {
        value.0
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificatePolicyPutPolicySansItem {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() > 253usize {
            return Err("longer than 253 characters".into());
        }
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificatePolicyPutPolicySansItem {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificatePolicyPutPolicySansItem
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificatePolicyPutPolicySansItem
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for IdentityDeviceCertificatePolicyPutPolicySansItem {
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
///Tenant comes from authenticated scope and device identity comes from the HTTP path.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutRequest",
///  "description": "Tenant comes from authenticated scope and device identity comes from the HTTP path.",
///  "type": "object",
///  "required": [
///    "expectedGeneration",
///    "idempotencyKey",
///    "policy"
///  ],
///  "properties": {
///    "expectedGeneration": {
///      "type": "integer",
///      "format": "int64",
///      "minimum": 0.0
///    },
///    "idempotencyKey": {
///      "description": "UUID scoped to the authenticated tenant and path device. Reuse is valid only for the same canonical request.",
///      "type": "string",
///      "format": "uuid",
///      "x-redaction": "internal"
///    },
///    "policy": {
///      "title": "IdentityDeviceCertificatePolicyPutPolicy",
///      "type": "object",
///      "required": [
///        "keyUsages",
///        "renewBeforeSeconds",
///        "validitySeconds"
///      ],
///      "properties": {
///        "keyUsages": {
///          "type": "array",
///          "items": {
///            "type": "string",
///            "enum": [
///              "clientAuth",
///              "serverAuth"
///            ]
///          },
///          "minItems": 1,
///          "uniqueItems": true,
///          "x-redaction": "internal"
///        },
///        "renewBeforeSeconds": {
///          "type": "integer",
///          "format": "int64",
///          "maximum": 31535999.0,
///          "minimum": 60.0
///        },
///        "sans": {
///          "type": "array",
///          "items": {
///            "type": "string",
///            "maxLength": 253,
///            "minLength": 1
///          },
///          "maxItems": 32,
///          "uniqueItems": true,
///          "x-pii": "generic",
///          "x-redaction": "drop"
///        },
///        "validitySeconds": {
///          "type": "integer",
///          "format": "int64",
///          "maximum": 31536000.0,
///          "minimum": 300.0
///        }
///      },
///      "additionalProperties": false
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeviceCertificatePolicyPutRequest {
    #[serde(rename = "expectedGeneration")]
    expected_generation: i64,
    ///UUID scoped to the authenticated tenant and path device. Reuse is valid only for the same canonical request.
    #[serde(rename = "idempotencyKey")]
    idempotency_key: ::uuid::Uuid,
    policy: IdentityDeviceCertificatePolicyPutPolicy,
}
///A 200 response records desired state but does not claim device convergence; an identical idempotency replay returns the same data value.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutResponse",
///  "description": "A 200 response records desired state but does not claim device convergence; an identical idempotency replay returns the same data value.",
///  "type": "object",
///  "required": [
///    "data"
///  ],
///  "properties": {
///    "data": {
///      "title": "IdentityDeviceCertificatePolicyPutData",
///      "type": "object",
///      "required": [
///        "acceptedGeneration",
///        "authorizationReceiptId",
///        "condition"
///      ],
///      "properties": {
///        "acceptedGeneration": {
///          "type": "integer",
///          "format": "int64",
///          "minimum": 1.0
///        },
///        "authorizationReceiptId": {
///          "$ref": "#/definitions/AuthorizationReceiptId",
///          "x-redaction": "internal"
///        },
///        "condition": {
///          "type": "string",
///          "enum": [
///            "Reconciling",
///            "PendingDevice"
///          ]
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
pub struct IdentityDeviceCertificatePolicyPutResponse {
    pub data: IdentityDeviceCertificatePolicyPutData,
}
///`IdentityDeviceCertificatePolicyPutValidationError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutValidationError",
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
pub struct IdentityDeviceCertificatePolicyPutValidationError {
    pub code: IdentityDeviceCertificatePolicyPutValidationErrorCode,
    pub details:
        ::std::vec::Vec<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub message: IdentityDeviceCertificatePolicyPutValidationErrorMessage,
    #[serde(rename = "requestId")]
    pub request_id: ::std::string::String,
    pub retryable: bool,
}
///`IdentityDeviceCertificatePolicyPutValidationErrorCode`
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
pub enum IdentityDeviceCertificatePolicyPutValidationErrorCode {
    #[serde(rename = "ERR_CORE_VALIDATION")]
    ErrCoreValidation,
}
impl ::std::fmt::Display for IdentityDeviceCertificatePolicyPutValidationErrorCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::ErrCoreValidation => f.write_str("ERR_CORE_VALIDATION"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificatePolicyPutValidationErrorCode {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "ERR_CORE_VALIDATION" => Ok(Self::ErrCoreValidation),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificatePolicyPutValidationErrorCode {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificatePolicyPutValidationErrorCode
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificatePolicyPutValidationErrorCode
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`IdentityDeviceCertificatePolicyPutValidationErrorMessage`
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
pub enum IdentityDeviceCertificatePolicyPutValidationErrorMessage {
    #[serde(rename = "validation failed")]
    ValidationFailed,
}
impl ::std::fmt::Display for IdentityDeviceCertificatePolicyPutValidationErrorMessage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::ValidationFailed => f.write_str("validation failed"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificatePolicyPutValidationErrorMessage {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "validation failed" => Ok(Self::ValidationFailed),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificatePolicyPutValidationErrorMessage {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificatePolicyPutValidationErrorMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificatePolicyPutValidationErrorMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///A semantically invalid desired policy is rejected before persistence.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutValidationResponse",
///  "description": "A semantically invalid desired policy is rejected before persistence.",
///  "type": "object",
///  "required": [
///    "error"
///  ],
///  "properties": {
///    "error": {
///      "title": "IdentityDeviceCertificatePolicyPutValidationError",
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
pub struct IdentityDeviceCertificatePolicyPutValidationResponse {
    pub error: IdentityDeviceCertificatePolicyPutValidationError,
}
///`IdentityDeviceCertificatePolicyPutVersionConflictMessage`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "IdentityDeviceCertificatePolicyPutVersionConflictMessage",
///  "type": "string",
///  "enum": [
///    "version conflict"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize, ::serde::Serialize, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum IdentityDeviceCertificatePolicyPutVersionConflictMessage {
    #[serde(rename = "version conflict")]
    VersionConflict,
}
impl ::std::fmt::Display for IdentityDeviceCertificatePolicyPutVersionConflictMessage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::VersionConflict => f.write_str("version conflict"),
        }
    }
}
impl ::std::str::FromStr for IdentityDeviceCertificatePolicyPutVersionConflictMessage {
    type Err = self::error::ConversionError;
    fn from_str(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "version conflict" => Ok(Self::VersionConflict),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for IdentityDeviceCertificatePolicyPutVersionConflictMessage {
    type Error = self::error::ConversionError;
    fn try_from(value: &str) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
    for IdentityDeviceCertificatePolicyPutVersionConflictMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
    for IdentityDeviceCertificatePolicyPutVersionConflictMessage
{
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}

/// Stable, payload-free policy constraint violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyConstraintError;

impl ::std::fmt::Display for PolicyConstraintError {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        formatter.write_str("device certificate policy violates schema constraints")
    }
}

impl ::std::error::Error for PolicyConstraintError {}

impl IdentityDeviceCertificatePolicyPutPolicy {
    pub fn try_new(
        key_usages: Vec<IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem>,
        renew_before_seconds: i64,
        sans: Option<Vec<IdentityDeviceCertificatePolicyPutPolicySansItem>>,
        validity_seconds: i64,
    ) -> Result<Self, PolicyConstraintError> {
        if !(300..=31_536_000).contains(&validity_seconds)
            || !(60..=31_535_999).contains(&renew_before_seconds)
            || renew_before_seconds >= validity_seconds
            || key_usages.is_empty()
            || key_usages
                .iter()
                .collect::<::std::collections::BTreeSet<_>>()
                .len()
                != key_usages.len()
            || sans.as_ref().is_some_and(|sans| {
                sans.len() > 32
                    || sans
                        .iter()
                        .collect::<::std::collections::BTreeSet<_>>()
                        .len()
                        != sans.len()
            })
        {
            return Err(PolicyConstraintError);
        }
        Ok(Self {
            key_usages,
            renew_before_seconds,
            sans,
            validity_seconds,
        })
    }

    pub fn key_usages(&self) -> &[IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem] {
        &self.key_usages
    }
    pub const fn renew_before_seconds(&self) -> i64 {
        self.renew_before_seconds
    }
    pub fn sans(&self) -> Option<&[IdentityDeviceCertificatePolicyPutPolicySansItem]> {
        self.sans.as_deref()
    }
    pub const fn validity_seconds(&self) -> i64 {
        self.validity_seconds
    }
}

#[derive(::serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityDeviceCertificatePolicyPutPolicyWire {
    #[serde(rename = "keyUsages")]
    key_usages: Vec<IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem>,
    #[serde(rename = "renewBeforeSeconds")]
    renew_before_seconds: i64,
    #[serde(default)]
    sans: Option<Vec<IdentityDeviceCertificatePolicyPutPolicySansItem>>,
    #[serde(rename = "validitySeconds")]
    validity_seconds: i64,
}

impl<'de> ::serde::Deserialize<'de> for IdentityDeviceCertificatePolicyPutPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        let wire =
            <IdentityDeviceCertificatePolicyPutPolicyWire as ::serde::Deserialize>::deserialize(
                deserializer,
            )?;
        Self::try_new(
            wire.key_usages,
            wire.renew_before_seconds,
            wire.sans,
            wire.validity_seconds,
        )
        .map_err(<D::Error as ::serde::de::Error>::custom)
    }
}

#[derive(::serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityDeviceCertificatePolicyPutRequestWire {
    #[serde(rename = "expectedGeneration")]
    expected_generation: i64,
    #[serde(rename = "idempotencyKey")]
    idempotency_key: ::uuid::Uuid,
    policy: IdentityDeviceCertificatePolicyPutPolicy,
}

impl<'de> ::serde::Deserialize<'de> for IdentityDeviceCertificatePolicyPutRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        let wire =
            <IdentityDeviceCertificatePolicyPutRequestWire as ::serde::Deserialize>::deserialize(
                deserializer,
            )?;
        Self::try_new(wire.expected_generation, wire.idempotency_key, wire.policy)
            .map_err(<D::Error as ::serde::de::Error>::custom)
    }
}

impl IdentityDeviceCertificatePolicyPutRequest {
    pub fn try_new(
        expected_generation: i64,
        idempotency_key: ::uuid::Uuid,
        policy: IdentityDeviceCertificatePolicyPutPolicy,
    ) -> Result<Self, PolicyConstraintError> {
        if expected_generation < 0 {
            return Err(PolicyConstraintError);
        }
        Ok(Self {
            expected_generation,
            idempotency_key,
            policy,
        })
    }
    pub const fn expected_generation(&self) -> i64 {
        self.expected_generation
    }
    pub const fn idempotency_key(&self) -> ::uuid::Uuid {
        self.idempotency_key
    }
    pub const fn policy(&self) -> &IdentityDeviceCertificatePolicyPutPolicy {
        &self.policy
    }
}

/// Canonical contract identity and aggregate schema digest.
pub const DESCRIPTOR: ::rss_contract::ContractDescriptor =
    ::rss_contract::ContractDescriptor::from_static_version(
        "identity.device-certificate-policy-put",
        "v2",
        "sha256:88a5d5145b14ae984c27edae2ad468e9aa6cd29ad955fe0771d7f9eabe5d7084",
    );
/// Candidate lifecycle; this package does not activate the contract.
pub const LIFECYCLE: &str = "draft";
/// Exact authored schema artifacts embedded in this package.
pub const SCHEMAS: &[crate::SchemaArtifact] = &[
    crate::SchemaArtifact::new(
        "request",
        "sha256:08a4167b834bb607e9a8d1ddca8d9930ab2b74bf311a560c47215f7019ba2b16",
        include_bytes!("../schema/policy_put/request.schema.json"),
    ),
    crate::SchemaArtifact::new(
        "response:200",
        "sha256:8bca19a4329ef4b4be8ea304c1b303a73be27ebcc42b48c2021f3ff36baff609",
        include_bytes!("../schema/policy_put/response.schema.json"),
    ),
    crate::SchemaArtifact::new(
        "response:400",
        "sha256:6cba221b2769c329c076284832191b0fe9af2a8a89408c64442f299afaa593de",
        include_bytes!("../schema/policy_put/validation.response.schema.json"),
    ),
    crate::SchemaArtifact::new(
        "response:404",
        "sha256:52a92e7586202064a7e60f5aa3c8fbd8caa9d7f9b402ef0d00eebd6fb69b1994",
        include_bytes!("../schema/policy_put/not-found.response.schema.json"),
    ),
    crate::SchemaArtifact::new(
        "response:409",
        "sha256:fa2788866d968ceb9fe67471239c3a9f48321912dec44499f59f40b1b898ffd5",
        include_bytes!("../schema/policy_put/conflict.response.schema.json"),
    ),
];
