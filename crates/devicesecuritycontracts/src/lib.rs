#![doc = include_str!("../README.md")]

/// Opaque, authority-free correlation identity for one durable authorization decision.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationReceiptId(::uuid::Uuid);

/// Stable, payload-free error returned for malformed or nil receipt identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationReceiptIdError;

impl ::std::fmt::Display for AuthorizationReceiptIdError {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        formatter.write_str("invalid authorization receipt id")
    }
}

impl ::std::error::Error for AuthorizationReceiptIdError {}

impl AuthorizationReceiptId {
    /// Restore a non-nil correlation identity at a trusted boundary.
    pub fn try_from_uuid(value: ::uuid::Uuid) -> Result<Self, AuthorizationReceiptIdError> {
        (!value.is_nil())
            .then_some(Self(value))
            .ok_or(AuthorizationReceiptIdError)
    }

    /// Return the opaque UUID value. This value is not an authorization capability.
    #[must_use]
    pub const fn as_uuid(self) -> ::uuid::Uuid {
        self.0
    }
}

impl ::std::fmt::Debug for AuthorizationReceiptId {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        formatter.write_str("AuthorizationReceiptId(<redacted>)")
    }
}

impl ::std::str::FromStr for AuthorizationReceiptId {
    type Err = AuthorizationReceiptIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = ::uuid::Uuid::parse_str(value).map_err(|_| AuthorizationReceiptIdError)?;
        Self::try_from_uuid(value)
    }
}

impl ::std::convert::TryFrom<::uuid::Uuid> for AuthorizationReceiptId {
    type Error = AuthorizationReceiptIdError;

    fn try_from(value: ::uuid::Uuid) -> Result<Self, Self::Error> {
        Self::try_from_uuid(value)
    }
}

impl ::serde::Serialize for AuthorizationReceiptId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        <::uuid::Uuid as ::serde::Serialize>::serialize(&self.0, serializer)
    }
}

impl<'de> ::serde::Deserialize<'de> for AuthorizationReceiptId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        let value = <::uuid::Uuid as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_from_uuid(value).map_err(<D::Error as ::serde::de::Error>::custom)
    }
}

/// One standalone resolved JSON Schema artifact embedded in the candidate package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaArtifact {
    role: &'static str,
    digest: &'static str,
    json: &'static [u8],
}

impl SchemaArtifact {
    pub(crate) const fn new(role: &'static str, digest: &'static str, json: &'static [u8]) -> Self {
        Self { role, digest, json }
    }

    /// Manifest schema role such as `request`, `response`, or `payload`.
    #[must_use]
    pub const fn role(self) -> &'static str {
        self.role
    }
    /// SHA-256 digest of the exact authored schema bytes.
    #[must_use]
    pub const fn digest(self) -> &'static str {
        self.digest
    }
    /// Standalone resolved JSON Schema bytes.
    #[must_use]
    pub const fn json(self) -> &'static [u8] {
        self.json
    }
}

pub mod apply_device_certificate;
pub mod device_certificate_reported;
pub mod device_command_acked;
pub mod device_ingress_receipted;
pub mod policy_put;
pub mod status_get;
