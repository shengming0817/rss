//! Device-certificate draft activation candidates generated from the canonical contract set.
//!
//! This registry is governance metadata only. Draft candidates are deliberately excluded from
//! active HTTP/event registries, L2 assurance, runtime wiring, and production artifacts.

/// A non-nil, opaque authorization correlation identity shared by the generated Draft carriers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ::secure::Redact)]
pub struct AuthorizationReceiptId(#[redact(sensitivity = internal)] ::uuid::Uuid);

/// A generated authorization receipt identity was nil or malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationReceiptIdError;

impl ::std::fmt::Display for AuthorizationReceiptIdError {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        formatter.write_str("authorization receipt identity is invalid")
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

    /// Return the opaque UUID value. It is not an authorization capability.
    pub const fn as_uuid(self) -> ::uuid::Uuid {
        self.0
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Typed governance metadata for one device-certificate Draft candidate.
pub struct DeviceCertificateCandidateSpec {
    binding: ::vocab::ContractBinding,
    kind: ::assembly_schema::contract_manifest::ContractKind,
    consistency_level: ::assembly_schema::contract_manifest::ConsistencyLevel,
    lifecycle: ::assembly_schema::contract_manifest::Lifecycle,
}

impl DeviceCertificateCandidateSpec {
    const fn new(
        binding: ::vocab::ContractBinding,
        kind: ::assembly_schema::contract_manifest::ContractKind,
        consistency_level: ::assembly_schema::contract_manifest::ConsistencyLevel,
        lifecycle: ::assembly_schema::contract_manifest::Lifecycle,
    ) -> Self {
        Self {
            binding,
            kind,
            consistency_level,
            lifecycle,
        }
    }

    /// Return the canonical contract binding.
    pub const fn binding(self) -> ::vocab::ContractBinding {
        self.binding
    }
    /// Return the governed contract kind.
    pub const fn kind(self) -> ::assembly_schema::contract_manifest::ContractKind {
        self.kind
    }
    /// Return the governed consistency level.
    pub const fn consistency_level(self) -> ::assembly_schema::contract_manifest::ConsistencyLevel {
        self.consistency_level
    }
    /// Return the governed lifecycle.
    pub const fn lifecycle(self) -> ::assembly_schema::contract_manifest::Lifecycle {
        self.lifecycle
    }
}

/// Exact generated projection of the six device-certificate Draft candidates.
pub const CANDIDATE_CONTRACTS: &[DeviceCertificateCandidateSpec] = &[
    DeviceCertificateCandidateSpec::new(
        crate::http::identity_v2::device_certificate_policy_put::CONTRACT,
        ::assembly_schema::contract_manifest::ContractKind::Http,
        ::assembly_schema::contract_manifest::ConsistencyLevel::DeviceLatent,
        ::assembly_schema::contract_manifest::Lifecycle::Draft,
    ),
    DeviceCertificateCandidateSpec::new(
        crate::http::identity_v2::device_certificate_status_get::CONTRACT,
        ::assembly_schema::contract_manifest::ContractKind::Http,
        ::assembly_schema::contract_manifest::ConsistencyLevel::LocalOnly,
        ::assembly_schema::contract_manifest::Lifecycle::Draft,
    ),
    DeviceCertificateCandidateSpec::new(
        crate::command::identity_v1::CONTRACT,
        ::assembly_schema::contract_manifest::ContractKind::Command,
        ::assembly_schema::contract_manifest::ConsistencyLevel::OutboxFact,
        ::assembly_schema::contract_manifest::Lifecycle::Draft,
    ),
    DeviceCertificateCandidateSpec::new(
        crate::event::identity_v1::device_command_acked::CONTRACT,
        ::assembly_schema::contract_manifest::ContractKind::Event,
        ::assembly_schema::contract_manifest::ConsistencyLevel::OutboxFact,
        ::assembly_schema::contract_manifest::Lifecycle::Draft,
    ),
    DeviceCertificateCandidateSpec::new(
        crate::event::identity_v1::device_certificate_reported::CONTRACT,
        ::assembly_schema::contract_manifest::ContractKind::Event,
        ::assembly_schema::contract_manifest::ConsistencyLevel::OutboxFact,
        ::assembly_schema::contract_manifest::Lifecycle::Draft,
    ),
    DeviceCertificateCandidateSpec::new(
        crate::event::identity_v1::device_ingress_receipted::CONTRACT,
        ::assembly_schema::contract_manifest::ContractKind::Event,
        ::assembly_schema::contract_manifest::ConsistencyLevel::OutboxFact,
        ::assembly_schema::contract_manifest::Lifecycle::Draft,
    ),
];
