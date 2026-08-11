//! Device-certificate draft activation candidates generated from the canonical contract set.
//!
//! This registry is governance metadata only. Draft candidates are deliberately excluded from
//! active HTTP/event registries, L2 assurance, runtime wiring, and production artifacts.

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
