//! Validated certificate artifact bindings for the DeviceLatent reconcile loop.
//!
//! Provider material enters as [`ProviderCertificateCandidate`]. Only the binding funnel in this
//! module can turn it into an [`AuthorizedCertificateArtifact`]; production eligibility remains an
//! unforgeable capability. The formal production mint additionally consumes separately sealed
//! assembly-wide provider closure and per-command verified evidence values whose provider/config
//! identities match.
//!
//! ref: instant-labs/instant-acme src/order.rs@8e4441f

use std::fmt;

use diport::{CertNotAfter, CertScope, CertSerial};
use sha2::{Digest, Sha256};

use crate::device_certificate::{
    ArtifactDigest, DeviceCertificateScope, DevicePolicyAuthorizationReceiptId, ExpectedGeneration,
    PolicyHash, ReportedStateHash,
};
use deviceloop::CertificatePolicy;

const MAX_ARTIFACT_ID_BYTES: usize = 256;
const MIN_ARTIFACT_ID_BYTES: usize = 16;

/// A candidate or expected binding supplied a malformed value or disagreed with another binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertificateArtifactError {
    /// Artifact identity was padded, outside 16..=256 UTF-8 octets, or contained control characters.
    #[error("certificate artifact id is invalid")]
    InvalidArtifactId,
    /// Provider output was not bound to the complete authorized request.
    #[error("certificate artifact binding mismatch")]
    BindingMismatch,
    /// The production artifact authority was temporarily unavailable.
    #[error("certificate artifact authority is unavailable")]
    Unavailable,
    /// The provider may have completed signing, so retrying could mint an untracked certificate.
    #[error("certificate artifact outcome is unknown")]
    OutcomeUnknown,
    /// The provider permanently rejected the caller or requested certificate policy.
    #[error("certificate artifact authority rejected the request")]
    Rejected,
    /// The selected production provider configuration is invalid.
    #[error("certificate artifact authority is misconfigured")]
    Misconfigured,
}

/// Stable provider artifact identity. The value is metadata, but Debug stays redacted so provider
/// naming conventions cannot accidentally become log data.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CertificateArtifactId(String);

impl fmt::Debug for CertificateArtifactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CertificateArtifactId(<redacted>)")
    }
}

impl CertificateArtifactId {
    /// Parse one bounded, canonical provider artifact identity.
    pub fn parse(raw: &str) -> Result<Self, CertificateArtifactError> {
        if raw.len() < MIN_ARTIFACT_ID_BYTES
            || raw.trim() != raw
            || raw.len() > MAX_ARTIFACT_ID_BYTES
            || raw.chars().any(char::is_control)
        {
            return Err(CertificateArtifactError::InvalidArtifactId);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Borrow the exact persistence value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! artifact_digest_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<sha256>)"))
            }
        }

        impl $name {
            /// Derive the exact SHA-256 binding from canonical public bytes.
            #[must_use]
            pub fn digest(bytes: &[u8]) -> Self {
                Self(Sha256::digest(bytes).into())
            }

            /// Restore the exact persistence representation.
            pub fn restore(bytes: &[u8]) -> Result<Self, CertificateArtifactError> {
                let value: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| CertificateArtifactError::BindingMismatch)?;
                Ok(Self(value))
            }

            /// Borrow the exact persistence representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

artifact_digest_type!(
    /// Digest of the public key expected to be certified.
    CertificatePublicKeyDigest
);

/// Draft eligibility. It is intentionally a distinct type from production eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftEligibility {}

/// Production eligibility. No public or non-test constructor exists; ADR-028 assigns any future
/// private mint and verified assembly-wide provider closure to an independently scoped candidate
/// integration rather than the superseded #1910 activation route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionEligibility {}

mod sealed {
    pub trait Sealed {}
}

/// Closed static eligibility carried from artifact acquisition through persistence and command
/// installation. External crates may name the marker selected by their provider, but cannot add a
/// third eligibility class or construct either marker as a runtime value.
pub trait ArtifactEligibility:
    sealed::Sealed + fmt::Debug + Clone + Copy + PartialEq + Eq + Send + Sync + 'static
{
    /// Exact durable label used by PostgreSQL's two hard-coded append entry points.
    #[doc(hidden)]
    const PERSISTENCE_LABEL: &'static str;
}

impl sealed::Sealed for DraftEligibility {}
impl ArtifactEligibility for DraftEligibility {
    const PERSISTENCE_LABEL: &'static str = "draft";
}

impl sealed::Sealed for ProductionEligibility {}
impl ArtifactEligibility for ProductionEligibility {
    const PERSISTENCE_LABEL: &'static str = "production";
}

/// Public certificate coordinates selected by one provider attempt.
///
/// Keeping these coordinates in one named value prevents positional projection drift without
/// granting authorization: the receipt-bound [`CertificateArtifactBinding`] is minted separately
/// from a sealed desired-state acquisition or restored persistence lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateArtifactMaterial {
    public_key_digest: CertificatePublicKeyDigest,
    artifact_digest: ArtifactDigest,
    expected_reported_state_hash: ReportedStateHash,
    artifact_id: CertificateArtifactId,
    cert_scope: CertScope,
    serial: CertSerial,
    not_after: CertNotAfter,
}

impl CertificateArtifactMaterial {
    /// Group one provider attempt's public certificate coordinates.
    #[must_use]
    pub fn new(
        public_key_digest: CertificatePublicKeyDigest,
        artifact_digest: ArtifactDigest,
        expected_reported_state_hash: ReportedStateHash,
        artifact_id: CertificateArtifactId,
        cert_scope: CertScope,
        serial: CertSerial,
        not_after: CertNotAfter,
    ) -> Self {
        Self {
            public_key_digest,
            artifact_digest,
            expected_reported_state_hash,
            artifact_id,
            cert_scope,
            serial,
            not_after,
        }
    }
}

/// Exact receipt-bound coordinates shared by request, candidate, authorization, and persistence.
///
/// Fields remain private so callers cannot partially project or mutate one coordinate. This value
/// is evidence data rather than append authority; only the consuming artifact funnel can mint an
/// [`ArtifactAppendAuthorization`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateArtifactBinding {
    scope: DeviceCertificateScope,
    generation: ExpectedGeneration,
    policy_hash: PolicyHash,
    authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
    public_key_digest: CertificatePublicKeyDigest,
    artifact_digest: ArtifactDigest,
    expected_reported_state_hash: ReportedStateHash,
    artifact_id: CertificateArtifactId,
    cert_scope: CertScope,
    serial: CertSerial,
    not_after: CertNotAfter,
}

impl CertificateArtifactBinding {
    /// Bind provider material to the exact authorized desired-state acquisition.
    pub fn from_acquisition(
        acquisition: &CertificateArtifactAcquisition,
        material: CertificateArtifactMaterial,
    ) -> Result<Self, CertificateArtifactError> {
        Self::restore(
            acquisition.scope(),
            acquisition.generation(),
            acquisition.policy_hash().clone(),
            acquisition.authorization_receipt_id(),
            material,
        )
    }

    /// Restore one complete binding while rechecking the redundant revocation scope.
    pub fn restore(
        scope: DeviceCertificateScope,
        generation: ExpectedGeneration,
        policy_hash: PolicyHash,
        authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
        material: CertificateArtifactMaterial,
    ) -> Result<Self, CertificateArtifactError> {
        if material.cert_scope.tenant() != scope.tenant()
            || material.cert_scope.device() != scope.device()
        {
            return Err(CertificateArtifactError::BindingMismatch);
        }
        Ok(Self {
            scope,
            generation,
            policy_hash,
            authorization_receipt_id,
            public_key_digest: material.public_key_digest,
            artifact_digest: material.artifact_digest,
            expected_reported_state_hash: material.expected_reported_state_hash,
            artifact_id: material.artifact_id,
            cert_scope: material.cert_scope,
            serial: material.serial,
            not_after: material.not_after,
        })
    }

    /// Authorized tenant/device coordinate.
    #[must_use]
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }
    /// Authorized desired generation.
    #[must_use]
    pub const fn generation(&self) -> ExpectedGeneration {
        self.generation
    }
    /// Canonical desired-policy digest.
    #[must_use]
    pub const fn policy_hash(&self) -> &PolicyHash {
        &self.policy_hash
    }
    /// Durable allow decision bound to this artifact.
    #[must_use]
    pub const fn authorization_receipt_id(&self) -> DevicePolicyAuthorizationReceiptId {
        self.authorization_receipt_id
    }
    /// Public key that the certificate binds.
    #[must_use]
    pub const fn public_key_digest(&self) -> &CertificatePublicKeyDigest {
        &self.public_key_digest
    }
    /// Canonical public artifact digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &ArtifactDigest {
        &self.artifact_digest
    }
    /// Expected device-reported public-state digest.
    #[must_use]
    pub const fn expected_reported_state_hash(&self) -> &ReportedStateHash {
        &self.expected_reported_state_hash
    }
    /// Stable provider artifact identity.
    #[must_use]
    pub const fn artifact_id(&self) -> &CertificateArtifactId {
        &self.artifact_id
    }
    /// Revocation scope bound to the same tenant/device.
    #[must_use]
    pub const fn cert_scope(&self) -> CertScope {
        self.cert_scope
    }
    /// RFC 5280 serial.
    #[must_use]
    pub const fn serial(&self) -> &CertSerial {
        &self.serial
    }
    /// Authoritative terminal expiry coordinate.
    #[must_use]
    pub const fn not_after(&self) -> CertNotAfter {
        self.not_after
    }
}

/// Complete expected binding derived from authorized desired state and canonical request state.
/// Fields are private so a provider cannot choose its own authorization coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateArtifactRequest {
    binding: CertificateArtifactBinding,
}

/// Sealed desired-state request supplied to the production artifact source.
///
/// The source may choose provider coordinates, but can return only an artifact carrying the
/// production eligibility marker introduced by the verified closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateArtifactAcquisition {
    scope: DeviceCertificateScope,
    generation: ExpectedGeneration,
    policy_hash: PolicyHash,
    authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
    policy: CertificatePolicy,
}

impl CertificateArtifactAcquisition {
    pub(crate) fn from_desired(
        scope: DeviceCertificateScope,
        desired: &crate::device_certificate::DesiredStateSnapshot,
    ) -> Result<Self, CertificateArtifactError> {
        Ok(Self {
            scope,
            generation: ExpectedGeneration::try_new(desired.generation().get())
                .map_err(|_| CertificateArtifactError::BindingMismatch)?,
            policy_hash: desired.policy_hash().clone(),
            authorization_receipt_id: desired.authorization_receipt_id(),
            policy: desired.policy().clone(),
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only construction of the sealed desired-state projection.
    pub fn for_test(
        scope: DeviceCertificateScope,
        generation: ExpectedGeneration,
        policy_hash: PolicyHash,
        authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
        policy: CertificatePolicy,
    ) -> Self {
        Self {
            scope,
            generation,
            policy_hash,
            authorization_receipt_id,
            policy,
        }
    }

    /// Authorized tenant/device scope.
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }
    /// Current desired generation.
    pub const fn generation(&self) -> ExpectedGeneration {
        self.generation
    }
    /// Canonical policy digest.
    pub const fn policy_hash(&self) -> &PolicyHash {
        &self.policy_hash
    }
    /// Durable allow decision owning this desired generation.
    pub const fn authorization_receipt_id(&self) -> DevicePolicyAuthorizationReceiptId {
        self.authorization_receipt_id
    }
    /// Canonical desired certificate policy.
    pub const fn policy(&self) -> &CertificatePolicy {
        &self.policy
    }
}

impl CertificateArtifactRequest {
    /// Bind deterministic draft-provider coordinates to one authorized desired-state acquisition.
    ///
    /// This is the sole non-test draft authoring funnel. The provider may choose its public
    /// artifact coordinates, but tenant, device, generation, and policy digest come only from the
    /// sealed acquisition supplied by the reconciler.
    pub fn for_draft_provider(
        acquisition: &CertificateArtifactAcquisition,
        material: CertificateArtifactMaterial,
    ) -> Result<Self, CertificateArtifactError> {
        Ok(Self {
            binding: CertificateArtifactBinding::from_acquisition(acquisition, material)?,
        })
    }

    /// Bind provider-verified public certificate coordinates to one sealed desired-state
    /// acquisition. Production eligibility is still minted separately and requires the
    /// assembly-wide external-PKI closure.
    pub fn for_external_pki_provider(
        acquisition: &CertificateArtifactAcquisition,
        material: CertificateArtifactMaterial,
    ) -> Result<Self, CertificateArtifactError> {
        Ok(Self {
            binding: CertificateArtifactBinding::from_acquisition(acquisition, material)?,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only constructor preserving the production validation funnel.
    pub fn for_test(
        scope: DeviceCertificateScope,
        generation: ExpectedGeneration,
        policy_hash: PolicyHash,
        material: CertificateArtifactMaterial,
    ) -> Result<Self, CertificateArtifactError> {
        Self::for_test_with_receipt(
            scope,
            generation,
            policy_hash,
            DevicePolicyAuthorizationReceiptId::restore(uuid::Uuid::from_bytes([1; 16]))
                .map_err(|_| CertificateArtifactError::BindingMismatch)?,
            material,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only constructor that preserves an explicit durable receipt correlation.
    pub fn for_test_with_receipt(
        scope: DeviceCertificateScope,
        generation: ExpectedGeneration,
        policy_hash: PolicyHash,
        authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
        material: CertificateArtifactMaterial,
    ) -> Result<Self, CertificateArtifactError> {
        Ok(Self {
            binding: CertificateArtifactBinding::restore(
                scope,
                generation,
                policy_hash,
                authorization_receipt_id,
                material,
            )?,
        })
    }

    /// Borrow the complete receipt-bound coordinates consumed by later artifact states.
    #[must_use]
    pub const fn binding(&self) -> &CertificateArtifactBinding {
        &self.binding
    }

    /// Authorized tenant/device coordinate.
    #[must_use]
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.binding.scope()
    }

    /// Authorized desired generation.
    #[must_use]
    pub const fn generation(&self) -> ExpectedGeneration {
        self.binding.generation()
    }

    /// Canonical desired-policy digest.
    #[must_use]
    pub const fn policy_hash(&self) -> &PolicyHash {
        self.binding.policy_hash()
    }
    /// Durable allow decision bound to this expected artifact.
    #[must_use]
    pub const fn authorization_receipt_id(&self) -> DevicePolicyAuthorizationReceiptId {
        self.binding.authorization_receipt_id()
    }
    /// Public key that the certificate must bind.
    #[must_use]
    pub const fn public_key_digest(&self) -> &CertificatePublicKeyDigest {
        self.binding.public_key_digest()
    }
    /// Expected public artifact digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &ArtifactDigest {
        self.binding.artifact_digest()
    }
    /// Expected device-reported public-state digest.
    #[must_use]
    pub const fn expected_reported_state_hash(&self) -> &ReportedStateHash {
        self.binding.expected_reported_state_hash()
    }
    /// Stable provider artifact identity.
    #[must_use]
    pub const fn artifact_id(&self) -> &CertificateArtifactId {
        self.binding.artifact_id()
    }
    /// Revocation scope bound to the same tenant/device.
    #[must_use]
    pub const fn cert_scope(&self) -> CertScope {
        self.binding.cert_scope()
    }
    /// Expected RFC 5280 serial.
    #[must_use]
    pub const fn serial(&self) -> &CertSerial {
        self.binding.serial()
    }
    /// Expected terminal expiry coordinate.
    #[must_use]
    pub const fn not_after(&self) -> CertNotAfter {
        self.binding.not_after()
    }
}

/// Provider output before authorization. It may be constructed by an adapter, but cannot enter a
/// production dependency slot or persistence port until every binding has been checked.
pub struct ProviderCertificateCandidate {
    artifact: Vec<u8>,
    binding: CertificateArtifactBinding,
}

impl fmt::Debug for ProviderCertificateCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderCertificateCandidate(<redacted>)")
    }
}

impl ProviderCertificateCandidate {
    /// Capture untrusted provider output. Authorization is a separate, consuming operation.
    #[must_use]
    pub fn new(artifact: Vec<u8>, binding: CertificateArtifactBinding) -> Self {
        Self { artifact, binding }
    }

    fn authorize<E: ArtifactEligibility>(
        self,
        expected: &CertificateArtifactRequest,
    ) -> Result<AuthorizedCertificateArtifact<E>, CertificateArtifactError> {
        let digest = ArtifactDigest::restore(&Sha256::digest(&self.artifact))
            .map_err(|_| CertificateArtifactError::BindingMismatch)?;
        if digest != *self.binding.artifact_digest() || self.binding != expected.binding {
            return Err(CertificateArtifactError::BindingMismatch);
        }
        Ok(AuthorizedCertificateArtifact {
            artifact: self.artifact,
            binding: self.binding,
            eligibility: std::marker::PhantomData,
        })
    }

    /// Authorize deterministic draft material. The resulting marker cannot satisfy a production
    /// slot and no runtime eligibility label can be selected by the caller.
    pub fn authorize_draft(
        self,
        expected: &CertificateArtifactRequest,
    ) -> Result<AuthorizedCertificateArtifact<DraftEligibility>, CertificateArtifactError> {
        self.authorize(expected)
    }

    /// Mint one per-command production artifact under an already sealed assembly-wide provider
    /// closure. The move-only verified evidence must carry the same provider configuration and
    /// exact command/material coordinates; the closure contains no command authority by itself.
    pub fn authorize_production(
        self,
        closure: &diport::ExternalPkiProviderClosure,
        evidence: diport::VerifiedExternalPkiArtifactEvidence,
        expected: &CertificateArtifactRequest,
    ) -> Result<AuthorizedCertificateArtifact<ProductionEligibility>, CertificateArtifactError>
    {
        let evidence_request = evidence.request();
        let candidate_receipt = self.binding.authorization_receipt_id().as_uuid();
        if closure.config_digest() != evidence.provider_config_digest()
            || evidence_request.scope().tenant() != self.binding.scope().tenant()
            || evidence_request.scope().device() != self.binding.scope().device()
            || evidence_request.generation().get() != self.binding.generation().get()
            || evidence_request.policy_digest().as_bytes() != self.binding.policy_hash().as_bytes()
            || evidence_request.authorization_receipt().as_bytes() != candidate_receipt.as_bytes()
            || evidence_request.spki_digest().as_bytes()
                != self.binding.public_key_digest().as_bytes()
            || evidence.chain_digest().as_bytes()
                != self.binding.expected_reported_state_hash().as_bytes()
            || evidence_request.scope() != self.binding.cert_scope()
            || evidence.serial() != self.binding.serial()
            || evidence.not_after() != self.binding.not_after()
        {
            return Err(CertificateArtifactError::BindingMismatch);
        }
        self.authorize(expected)
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only production marker for executable coordinator component fakes.
    pub fn authorize_production_for_test(
        self,
        expected: &CertificateArtifactRequest,
    ) -> Result<AuthorizedCertificateArtifact<ProductionEligibility>, CertificateArtifactError>
    {
        self.authorize(expected)
    }
}

/// Fully bound certificate material. It deliberately does not implement `Clone`; command
/// authoring must consume the one authorized value rather than silently duplicating key material.
pub struct AuthorizedCertificateArtifact<E: ArtifactEligibility> {
    artifact: Vec<u8>,
    binding: CertificateArtifactBinding,
    eligibility: std::marker::PhantomData<E>,
}

impl<E: ArtifactEligibility> fmt::Debug for AuthorizedCertificateArtifact<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.eligibility, self.artifact.len());
        formatter.write_str("AuthorizedCertificateArtifact(<redacted>)")
    }
}

impl<E: ArtifactEligibility> AuthorizedCertificateArtifact<E> {
    /// Consume the authorization and return provider material for canonical command authoring.
    #[must_use]
    pub fn into_artifact(self) -> Vec<u8> {
        self.artifact
    }

    /// Consume the statically selected eligibility to mint the only capability accepted by
    /// artifact append.
    ///
    /// Restored persistence snapshots cannot traverse this funnel, so durable evidence never
    /// regains the authority that originally created it.
    #[must_use]
    pub fn into_append_authorization(self) -> ArtifactAppendAuthorization<E> {
        ArtifactAppendAuthorization {
            snapshot: PersistedCertificateArtifactSnapshot {
                binding: self.binding,
                eligibility: std::marker::PhantomData,
            },
        }
    }
}

/// Move-only authorization to append one production-eligible artifact snapshot.
///
/// This type deliberately does not implement `Clone` and has no restore constructor. Repository
/// implementations consume it exactly once and may only recover immutable evidence from it.
pub struct ArtifactAppendAuthorization<E: ArtifactEligibility> {
    snapshot: PersistedCertificateArtifactSnapshot<E>,
}

impl<E: ArtifactEligibility> fmt::Debug for ArtifactAppendAuthorization<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArtifactAppendAuthorization(<sealed>)")
    }
}

impl<E: ArtifactEligibility> ArtifactAppendAuthorization<E> {
    /// Borrow the immutable snapshot that the append transaction must persist exactly.
    #[must_use]
    pub const fn snapshot(&self) -> &PersistedCertificateArtifactSnapshot<E> {
        &self.snapshot
    }

    /// Consume append authority and return only immutable durable evidence.
    #[must_use]
    pub fn into_snapshot(self) -> PersistedCertificateArtifactSnapshot<E> {
        self.snapshot
    }
}

/// Immutable durable evidence restored from or derived for persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedCertificateArtifactSnapshot<E: ArtifactEligibility> {
    binding: CertificateArtifactBinding,
    eligibility: std::marker::PhantomData<E>,
}

impl<E: ArtifactEligibility> PersistedCertificateArtifactSnapshot<E> {
    /// Restore one immutable receipt from an already validated complete binding. Raw artifact
    /// bytes are never restored through this path.
    #[must_use]
    pub fn restore(binding: CertificateArtifactBinding) -> Self {
        Self {
            binding,
            eligibility: std::marker::PhantomData,
        }
    }

    /// Borrow the complete receipt-bound coordinates restored from persistence.
    #[must_use]
    pub const fn binding(&self) -> &CertificateArtifactBinding {
        &self.binding
    }

    /// Authorized tenant/device coordinate.
    #[must_use]
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.binding.scope()
    }
    /// Authorized desired generation.
    #[must_use]
    pub const fn generation(&self) -> ExpectedGeneration {
        self.binding.generation()
    }
    /// Canonical desired-policy digest.
    #[must_use]
    pub const fn policy_hash(&self) -> &PolicyHash {
        self.binding.policy_hash()
    }
    /// Durable allow decision that owns this generation's artifact.
    #[must_use]
    pub const fn authorization_receipt_id(&self) -> DevicePolicyAuthorizationReceiptId {
        self.binding.authorization_receipt_id()
    }
    /// Certified public-key digest.
    #[must_use]
    pub const fn public_key_digest(&self) -> &CertificatePublicKeyDigest {
        self.binding.public_key_digest()
    }
    /// Authorized public artifact digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &ArtifactDigest {
        self.binding.artifact_digest()
    }
    /// Expected reported public-state digest.
    #[must_use]
    pub const fn expected_reported_state_hash(&self) -> &ReportedStateHash {
        self.binding.expected_reported_state_hash()
    }
    /// Stable provider artifact identity.
    #[must_use]
    pub const fn artifact_id(&self) -> &CertificateArtifactId {
        self.binding.artifact_id()
    }
    /// Revocation scope, bound to the same tenant/device.
    #[must_use]
    pub const fn cert_scope(&self) -> CertScope {
        self.binding.cert_scope()
    }
    /// RFC 5280 serial used by the single revocation truth source.
    #[must_use]
    pub const fn serial(&self) -> &CertSerial {
        self.binding.serial()
    }
    /// Authoritative terminal expiry coordinate.
    #[must_use]
    pub const fn not_after(&self) -> CertNotAfter {
        self.binding.not_after()
    }
}

/// Domain-shaped artifact dependency slot with one statically selected sealed eligibility.
/// `diport::Signer` cannot be substituted accidentally, and draft/production providers remain
/// incompatible through the associated marker type.
pub trait CertificateArtifactSource: Send + Sync {
    /// Eligibility selected by this provider for its entire lifetime.
    type Eligibility: ArtifactEligibility;

    /// Acquire an already verified and fully bound artifact.
    fn acquire(
        &self,
        request: CertificateArtifactAcquisition,
    ) -> impl std::future::Future<
        Output = Result<AuthorizedCertificateArtifact<Self::Eligibility>, CertificateArtifactError>,
    > + Send;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ids::DeviceId;
    use rss_request_context::TenantId;
    use uuid::Uuid;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn scope() -> DeviceCertificateScope {
        DeviceCertificateScope::for_test(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
            DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        )
    }

    fn authorization_receipt_id() -> crate::device_certificate::DevicePolicyAuthorizationReceiptId {
        crate::device_certificate::DevicePolicyAuthorizationReceiptId::restore(
            Uuid::parse_str("018f7f3e-7b7a-7c4c-8d2a-8ebad5dbe001").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn receipt_bound_binding_is_shared_across_request_candidate_and_snapshot() {
        let scope = scope();
        let artifact = b"shared-binding-certificate-chain".to_vec();
        let material = CertificateArtifactMaterial::new(
            CertificatePublicKeyDigest::digest(b"shared-public-key"),
            ArtifactDigest::restore(&Sha256::digest(&artifact)).unwrap(),
            ReportedStateHash::parse(&digest('b')).unwrap(),
            CertificateArtifactId::parse("vault-pki-sha256:shared-binding").unwrap(),
            CertScope::new(scope.tenant(), scope.device()),
            CertSerial::try_new([7]).unwrap(),
            CertNotAfter::try_from_system_time(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(7_200),
            )
            .unwrap(),
        );
        let expected = CertificateArtifactRequest::for_test_with_receipt(
            scope,
            ExpectedGeneration::try_new(7).unwrap(),
            PolicyHash::parse(&digest('a')).unwrap(),
            authorization_receipt_id(),
            material,
        )
        .unwrap();
        let binding = expected.binding().clone();
        let candidate = ProviderCertificateCandidate::new(artifact, binding.clone());
        let snapshot = candidate
            .authorize_production_for_test(&expected)
            .unwrap()
            .into_append_authorization()
            .into_snapshot();

        assert_eq!(snapshot.binding(), &binding);
    }

    #[test]
    fn production_mint_requires_provider_closure_and_authorization_receipt() {
        let scope = scope();
        let receipt_id = authorization_receipt_id();
        let artifact = b"receipt-bound-production-certificate-chain".to_vec();
        let artifact_digest = ArtifactDigest::restore(&Sha256::digest(&artifact)).unwrap();
        let expected = CertificateArtifactRequest::for_test_with_receipt(
            scope,
            ExpectedGeneration::try_new(7).unwrap(),
            PolicyHash::parse(&digest('a')).unwrap(),
            receipt_id,
            CertificateArtifactMaterial::new(
                CertificatePublicKeyDigest::digest(b"public-key"),
                artifact_digest,
                ReportedStateHash::parse(&digest('b')).unwrap(),
                CertificateArtifactId::parse("vault-pki-sha256:artifact-0007").unwrap(),
                CertScope::new(scope.tenant(), scope.device()),
                CertSerial::try_new([7]).unwrap(),
                CertNotAfter::try_from_system_time(
                    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(7_200),
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let candidate = ProviderCertificateCandidate::new(artifact, expected.binding().clone());
        let authorized = candidate.authorize_production_for_test(&expected).unwrap();
        let snapshot = authorized.into_append_authorization().into_snapshot();

        assert_eq!(snapshot.authorization_receipt_id(), receipt_id);
    }

    #[test]
    fn complete_binding_authorizes_and_debug_is_redacted() {
        let scope = scope();
        let artifact = b"public-certificate-der".to_vec();
        let artifact_digest = ArtifactDigest::restore(&Sha256::digest(&artifact)).unwrap();
        let expected = CertificateArtifactRequest::for_test(
            scope,
            ExpectedGeneration::try_new(1).unwrap(),
            PolicyHash::parse(&digest('a')).unwrap(),
            CertificateArtifactMaterial::new(
                CertificatePublicKeyDigest::digest(b"public-key"),
                artifact_digest.clone(),
                ReportedStateHash::parse(&digest('b')).unwrap(),
                CertificateArtifactId::parse("provider/artifact/1").unwrap(),
                CertScope::new(scope.tenant(), scope.device()),
                CertSerial::try_new([1]).unwrap(),
                CertNotAfter::try_from_system_time(
                    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(3600),
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let candidate = ProviderCertificateCandidate::new(artifact, expected.binding().clone());
        let authorized = candidate.authorize_draft(&expected).unwrap();
        assert_eq!(
            format!("{authorized:?}"),
            "AuthorizedCertificateArtifact(<redacted>)"
        );
        let append = authorized.into_append_authorization();
        fn requires_draft(_: &ArtifactAppendAuthorization<DraftEligibility>) {}
        requires_draft(&append);
        assert_eq!(append.snapshot().artifact_digest(), &artifact_digest);
    }

    #[test]
    fn mismatched_binding_fails_closed() {
        let scope = scope();
        let expected = CertificateArtifactRequest::for_test(
            scope,
            ExpectedGeneration::try_new(1).unwrap(),
            PolicyHash::parse(&digest('a')).unwrap(),
            CertificateArtifactMaterial::new(
                CertificatePublicKeyDigest::digest(b"key-a"),
                ArtifactDigest::restore(&Sha256::digest(b"artifact")).unwrap(),
                ReportedStateHash::parse(&digest('b')).unwrap(),
                CertificateArtifactId::parse("artifact-id-0001").unwrap(),
                CertScope::new(scope.tenant(), scope.device()),
                CertSerial::try_new([1]).unwrap(),
                CertNotAfter::try_from_system_time(
                    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(3600),
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let valid =
            || ProviderCertificateCandidate::new(b"artifact".to_vec(), expected.binding().clone());
        let other_device = DeviceId::parse("650e8400-e29b-41d4-a716-446655440000").unwrap();
        let mut candidates = Vec::new();
        let mut value = valid();
        value.binding.scope = DeviceCertificateScope::for_test(scope.tenant(), other_device);
        candidates.push(value);
        let mut value = valid();
        value.binding.generation = ExpectedGeneration::try_new(2).unwrap();
        candidates.push(value);
        let mut value = valid();
        value.binding.policy_hash = PolicyHash::parse(&digest('d')).unwrap();
        candidates.push(value);
        let mut value = valid();
        value.binding.authorization_receipt_id = authorization_receipt_id();
        candidates.push(value);
        let mut value = valid();
        value.binding.public_key_digest = CertificatePublicKeyDigest::digest(b"key-b");
        candidates.push(value);
        let mut value = valid();
        value.artifact = b"other-artifact".to_vec();
        candidates.push(value);
        let mut value = valid();
        value.binding.expected_reported_state_hash =
            ReportedStateHash::parse(&digest('e')).unwrap();
        candidates.push(value);
        let mut value = valid();
        value.binding.artifact_id = CertificateArtifactId::parse("artifact-id-0002").unwrap();
        candidates.push(value);
        let mut value = valid();
        value.binding.cert_scope = CertScope::new(scope.tenant(), other_device);
        candidates.push(value);
        let mut value = valid();
        value.binding.serial = CertSerial::try_new([2]).unwrap();
        candidates.push(value);
        let mut value = valid();
        value.binding.not_after = CertNotAfter::try_from_system_time(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(3601),
        )
        .unwrap();
        candidates.push(value);

        for candidate in candidates {
            assert_eq!(
                candidate.authorize_draft(&expected).unwrap_err(),
                CertificateArtifactError::BindingMismatch
            );
        }
    }

    #[test]
    fn artifact_id_enforces_generated_utf8_octet_bounds() {
        assert_eq!(
            CertificateArtifactId::parse(&"é".repeat(7)),
            Err(CertificateArtifactError::InvalidArtifactId)
        );
        assert!(CertificateArtifactId::parse(&"é".repeat(8)).is_ok());
        assert!(CertificateArtifactId::parse(&"a".repeat(256)).is_ok());
        assert_eq!(
            CertificateArtifactId::parse(&"a".repeat(257)),
            Err(CertificateArtifactError::InvalidArtifactId)
        );
    }
}
