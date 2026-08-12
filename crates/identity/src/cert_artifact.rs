//! Validated certificate artifact bindings for the DeviceLatent reconcile loop.
//!
//! Provider material enters as [`ProviderCertificateCandidate`]. Only the binding funnel in this
//! module can turn it into an [`AuthorizedCertificateArtifact`]; production eligibility remains an
//! unforgeable capability. ADR-028 supersedes #1910: a future candidate integration must bind any
//! private production mint to its separately authorized, assembly-wide verified provider closure.
//!
//! ref: instant-labs/instant-acme src/order.rs@8e4441f

use std::fmt;

use diport::{CertNotAfter, CertScope, CertSerial};
use sha2::{Digest, Sha256};

use crate::device_certificate::{
    ArtifactDigest, DeviceCertificateScope, ExpectedGeneration, PolicyHash, ReportedStateHash,
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

/// Complete expected binding derived from authorized desired state and canonical request state.
/// Fields are private so a provider cannot choose its own authorization coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateArtifactRequest {
    scope: DeviceCertificateScope,
    generation: ExpectedGeneration,
    policy_hash: PolicyHash,
    public_key_digest: CertificatePublicKeyDigest,
    artifact_digest: ArtifactDigest,
    expected_reported_state_hash: ReportedStateHash,
    artifact_id: CertificateArtifactId,
    cert_scope: CertScope,
    serial: CertSerial,
    not_after: CertNotAfter,
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
            policy: desired.policy().clone(),
        })
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
    /// Canonical desired certificate policy.
    pub const fn policy(&self) -> &CertificatePolicy {
        &self.policy
    }
}

impl CertificateArtifactRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_authorized(
        scope: DeviceCertificateScope,
        generation: ExpectedGeneration,
        policy_hash: PolicyHash,
        public_key_digest: CertificatePublicKeyDigest,
        artifact_digest: ArtifactDigest,
        expected_reported_state_hash: ReportedStateHash,
        artifact_id: CertificateArtifactId,
        cert_scope: CertScope,
        serial: CertSerial,
        not_after: CertNotAfter,
    ) -> Result<Self, CertificateArtifactError> {
        if cert_scope.tenant() != scope.tenant() || cert_scope.device() != scope.device() {
            return Err(CertificateArtifactError::BindingMismatch);
        }
        Ok(Self {
            scope,
            generation,
            policy_hash,
            public_key_digest,
            artifact_digest,
            expected_reported_state_hash,
            artifact_id,
            cert_scope,
            serial,
            not_after,
        })
    }

    /// Bind deterministic draft-provider coordinates to one authorized desired-state acquisition.
    ///
    /// This is the sole non-test draft authoring funnel. The provider may choose its public
    /// artifact coordinates, but tenant, device, generation, and policy digest come only from the
    /// sealed acquisition supplied by the reconciler.
    #[allow(clippy::too_many_arguments)]
    pub fn for_draft_provider(
        acquisition: &CertificateArtifactAcquisition,
        public_key_digest: CertificatePublicKeyDigest,
        artifact_digest: ArtifactDigest,
        expected_reported_state_hash: ReportedStateHash,
        artifact_id: CertificateArtifactId,
        cert_scope: CertScope,
        serial: CertSerial,
        not_after: CertNotAfter,
    ) -> Result<Self, CertificateArtifactError> {
        Self::from_authorized(
            acquisition.scope(),
            acquisition.generation(),
            acquisition.policy_hash().clone(),
            public_key_digest,
            artifact_digest,
            expected_reported_state_hash,
            artifact_id,
            cert_scope,
            serial,
            not_after,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only constructor preserving the production validation funnel.
    #[allow(clippy::too_many_arguments)]
    pub fn for_test(
        scope: DeviceCertificateScope,
        generation: ExpectedGeneration,
        policy_hash: PolicyHash,
        public_key_digest: CertificatePublicKeyDigest,
        artifact_digest: ArtifactDigest,
        expected_reported_state_hash: ReportedStateHash,
        artifact_id: CertificateArtifactId,
        cert_scope: CertScope,
        serial: CertSerial,
        not_after: CertNotAfter,
    ) -> Result<Self, CertificateArtifactError> {
        Self::from_authorized(
            scope,
            generation,
            policy_hash,
            public_key_digest,
            artifact_digest,
            expected_reported_state_hash,
            artifact_id,
            cert_scope,
            serial,
            not_after,
        )
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
    /// Public key that the certificate must bind.
    #[must_use]
    pub const fn public_key_digest(&self) -> &CertificatePublicKeyDigest {
        &self.public_key_digest
    }
    /// Expected public artifact digest.
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
    /// Expected RFC 5280 serial.
    #[must_use]
    pub const fn serial(&self) -> &CertSerial {
        &self.serial
    }
    /// Expected terminal expiry coordinate.
    #[must_use]
    pub const fn not_after(&self) -> CertNotAfter {
        self.not_after
    }
}

/// Provider output before authorization. It may be constructed by an adapter, but cannot enter a
/// production dependency slot or persistence port until every binding has been checked.
pub struct ProviderCertificateCandidate {
    artifact: Vec<u8>,
    scope: DeviceCertificateScope,
    generation: ExpectedGeneration,
    policy_hash: PolicyHash,
    public_key_digest: CertificatePublicKeyDigest,
    expected_reported_state_hash: ReportedStateHash,
    artifact_id: CertificateArtifactId,
    cert_scope: CertScope,
    serial: CertSerial,
    not_after: CertNotAfter,
}

impl fmt::Debug for ProviderCertificateCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderCertificateCandidate(<redacted>)")
    }
}

impl ProviderCertificateCandidate {
    /// Capture untrusted provider output. Authorization is a separate, consuming operation.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        artifact: Vec<u8>,
        scope: DeviceCertificateScope,
        generation: ExpectedGeneration,
        policy_hash: PolicyHash,
        public_key_digest: CertificatePublicKeyDigest,
        expected_reported_state_hash: ReportedStateHash,
        artifact_id: CertificateArtifactId,
        cert_scope: CertScope,
        serial: CertSerial,
        not_after: CertNotAfter,
    ) -> Self {
        Self {
            artifact,
            scope,
            generation,
            policy_hash,
            public_key_digest,
            expected_reported_state_hash,
            artifact_id,
            cert_scope,
            serial,
            not_after,
        }
    }

    fn authorize<E: ArtifactEligibility>(
        self,
        expected: &CertificateArtifactRequest,
    ) -> Result<AuthorizedCertificateArtifact<E>, CertificateArtifactError> {
        let digest = ArtifactDigest::restore(&Sha256::digest(&self.artifact))
            .map_err(|_| CertificateArtifactError::BindingMismatch)?;
        if self.scope != expected.scope
            || self.generation != expected.generation
            || self.policy_hash != expected.policy_hash
            || self.public_key_digest != expected.public_key_digest
            || digest != expected.artifact_digest
            || self.expected_reported_state_hash != expected.expected_reported_state_hash
            || self.artifact_id != expected.artifact_id
            || self.cert_scope != expected.cert_scope
            || self.serial != expected.serial
            || self.not_after != expected.not_after
        {
            return Err(CertificateArtifactError::BindingMismatch);
        }
        Ok(AuthorizedCertificateArtifact {
            artifact: self.artifact,
            scope: self.scope,
            generation: self.generation,
            policy_hash: self.policy_hash,
            public_key_digest: self.public_key_digest,
            artifact_digest: digest,
            expected_reported_state_hash: self.expected_reported_state_hash,
            artifact_id: self.artifact_id,
            cert_scope: self.cert_scope,
            serial: self.serial,
            not_after: self.not_after,
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
    scope: DeviceCertificateScope,
    generation: ExpectedGeneration,
    policy_hash: PolicyHash,
    public_key_digest: CertificatePublicKeyDigest,
    artifact_digest: ArtifactDigest,
    expected_reported_state_hash: ReportedStateHash,
    artifact_id: CertificateArtifactId,
    cert_scope: CertScope,
    serial: CertSerial,
    not_after: CertNotAfter,
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
                scope: self.scope,
                generation: self.generation,
                policy_hash: self.policy_hash,
                public_key_digest: self.public_key_digest,
                artifact_digest: self.artifact_digest,
                expected_reported_state_hash: self.expected_reported_state_hash,
                artifact_id: self.artifact_id,
                cert_scope: self.cert_scope,
                serial: self.serial,
                not_after: self.not_after,
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
    scope: DeviceCertificateScope,
    generation: ExpectedGeneration,
    policy_hash: PolicyHash,
    public_key_digest: CertificatePublicKeyDigest,
    artifact_digest: ArtifactDigest,
    expected_reported_state_hash: ReportedStateHash,
    artifact_id: CertificateArtifactId,
    cert_scope: CertScope,
    serial: CertSerial,
    not_after: CertNotAfter,
    eligibility: std::marker::PhantomData<E>,
}

impl<E: ArtifactEligibility> PersistedCertificateArtifactSnapshot<E> {
    /// Restore one immutable receipt from persistence while rechecking the redundant revocation
    /// scope binding. Raw artifact bytes are never restored through this path.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        scope: DeviceCertificateScope,
        generation: ExpectedGeneration,
        policy_hash: PolicyHash,
        public_key_digest: CertificatePublicKeyDigest,
        artifact_digest: ArtifactDigest,
        expected_reported_state_hash: ReportedStateHash,
        artifact_id: CertificateArtifactId,
        cert_scope: CertScope,
        serial: CertSerial,
        not_after: CertNotAfter,
    ) -> Result<Self, CertificateArtifactError> {
        if cert_scope.tenant() != scope.tenant() || cert_scope.device() != scope.device() {
            return Err(CertificateArtifactError::BindingMismatch);
        }
        Ok(Self {
            scope,
            generation,
            policy_hash,
            public_key_digest,
            artifact_digest,
            expected_reported_state_hash,
            artifact_id,
            cert_scope,
            serial,
            not_after,
            eligibility: std::marker::PhantomData,
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
    /// Certified public-key digest.
    #[must_use]
    pub const fn public_key_digest(&self) -> &CertificatePublicKeyDigest {
        &self.public_key_digest
    }
    /// Authorized public artifact digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &ArtifactDigest {
        &self.artifact_digest
    }
    /// Expected reported public-state digest.
    #[must_use]
    pub const fn expected_reported_state_hash(&self) -> &ReportedStateHash {
        &self.expected_reported_state_hash
    }
    /// Stable provider artifact identity.
    #[must_use]
    pub const fn artifact_id(&self) -> &CertificateArtifactId {
        &self.artifact_id
    }
    /// Revocation scope, bound to the same tenant/device.
    #[must_use]
    pub const fn cert_scope(&self) -> CertScope {
        self.cert_scope
    }
    /// RFC 5280 serial used by the single revocation truth source.
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

/// Domain-shaped artifact dependency slot with one statically selected sealed eligibility.
/// `diport::Signer` cannot be substituted accidentally, and draft/production providers remain
/// incompatible through the associated marker type.
#[allow(async_fn_in_trait)]
pub trait CertificateArtifactSource: Send + Sync {
    /// Eligibility selected by this provider for its entire lifetime.
    type Eligibility: ArtifactEligibility;

    /// Acquire an already verified and fully bound artifact.
    async fn acquire(
        &self,
        request: CertificateArtifactAcquisition,
    ) -> Result<AuthorizedCertificateArtifact<Self::Eligibility>, CertificateArtifactError>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ids::DeviceId;
    use rss_request_context::TenantId;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn scope() -> DeviceCertificateScope {
        DeviceCertificateScope::for_test(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
            DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        )
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
        )
        .unwrap();
        let candidate = ProviderCertificateCandidate::new(
            artifact,
            scope,
            expected.generation,
            expected.policy_hash.clone(),
            expected.public_key_digest.clone(),
            expected.expected_reported_state_hash.clone(),
            expected.artifact_id.clone(),
            expected.cert_scope,
            expected.serial.clone(),
            expected.not_after,
        );
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
        )
        .unwrap();
        let valid = || {
            ProviderCertificateCandidate::new(
                b"artifact".to_vec(),
                scope,
                expected.generation,
                expected.policy_hash.clone(),
                expected.public_key_digest.clone(),
                expected.expected_reported_state_hash.clone(),
                expected.artifact_id.clone(),
                expected.cert_scope,
                expected.serial.clone(),
                expected.not_after,
            )
        };
        let other_device = DeviceId::parse("650e8400-e29b-41d4-a716-446655440000").unwrap();
        let mut candidates = Vec::new();
        let mut value = valid();
        value.scope = DeviceCertificateScope::for_test(scope.tenant(), other_device);
        candidates.push(value);
        let mut value = valid();
        value.generation = ExpectedGeneration::try_new(2).unwrap();
        candidates.push(value);
        let mut value = valid();
        value.policy_hash = PolicyHash::parse(&digest('d')).unwrap();
        candidates.push(value);
        let mut value = valid();
        value.public_key_digest = CertificatePublicKeyDigest::digest(b"key-b");
        candidates.push(value);
        let mut value = valid();
        value.artifact = b"other-artifact".to_vec();
        candidates.push(value);
        let mut value = valid();
        value.expected_reported_state_hash = ReportedStateHash::parse(&digest('e')).unwrap();
        candidates.push(value);
        let mut value = valid();
        value.artifact_id = CertificateArtifactId::parse("artifact-id-0002").unwrap();
        candidates.push(value);
        let mut value = valid();
        value.cert_scope = CertScope::new(scope.tenant(), other_device);
        candidates.push(value);
        let mut value = valid();
        value.serial = CertSerial::try_new([2]).unwrap();
        candidates.push(value);
        let mut value = valid();
        value.not_after = CertNotAfter::try_from_system_time(
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
