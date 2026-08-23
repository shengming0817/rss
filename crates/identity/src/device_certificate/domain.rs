//! Validated identity-owned device-certificate persistence values.
//!
//! `deviceloop` owns certificate policy and condition vocabulary. This module binds those closed
//! values to authenticated tenant/device persistence coordinates without creating a second
//! generation/fence authority.

use std::time::SystemTime;

pub use deviceloop::DeviceSequence;
use deviceloop::{
    CertificatePolicy, DesiredGeneration, DeviceCondition, DeviceConditionKind,
    DeviceConditionRestore, DeviceConditionSnapshot, DeviceConditionState, FenceEpoch,
    ObservedGeneration,
};
use ids::DeviceId;
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const DIGEST_PREFIX: &str = "sha256:";
const DIGEST_BYTES: usize = 32;
const DIGEST_HEX_LEN: usize = DIGEST_BYTES * 2;
const MAX_REPORT_ENVELOPE_ID_BYTES: usize = 256;
const MAX_SIGNED_COORDINATE: u64 = i64::MAX as u64;
const POLICY_REQUEST_DIGEST_DOMAIN: &[u8] = b"rss.identity.device-certificate-policy-request.v1";
const POLICY_WRITE_CONTRACT_ID: &str =
    generated::http::identity_v2::device_certificate_policy_put::CONTRACT_ID;
const POLICY_WRITE_PERMISSION: vocab::RoutePermissionId =
    vocab::RoutePermissionId::IdentityDeviceCertificatePolicyWrite;

/// A malformed device-certificate persistence value or restored aggregate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceCertificateError {
    /// Expected generation must fit the nonnegative signed database range.
    #[error("expected generation must be in 0..=i64::MAX")]
    InvalidExpectedGeneration,
    /// The desired generation cannot advance beyond the database maximum.
    #[error("desired generation cannot advance beyond i64::MAX")]
    GenerationExhausted,
    /// A semantic SHA-256 digest was not canonical.
    #[error("SHA-256 digest is not canonical")]
    InvalidDigest,
    /// A report envelope identity was empty, unbounded, padded, or contained control bytes.
    #[error("report envelope id is invalid")]
    InvalidReportEnvelopeId,
    /// Device sequence must fit the nonnegative signed database range.
    #[error(transparent)]
    InvalidDeviceSequence(#[from] deviceloop::InvalidDeviceSequence),
    /// Server-owned desired timestamps were not monotonic.
    #[error("desired-state timestamps are not monotonic")]
    InvalidTimestampOrder,
    /// Persisted reported state existed without authoritative desired state.
    #[error("reported state cannot exist without desired state")]
    ReportedWithoutDesired,
    /// Persisted reported state exceeded desired generation.
    #[error("reported generation cannot exceed desired generation")]
    ReportedAheadOfDesired,
    /// A condition batch contained the same condition kind more than once.
    #[error("condition state batch contains a duplicate kind")]
    DuplicateConditionKind,
    /// A condition referenced a generation beyond desired state.
    #[error("condition observed generation cannot exceed desired generation")]
    ConditionAheadOfDesired,
    /// Persisted generation coordinates were invalid.
    #[error(transparent)]
    InvalidGeneration(#[from] deviceloop::InvalidGenerationCoordinate),
    /// Persisted certificate policy violated the canonical DeviceLatent vocabulary.
    #[error(transparent)]
    InvalidPolicy(#[from] deviceloop::CertificatePolicyError),
    /// Persisted condition state violated the closed condition vocabulary.
    #[error(transparent)]
    InvalidCondition(#[from] deviceloop::ConditionRestoreError),
    /// Persisted storage values fell outside the closed representation.
    #[error("persisted device-certificate value is invalid")]
    InvalidPersistedValue,
}

/// Tenant/device capability for device-certificate repository access.
///
/// Fields and the production constructor are crate-private, so storage scope cannot be minted from
/// caller-controlled body data.
///
/// ```compile_fail
/// use identity::ports::device_certificate::DeviceCertificateScope;
/// use ids::DeviceId;
/// use rss_request_context::TenantId;
/// fn forge(tenant: TenantId, device: DeviceId) {
///     let _ = DeviceCertificateScope { tenant, device, seal: () };
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceCertificateScope {
    tenant: TenantId,
    device: DeviceId,
    seal: (),
}

impl DeviceCertificateScope {
    #[allow(dead_code)]
    pub(crate) fn from_authorized(tenant: TenantId, device: DeviceId) -> Self {
        Self {
            tenant,
            device,
            seal: (),
        }
    }

    /// Owning tenant used for RLS lowering.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Authorized path device.
    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.device
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only scope constructor for adapter conformance.
    #[must_use]
    pub fn for_test(tenant: TenantId, device: DeviceId) -> Self {
        Self::from_authorized(tenant, device)
    }
}

/// Nonnegative generation supplied to desired-state compare-and-swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpectedGeneration(u64);

impl ExpectedGeneration {
    /// Validate request input. Zero is reserved for an absent desired row.
    pub fn try_new(raw: u64) -> Result<Self, DeviceCertificateError> {
        (raw <= MAX_SIGNED_COORDINATE)
            .then_some(Self(raw))
            .ok_or(DeviceCertificateError::InvalidExpectedGeneration)
    }

    /// Restore a signed database value.
    pub fn restore(raw: i64) -> Result<Self, DeviceCertificateError> {
        u64::try_from(raw)
            .map_err(|_| DeviceCertificateError::InvalidExpectedGeneration)
            .and_then(Self::try_new)
    }

    /// Database/request representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Derive the only desired generation valid for this expectation.
    pub fn next(self) -> Result<DesiredGeneration, DeviceCertificateError> {
        let next = self
            .0
            .checked_add(1)
            .filter(|value| *value <= MAX_SIGNED_COORDINATE)
            .ok_or(DeviceCertificateError::GenerationExhausted)?;
        DesiredGeneration::try_new(next).map_err(DeviceCertificateError::from)
    }
}

fn parse_digest(raw: &str) -> Result<[u8; DIGEST_BYTES], DeviceCertificateError> {
    let Some(hex) = raw.strip_prefix(DIGEST_PREFIX) else {
        return Err(DeviceCertificateError::InvalidDigest);
    };
    if hex.len() != DIGEST_HEX_LEN
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DeviceCertificateError::InvalidDigest);
    }
    let mut bytes = [0_u8; DIGEST_BYTES];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(bytes)
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn restore_digest(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], DeviceCertificateError> {
    bytes
        .try_into()
        .map_err(|_| DeviceCertificateError::InvalidDigest)
}

macro_rules! semantic_digest {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name([u8; DIGEST_BYTES]);

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<sha256>)"))
            }
        }

        impl $name {
            /// Parse the canonical `sha256:<lowercase-hex>` boundary representation.
            pub fn parse(raw: &str) -> Result<Self, DeviceCertificateError> {
                parse_digest(raw).map(Self)
            }

            /// Restore the exact 32-byte persistence representation.
            pub fn restore(bytes: &[u8]) -> Result<Self, DeviceCertificateError> {
                restore_digest(bytes).map(Self)
            }

            /// Borrow bytes for provider binding.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
                &self.0
            }
        }
    };
}

semantic_digest!(
    /// Database-owned digest of the canonical desired certificate policy.
    PolicyHash
);
semantic_digest!(
    /// Digest of the public certificate state reported by a device.
    ReportedStateHash
);
semantic_digest!(
    /// Digest of the public certificate artifact reported by a device.
    ArtifactDigest
);

/// Stable identity of a reported-state envelope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReportEnvelopeId(String);

impl ReportEnvelopeId {
    /// Parse a bounded canonical envelope identity.
    pub fn parse(raw: &str) -> Result<Self, DeviceCertificateError> {
        if raw.is_empty()
            || raw.trim() != raw
            || raw.len() > MAX_REPORT_ENVELOPE_ID_BYTES
            || raw.chars().any(char::is_control)
        {
            return Err(DeviceCertificateError::InvalidReportEnvelopeId);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Borrow the persistence value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Caller-supplied UUID scoped by the sealed tenant/device policy-accept operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DevicePolicyIdempotencyKey(Uuid);

impl std::fmt::Debug for DevicePolicyIdempotencyKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DevicePolicyIdempotencyKey(<uuid>)")
    }
}

/// Durable identity minted by the PostgreSQL acceptance funnel for one authorization decision.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DevicePolicyAuthorizationReceiptId(Uuid);

impl std::fmt::Debug for DevicePolicyAuthorizationReceiptId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DevicePolicyAuthorizationReceiptId(<uuid>)")
    }
}

impl DevicePolicyAuthorizationReceiptId {
    /// Restore a database-minted non-nil receipt identity.
    pub fn restore(raw: Uuid) -> Result<Self, DeviceCertificateError> {
        if raw.is_nil() {
            return Err(DeviceCertificateError::InvalidPersistedValue);
        }
        Ok(Self(raw))
    }

    /// Exact PostgreSQL UUID representation.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl DevicePolicyIdempotencyKey {
    /// Preserve any syntactically valid UUID; uniqueness and replay scope are provider concerns.
    #[must_use]
    pub const fn new(raw: Uuid) -> Self {
        Self(raw)
    }

    /// Exact provider representation.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Domain-owned digest of expected generation plus canonical certificate policy.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DevicePolicyRequestDigest([u8; DIGEST_BYTES]);

impl std::fmt::Debug for DevicePolicyRequestDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DevicePolicyRequestDigest(<sha256>)")
    }
}

impl DevicePolicyRequestDigest {
    /// Derive the versioned, domain-separated request identity.
    #[must_use]
    pub fn derive(expected_generation: ExpectedGeneration, policy: &CertificatePolicy) -> Self {
        let mut hasher = Sha256::new();
        digest_frame(&mut hasher, POLICY_REQUEST_DIGEST_DOMAIN);
        digest_frame(&mut hasher, &expected_generation.get().to_be_bytes());
        digest_frame(&mut hasher, &policy.canonical_bytes());
        Self(hasher.finalize().into())
    }

    /// Restore the exact 32-byte persistence representation.
    pub fn restore(bytes: &[u8]) -> Result<Self, DeviceCertificateError> {
        restore_digest(bytes).map(Self)
    }

    /// Borrow bytes for provider binding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

fn digest_frame(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Move-only device-policy authorization receipt.
pub struct DevicePolicyAuthorizationReceipt {
    provenance: httpserve::AuthorizationProvenance,
    durable_policy: httpserve::DurablePolicyAuthorization,
    scope: DeviceCertificateScope,
    request_digest: DevicePolicyRequestDigest,
}

impl DevicePolicyAuthorizationReceipt {
    fn mint(
        provenance: httpserve::AuthorizationProvenance,
        binding: &httpserve::DevicePolicyCandidateBindingKey,
        device: DeviceId,
        request_digest: DevicePolicyRequestDigest,
    ) -> Option<Self> {
        let expected_resource = device.as_uuid().hyphenated().to_string();
        let durable_policy = provenance.device_policy_candidate(binding).cloned()?;
        let exact = provenance.contract_id() == POLICY_WRITE_CONTRACT_ID
            && provenance.permission() == POLICY_WRITE_PERMISSION
            && provenance.principal_kind() == rss_request_context::PrincipalKind::User
            && provenance
                .resource()
                .is_some_and(|resource| resource.id() == expected_resource);
        if !exact {
            return None;
        }
        Some(Self {
            scope: DeviceCertificateScope::from_authorized(provenance.tenant_id(), device),
            provenance,
            durable_policy,
            request_digest,
        })
    }

    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }

    pub const fn request_digest(&self) -> &DevicePolicyRequestDigest {
        &self.request_digest
    }

    pub fn principal_kind(&self) -> rss_request_context::PrincipalKind {
        self.provenance.principal_kind()
    }

    pub fn principal_id(&self) -> &str {
        self.provenance.principal_id()
    }

    pub fn contract_id(&self) -> &'static str {
        self.provenance.contract_id()
    }

    pub fn permission(&self) -> vocab::RoutePermissionId {
        self.provenance.permission()
    }

    pub fn durable_policy(&self) -> &httpserve::DurablePolicyAuthorization {
        &self.durable_policy
    }
}

impl std::fmt::Debug for DevicePolicyAuthorizationReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DevicePolicyAuthorizationReceipt(<redacted>)")
    }
}

/// Sealed desired-policy accept input. Scope, digest, and lineage come from one receipt.
pub struct AcceptDesiredPolicy {
    authorization: DevicePolicyAuthorizationReceipt,
    expected_generation: ExpectedGeneration,
    idempotency_key: DevicePolicyIdempotencyKey,
    policy: CertificatePolicy,
    request_id: httpserve::VerifiedRequestId,
    correlation_id: diagctx::CorrelationId,
}

impl AcceptDesiredPolicy {
    /// Consume exact route authorization into a sealed desired-policy input.
    ///
    /// The subject must bind the policy-put contract, write permission, path device, and a durable
    /// policy basis. All clones share one provenance slot: once authorization is taken, later
    /// attempts return [`DevicePolicyAcceptInputError::Unauthorized`], including an attempt that
    /// fails exact receipt binding. Invalid generation input is rejected before consuming that
    /// slot.
    pub(crate) fn from_authorized_http_subject(
        subject: &httpserve::AuthorizedSubject,
        binding: &httpserve::DevicePolicyCandidateBindingKey,
        device: DeviceId,
        expected_generation: ExpectedGeneration,
        idempotency_key: DevicePolicyIdempotencyKey,
        policy: CertificatePolicy,
        request_id: httpserve::VerifiedRequestId,
        correlation_id: diagctx::CorrelationId,
    ) -> Result<Self, DevicePolicyAcceptInputError> {
        expected_generation
            .next()
            .map_err(DevicePolicyAcceptInputError::InvalidInput)?;
        let request_digest = DevicePolicyRequestDigest::derive(expected_generation, &policy);
        let provenance = subject
            .take_authorization_provenance()
            .map_err(|_| DevicePolicyAcceptInputError::Unauthorized)?;
        let authorization =
            DevicePolicyAuthorizationReceipt::mint(provenance, binding, device, request_digest)
                .ok_or(DevicePolicyAcceptInputError::Unauthorized)?;
        Ok(Self {
            authorization,
            expected_generation,
            idempotency_key,
            policy,
            request_id,
            correlation_id,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only constructor for downstream adapter conformance.
    pub fn for_test(
        scope: DeviceCertificateScope,
        expected_generation: ExpectedGeneration,
        idempotency_key: DevicePolicyIdempotencyKey,
        policy: CertificatePolicy,
        request_id: httpserve::VerifiedRequestId,
        correlation_id: diagctx::CorrelationId,
    ) -> Result<Self, DevicePolicyAcceptInputError> {
        use std::num::NonZeroU32;

        let policy_ref =
            httpserve::AuthorizationPolicyReference::new("test-device-policy", NonZeroU32::MIN)
                .ok_or(DevicePolicyAcceptInputError::Unauthorized)?;
        Self::for_test_with_authorization_basis(
            scope,
            expected_generation,
            idempotency_key,
            policy,
            request_id,
            correlation_id,
            "test-device-policy-authorizer",
            vec![policy_ref],
            [0xA5; httpserve::AUTHORIZATION_FINGERPRINT_BYTES],
            SystemTime::UNIX_EPOCH,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    /// Test-only constructor that preserves an explicit durable authorization basis.
    pub fn for_test_with_authorization_basis(
        scope: DeviceCertificateScope,
        expected_generation: ExpectedGeneration,
        idempotency_key: DevicePolicyIdempotencyKey,
        policy: CertificatePolicy,
        request_id: httpserve::VerifiedRequestId,
        correlation_id: diagctx::CorrelationId,
        principal_id: impl Into<String>,
        policies: Vec<httpserve::AuthorizationPolicyReference>,
        obligation_fingerprint: [u8; httpserve::AUTHORIZATION_FINGERPRINT_BYTES],
        evaluated_at: SystemTime,
    ) -> Result<Self, DevicePolicyAcceptInputError> {
        let resource =
            httpserve::RouteResource::new(scope.device().as_uuid().hyphenated().to_string())
                .ok_or(DevicePolicyAcceptInputError::Unauthorized)?;
        let binding = httpserve::DevicePolicyCandidateBindingKey::new();
        let subject = httpserve::AuthorizedSubject::for_test_with_device_policy_candidate(
            binding.clone(),
            POLICY_WRITE_CONTRACT_ID,
            POLICY_WRITE_PERMISSION,
            scope.tenant(),
            rss_request_context::PrincipalKind::User,
            principal_id,
            Some(resource),
            policies,
            obligation_fingerprint,
            evaluated_at,
        )
        .ok_or(DevicePolicyAcceptInputError::Unauthorized)?;
        Self::from_authorized_http_subject(
            &subject,
            &binding,
            scope.device(),
            expected_generation,
            idempotency_key,
            policy,
            request_id,
            correlation_id,
        )
    }

    /// Tenant/device persistence scope.
    #[must_use]
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.authorization.scope()
    }

    /// Expected current generation.
    #[must_use]
    pub const fn expected_generation(&self) -> ExpectedGeneration {
        self.expected_generation
    }

    /// Caller UUID under the sealed tenant/device operation scope.
    #[must_use]
    pub const fn idempotency_key(&self) -> DevicePolicyIdempotencyKey {
        self.idempotency_key
    }

    /// Canonical request identity derived inside the sealed constructor.
    #[must_use]
    pub const fn request_digest(&self) -> &DevicePolicyRequestDigest {
        self.authorization.request_digest()
    }

    /// Strictly newer generation derived from the expectation.
    pub fn next_generation(&self) -> Result<DesiredGeneration, DeviceCertificateError> {
        self.expected_generation.next()
    }

    /// Canonical desired policy. No independent hash can be supplied.
    #[must_use]
    pub const fn policy(&self) -> &CertificatePolicy {
        &self.policy
    }

    /// Transport-verified request identity persisted with the accepted operation.
    #[must_use]
    pub fn request_id(&self) -> &str {
        self.request_id.as_str()
    }

    /// Validated diagnostic correlation identity persisted with the accepted operation.
    #[must_use]
    pub fn correlation_id(&self) -> &str {
        self.correlation_id.as_str()
    }

    pub const fn authorization(&self) -> &DevicePolicyAuthorizationReceipt {
        &self.authorization
    }
}

impl std::fmt::Debug for AcceptDesiredPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AcceptDesiredPolicy(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DevicePolicyAcceptInputError {
    #[error("device policy input is invalid")]
    InvalidInput(#[source] DeviceCertificateError),
    #[error("device policy request is not authorized")]
    Unauthorized,
}

/// Closed deterministic condition returned when a desired policy is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DesiredPolicyAcceptedCondition {
    /// Desired intent is durable and reconciliation has not yet converged.
    Reconciling,
}

impl DesiredPolicyAcceptedCondition {
    /// Stable persistence/wire label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Reconciling => "reconciling",
        }
    }
}

/// Deterministic accepted response persisted for exact idempotency replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredPolicyAccepted {
    authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
    accepted_generation: DesiredGeneration,
    condition: DesiredPolicyAcceptedCondition,
}

impl DesiredPolicyAccepted {
    /// Construct the only condition valid for a newly accepted desired policy.
    #[must_use]
    pub const fn fresh(
        authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
        accepted_generation: DesiredGeneration,
    ) -> Self {
        Self {
            authorization_receipt_id,
            accepted_generation,
            condition: DesiredPolicyAcceptedCondition::Reconciling,
        }
    }

    /// Restore the append-once accepted operation result.
    #[must_use]
    pub const fn restore(
        authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
        accepted_generation: DesiredGeneration,
        condition: DesiredPolicyAcceptedCondition,
    ) -> Self {
        Self {
            authorization_receipt_id,
            accepted_generation,
            condition,
        }
    }

    /// Durable authorization decision committed with this accepted generation.
    #[must_use]
    pub const fn authorization_receipt_id(&self) -> DevicePolicyAuthorizationReceiptId {
        self.authorization_receipt_id
    }

    /// Desired generation committed by the accepted operation.
    #[must_use]
    pub const fn accepted_generation(&self) -> DesiredGeneration {
        self.accepted_generation
    }

    /// Closed accepted condition.
    #[must_use]
    pub const fn condition(&self) -> DesiredPolicyAcceptedCondition {
        self.condition
    }
}

/// Raw desired row accepted only by [`DesiredStateSnapshot::restore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredStateRestore {
    generation: u64,
    authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
    policy_hash: PolicyHash,
    policy: CertificatePolicy,
    created_at: SystemTime,
    updated_at: SystemTime,
}

impl DesiredStateRestore {
    /// Assemble raw database values for the restore funnel.
    #[must_use]
    pub fn new(
        generation: u64,
        authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
        policy_hash: PolicyHash,
        policy: CertificatePolicy,
        created_at: SystemTime,
        updated_at: SystemTime,
    ) -> Self {
        Self {
            generation,
            authorization_receipt_id,
            policy_hash,
            policy,
            created_at,
            updated_at,
        }
    }
}

/// Always-valid desired persistence snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredStateSnapshot {
    generation: DesiredGeneration,
    authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
    policy_hash: PolicyHash,
    policy: CertificatePolicy,
    created_at: SystemTime,
    updated_at: SystemTime,
}

impl DesiredStateSnapshot {
    /// Validate one raw desired row.
    pub fn restore(input: DesiredStateRestore) -> Result<Self, DeviceCertificateError> {
        if input.updated_at < input.created_at {
            return Err(DeviceCertificateError::InvalidTimestampOrder);
        }
        Ok(Self {
            generation: DesiredGeneration::try_new(input.generation)?,
            authorization_receipt_id: input.authorization_receipt_id,
            policy_hash: input.policy_hash,
            policy: input.policy,
            created_at: input.created_at,
            updated_at: input.updated_at,
        })
    }

    /// Desired high-water generation.
    #[must_use]
    pub const fn generation(&self) -> DesiredGeneration {
        self.generation
    }

    /// Authorization receipt whose allow decision owns this desired generation.
    #[must_use]
    pub const fn authorization_receipt_id(&self) -> DevicePolicyAuthorizationReceiptId {
        self.authorization_receipt_id
    }

    /// Database-generated policy hash.
    #[must_use]
    pub const fn policy_hash(&self) -> &PolicyHash {
        &self.policy_hash
    }

    /// Canonical desired policy.
    #[must_use]
    pub const fn policy(&self) -> &CertificatePolicy {
        &self.policy
    }

    /// Database creation time.
    #[must_use]
    pub const fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Database update time.
    #[must_use]
    pub const fn updated_at(&self) -> SystemTime {
        self.updated_at
    }
}

/// Sealed reported-state high-water mutation input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedStateWrite {
    scope: DeviceCertificateScope,
    observed_generation: ObservedGeneration,
    fence_epoch: FenceEpoch,
    state_hash: ReportedStateHash,
    artifact_digest: ArtifactDigest,
    report_envelope_id: ReportEnvelopeId,
    device_sequence: DeviceSequence,
    expires_at: Option<SystemTime>,
    device_observed_at: Option<SystemTime>,
}

impl ReportedStateWrite {
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn from_authenticated_report(
        scope: DeviceCertificateScope,
        observed_generation: ObservedGeneration,
        fence_epoch: FenceEpoch,
        state_hash: ReportedStateHash,
        artifact_digest: ArtifactDigest,
        report_envelope_id: ReportEnvelopeId,
        device_sequence: DeviceSequence,
        expires_at: Option<SystemTime>,
        device_observed_at: Option<SystemTime>,
    ) -> Self {
        Self {
            scope,
            observed_generation,
            fence_epoch,
            state_hash,
            artifact_digest,
            report_envelope_id,
            device_sequence,
            expires_at,
            device_observed_at,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only constructor for adapter conformance.
    #[allow(clippy::too_many_arguments)]
    pub fn for_test(
        scope: DeviceCertificateScope,
        observed_generation: ObservedGeneration,
        fence_epoch: FenceEpoch,
        state_hash: ReportedStateHash,
        artifact_digest: ArtifactDigest,
        report_envelope_id: ReportEnvelopeId,
        device_sequence: DeviceSequence,
        expires_at: Option<SystemTime>,
        device_observed_at: Option<SystemTime>,
    ) -> Self {
        Self::from_authenticated_report(
            scope,
            observed_generation,
            fence_epoch,
            state_hash,
            artifact_digest,
            report_envelope_id,
            device_sequence,
            expires_at,
            device_observed_at,
        )
    }

    /// Tenant/device persistence scope.
    #[must_use]
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }

    /// Positive observed generation.
    #[must_use]
    pub const fn observed_generation(&self) -> ObservedGeneration {
        self.observed_generation
    }

    /// Positive report epoch, recorded but not validated as current by this repository.
    #[must_use]
    pub const fn fence_epoch(&self) -> FenceEpoch {
        self.fence_epoch
    }

    /// Reported public-state digest.
    #[must_use]
    pub const fn state_hash(&self) -> &ReportedStateHash {
        &self.state_hash
    }

    /// Reported public artifact digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &ArtifactDigest {
        &self.artifact_digest
    }

    /// Stable report envelope identity.
    #[must_use]
    pub const fn report_envelope_id(&self) -> &ReportEnvelopeId {
        &self.report_envelope_id
    }

    /// Device sequence high-water candidate.
    #[must_use]
    pub const fn device_sequence(&self) -> DeviceSequence {
        self.device_sequence
    }

    /// Informative observed expiry.
    #[must_use]
    pub const fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// Informative device clock value.
    #[must_use]
    pub const fn device_observed_at(&self) -> Option<SystemTime> {
        self.device_observed_at
    }
}

/// Raw reported row accepted only by [`ReportedStateSnapshot::restore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedStateRestore {
    observed_generation: u64,
    fence_epoch: u64,
    state_hash: ReportedStateHash,
    artifact_digest: ArtifactDigest,
    report_envelope_id: ReportEnvelopeId,
    device_sequence: DeviceSequence,
    expires_at: Option<SystemTime>,
    device_observed_at: Option<SystemTime>,
    received_at: SystemTime,
}

impl ReportedStateRestore {
    /// Assemble raw database values for the restore funnel.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        observed_generation: u64,
        fence_epoch: u64,
        state_hash: ReportedStateHash,
        artifact_digest: ArtifactDigest,
        report_envelope_id: ReportEnvelopeId,
        device_sequence: DeviceSequence,
        expires_at: Option<SystemTime>,
        device_observed_at: Option<SystemTime>,
        received_at: SystemTime,
    ) -> Self {
        Self {
            observed_generation,
            fence_epoch,
            state_hash,
            artifact_digest,
            report_envelope_id,
            device_sequence,
            expires_at,
            device_observed_at,
            received_at,
        }
    }
}

/// Always-valid positive reported high-water snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedStateSnapshot {
    observed_generation: ObservedGeneration,
    fence_epoch: FenceEpoch,
    state_hash: ReportedStateHash,
    artifact_digest: ArtifactDigest,
    report_envelope_id: ReportEnvelopeId,
    device_sequence: DeviceSequence,
    expires_at: Option<SystemTime>,
    device_observed_at: Option<SystemTime>,
    received_at: SystemTime,
}

impl ReportedStateSnapshot {
    /// Validate one raw reported row.
    pub fn restore(input: ReportedStateRestore) -> Result<Self, DeviceCertificateError> {
        Ok(Self {
            observed_generation: ObservedGeneration::try_new(input.observed_generation)?,
            fence_epoch: FenceEpoch::try_new(input.fence_epoch)?,
            state_hash: input.state_hash,
            artifact_digest: input.artifact_digest,
            report_envelope_id: input.report_envelope_id,
            device_sequence: input.device_sequence,
            expires_at: input.expires_at,
            device_observed_at: input.device_observed_at,
            received_at: input.received_at,
        })
    }

    /// Positive observed generation.
    #[must_use]
    pub const fn observed_generation(&self) -> ObservedGeneration {
        self.observed_generation
    }

    /// Report-carried epoch.
    #[must_use]
    pub const fn fence_epoch(&self) -> FenceEpoch {
        self.fence_epoch
    }

    /// Reported public-state digest.
    #[must_use]
    pub const fn state_hash(&self) -> &ReportedStateHash {
        &self.state_hash
    }

    /// Reported public artifact digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &ArtifactDigest {
        &self.artifact_digest
    }

    /// Stable report envelope identity.
    #[must_use]
    pub const fn report_envelope_id(&self) -> &ReportEnvelopeId {
        &self.report_envelope_id
    }

    /// Accepted device sequence.
    #[must_use]
    pub const fn device_sequence(&self) -> DeviceSequence {
        self.device_sequence
    }

    /// Informative observed expiry.
    #[must_use]
    pub const fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// Informative device observation time.
    #[must_use]
    pub const fn device_observed_at(&self) -> Option<SystemTime> {
        self.device_observed_at
    }

    /// Authoritative database receive time.
    #[must_use]
    pub const fn received_at(&self) -> SystemTime {
        self.received_at
    }
}

/// Duplicate-free, canonically ordered timestamp-free condition mutations.
///
/// Production callers cannot mint a batch directly; an authorized identity use case must perform
/// that step inside this crate.
///
/// ```compile_fail
/// use identity::ports::device_certificate::ConditionStateBatch;
///
/// let _ = ConditionStateBatch::new(Vec::new());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionStateBatch(Vec<DeviceConditionState>);

impl ConditionStateBatch {
    /// Validate one mutation batch without accepting transition timestamps.
    #[allow(dead_code)]
    pub(crate) fn new(
        mut states: Vec<DeviceConditionState>,
    ) -> Result<Self, DeviceCertificateError> {
        states.sort_by_key(|state| condition_rank(state.kind()));
        if states
            .windows(2)
            .any(|pair| pair[0].kind() == pair[1].kind())
        {
            return Err(DeviceCertificateError::DuplicateConditionKind);
        }
        Ok(Self(states))
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only constructor for downstream adapter conformance.
    pub fn for_test(states: Vec<DeviceConditionState>) -> Result<Self, DeviceCertificateError> {
        Self::new(states)
    }

    /// Borrow canonical condition states.
    #[must_use]
    pub fn states(&self) -> &[DeviceConditionState] {
        &self.0
    }

    /// Consume for adapter lowering.
    #[must_use]
    pub fn into_states(self) -> Vec<DeviceConditionState> {
        self.0
    }
}

fn condition_rank(kind: DeviceConditionKind) -> usize {
    DeviceConditionKind::ALL
        .iter()
        .position(|candidate| *candidate == kind)
        .unwrap_or(DeviceConditionKind::ALL.len())
}

fn snapshot_observed_generation(snapshot: &DeviceConditionSnapshot) -> Option<ObservedGeneration> {
    match snapshot {
        DeviceConditionSnapshot::Ready(value) => value.observed_generation(),
        DeviceConditionSnapshot::Reconciling(value) => value.observed_generation(),
        DeviceConditionSnapshot::PendingDevice(value) => value.observed_generation(),
        DeviceConditionSnapshot::Degraded(value) => value.observed_generation(),
        DeviceConditionSnapshot::Quarantined(value) => value.observed_generation(),
        DeviceConditionSnapshot::Deleting(value) => value.observed_generation(),
    }
}

/// Complete validated persistence snapshot. It carries no current-fence or readiness evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificateStateSnapshot {
    scope: DeviceCertificateScope,
    desired: DesiredStateSnapshot,
    reported: Option<ReportedStateSnapshot>,
    conditions: Vec<DeviceConditionSnapshot>,
}

impl DeviceCertificateStateSnapshot {
    /// Restore all rows while preserving storage-level generation invariants.
    pub fn restore(
        scope: DeviceCertificateScope,
        desired: DesiredStateRestore,
        reported: Option<ReportedStateRestore>,
        conditions: Vec<DeviceConditionRestore>,
    ) -> Result<Self, DeviceCertificateError> {
        Self::restore_inner(scope, desired, reported, conditions, None)
    }

    /// Restore persisted state containing `Ready=True` only with freshly revalidated current
    /// certificate evidence. The proof is consumed by the shared DeviceLatent restore funnel.
    pub fn restore_with_ready_proof(
        scope: DeviceCertificateScope,
        desired: DesiredStateRestore,
        reported: Option<ReportedStateRestore>,
        conditions: Vec<DeviceConditionRestore>,
        proof: super::CertificateReadyProof,
    ) -> Result<Self, DeviceCertificateError> {
        Self::restore_inner(scope, desired, reported, conditions, Some(proof))
    }

    fn restore_inner(
        scope: DeviceCertificateScope,
        desired: DesiredStateRestore,
        reported: Option<ReportedStateRestore>,
        conditions: Vec<DeviceConditionRestore>,
        mut ready_proof: Option<super::CertificateReadyProof>,
    ) -> Result<Self, DeviceCertificateError> {
        let desired = DesiredStateSnapshot::restore(desired)?;
        let reported = reported.map(ReportedStateSnapshot::restore).transpose()?;
        if reported
            .as_ref()
            .is_some_and(|value| value.observed_generation().get() > desired.generation().get())
        {
            return Err(DeviceCertificateError::ReportedAheadOfDesired);
        }
        if ready_proof.as_ref().is_some_and(|proof| {
            proof.scope() != scope
                || proof.generation().get() != desired.generation().get()
                || proof.policy_hash() != desired.policy_hash()
                || reported.as_ref().is_none_or(|report| {
                    proof.fence_epoch() != report.fence_epoch()
                        || proof.state_hash() != report.state_hash()
                        || proof.artifact_digest() != report.artifact_digest()
                        || proof.report_envelope_id() != report.report_envelope_id()
                        || proof.device_sequence() != report.device_sequence()
                        || proof.report_received_at() != report.received_at()
                })
        }) {
            return Err(DeviceCertificateError::InvalidPersistedValue);
        }
        let mut restored_conditions = Vec::with_capacity(conditions.len());
        for condition in conditions {
            let restored = match &condition {
                DeviceConditionRestore::Ready(value)
                    if value.status() == deviceloop::ConditionStatus::True =>
                {
                    let proof = ready_proof
                        .take()
                        .ok_or(DeviceCertificateError::InvalidPersistedValue)?;
                    DeviceCondition::restore_ready(condition, proof.into_core())?
                }
                _ => DeviceCondition::restore(condition)?,
            };
            restored_conditions.push(restored.snapshot());
        }
        if ready_proof.is_some() {
            return Err(DeviceCertificateError::InvalidPersistedValue);
        }
        let mut conditions = restored_conditions;
        conditions.sort_by_key(|condition| condition_rank(condition.kind()));
        if conditions
            .windows(2)
            .any(|pair| pair[0].kind() == pair[1].kind())
        {
            return Err(DeviceCertificateError::DuplicateConditionKind);
        }
        if conditions.iter().any(|condition| {
            snapshot_observed_generation(condition)
                .is_some_and(|generation| generation.get() > desired.generation().get())
        }) {
            return Err(DeviceCertificateError::ConditionAheadOfDesired);
        }
        Ok(Self {
            scope,
            desired,
            reported,
            conditions,
        })
    }

    /// Tenant/device persistence scope.
    #[must_use]
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }

    /// Desired snapshot.
    #[must_use]
    pub const fn desired(&self) -> &DesiredStateSnapshot {
        &self.desired
    }

    /// Optional positive reported high-water.
    #[must_use]
    pub const fn reported(&self) -> Option<&ReportedStateSnapshot> {
        self.reported.as_ref()
    }

    /// Canonically ordered current conditions.
    #[must_use]
    pub fn conditions(&self) -> &[DeviceConditionSnapshot] {
        &self.conditions
    }
}

/// Compile-time proof that independently meaningful digests cannot be swapped.
///
/// ```compile_fail
/// use identity::ports::device_certificate::{ArtifactDigest, ReportedStateHash};
/// fn wrong(artifact: ArtifactDigest) -> ReportedStateHash { artifact }
/// ```
const _: () = ();
