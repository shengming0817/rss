//! Authenticated ACK/report decoding and durable ingress repository boundary.

use std::num::NonZeroU64;
use std::time::{Duration, SystemTime};

use deviceloop::{
    DesiredGeneration, DeviceCommandId, DeviceIngressDisposition, DeviceIngressEnvelopeId,
    DeviceIngressEvidence, DeviceIngressEvidenceView, DeviceIngressFingerprint,
    DeviceIngressReceipt, DeviceSequence, FenceCoordinate, FenceEpoch, ObservedGeneration,
};
use generated::event::identity_v1::{
    device_certificate_reported, device_command_acked, device_ingress_receipted,
};
use sha2::{Digest as _, Sha256};

use crate::cert_artifact::ArtifactEligibility;

use super::{
    ArtifactDigest, DeviceCertificateScope, DevicePolicyAuthorizationReceiptId, ReportEnvelopeId,
    ReportedStateHash, ReportedStateWrite,
};

const FINGERPRINT_DOMAIN: &[u8] = b"rss.identity.device-ingress-fingerprint.v1";
const PROTOCOL_VIOLATION_FINGERPRINT_DOMAIN: &[u8] =
    b"rss.identity.device-ingress-protocol-violation.v1";
// Payload lineage became mandatory in the v2 projection. The identity version is part of the
// durable id so replay can never reinterpret a pre-lineage v1 fact under the same event id.
const RECEIPT_ID_DOMAIN: &[u8] = b"identity.device-ingress-receipted:v2";

/// Closed set of authenticated MQTT uplink contracts handled by this durable ingress path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceIngressContract {
    CommandAcked,
    CertificateReported,
}

/// Authenticated delivery data accepted by the identity ingress decoder.
///
/// This trait deliberately has no settlement method. Decoding authenticated input and deciding a
/// domain outcome do not prove that a storage transaction committed, so neither operation may
/// mint transport acknowledgement authority.
pub trait DeviceIngressDelivery: Sized + Send {
    fn tenant(&self) -> rss_request_context::TenantId;
    fn device(&self) -> ids::DeviceId;
    fn credential_generation(&self) -> u64;
    fn contract(&self) -> DeviceIngressContract;
    fn correlation_data(&self) -> Option<&[u8]>;
    fn payload(&self) -> &[u8];
}

struct DeviceIngressRequest<'a> {
    tenant: rss_request_context::TenantId,
    device: ids::DeviceId,
    credential_generation: u64,
    contract: DeviceIngressContract,
    ingress_event_id: &'a str,
    payload: &'a [u8],
}

impl DeviceIngressRequest<'_> {
    const fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }
    const fn device(&self) -> ids::DeviceId {
        self.device
    }
    const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }
    const fn contract(&self) -> DeviceIngressContract {
        self.contract
    }
    fn ingress_event_id(&self) -> &str {
        self.ingress_event_id
    }
    const fn payload(&self) -> &[u8] {
        self.payload
    }
}

/// Frozen FACT identity exposed through the owning domain so adapters never depend on codegen.
pub const fn device_ingress_receipt_fact() -> vocab::EventFactBinding {
    device_ingress_receipted::FACT
}

/// Fail-closed decode or public-receipt construction failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceIngressError {
    #[error("device ingress payload is invalid")]
    InvalidPayload,
    #[error("device ingress coordinate is invalid")]
    InvalidCoordinate,
    #[error("device ingress receipt is invalid")]
    InvalidReceipt,
}

/// One typed authenticated ingress mutation. All fields are immutable after decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIngressWrite {
    scope: DeviceCertificateScope,
    credential_generation: u64,
    evidence: DeviceIngressEvidence,
    reported: Option<ReportedStateWrite>,
    payload_scope_matches: bool,
}

impl DeviceIngressWrite {
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub const fn evidence(&self) -> &DeviceIngressEvidence {
        &self.evidence
    }

    pub const fn reported(&self) -> Option<&ReportedStateWrite> {
        self.reported.as_ref()
    }

    pub const fn payload_scope_matches(&self) -> bool {
        self.payload_scope_matches
    }

    /// Derive authority to bind a persistence-joined lineage to this reviewed write.
    pub const fn application_lineage_authority(&self) -> DeviceIngressApplicationLineageAuthority {
        DeviceIngressApplicationLineageAuthority { scope: self.scope }
    }
}

/// Persistence port retained for domain storage integration.
///
/// A successful return is domain data only: callers must not treat this trait or its receipt as a
/// settlement proof. Production settlement additionally requires the concrete provider's opaque
/// commit proof, which is intentionally absent from this interface.
#[allow(async_fn_in_trait)]
pub trait DeviceIngressRepository<E: ArtifactEligibility>: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;
    /// Provider-owned commit result. Identity intentionally imposes no public hydration contract.
    type Commit: Send;

    async fn commit(&self, input: DeviceIngressWrite) -> Result<Self::Commit, Self::Error>;
}

/// Closed preparation result for every authenticated delivery.
pub enum DeviceIngressPreparation {
    /// Well-formed input that must be committed before settlement.
    Accepted(PreparedDeviceIngress),
    /// Stable-envelope malformed input represented by a durable protocol-violation write.
    Rejected(PreparedDeviceIngress),
    /// Input without a persistable stable identity; it may only enter the poison terminal.
    UnaddressablePoison(UnaddressableDeviceIngress),
}

/// Closed, low-cardinality reason for the bounded poison terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaddressableDeviceIngressReason {
    MissingEnvelopeIdentity,
    InvalidEnvelopeIdentity,
    InvalidCredentialGeneration,
}

/// Move-only authority proving identity classified an authenticated delivery as unaddressable.
pub struct UnaddressableDeviceIngress {
    reason: UnaddressableDeviceIngressReason,
}

impl UnaddressableDeviceIngress {
    pub const fn reason(&self) -> UnaddressableDeviceIngressReason {
        self.reason
    }
}

/// Prepared domain write plus the expected receipt identity retained across a provider commit.
///
/// The value is not a durability proof. The storage provider must consume [`Self::into_parts`],
/// commit the write, and return its own opaque commit proof alongside the receipt.
pub struct PreparedDeviceIngress {
    write: DeviceIngressWrite,
    pending: PendingDeviceIngress,
}

impl PreparedDeviceIngress {
    pub const fn write(&self) -> &DeviceIngressWrite {
        &self.write
    }

    pub fn into_parts(self) -> (DeviceIngressWrite, PendingDeviceIngress) {
        (self.write, self.pending)
    }
}

/// Expected receipt identity retained while a concrete provider commits the prepared write.
///
/// Verifying a receipt produces domain data only. It does not authorize PUBACK; only the concrete
/// provider's separately returned opaque proof may enter an assembly-private settlement runner.
pub struct PendingDeviceIngress {
    tenant: rss_request_context::TenantId,
    device: ids::DeviceId,
    ingress_event_id: String,
    expected_evidence: DeviceIngressEvidence,
}

impl PendingDeviceIngress {
    pub fn verify_receipt(
        self,
        receipt: DeviceIngressReceipt,
    ) -> Result<DeviceIngressDomainOutcome, DeviceIngressReceiptMismatch> {
        if receipt.evidence() != &self.expected_evidence {
            return Err(DeviceIngressReceiptMismatch);
        }
        Ok(DeviceIngressDomainOutcome {
            tenant: self.tenant,
            device: self.device,
            ingress_event_id: self.ingress_event_id,
            receipt,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("device ingress repository returned mismatched evidence")]
pub struct DeviceIngressReceiptMismatch;

/// Verified domain outcome. This is intentionally not a settlement proof.
pub struct DeviceIngressDomainOutcome {
    tenant: rss_request_context::TenantId,
    device: ids::DeviceId,
    ingress_event_id: String,
    receipt: DeviceIngressReceipt,
}

impl DeviceIngressDomainOutcome {
    pub const fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    pub const fn device(&self) -> ids::DeviceId {
        self.device
    }

    pub fn ingress_event_id(&self) -> &str {
        &self.ingress_event_id
    }

    pub const fn receipt(&self) -> &DeviceIngressReceipt {
        &self.receipt
    }

    pub fn into_receipt(self) -> DeviceIngressReceipt {
        self.receipt
    }
}

/// Decode one authenticated delivery without committing or settling it.
pub fn prepare_device_ingress<D>(delivery: &D) -> DeviceIngressPreparation
where
    D: DeviceIngressDelivery,
{
    let Some(correlation) = delivery.correlation_data() else {
        return unaddressable(UnaddressableDeviceIngressReason::MissingEnvelopeIdentity);
    };
    let Some(event_id) = std::str::from_utf8(correlation).ok().filter(|value| {
        !value.is_empty()
            && value.len() <= 256
            && value.trim() == *value
            && !value.chars().any(char::is_control)
    }) else {
        return unaddressable(UnaddressableDeviceIngressReason::InvalidEnvelopeIdentity);
    };
    let Ok(envelope_id) = DeviceIngressEnvelopeId::parse(event_id) else {
        return unaddressable(UnaddressableDeviceIngressReason::InvalidEnvelopeIdentity);
    };
    let Some(credential_generation) = NonZeroU64::new(delivery.credential_generation()) else {
        return unaddressable(UnaddressableDeviceIngressReason::InvalidCredentialGeneration);
    };
    let event_id = event_id.to_owned();
    let tenant = delivery.tenant();
    let device = delivery.device();
    let request = DeviceIngressRequest {
        tenant,
        device,
        credential_generation: delivery.credential_generation(),
        contract: delivery.contract(),
        ingress_event_id: &event_id,
        payload: delivery.payload(),
    };
    let write = match decode_device_ingress(request) {
        Ok(write) => write,
        Err(_) => {
            let scope = DeviceCertificateScope::from_authorized(tenant, device);
            let fingerprint = protocol_violation_fingerprint(delivery);
            let write = DeviceIngressWrite {
                scope,
                credential_generation: credential_generation.get(),
                evidence: DeviceIngressEvidence::protocol_violation(
                    envelope_id,
                    credential_generation,
                    fingerprint,
                ),
                reported: None,
                payload_scope_matches: true,
            };
            return DeviceIngressPreparation::Rejected(prepared(tenant, device, event_id, write));
        }
    };
    DeviceIngressPreparation::Accepted(prepared(tenant, device, event_id, write))
}

fn prepared(
    tenant: rss_request_context::TenantId,
    device: ids::DeviceId,
    event_id: String,
    write: DeviceIngressWrite,
) -> PreparedDeviceIngress {
    let expected_evidence = write.evidence().clone();
    PreparedDeviceIngress {
        write,
        pending: PendingDeviceIngress {
            tenant,
            device,
            ingress_event_id: event_id,
            expected_evidence,
        },
    }
}

const fn unaddressable(reason: UnaddressableDeviceIngressReason) -> DeviceIngressPreparation {
    DeviceIngressPreparation::UnaddressablePoison(UnaddressableDeviceIngress { reason })
}

fn decode_device_ingress(
    request: DeviceIngressRequest<'_>,
) -> Result<DeviceIngressWrite, DeviceIngressError> {
    if request.credential_generation() == 0 {
        return Err(DeviceIngressError::InvalidCoordinate);
    }
    let scope = DeviceCertificateScope::from_authorized(request.tenant(), request.device());
    let envelope_id = DeviceIngressEnvelopeId::parse(request.ingress_event_id())
        .map_err(|_| DeviceIngressError::InvalidCoordinate)?;
    match request.contract() {
        DeviceIngressContract::CommandAcked => {
            let payload: device_command_acked::IdentityDeviceCommandAckedPayload =
                serde_json::from_slice(request.payload())
                    .map_err(|_| DeviceIngressError::InvalidPayload)?;
            let canonical =
                serde_json::to_vec(&payload).map_err(|_| DeviceIngressError::InvalidPayload)?;
            let fingerprint = fingerprint(&request, &canonical);
            let (payload_device, evidence) = match payload {
                device_command_acked::IdentityDeviceCommandAckedPayload::ReceivedPayload(value) => {
                    let coordinate = FenceCoordinate::new(
                        DesiredGeneration::try_new(value.desired_generation.get())
                            .map_err(|_| DeviceIngressError::InvalidCoordinate)?,
                        FenceEpoch::try_new(value.fence_epoch.get())
                            .map_err(|_| DeviceIngressError::InvalidCoordinate)?,
                    );
                    let sequence = sequence(value.device_sequence)?;
                    let command_id = DeviceCommandId::parse(&value.command_id)
                        .map_err(|_| DeviceIngressError::InvalidCoordinate)?;
                    (
                        value.device_id,
                        DeviceIngressEvidence::ack_received(
                            envelope_id,
                            command_id,
                            coordinate,
                            sequence,
                            fingerprint,
                        ),
                    )
                }
                device_command_acked::IdentityDeviceCommandAckedPayload::RejectedPayload(value) => {
                    let coordinate = FenceCoordinate::new(
                        DesiredGeneration::try_new(value.desired_generation.get())
                            .map_err(|_| DeviceIngressError::InvalidCoordinate)?,
                        FenceEpoch::try_new(value.fence_epoch.get())
                            .map_err(|_| DeviceIngressError::InvalidCoordinate)?,
                    );
                    let sequence = sequence(value.device_sequence)?;
                    let command_id = DeviceCommandId::parse(&value.command_id)
                        .map_err(|_| DeviceIngressError::InvalidCoordinate)?;
                    (
                        value.device_id,
                        DeviceIngressEvidence::ack_rejected(
                            envelope_id,
                            command_id,
                            coordinate,
                            sequence,
                            fingerprint,
                        ),
                    )
                }
            };
            Ok(DeviceIngressWrite {
                scope,
                credential_generation: request.credential_generation(),
                evidence,
                reported: None,
                payload_scope_matches: payload_device == request.device().as_uuid(),
            })
        }
        DeviceIngressContract::CertificateReported => {
            let payload: device_certificate_reported::IdentityDeviceCertificateReportedPayload =
                serde_json::from_slice(request.payload())
                    .map_err(|_| DeviceIngressError::InvalidPayload)?;
            let canonical =
                serde_json::to_vec(&payload).map_err(|_| DeviceIngressError::InvalidPayload)?;
            let fingerprint = fingerprint(&request, &canonical);
            let observed = ObservedGeneration::try_new(payload.observed_generation.get())
                .map_err(|_| DeviceIngressError::InvalidCoordinate)?;
            let epoch = FenceEpoch::try_new(payload.fence_epoch.get())
                .map_err(|_| DeviceIngressError::InvalidCoordinate)?;
            let sequence = sequence(payload.device_sequence)?;
            let state_hash = ReportedStateHash::parse(&payload.state_hash)
                .map_err(|_| DeviceIngressError::InvalidCoordinate)?;
            let artifact_digest = ArtifactDigest::parse(&payload.artifact_digest)
                .map_err(|_| DeviceIngressError::InvalidCoordinate)?;
            let report_id = ReportEnvelopeId::parse(request.ingress_event_id())
                .map_err(|_| DeviceIngressError::InvalidCoordinate)?;
            let reported = ReportedStateWrite::from_authenticated_report(
                scope,
                observed,
                epoch,
                state_hash,
                artifact_digest,
                report_id,
                sequence,
                payload.expires_at.map(system_time),
                Some(system_time(payload.observed_at)),
            );
            Ok(DeviceIngressWrite {
                scope,
                credential_generation: request.credential_generation(),
                evidence: DeviceIngressEvidence::report(
                    envelope_id,
                    observed,
                    epoch,
                    sequence,
                    fingerprint,
                ),
                reported: Some(reported),
                payload_scope_matches: payload.device_id == request.device().as_uuid(),
            })
        }
    }
}

fn sequence(value: i64) -> Result<DeviceSequence, DeviceIngressError> {
    DeviceSequence::restore(value).map_err(|_| DeviceIngressError::InvalidCoordinate)
}

fn system_time(epoch_micros: i64) -> SystemTime {
    if epoch_micros >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_micros(epoch_micros.unsigned_abs())
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_micros(epoch_micros.unsigned_abs())
    }
}

fn fingerprint(
    request: &DeviceIngressRequest<'_>,
    canonical_payload: &[u8],
) -> DeviceIngressFingerprint {
    let mut digest = Sha256::new();
    digest.update(FINGERPRINT_DOMAIN);
    digest.update(request.tenant().to_string().as_bytes());
    digest.update(request.device().as_uuid().as_bytes());
    digest.update(request.credential_generation().to_be_bytes());
    digest.update(match request.contract() {
        DeviceIngressContract::CommandAcked => b"ack".as_slice(),
        DeviceIngressContract::CertificateReported => b"report".as_slice(),
    });
    digest.update(canonical_payload);
    DeviceIngressFingerprint::from_bytes(digest.finalize().into())
}

fn protocol_violation_fingerprint<D>(delivery: &D) -> DeviceIngressFingerprint
where
    D: DeviceIngressDelivery,
{
    let mut digest = Sha256::new();
    digest.update(PROTOCOL_VIOLATION_FINGERPRINT_DOMAIN);
    digest.update(delivery.tenant().to_string().as_bytes());
    digest.update(delivery.device().as_uuid().as_bytes());
    digest.update(delivery.credential_generation().to_be_bytes());
    digest.update(match delivery.contract() {
        DeviceIngressContract::CommandAcked => b"ack".as_slice(),
        DeviceIngressContract::CertificateReported => b"report".as_slice(),
    });
    digest.update(delivery.payload());
    DeviceIngressFingerprint::from_bytes(digest.finalize().into())
}

/// Exact generated application receipt and deterministic Outbox id.
pub struct DeviceIngressApplicationReceipt {
    scope: DeviceCertificateScope,
    payload: device_ingress_receipted::IdentityDeviceIngressReceiptedPayload,
    outbox_event_id: String,
}

/// Server-restored authorization lineage used only to author a public application receipt.
pub struct DeviceIngressApplicationLineage {
    scope: DeviceCertificateScope,
    authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
    desired_generation: DesiredGeneration,
}

/// Move-only authority derived from one identity-reviewed ingress write.
pub struct DeviceIngressApplicationLineageAuthority {
    scope: DeviceCertificateScope,
}

impl DeviceIngressApplicationLineageAuthority {
    #[cfg(any(test, feature = "test-support"))]
    /// Test-only constructor for provider conformance and persistence fault proofs.
    pub const fn for_test(scope: DeviceCertificateScope) -> Self {
        Self { scope }
    }

    /// Scope that the persistence join must use.
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }

    /// Bind the tenant/device/generation persistence join to the reviewed scope.
    #[must_use]
    pub const fn bind_persisted_join(
        self,
        authorization_receipt_id: DevicePolicyAuthorizationReceiptId,
        desired_generation: DesiredGeneration,
    ) -> DeviceIngressApplicationLineage {
        DeviceIngressApplicationLineage {
            scope: self.scope,
            authorization_receipt_id,
            desired_generation,
        }
    }
}

impl std::fmt::Debug for DeviceIngressApplicationLineage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceIngressApplicationLineage(<redacted>)")
    }
}

impl DeviceIngressApplicationReceipt {
    pub const fn payload(
        &self,
    ) -> &device_ingress_receipted::IdentityDeviceIngressReceiptedPayload {
        &self.payload
    }

    pub fn outbox_event_id(&self) -> &str {
        &self.outbox_event_id
    }

    /// Encode only the frozen receipt FACT with a device-scoped actor and deterministic event id.
    pub async fn reviewed_event(
        &self,
    ) -> Result<eventexec::event::ReviewedEvent, eventexec::event::EventEncodeError> {
        let scope = self.scope;
        crate::outbox_emit::emit_device_ingress_receipted(
            self.payload.clone(),
            scope.tenant(),
            scope.device(),
            consistency::IdemKey::parse(&self.outbox_event_id)
                .map_err(|_| eventexec::event::EventEncodeError::IdempotencyKey)?,
        )
        .await
    }
}

/// Map a receipt carrying verified tenant/device lineage to the frozen public contract.
pub fn application_receipt_with_lineage(
    lineage: DeviceIngressApplicationLineage,
    receipt: &DeviceIngressReceipt,
) -> Result<DeviceIngressApplicationReceipt, DeviceIngressError> {
    let scope = lineage.scope;
    application_receipt(scope, receipt, Some(lineage))
}

/// Map only a non-oracle rejection that has no verified authorization lineage.
pub fn application_receipt_without_lineage(
    scope: DeviceCertificateScope,
    receipt: &DeviceIngressReceipt,
) -> Result<DeviceIngressApplicationReceipt, DeviceIngressError> {
    application_receipt(scope, receipt, None)
}

fn application_receipt(
    scope: DeviceCertificateScope,
    receipt: &DeviceIngressReceipt,
    lineage: Option<DeviceIngressApplicationLineage>,
) -> Result<DeviceIngressApplicationReceipt, DeviceIngressError> {
    let event_id = receipt.evidence().envelope_id().as_str();
    let committed_at = epoch_micros(receipt.committed_at())?;
    let device_id = scope.device().as_uuid();
    let payload = match receipt.disposition() {
        DeviceIngressDisposition::Advanced | DeviceIngressDisposition::DeviceRejected => {
            let lineage = exact_application_lineage(scope, receipt, lineage)?;
            device_ingress_receipted::IdentityDeviceIngressCommittedPayload {
                authorization_receipt_id:
                    generated::device_certificate::AuthorizationReceiptId::try_from_uuid(
                        lineage.authorization_receipt_id.as_uuid(),
                    )
                    .map_err(|_| DeviceIngressError::InvalidReceipt)?,
                committed_at,
                desired_generation: std::num::NonZeroU64::new(
                    lineage.desired_generation.get(),
                )
                .ok_or(DeviceIngressError::InvalidReceipt)?,
                device_id,
                ingress_envelope_id: event_id
                    .parse()
                    .map_err(|_| DeviceIngressError::InvalidReceipt)?,
                outcome: device_ingress_receipted::IdentityDeviceIngressCommittedPayloadOutcome::Committed,
                reason: device_ingress_receipted::IdentityDeviceIngressCommittedPayloadReason::None,
            }
            .into()
        }
        DeviceIngressDisposition::Duplicate => {
            let lineage = exact_application_lineage(scope, receipt, lineage)?;
            device_ingress_receipted::IdentityDeviceIngressDuplicatePayload {
                authorization_receipt_id:
                    generated::device_certificate::AuthorizationReceiptId::try_from_uuid(
                        lineage.authorization_receipt_id.as_uuid(),
                    )
                    .map_err(|_| DeviceIngressError::InvalidReceipt)?,
                committed_at,
                desired_generation: std::num::NonZeroU64::new(
                    lineage.desired_generation.get(),
                )
                .ok_or(DeviceIngressError::InvalidReceipt)?,
                device_id,
                ingress_envelope_id: event_id
                    .parse()
                    .map_err(|_| DeviceIngressError::InvalidReceipt)?,
                outcome: device_ingress_receipted::IdentityDeviceIngressDuplicatePayloadOutcome::Duplicate,
                reason: device_ingress_receipted::IdentityDeviceIngressDuplicatePayloadReason::AlreadyCommitted,
            }
            .into()
        }
        DeviceIngressDisposition::StaleGeneration
        | DeviceIngressDisposition::StaleFence
        | DeviceIngressDisposition::StaleSequence => {
            let Some(lineage) = lineage else {
                return Ok(DeviceIngressApplicationReceipt {
                    scope,
                    payload: rejected_payload(
                        event_id,
                        device_id,
                        committed_at,
                        device_ingress_receipted::IdentityDeviceIngressRejectedPayloadReason::NotAccepted,
                    )?,
                    outbox_event_id: receipt_event_id(scope, event_id),
                });
            };
            let lineage = exact_application_lineage(scope, receipt, Some(lineage))?;
            let reason = match receipt.disposition() {
                DeviceIngressDisposition::StaleGeneration => device_ingress_receipted::IdentityDeviceIngressStalePayloadReason::GenerationStale,
                DeviceIngressDisposition::StaleFence => device_ingress_receipted::IdentityDeviceIngressStalePayloadReason::FenceEpochStale,
                DeviceIngressDisposition::StaleSequence => device_ingress_receipted::IdentityDeviceIngressStalePayloadReason::DeviceSequenceStale,
                _ => return Err(DeviceIngressError::InvalidReceipt),
            };
            device_ingress_receipted::IdentityDeviceIngressStalePayload {
                authorization_receipt_id:
                    generated::device_certificate::AuthorizationReceiptId::try_from_uuid(
                        lineage.authorization_receipt_id.as_uuid(),
                    )
                    .map_err(|_| DeviceIngressError::InvalidReceipt)?,
                committed_at,
                desired_generation: std::num::NonZeroU64::new(lineage.desired_generation.get())
                    .ok_or(DeviceIngressError::InvalidReceipt)?,
                device_id,
                ingress_envelope_id: event_id
                    .parse()
                    .map_err(|_| DeviceIngressError::InvalidReceipt)?,
                outcome: device_ingress_receipted::IdentityDeviceIngressStalePayloadOutcome::Stale,
                reason,
            }
            .into()
        }
        DeviceIngressDisposition::ScopeMismatch => {
            if lineage.is_some() {
                return Err(DeviceIngressError::InvalidReceipt);
            }
            rejected_payload(
                event_id,
                device_id,
                committed_at,
                device_ingress_receipted::IdentityDeviceIngressRejectedPayloadReason::NotAccepted,
            )?
        }
        DeviceIngressDisposition::Rejected => {
            if lineage.is_some() {
                return Err(DeviceIngressError::InvalidReceipt);
            }
            let reason = if matches!(
                receipt.evidence().view(),
                DeviceIngressEvidenceView::ProtocolViolation { .. }
            ) {
                device_ingress_receipted::IdentityDeviceIngressRejectedPayloadReason::ProtocolViolation
            } else {
                device_ingress_receipted::IdentityDeviceIngressRejectedPayloadReason::NotAccepted
            };
            rejected_payload(event_id, device_id, committed_at, reason)?
        }
        DeviceIngressDisposition::OutOfOrder | DeviceIngressDisposition::Late => {
            if lineage.is_some() {
                return Err(DeviceIngressError::InvalidReceipt);
            }
            rejected_payload(event_id, device_id, committed_at, device_ingress_receipted::IdentityDeviceIngressRejectedPayloadReason::ProtocolViolation)?
        }
    };
    Ok(DeviceIngressApplicationReceipt {
        scope,
        payload,
        outbox_event_id: receipt_event_id(scope, event_id),
    })
}

fn exact_application_lineage(
    scope: DeviceCertificateScope,
    receipt: &DeviceIngressReceipt,
    lineage: Option<DeviceIngressApplicationLineage>,
) -> Result<DeviceIngressApplicationLineage, DeviceIngressError> {
    let lineage = lineage.ok_or(DeviceIngressError::InvalidReceipt)?;
    let evidence_generation = match receipt.evidence().view() {
        DeviceIngressEvidenceView::AckReceived { coordinate, .. }
        | DeviceIngressEvidenceView::AckRejected { coordinate, .. } => coordinate.generation(),
        DeviceIngressEvidenceView::Report {
            observed_generation,
            ..
        } => DesiredGeneration::try_new(observed_generation.get())
            .map_err(|_| DeviceIngressError::InvalidReceipt)?,
        DeviceIngressEvidenceView::ProtocolViolation { .. } => {
            return Err(DeviceIngressError::InvalidReceipt);
        }
    };
    if lineage.scope != scope || evidence_generation != lineage.desired_generation {
        return Err(DeviceIngressError::InvalidReceipt);
    }
    Ok(lineage)
}

fn rejected_payload(
    event_id: &str,
    device_id: uuid::Uuid,
    committed_at: i64,
    reason: device_ingress_receipted::IdentityDeviceIngressRejectedPayloadReason,
) -> Result<device_ingress_receipted::IdentityDeviceIngressReceiptedPayload, DeviceIngressError> {
    Ok(
        device_ingress_receipted::IdentityDeviceIngressRejectedPayload {
            committed_at,
            device_id,
            ingress_envelope_id: event_id
                .parse()
                .map_err(|_| DeviceIngressError::InvalidReceipt)?,
            outcome:
                device_ingress_receipted::IdentityDeviceIngressRejectedPayloadOutcome::Rejected,
            reason,
        }
        .into(),
    )
}

fn receipt_event_id(scope: DeviceCertificateScope, event_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(RECEIPT_ID_DOMAIN);
    digest.update(scope.tenant().to_string().as_bytes());
    digest.update(event_id.as_bytes());
    format!("sha256:{:x}", digest.finalize())
}

fn epoch_micros(value: SystemTime) -> Result<i64, DeviceIngressError> {
    let micros = match value.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            i128::try_from(duration.as_micros()).map_err(|_| DeviceIngressError::InvalidReceipt)?
        }
        Err(error) => -i128::try_from(error.duration().as_micros())
            .map_err(|_| DeviceIngressError::InvalidReceipt)?,
    };
    i64::try_from(micros).map_err(|_| DeviceIngressError::InvalidReceipt)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scope() -> DeviceCertificateScope {
        DeviceCertificateScope::for_test(
            rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001")
                .expect("tenant"),
            ids::DeviceId::parse("00000000-0000-4000-8000-000000000002").expect("device"),
        )
    }

    fn receipt(disposition: DeviceIngressDisposition) -> DeviceIngressReceipt {
        DeviceIngressReceipt::restore(
            DeviceIngressEvidence::report(
                DeviceIngressEnvelopeId::parse("ingress-1").expect("event"),
                ObservedGeneration::try_new(1).expect("generation"),
                FenceEpoch::try_new(2).expect("epoch"),
                DeviceSequence::try_new(3).expect("sequence"),
                DeviceIngressFingerprint::from_bytes([7; 32]),
            ),
            disposition,
            SystemTime::UNIX_EPOCH + Duration::from_micros(10),
            SystemTime::UNIX_EPOCH + Duration::from_micros(11),
        )
        .expect("receipt")
    }

    fn lineage() -> DeviceIngressApplicationLineage {
        DeviceIngressWrite {
            scope: scope(),
            credential_generation: 1,
            evidence: receipt(DeviceIngressDisposition::Advanced)
                .evidence()
                .clone(),
            reported: None,
            payload_scope_matches: true,
        }
        .application_lineage_authority()
        .bind_persisted_join(
            DevicePolicyAuthorizationReceiptId::restore(
                uuid::Uuid::parse_str("6cce9c6b-a7c3-4c95-91db-c744dcee8958").expect("receipt id"),
            )
            .expect("receipt id"),
            DesiredGeneration::try_new(1).expect("generation"),
        )
    }

    #[test]
    fn non_oracle_failures_share_not_accepted_wire_reason() {
        for disposition in [
            DeviceIngressDisposition::ScopeMismatch,
            DeviceIngressDisposition::Rejected,
        ] {
            let receipt = application_receipt_without_lineage(scope(), &receipt(disposition))
                .expect("mapping");
            let json = serde_json::to_value(receipt.payload()).expect("json");
            assert_eq!(json["outcome"], "rejected");
            assert_eq!(json["reason"], "NotAccepted");
        }
    }

    #[test]
    fn receipt_event_id_is_stable_and_tenant_scoped() {
        let first = application_receipt_with_lineage(
            lineage(),
            &receipt(DeviceIngressDisposition::Advanced),
        )
        .expect("mapping");
        let second = application_receipt_with_lineage(
            lineage(),
            &receipt(DeviceIngressDisposition::Advanced),
        )
        .expect("mapping");
        assert_eq!(first.outbox_event_id(), second.outbox_event_id());
        assert_ne!(first.outbox_event_id(), "ingress-1");
        let json = serde_json::to_value(first.payload()).expect("json");
        assert_eq!(
            json["authorizationReceiptId"],
            "6cce9c6b-a7c3-4c95-91db-c744dcee8958"
        );
        assert_eq!(json["desiredGeneration"], 1);
    }

    #[test]
    fn lineaged_receipt_identity_never_aliases_pre_lineage_v1_payload() {
        let current = receipt_event_id(scope(), "ingress-1");
        let mut legacy = Sha256::new();
        legacy.update(b"identity.device-ingress-receipted:v1");
        legacy.update(scope().tenant().to_string().as_bytes());
        legacy.update(b"ingress-1");
        assert_ne!(current, format!("sha256:{:x}", legacy.finalize()));
    }

    #[test]
    fn lineaged_outcomes_fail_closed_without_exact_join() {
        let advanced = receipt(DeviceIngressDisposition::Advanced);
        assert!(matches!(
            application_receipt_without_lineage(scope(), &advanced),
            Err(DeviceIngressError::InvalidReceipt)
        ));

        let mismatched = DeviceIngressWrite {
            scope: scope(),
            credential_generation: 1,
            evidence: advanced.evidence().clone(),
            reported: None,
            payload_scope_matches: true,
        }
        .application_lineage_authority()
        .bind_persisted_join(
            DevicePolicyAuthorizationReceiptId::restore(
                uuid::Uuid::parse_str("6cce9c6b-a7c3-4c95-91db-c744dcee8958").expect("receipt"),
            )
            .expect("receipt"),
            DesiredGeneration::try_new(2).expect("generation"),
        );
        assert!(matches!(
            application_receipt_with_lineage(mismatched, &advanced),
            Err(DeviceIngressError::InvalidReceipt)
        ));

        assert!(matches!(
            application_receipt_with_lineage(
                lineage(),
                &receipt(DeviceIngressDisposition::Rejected),
            ),
            Err(DeviceIngressError::InvalidReceipt)
        ));
    }

    #[test]
    fn typed_payload_canonicalization_ignores_json_layout_but_binds_credential_generation() {
        let payload_a = br#"{
            "deviceId":"00000000-0000-4000-8000-000000000002",
            "commandId":"command-1","desiredGeneration":1,"fenceEpoch":2,
            "deviceSequence":3,"result":"received","reason":"None","observedAt":10
        }"#;
        let payload_b = br#"{"observedAt":10,"reason":"None","result":"received",
            "deviceSequence":3,"fenceEpoch":2,"desiredGeneration":1,"commandId":"command-1",
            "deviceId":"00000000-0000-4000-8000-000000000002"}"#;
        let decode = |generation, payload: &[u8]| {
            decode_device_ingress(DeviceIngressRequest {
                tenant: scope().tenant(),
                device: scope().device(),
                credential_generation: generation,
                contract: DeviceIngressContract::CommandAcked,
                ingress_event_id: "ingress-canonical",
                payload,
            })
            .expect("typed ACK")
        };
        let first = decode(7, payload_a);
        let reordered = decode(7, payload_b);
        let rotated_credential = decode(8, payload_b);
        assert_eq!(
            first.evidence().fingerprint(),
            reordered.evidence().fingerprint()
        );
        assert_ne!(
            first.evidence().fingerprint(),
            rotated_credential.evidence().fingerprint()
        );
    }

    #[test]
    fn payload_device_cannot_replace_authenticated_principal() {
        let payload = br#"{
            "deviceId":"00000000-0000-4000-8000-000000000099",
            "commandId":"command-1","desiredGeneration":1,"fenceEpoch":2,
            "deviceSequence":3,"result":"received","reason":"None","observedAt":10
        }"#;
        let write = decode_device_ingress(DeviceIngressRequest {
            tenant: scope().tenant(),
            device: scope().device(),
            credential_generation: 7,
            contract: DeviceIngressContract::CommandAcked,
            ingress_event_id: "ingress-scope-mismatch",
            payload,
        })
        .expect("typed ACK");
        assert_eq!(write.scope(), scope());
        assert!(!write.payload_scope_matches());
    }
}
