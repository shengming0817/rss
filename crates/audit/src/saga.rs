//! Audit-owned typed Saga actions used by the production activation carrier.

use consistency::CompensationOutcome;
use eventexec::{
    SagaAttemptOutcome, SagaCompensationContext, SagaForwardContext, SagaProbeOutcome, SagaStep,
    TypedSagaActionFactory,
};
use generated::saga::audit_v1::{AuditSyntheticMarkerReceipt, Definition, RecordMarkerStep};

#[derive(Debug)]
struct RecordSyntheticMarker;

impl SagaStep<RecordMarkerStep> for RecordSyntheticMarker {
    async fn execute(
        &self,
        context: SagaForwardContext,
    ) -> SagaAttemptOutcome<AuditSyntheticMarkerReceipt> {
        SagaAttemptOutcome::Applied(AuditSyntheticMarkerReceipt {
            marker_id: context.saga_id().as_uuid().to_string(),
        })
    }

    async fn probe(
        &self,
        _context: SagaForwardContext,
    ) -> SagaProbeOutcome<AuditSyntheticMarkerReceipt> {
        SagaProbeOutcome::NotApplied
    }

    async fn compensate(
        &self,
        _context: SagaCompensationContext,
        _receipt: AuditSyntheticMarkerReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }

    async fn probe_compensation(
        &self,
        _context: SagaCompensationContext,
        _receipt: AuditSyntheticMarkerReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        SagaProbeOutcome::NotApplied
    }
}

/// Return the exact generated factory owned by the audit domain.
#[must_use]
pub fn synthetic_activation_factory() -> TypedSagaActionFactory<Definition> {
    TypedSagaActionFactory::<Definition>::builder()
        .register::<RecordSyntheticMarker, _>(|| RecordSyntheticMarker)
        .finish()
}
