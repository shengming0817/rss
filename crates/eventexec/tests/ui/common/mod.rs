use consistency::CompensationOutcome;
use eventexec::{
    SagaAttemptOutcome, SagaCompensationContext, SagaForwardContext, SagaProbeOutcome, SagaStep,
};
use generated::saga::test_support::test_v1::primary::{
    CommitStep, PrepareStep, SagaConformanceCommitReceipt, SagaConformancePrepareReceipt,
};

#[derive(Debug)]
pub struct Prepare;
impl SagaStep<PrepareStep> for Prepare {
    async fn execute(&self, _: SagaForwardContext) -> SagaAttemptOutcome<SagaConformancePrepareReceipt> {
        SagaAttemptOutcome::Applied(SagaConformancePrepareReceipt { operation_id: "p".into() })
    }
    async fn probe(&self, _: SagaForwardContext) -> SagaProbeOutcome<SagaConformancePrepareReceipt> {
        SagaProbeOutcome::NotApplied
    }
    async fn compensate(&self, _: SagaCompensationContext, _: SagaConformancePrepareReceipt) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }
    async fn probe_compensation(&self, _: SagaCompensationContext, _: SagaConformancePrepareReceipt) -> SagaProbeOutcome<CompensationOutcome> {
        SagaProbeOutcome::NotApplied
    }
}

#[derive(Debug)]
pub struct Commit;
impl SagaStep<CommitStep> for Commit {
    async fn execute(&self, _: SagaForwardContext) -> SagaAttemptOutcome<SagaConformanceCommitReceipt> {
        SagaAttemptOutcome::Applied(SagaConformanceCommitReceipt { operation_id: "c".into() })
    }
    async fn probe(&self, _: SagaForwardContext) -> SagaProbeOutcome<SagaConformanceCommitReceipt> {
        SagaProbeOutcome::NotApplied
    }
    async fn compensate(&self, _: SagaCompensationContext, _: SagaConformanceCommitReceipt) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }
    async fn probe_compensation(&self, _: SagaCompensationContext, _: SagaConformanceCommitReceipt) -> SagaProbeOutcome<CompensationOutcome> {
        SagaProbeOutcome::NotApplied
    }
}
