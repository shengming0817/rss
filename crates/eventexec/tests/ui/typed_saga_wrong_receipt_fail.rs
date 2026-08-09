use consistency::CompensationOutcome;
use eventexec::{SagaAttemptOutcome, SagaCompensationContext, SagaForwardContext, SagaProbeOutcome, SagaStep};
use generated::saga::test_support::test_v1::primary::{
    PrepareStep, SagaConformanceCommitReceipt,
};

#[derive(Debug)]
struct WrongReceipt;

impl SagaStep<PrepareStep> for WrongReceipt {
    async fn execute(&self, _: SagaForwardContext) -> SagaAttemptOutcome<SagaConformanceCommitReceipt> {
        SagaAttemptOutcome::Applied(SagaConformanceCommitReceipt { operation_id: "c".into() })
    }
    async fn probe(&self, _: SagaForwardContext) -> SagaProbeOutcome<SagaConformanceCommitReceipt> {
        SagaProbeOutcome::NotApplied
    }
    async fn compensate(
        &self,
        _: SagaCompensationContext,
        _: SagaConformanceCommitReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }
    async fn probe_compensation(
        &self,
        _: SagaCompensationContext,
        _: SagaConformanceCommitReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        SagaProbeOutcome::NotApplied
    }
}

fn main() {}
