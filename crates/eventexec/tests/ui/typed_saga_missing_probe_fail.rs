use consistency::CompensationOutcome;
use eventexec::{
    SagaAttemptOutcome, SagaCompensationContext, SagaForwardContext, SagaStep,
};
use generated::saga::test_support::test_v1::primary::{
    PrepareStep, SagaConformancePrepareReceipt,
};

#[derive(Debug)]
struct MissingProbe;

impl SagaStep<PrepareStep> for MissingProbe {
    async fn execute(&self, _: SagaForwardContext) -> SagaAttemptOutcome<SagaConformancePrepareReceipt> {
        SagaAttemptOutcome::Applied(SagaConformancePrepareReceipt { operation_id: "p".into() })
    }

    async fn compensate(
        &self,
        _: SagaCompensationContext,
        _: SagaConformancePrepareReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }
}

fn main() {}
