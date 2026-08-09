use eventexec::{SagaAttemptOutcome, SagaForwardContext, SagaProbeOutcome, SagaStep};
use generated::saga::test_support::test_v1::primary::{
    PrepareStep, SagaConformancePrepareReceipt,
};

#[derive(Debug)]
struct Reserve;

impl SagaStep<PrepareStep> for Reserve {
    async fn execute(&self, _: SagaForwardContext) -> SagaAttemptOutcome<SagaConformancePrepareReceipt> {
        SagaAttemptOutcome::Applied(SagaConformancePrepareReceipt { operation_id: "p".into() })
    }
    async fn probe(&self, _: SagaForwardContext) -> SagaProbeOutcome<SagaConformancePrepareReceipt> {
        SagaProbeOutcome::NotApplied
    }
}

fn main() {}
