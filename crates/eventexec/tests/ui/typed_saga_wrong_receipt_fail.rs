use consistency::CompensationOutcome;
use eventexec::{SagaAttemptOutcome, SagaCompensationContext, SagaForwardContext, SagaProbeOutcome, SagaStep};
use generated::saga::billing_v1::{BillingCaptureReceipt, ReserveFundsStep};

#[derive(Debug)]
struct WrongReceipt;

impl SagaStep<ReserveFundsStep> for WrongReceipt {
    async fn execute(&self, _: SagaForwardContext) -> SagaAttemptOutcome<BillingCaptureReceipt> {
        SagaAttemptOutcome::Applied(BillingCaptureReceipt { capture_id: "c".into() })
    }
    async fn probe(&self, _: SagaForwardContext) -> SagaProbeOutcome<BillingCaptureReceipt> {
        SagaProbeOutcome::NotApplied
    }
    async fn compensate(
        &self,
        _: SagaCompensationContext,
        _: BillingCaptureReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }
    async fn probe_compensation(
        &self,
        _: SagaCompensationContext,
        _: BillingCaptureReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        SagaProbeOutcome::NotApplied
    }
}

fn main() {}
