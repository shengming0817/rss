use consistency::{CompensationOutcome, EngineError};
use eventexec::{SagaCompensationContext, SagaForwardContext, SagaStep};
use generated::saga::billing_v1::{BillingCaptureReceipt, ReserveFundsStep};

#[derive(Debug)]
struct WrongReceipt;

impl SagaStep<ReserveFundsStep> for WrongReceipt {
    async fn execute(&self, _: SagaForwardContext) -> Result<BillingCaptureReceipt, EngineError> {
        Ok(BillingCaptureReceipt { capture_id: "c".into() })
    }
    async fn compensate(
        &self,
        _: SagaCompensationContext,
        _: BillingCaptureReceipt,
    ) -> Result<CompensationOutcome, EngineError> {
        Ok(CompensationOutcome::Compensated)
    }
}

fn main() {}
