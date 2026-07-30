use consistency::{CompensationOutcome, EngineError};
use eventexec::{SagaCompensationContext, SagaForwardContext, SagaStep};
use generated::saga::billing_v1::{
    BillingCaptureReceipt, BillingReserveFundsReceipt, CaptureStep, ReserveFundsStep,
};

#[derive(Debug)]
pub struct Reserve;
impl SagaStep<ReserveFundsStep> for Reserve {
    async fn execute(&self, _: SagaForwardContext) -> Result<BillingReserveFundsReceipt, EngineError> {
        Ok(BillingReserveFundsReceipt { reservation_id: "r".into() })
    }
    async fn compensate(&self, _: SagaCompensationContext, _: BillingReserveFundsReceipt) -> Result<CompensationOutcome, EngineError> {
        Ok(CompensationOutcome::Compensated)
    }
}

#[derive(Debug)]
pub struct Capture;
impl SagaStep<CaptureStep> for Capture {
    async fn execute(&self, _: SagaForwardContext) -> Result<BillingCaptureReceipt, EngineError> {
        Ok(BillingCaptureReceipt { capture_id: "c".into() })
    }
    async fn compensate(&self, _: SagaCompensationContext, _: BillingCaptureReceipt) -> Result<CompensationOutcome, EngineError> {
        Ok(CompensationOutcome::Compensated)
    }
}
