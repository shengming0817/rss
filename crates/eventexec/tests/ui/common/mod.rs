use consistency::CompensationOutcome;
use eventexec::{
    SagaAttemptOutcome, SagaCompensationContext, SagaForwardContext, SagaProbeOutcome, SagaStep,
};
use generated::saga::billing_v1::{
    BillingCaptureReceipt, BillingReserveFundsReceipt, CaptureStep, ReserveFundsStep,
};

#[derive(Debug)]
pub struct Reserve;
impl SagaStep<ReserveFundsStep> for Reserve {
    async fn execute(&self, _: SagaForwardContext) -> SagaAttemptOutcome<BillingReserveFundsReceipt> {
        SagaAttemptOutcome::Applied(BillingReserveFundsReceipt { reservation_id: "r".into() })
    }
    async fn probe(&self, _: SagaForwardContext) -> SagaProbeOutcome<BillingReserveFundsReceipt> {
        SagaProbeOutcome::NotApplied
    }
    async fn compensate(&self, _: SagaCompensationContext, _: BillingReserveFundsReceipt) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }
    async fn probe_compensation(&self, _: SagaCompensationContext, _: BillingReserveFundsReceipt) -> SagaProbeOutcome<CompensationOutcome> {
        SagaProbeOutcome::NotApplied
    }
}

#[derive(Debug)]
pub struct Capture;
impl SagaStep<CaptureStep> for Capture {
    async fn execute(&self, _: SagaForwardContext) -> SagaAttemptOutcome<BillingCaptureReceipt> {
        SagaAttemptOutcome::Applied(BillingCaptureReceipt { capture_id: "c".into() })
    }
    async fn probe(&self, _: SagaForwardContext) -> SagaProbeOutcome<BillingCaptureReceipt> {
        SagaProbeOutcome::NotApplied
    }
    async fn compensate(&self, _: SagaCompensationContext, _: BillingCaptureReceipt) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }
    async fn probe_compensation(&self, _: SagaCompensationContext, _: BillingCaptureReceipt) -> SagaProbeOutcome<CompensationOutcome> {
        SagaProbeOutcome::NotApplied
    }
}
