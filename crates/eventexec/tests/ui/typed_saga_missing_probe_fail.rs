use consistency::CompensationOutcome;
use eventexec::{
    SagaAttemptOutcome, SagaCompensationContext, SagaForwardContext, SagaStep,
};
use generated::saga::billing_v1::{BillingReserveFundsReceipt, ReserveFundsStep};

#[derive(Debug)]
struct MissingProbe;

impl SagaStep<ReserveFundsStep> for MissingProbe {
    async fn execute(&self, _: SagaForwardContext) -> SagaAttemptOutcome<BillingReserveFundsReceipt> {
        SagaAttemptOutcome::Applied(BillingReserveFundsReceipt { reservation_id: "r".into() })
    }

    async fn compensate(
        &self,
        _: SagaCompensationContext,
        _: BillingReserveFundsReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }
}

fn main() {}
