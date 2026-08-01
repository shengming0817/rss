use eventexec::{SagaAttemptOutcome, SagaForwardContext, SagaProbeOutcome, SagaStep};
use generated::saga::billing_v1::{BillingReserveFundsReceipt, ReserveFundsStep};

#[derive(Debug)]
struct Reserve;

impl SagaStep<ReserveFundsStep> for Reserve {
    async fn execute(&self, _: SagaForwardContext) -> SagaAttemptOutcome<BillingReserveFundsReceipt> {
        SagaAttemptOutcome::Applied(BillingReserveFundsReceipt { reservation_id: "r".into() })
    }
    async fn probe(&self, _: SagaForwardContext) -> SagaProbeOutcome<BillingReserveFundsReceipt> {
        SagaProbeOutcome::NotApplied
    }
}

fn main() {}
