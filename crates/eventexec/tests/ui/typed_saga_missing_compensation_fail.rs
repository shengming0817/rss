use consistency::EngineError;
use eventexec::{SagaForwardContext, SagaStep};
use generated::saga::billing_v1::{BillingReserveFundsReceipt, ReserveFundsStep};

#[derive(Debug)]
struct Reserve;

impl SagaStep<ReserveFundsStep> for Reserve {
    async fn execute(&self, _: SagaForwardContext) -> Result<BillingReserveFundsReceipt, EngineError> {
        Ok(BillingReserveFundsReceipt { reservation_id: "r".into() })
    }
}

fn main() {}
