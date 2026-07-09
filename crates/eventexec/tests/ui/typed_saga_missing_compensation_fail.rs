//! compile-fail：SagaStep 必须实现 compensate；缺失补偿不能通过 typed wrapper。

use std::future::Future;

use consistency::{EngineError, SagaStep, SagaStepCtx};

const CONTRACT: vocab::ContractBinding = vocab::ContractBinding::from_static(
    "billing",
    "billing.checkout",
    "v1",
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);
const STEP: vocab::SagaStepBinding =
    vocab::SagaStepBinding::from_static(CONTRACT, "reserve_funds", "reserve.schema.json");

#[derive(Debug, serde::Serialize)]
struct Output;

impl vocab::SagaStepOutputBinding for Output {
    const BINDING: vocab::SagaStepBinding = STEP;
}

#[derive(Debug)]
struct ReserveFundsStep;

impl SagaStep for ReserveFundsStep {
    const BINDING: vocab::SagaStepBinding = STEP;

    type Output = Output;

    fn execute(
        &self,
        _ctx: SagaStepCtx,
    ) -> impl Future<Output = Result<Self::Output, EngineError>> + Send {
        async { Ok(Output) }
    }
}

fn main() {}
