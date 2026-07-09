//! compile-pass：typed SagaStep 经 generated SagaContractBinding builder 注册后可 finish。

use std::future::Future;

use consistency::{CompensationOutcome, EngineError, SagaStep, SagaStepCtx};
use eventexec::TypedSagaActionFactory;

const CONTRACT: vocab::ContractBinding = vocab::ContractBinding::from_static(
    "billing",
    "billing.checkout",
    "v1",
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);
const POLICY: vocab::SagaRuntimePolicySpec = vocab::SagaRuntimePolicySpec::from_millis(0, 0);
const STEP: vocab::SagaStepBinding =
    vocab::SagaStepBinding::from_static(CONTRACT, "reserve_funds", "reserve.schema.json");
const STEPS: &[vocab::SagaStepBinding] = &[STEP];
const SPEC: vocab::SagaContractBinding =
    vocab::SagaContractBinding::from_parts(CONTRACT, POLICY, STEPS);

#[derive(Debug, serde::Serialize)]
struct Output {
    reserved: bool,
}

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
        async { Ok(Output { reserved: true }) }
    }

    fn compensate(
        &self,
        _ctx: SagaStepCtx,
    ) -> impl Future<Output = Result<CompensationOutcome, EngineError>> + Send {
        async { Ok(CompensationOutcome::Compensated) }
    }
}

fn main() {
    let mut builder = TypedSagaActionFactory::builder(SPEC);
    builder
        .register_step::<ReserveFundsStep, _>(|| ReserveFundsStep)
        .unwrap();
    let _factory = builder.finish().unwrap();
}
