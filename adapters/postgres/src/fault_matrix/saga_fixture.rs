//! Dedicated typed saga fixture for the postgres fault matrix.
//!
//! This file is the only adapter-side test-support source allowed to hand-author saga binding
//! constants. The public `fault_matrix` harness remains scanned by `contract-binding-guard`.

const CONTRACT: vocab::ContractBinding = vocab::ContractBinding::from_static(
    "billing",
    "billing.checkout",
    "v1",
    "sha256:2196dede9f6ebd39904f753bc7bae7a79d603768018aa9fc4a50f448d23b0e77",
);
pub(super) const RESERVE_STEP: vocab::SagaStepBinding =
    vocab::SagaStepBinding::from_static(CONTRACT, "reserve_funds", "reserve.schema.json");
pub(super) const CAPTURE_STEP: vocab::SagaStepBinding =
    vocab::SagaStepBinding::from_static(CONTRACT, "capture", "capture.schema.json");

#[derive(Debug, serde::Serialize)]
pub(super) struct ReserveFundsOutput {
    step: &'static str,
}

impl ReserveFundsOutput {
    pub(super) const fn new(step: &'static str) -> Self {
        Self { step }
    }
}

impl vocab::SagaStepOutputBinding for ReserveFundsOutput {
    const BINDING: vocab::SagaStepBinding = RESERVE_STEP;
}

#[derive(Debug, serde::Serialize)]
pub(super) struct CaptureOutput {
    step: &'static str,
}

impl CaptureOutput {
    pub(super) const fn new(step: &'static str) -> Self {
        Self { step }
    }
}

impl vocab::SagaStepOutputBinding for CaptureOutput {
    const BINDING: vocab::SagaStepBinding = CAPTURE_STEP;
}
