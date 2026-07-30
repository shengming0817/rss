use generated::saga::{Definition, Step};
use generated::saga::billing_v1::ReserveFundsStep;

struct OtherDefinition;

impl Definition for OtherDefinition {
    type Start = ReserveFundsStep;
    const SPEC: generated::saga::SagaSpec = generated::saga::billing_v1::SPEC;
}

fn requires_other_definition_step<S: Step<OtherDefinition>>() {}

fn main() {
    requires_other_definition_step::<ReserveFundsStep>();
}
