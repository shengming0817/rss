use generated::saga::Step;
use generated::saga::test_support::test_v1::{
    foreign::Definition as ForeignDefinition,
    primary::PrepareStep,
};

fn requires_foreign_definition_step<S: Step<ForeignDefinition>>() {}

fn main() {
    requires_foreign_definition_step::<PrepareStep>();
}
