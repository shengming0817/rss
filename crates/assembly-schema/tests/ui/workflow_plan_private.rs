use assembly_schema::{ProjectionActivation, WorkflowActivation, WorkflowPlan};

fn main() {
    let activation = WorkflowActivation::Projection {
        id: "identity.account-view".to_owned(),
        definition_version: "v1".to_owned(),
        definition_schema_digest:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap(),
        target_generation: "materialized-v7".to_owned(),
        activation: ProjectionActivation::Active,
    };
    let _forged = WorkflowPlan(activation);
}
