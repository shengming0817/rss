use eventexec::WorkflowRuntimePlan;

fn main() {
    let _forged = WorkflowRuntimePlan {
        source_runtime_plan_fingerprint: "forged".to_owned(),
        projection_inputs: Vec::new(),
        _projection_captures: Vec::new(),
        projection_targets: Vec::new(),
        sagas: Vec::new(),
        activated: Vec::new(),
    };
}
