use eventexec::ActivatedWorkflowsView;

fn main() {
    let _forged = ActivatedWorkflowsView {
        source_runtime_plan_fingerprint: "forged",
        workflows: &[],
    };
}
