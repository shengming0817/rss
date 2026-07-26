use assembly_schema::{DeploymentFingerprint, DeploymentPlan, WorkloadPlan};

fn forge(_: DeploymentPlan, _: WorkloadPlan) {
    let _ = DeploymentFingerprint("sha256:00".to_owned());
    let _ = DeploymentPlan {};
    let _ = WorkloadPlan {};
}

fn main() {}
