use eventexec::{ProjectionPurpose, ProjectionSystemIdentity};

fn main() {
    let _forged = ProjectionSystemIdentity {
        actor: "request-trigger",
        purpose: ProjectionPurpose::BackgroundWorker,
    };
}
