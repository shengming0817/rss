use std::sync::Arc;

use eventexec::{ProjectionId, ProjectionTarget, ProjectionTargetRegistry};

fn old_register(
    registry: &mut ProjectionTargetRegistry,
    projection: ProjectionId,
    target: Arc<dyn ProjectionTarget>,
) {
    registry.register_target(projection, target).unwrap();
}

fn main() {}
