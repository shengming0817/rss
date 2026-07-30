use std::sync::Arc;

use eventexec::{ProjectionId, ProjectionReplayTarget, ProjectionTargetRegistry};

fn old_register(
    registry: &mut ProjectionTargetRegistry,
    projection: ProjectionId,
    target: Arc<dyn ProjectionReplayTarget>,
) {
    registry.register_target(projection, target).unwrap();
}

fn main() {}
