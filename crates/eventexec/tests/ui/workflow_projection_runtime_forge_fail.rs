use std::sync::Arc;

use eventexec::{ProjectionRuntime, ProjectionTarget};

fn forge(target: Arc<dyn ProjectionTarget>) -> ProjectionRuntime {
    ProjectionRuntime {
        target,
        spawn: Arc::new(|_, _, _| loop {}),
    }
}

fn main() {}
