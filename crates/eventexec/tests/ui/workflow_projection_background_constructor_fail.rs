use std::sync::Arc;

use eventexec::{ProjectionProjector, ProjectionSelector, ProjectionTarget};

fn selector() -> ProjectionSelector {
    panic!("compile-only fixture")
}

fn target() -> Arc<dyn ProjectionTarget> {
    panic!("compile-only fixture")
}

fn main() {
    let _ = ProjectionProjector::new(selector(), target());
}
