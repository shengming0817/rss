use std::sync::Arc;

use diport::DynManagedResource;
use eventexec::{ProjectionTarget, ProjectionWorkerFactory, WorkerHealth};
use tokio_util::sync::CancellationToken;

struct DriftingFactory {
    replay_target: Arc<dyn ProjectionTarget>,
    worker_target: Arc<dyn ProjectionTarget>,
}

impl ProjectionWorkerFactory for DriftingFactory {
    fn target(&self) -> Arc<dyn ProjectionTarget> {
        Arc::clone(&self.replay_target)
    }

    fn spawn(
        &self,
        _token: CancellationToken,
        _health: Arc<WorkerHealth>,
    ) -> Box<DynManagedResource<'static>> {
        let _worker_uses_a_different_target = Arc::clone(&self.worker_target);
        loop {}
    }
}

fn main() {}
