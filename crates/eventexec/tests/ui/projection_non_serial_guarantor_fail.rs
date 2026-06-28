//! compile-fail：第 5 参传 `()`（不满足 `SerialInOrderGuarantor` bound）→ E0277。
//!
//! anti-vacuity：证明 bound load-bearing——非 SerialInOrderGuarantor 类型无法绕过门禁
//! （INVARIANT: PROJECTION-SERIAL-WITNESS-01 { level = "Hard", exec = "verify", source = "trybuild" }Hard）。

use std::sync::Arc;

use consistency::{EngineError, Lsn, ProjectionEvent, Projector};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    OwnerCheckpointStore, SaveOutcome,
};
use eventexec::projection::ProjectionHarness;

struct NoopProjector;
impl Projector for NoopProjector {
    async fn apply<E: ProjectionEvent>(&self, _: &E) -> Result<(), EngineError> {
        Ok(())
    }
}

struct NoopCheckpoint;
impl OwnerCheckpointStore for NoopCheckpoint {
    async fn get_checkpoint(
        &self,
        _: &CheckpointOwner,
        _: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
        Ok(None)
    }
    async fn save_checkpoint(
        &self,
        _: &CheckpointOwner,
        _: &CheckpointId,
        _: Lsn,
        _: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError> {
        Ok(SaveOutcome::Saved)
    }
    async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
        Ok(())
    }
}

fn main() {
    // 第 5 参传 `()`：不满足 `SerialInOrderGuarantor` bound → E0277（bound load-bearing anti-vacuity）。
    let _h = ProjectionHarness::new(
        Arc::new(NoopProjector),
        Arc::new(NoopCheckpoint),
        CheckpointOwner::new("owner"),
        CheckpointId::new("proj"),
        (),
    );
}
