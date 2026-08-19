//! compile-fail：第 6 参传 `()`（不满足 `SerialInOrderGuarantor` bound）→ E0277。
//!
//! anti-vacuity：证明 bound load-bearing——非 SerialInOrderGuarantor 类型无法绕过门禁
//! （INVARIANT: PROJECTION-SERIAL-WITNESS-01 { level = "Medium", exec = "test", source = "trybuild" }，支持 production 类型 Hard）。

use std::sync::Arc;

use consistency::{Lsn, ProjectionApplyError, ProjectionApplyOutcome, ProjectionEvent, Projector};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, OwnerCheckpointStore, SaveOutcome,
};
use eventexec::projection::ProjectionHarness;

struct NoopProjector;
impl Projector for NoopProjector {
    async fn apply<E: ProjectionEvent>(
        &self,
        _: &E,
    ) -> Result<ProjectionApplyOutcome, ProjectionApplyError> {
        Ok(ProjectionApplyOutcome::Applied)
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

struct NoopDlx;
impl DeadLetterStore for NoopDlx {
    async fn write_dead_letter(&self, _: DeadLetterRecord) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

fn main() {
    // 第 6 参传 `()`：不满足 `SerialInOrderGuarantor` bound → E0277（bound load-bearing anti-vacuity）。
    let _h = ProjectionHarness::new(
        Arc::new(NoopProjector),
        Arc::new(NoopCheckpoint),
        CheckpointOwner::new("owner"),
        CheckpointId::new("proj"),
        Arc::new(NoopDlx),
        (),
    );
}
