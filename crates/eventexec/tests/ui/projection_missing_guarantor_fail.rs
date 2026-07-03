//! compile-fail：漏第 6 参（`_guarantor` witness）→ E0061（PROJECTION-SERIAL-WITNESS-01 Hard）。
//!
//! 红向：非串行投递路径拿不到 witness ⇒ **编译期**挂不上 projection（fail-closed by absence）。

use std::sync::Arc;

use consistency::{EngineError, Lsn, ProjectionEvent, Projector};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, OwnerCheckpointStore, SaveOutcome,
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
    // 漏第 6 参（_guarantor）→ E0061（参数个数不符，门禁 INVARIANT PROJECTION-SERIAL-WITNESS-01）。
    let _h = ProjectionHarness::new(
        Arc::new(NoopProjector),
        Arc::new(NoopCheckpoint),
        CheckpointOwner::new("owner"),
        CheckpointId::new("proj"),
        Arc::new(NoopDlx),
    );
}
