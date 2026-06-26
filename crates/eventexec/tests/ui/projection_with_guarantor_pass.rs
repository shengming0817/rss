//! compile-pass：传 `SerialInOrderGuarantor` witness（第 5 参）→ ProjectionHarness 正常构造。
//!
//! 覆盖 INVARIANT: PROJECTION-SERIAL-WITNESS-01（Hard）绿向：串行 source 铸造 witness 可通过门禁。

use std::sync::Arc;

use consistency::{EngineError, Lsn, PartitionSerialDelivery, ProjectionEvent, Projector, SerialInOrder};
use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    OwnerCheckpointStore, SaveOutcome,
};
use eventexec::projection::ProjectionHarness;

// ── 最小 fake Projector ───────────────────────────────────────────────────────

struct NoopProjector;

impl Projector for NoopProjector {
    async fn apply<E: ProjectionEvent>(&self, _: &E) -> Result<(), EngineError> {
        Ok(())
    }
}

// ── 最小 fake OwnerCheckpointStore ───────────────────────────────────────────

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

// ── 测试 fake 串行 source（PartitionSerialDelivery impl 铸造 witness）──────────

struct SerialSrc;
impl PartitionSerialDelivery for SerialSrc {}

fn main() {
    let _h = ProjectionHarness::new(
        Arc::new(NoopProjector),
        Arc::new(NoopCheckpoint),
        CheckpointOwner::new("owner"),
        CheckpointId::new("proj"),
        SerialInOrder::from_source(&SerialSrc),
    );
}
