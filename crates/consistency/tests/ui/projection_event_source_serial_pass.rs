//! 串行 ProjectionEventSource 可以泛型静态分发，并可 mint SerialInOrder witness。

use consistency::{
    EngineError, Lsn, PartitionSerialDelivery, ProjectionBatchLimit, ProjectionEventRecord,
    ProjectionEventSource, SerialInOrder,
};

struct SerialSource;

impl PartitionSerialDelivery for SerialSource {}

impl ProjectionEventSource for SerialSource {
    async fn read_from(
        &self,
        _after: Lsn,
        _limit: ProjectionBatchLimit,
    ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
        Ok(Vec::new())
    }
}

fn drives_source<S: ProjectionEventSource>(_source: &S) {}

fn main() {
    let source = SerialSource;
    drives_source(&source);
    let _witness = SerialInOrder::from_source(&source);
}
