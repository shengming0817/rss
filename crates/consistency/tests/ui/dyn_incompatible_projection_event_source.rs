//! ProjectionEventSource 是 native AFIT 引擎策略端口，不能走 Box<dyn ...>。

use consistency::ProjectionEventSource;

fn main() {
    let _source: Box<dyn ProjectionEventSource>;
}
