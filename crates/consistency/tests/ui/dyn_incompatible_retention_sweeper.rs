//! compile-fail：RetentionSweeper 是 native AFIT 引擎策略端口，只能泛型静态分发。

use consistency::RetentionSweeper;

fn main() {
    let _sweeper: Box<dyn RetentionSweeper>;
}
