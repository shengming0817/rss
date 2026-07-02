//! compile-fail：Reconciler 是 native AFIT 引擎策略端口，只能泛型静态分发。

use consistency::Reconciler;

fn main() {
    let _reconciler: Box<dyn Reconciler>;
}
