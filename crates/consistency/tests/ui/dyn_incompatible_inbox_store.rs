//! compile-fail：InboxStore 是 native AFIT 引擎策略端口，只能泛型静态分发。

use consistency::InboxStore;

fn main() {
    let _store: Box<dyn InboxStore>;
}
