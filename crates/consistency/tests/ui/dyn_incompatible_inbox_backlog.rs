//! compile-fail：InboxBacklog 是 native AFIT 引擎策略端口，只能泛型静态分发。

use consistency::InboxBacklog;

fn main() {
    let _backlog: Box<dyn InboxBacklog>;
}
