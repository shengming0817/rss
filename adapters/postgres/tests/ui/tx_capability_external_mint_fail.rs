//! fail：外部 crate 不可调用 postgres 内部的 TxCapability mint 入口。
fn main() {
    let _mint = postgres::TxCapability::from_transaction;
}
