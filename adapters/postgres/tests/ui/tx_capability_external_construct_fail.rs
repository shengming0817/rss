//! fail：外部 crate 不可 struct-literal 构造 `TxCapability`。
fn main() {
    let _ = postgres::TxCapability {};
}
