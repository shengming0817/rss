//! fail：外部 crate 不可经假想 sibling 路径伪造 LocalTxAttempt。
fn main() {
    let _ = postgres::cotx::LocalTxAttempt::<u32, ()>::committed(1);
}
