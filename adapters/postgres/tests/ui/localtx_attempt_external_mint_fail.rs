//! fail：外部 crate 不可 mint LocalTxAttempt 结算证据。
fn main() {
    let _mint = postgres::LocalTxAttempt::<(), ()>::committed;
}
