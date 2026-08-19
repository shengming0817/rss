//! INVARIANT: SAGA-RECEIPT-COMPLETION-TYPE-01 { level = "Medium", exec = "test", source = "trybuild" }
//! Private fields: external crates cannot forge [`diport::SagaForwardCompletion`] via struct literal.

fn main() {
    let _forged = diport::SagaForwardCompletion {};
}
