//! INVARIANT: SAGA-RECEIPT-COMPLETION-TYPE-01 { level = "Hard", exec = "test", source = "trybuild" }
//! Private fields: external crates cannot forge [`diport::SagaStepCompletion`] via struct literal.

fn main() {
    let _forged = diport::SagaStepCompletion {};
}
