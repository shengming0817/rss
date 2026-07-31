//! INVARIANT: SAGA-RECEIPT-COMPLETION-TYPE-01 { level = "Hard", exec = "test", source = "trybuild" }
//! Public callers cannot construct a Completed journal append outside the receipt-store funnel.

use consistency::{SagaJournalAppendRecord, StepName};

fn main() {
    let step = StepName::parse("reserve_funds").expect("valid step");
    let _forged = SagaJournalAppendRecord::completed(1, step);
}
