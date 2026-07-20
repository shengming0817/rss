//! INVARIANT: AUTH-GRANT-PERSISTED-RECEIPT-01 { level = "Hard", exec = "verify", source = "trybuild" }

use identity::ports::PersistedLoginGrantReceipt;

fn main() {
    let _forged = PersistedLoginGrantReceipt(());
}
