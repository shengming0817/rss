//! INVARIANT: REFRESH-PRODUCER-RECEIPT-01 { level = "Hard", exec = "test", source = "trybuild" }

use identity::ports::{
    PersistedRefreshRotationReceipt, RefreshCommitAcknowledgement, RefreshProducerReceipt,
};

fn main() {
    let _route = RefreshProducerReceipt(());
    let _commit = PersistedRefreshRotationReceipt(());
    let _acknowledgement = RefreshCommitAcknowledgement(());
}
