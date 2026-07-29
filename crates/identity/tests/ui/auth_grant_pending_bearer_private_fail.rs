//! INVARIANT: AUTH-GRANT-BEARER-RELEASE-01 { level = "Hard", exec = "test", source = "trybuild" }

use identity::application::{
    PendingLoginSecrets, PersistedLoginGrantReceipt,
};

fn release_before_persist(
    pending: PendingLoginSecrets,
    forged: PersistedLoginGrantReceipt,
) {
    let _ = pending.release(forged);
}

fn main() {}
