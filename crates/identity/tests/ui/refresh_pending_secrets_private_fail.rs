//! INVARIANT: REFRESH-PENDING-SECRETS-01 { level = "Hard", exec = "verify", source = "trybuild" }

use identity::application::PendingRotatedSecrets;

fn main() {
    let _release = PendingRotatedSecrets::release;
}
