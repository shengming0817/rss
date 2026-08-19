//! INVARIANT: REFRESH-PENDING-SECRETS-01 { level = "Medium", exec = "test", source = "trybuild" }

use identity::application::PendingRotatedSecrets;

fn main() {
    let _release = PendingRotatedSecrets::release;
}
