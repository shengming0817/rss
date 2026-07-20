//! INVARIANT: AUTH-GRANT-STATE-01 { level = "Hard", exec = "verify", source = "trybuild" }

use identity::ports::AuthGrant;

fn main() {
    let _ = AuthGrant::new_active;
}
