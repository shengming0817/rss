//! INVARIANT: AUTH-GRANT-STATE-01 { level = "Hard", exec = "verify", source = "trybuild" }

use identity::ports::AuthGrant;

fn value<T>() -> T {
    panic!("compile-fail fixture")
}

fn main() {
    let _ = AuthGrant {
        id: value(),
        tenant: value(),
        user_id: value(),
        auth_time: value(),
        authn_epoch_at_issue: value(),
        status: value(),
        expires_at: value(),
        created_at: value(),
        closed_at: value(),
        close_reason: value(),
    };
}
