//! INVARIANT: IDENTITY-LOCALTX-COMMAND-01 { level = "Hard", exec = "verify", source = "trybuild" }

use identity::ports::{PasswordChangeMutation, SessionLogoutMutation};

fn value<T>() -> T {
    panic!("compile-fail fixture")
}

fn main() {
    let _logout = SessionLogoutMutation {
        session_id: value(),
        observation: value(),
    };
    let _password = PasswordChangeMutation {
        expected: 1,
        next: value(),
        observation: value(),
    };
}
