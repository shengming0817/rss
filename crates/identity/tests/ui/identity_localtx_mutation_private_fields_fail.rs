//! INVARIANT: IDENTITY-LOCALTX-COMMAND-01 { level = "Hard", exec = "verify", source = "trybuild" }

use identity::ports::{AuthGrantCloseCommand, LoginGrantMutation};

fn value<T>() -> T {
    panic!("compile-fail fixture")
}

fn main() {
    let _login = LoginGrantMutation {
        grant: value(),
        initial_refresh: value(),
        persistence: value(),
    };
    let _logout = AuthGrantCloseCommand {
        mutation: value(),
        observation: value(),
    };
}
