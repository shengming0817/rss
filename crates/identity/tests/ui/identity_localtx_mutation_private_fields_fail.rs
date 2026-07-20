//! INVARIANT: IDENTITY-LOCALTX-COMMAND-01 { level = "Hard", exec = "verify", source = "trybuild" }

use identity::ports::{
    AuthGrantCloseCommand, LoginGrantMutation, PasswordChangeMutation,
};

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
    let _password = PasswordChangeMutation {
        expected: 1,
        next: value(),
        observation: value(),
    };
}
