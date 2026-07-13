//! INVARIANT: IDENTITY-LOCALTX-COMMAND-01 { level = "Hard", exec = "verify", source = "trybuild" }

use identity::ports::{PasswordChangeMutation, SessionId, SessionLogoutMutation};

fn main() {
    let _logout: fn(SessionId) -> SessionLogoutMutation = SessionLogoutMutation::new;
    let _password = PasswordChangeMutation::new;
}
