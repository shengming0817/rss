//! INVARIANT: IDENTITY-LOCALTX-COMMAND-01 { level = "Hard", exec = "verify", source = "trybuild" }

use identity::ports::{AuthGrantCloseCommand, LoginGrantMutation};

fn main() {
    let _login = LoginGrantMutation::new;
    let _logout = AuthGrantCloseCommand::new;
}
