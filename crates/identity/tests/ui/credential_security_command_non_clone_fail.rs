use identity::ports::{
    AccountCredentialSecurityCommand, CredentialSecurityCommand, GrantCredentialSecurityCommand,
    PendingCredentialSecurityCommit,
};

fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<AccountCredentialSecurityCommand>();
    assert_clone::<GrantCredentialSecurityCommand>();
    assert_clone::<CredentialSecurityCommand>();
    assert_clone::<PendingCredentialSecurityCommit>();
}
