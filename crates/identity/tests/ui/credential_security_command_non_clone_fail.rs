use identity::ports::{
    AccountCredentialSecurityCommand, CredentialSecurityCommand,
    CredentialSecurityFactAuthorization, GrantCredentialSecurityCommand,
    PendingCredentialSecurityCommit,
};

fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<AccountCredentialSecurityCommand>();
    assert_clone::<GrantCredentialSecurityCommand>();
    assert_clone::<CredentialSecurityCommand>();
    assert_clone::<CredentialSecurityFactAuthorization>();
    assert_clone::<PendingCredentialSecurityCommit>();
}
