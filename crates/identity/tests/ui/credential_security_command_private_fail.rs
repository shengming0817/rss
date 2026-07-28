use identity::ports::{
    AccountCredentialSecurityCommand, AccountSecurityMutation, CredentialSecurityEvent,
    PendingCredentialSecurityCommit,
};

fn forge(
    mutation: AccountSecurityMutation,
    event: CredentialSecurityEvent,
    pending: PendingCredentialSecurityCommit,
) {
    let _ = AccountCredentialSecurityCommand {
        mutation,
        event,
        pending,
    };
}

fn main() {}
