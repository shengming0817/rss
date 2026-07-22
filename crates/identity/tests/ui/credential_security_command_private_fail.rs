use identity::ports::{
    AccountCredentialSecurityCommand, AccountSecurityMutation, CredentialSecurityEvent,
    CredentialSecurityFactAuthorization, PendingCredentialSecurityCommit,
};

fn forge(
    mutation: AccountSecurityMutation,
    event: CredentialSecurityEvent,
    pending: PendingCredentialSecurityCommit,
    authorization: CredentialSecurityFactAuthorization,
) {
    let _ = AccountCredentialSecurityCommand {
        mutation,
        event,
        pending,
        authorization,
    };
}

fn main() {}
