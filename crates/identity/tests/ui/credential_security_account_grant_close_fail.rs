use std::time::SystemTime;

use identity::ports::{
    AccountSecurityEventKind, AuthGrant, CredentialSecurityEventKind,
};

fn lower_account_event_to_one_grant(grant: AuthGrant) {
    let _ = grant.close(
        CredentialSecurityEventKind::Account(AccountSecurityEventKind::LogoutAll),
        SystemTime::UNIX_EPOCH,
    );
}

fn main() {}
