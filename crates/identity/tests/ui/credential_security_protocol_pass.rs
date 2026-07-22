use identity::ports::{
    AccountSecurityEventKind, CredentialSecurityEventKind, GrantSecurityEventKind,
};

fn main() {
    let account = CredentialSecurityEventKind::Account(AccountSecurityEventKind::PasswordChanged);
    assert_eq!(account.as_db_str(), "password_changed");
    assert_eq!(
        CredentialSecurityEventKind::from_db_str("password_changed"),
        Some(account)
    );

    let logout = CredentialSecurityEventKind::Grant(GrantSecurityEventKind::LogoutCurrent);
    assert_eq!(logout.as_db_str(), "logout_current");

    let reuse = CredentialSecurityEventKind::Grant(GrantSecurityEventKind::RefreshReuseDetected);
    assert_eq!(reuse.as_db_str(), "refresh_reuse_detected");
}
