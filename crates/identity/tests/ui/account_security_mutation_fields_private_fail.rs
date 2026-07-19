use identity::ports::{AccountSecurityMutation, AccountSecurityState};

fn illegal(expected: AccountSecurityState, next: AccountSecurityState) {
    let _ = AccountSecurityMutation { expected, next };
}

fn main() {}
