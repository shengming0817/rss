//! INVARIANT: IDENTITY-SECURITY-ROUTE-RECEIPT-01 { level = "Hard", exec = "verify", source = "trybuild" }

use identity::ports::CredentialSecurityFactAuthorization;

fn main() {
    let _ = core::mem::size_of::<CredentialSecurityFactAuthorization>();
}
