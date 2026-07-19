use identity::ports::{CredentialRepo, LoginIdentifier, TenantRepoScope};

async fn old_split_gate<R: CredentialRepo>(
    repo: &R,
    scope: TenantRepoScope,
    login: LoginIdentifier,
) {
    let _ = repo
        .lockout_status(scope, login, std::time::SystemTime::UNIX_EPOCH)
        .await;
}

fn main() {}
