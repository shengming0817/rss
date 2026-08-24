use identity::ports::{CredentialRepo, LoginIdentifier, TenantRepoScope};

async fn split_authentication<R: CredentialRepo>(
    repo: &R,
    scope: TenantRepoScope,
    login: LoginIdentifier,
) {
    let _ = repo
        .authenticate(scope, login, std::time::SystemTime::UNIX_EPOCH)
        .await;
}

fn main() {}
