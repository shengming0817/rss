use settings::ports::{SecretEntry, SecretKey, SecretRepo, TenantRepoScope};

async fn mutation_cannot_enter_secret_read_slot<R: SecretRepo>(
    repo: &R,
    scope: TenantRepoScope,
    key: &SecretKey,
    entry: SecretEntry,
) {
    repo.save(scope, entry).await;
    repo.delete(scope, key).await;
}

fn main() {}
