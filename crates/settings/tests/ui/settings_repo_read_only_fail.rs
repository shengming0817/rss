use settings::ports::{ConfigEntry, ConfigRepo, SettingKey, TenantRepoScope};

async fn mutation_cannot_enter_read_slot<R: ConfigRepo>(
    repo: &R,
    scope: TenantRepoScope,
    key: &SettingKey,
    entry: ConfigEntry,
) {
    repo.save(scope, entry).await;
    repo.delete(scope, key).await;
}

fn main() {}
