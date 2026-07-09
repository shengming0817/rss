use settings::ports::{ConfigRepo, SettingKey, TenantRepoScope};

async fn good<R: ConfigRepo>(repo: &R, scope: TenantRepoScope) {
    let key = SettingKey::parse("app.key").unwrap();
    let _ = repo.find(scope, &key).await;
}

fn main() {}
