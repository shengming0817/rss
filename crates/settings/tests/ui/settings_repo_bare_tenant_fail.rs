use settings::ports::{ConfigRepo, SettingKey, TenantId};

async fn bad<R: ConfigRepo>(repo: &R, tenant: TenantId) {
    let key = SettingKey::parse("app.key").unwrap();
    let _ = repo.find(tenant, &key).await;
}

fn main() {}
