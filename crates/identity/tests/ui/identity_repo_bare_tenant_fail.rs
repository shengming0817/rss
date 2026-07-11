use identity::ports::{RoleId, RoleReadRepo, TenantId};

async fn bad<R: RoleReadRepo>(repo: &R, tenant: TenantId, id: RoleId) {
    let _ = repo.find(tenant, id).await;
}

fn main() {}
