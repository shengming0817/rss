use identity::ports::{RoleId, RoleRepo, TenantId};

async fn bad<R: RoleRepo>(repo: &R, tenant: TenantId, id: RoleId) {
    let _ = repo.find(tenant, id).await;
}

fn main() {}
