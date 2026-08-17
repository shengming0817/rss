use identity::ports::{RoleId, RoleReadRepo};

async fn bad<R: RoleReadRepo>(repo: &R, tenant: rss_request_context::TenantId, id: RoleId) {
    let _ = repo.find(tenant, id).await;
}

fn main() {}
