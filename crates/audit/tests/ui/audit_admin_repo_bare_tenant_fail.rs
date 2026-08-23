use audit::ports::{AuditAdminRepo, AuditPage};
use rss_request_context::TenantId;

async fn bad<R: AuditAdminRepo>(repo: &R, tenant: TenantId) {
    let page = AuditPage {
        limit: vocab::Limit::new(10).unwrap(),
        cursor: None,
    };
    let _ = repo.list_tenant(tenant, page).await;
}

fn main() {}
