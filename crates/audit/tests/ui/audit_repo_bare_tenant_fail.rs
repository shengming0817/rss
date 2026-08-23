use audit::ports::{AuditPage, AuditReadRepo};
use rss_request_context::TenantId;

async fn bad<R: AuditReadRepo>(repo: &R, tenant: TenantId) {
    let page = AuditPage {
        limit: vocab::Limit::new(10).unwrap(),
        cursor: None,
    };
    let _ = repo.list(tenant, page).await;
}

fn main() {}
