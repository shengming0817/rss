use audit::ports::{AuditPage, AuditRepo, TenantId};

async fn bad<R: AuditRepo>(repo: &R, tenant: TenantId) {
    let page = AuditPage {
        limit: vocab::Limit::new(10).unwrap(),
        cursor: None,
    };
    let _ = repo.list(tenant, page).await;
}

fn main() {}
