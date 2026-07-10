use audit::ports::{AuditAdminRepo, AuditPage, CrossTenantReadScope};

async fn good<R: AuditAdminRepo>(repo: &R, scope: CrossTenantReadScope) {
    let page = AuditPage {
        limit: vocab::Limit::new(10).unwrap(),
        cursor: None,
    };
    let _ = repo.list_tenant(scope, page).await;
}

fn main() {}
