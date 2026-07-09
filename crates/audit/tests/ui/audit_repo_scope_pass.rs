use audit::ports::{AuditPage, AuditRepo, TenantRepoScope};

async fn good<R: AuditRepo>(repo: &R, scope: TenantRepoScope) {
    let page = AuditPage {
        limit: vocab::Limit::new(10).unwrap(),
        cursor: None,
    };
    let _ = repo.list(scope, page).await;
}

fn main() {}
