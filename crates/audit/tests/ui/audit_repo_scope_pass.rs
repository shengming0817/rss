use audit::ports::{AuditPage, AuditReadRepo, TenantRepoScope};

async fn good<R: AuditReadRepo>(repo: &R, scope: TenantRepoScope) {
    let page = AuditPage {
        limit: vocab::Limit::new(10).unwrap(),
        cursor: None,
    };
    let _ = repo.list(scope, page).await;
}

fn main() {}
