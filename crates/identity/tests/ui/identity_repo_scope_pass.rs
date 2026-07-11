use identity::ports::{RoleId, RoleReadRepo, TenantRepoScope};

async fn good<R: RoleReadRepo>(repo: &R, scope: TenantRepoScope, id: RoleId) {
    let _ = repo.find(scope, id).await;
}

fn main() {}
