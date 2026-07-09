use identity::ports::{RoleId, RoleRepo, TenantRepoScope};

async fn good<R: RoleRepo>(repo: &R, scope: TenantRepoScope, id: RoleId) {
    let _ = repo.find(scope, id).await;
}

fn main() {}
