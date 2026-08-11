use identity::ports::{Role, RoleDefinitionLifecycle, TenantRepoScope};

async fn actorless_write<T: RoleDefinitionLifecycle>(
    lifecycle: &T,
    scope: TenantRepoScope,
    role: Role,
) {
    let _ = lifecycle.create_or_update(scope, role).await;
}

fn main() {}
