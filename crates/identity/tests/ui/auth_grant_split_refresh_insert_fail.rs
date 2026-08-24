//! INVARIANT: AUTH-GRANT-INITIAL-REFRESH-01 { level = "Medium", exec = "test", source = "trybuild" }

use identity::ports::{AuthGrantLifecycle, LoginGrantMutation, TenantRepoScope};

async fn split_refresh_insert<S: AuthGrantLifecycle>(
    lifecycle: &S,
    scope: TenantRepoScope,
    mutation: LoginGrantMutation,
) {
    let _ = lifecycle.persist_login_grant(scope, mutation).await;
}

fn main() {}
