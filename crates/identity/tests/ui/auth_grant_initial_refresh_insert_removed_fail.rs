//! INVARIANT: AUTH-GRANT-INITIAL-REFRESH-01 { level = "Medium", exec = "test", source = "trybuild" }

use identity::ports::{
    IdentityError, RefreshTokenRecord, RefreshTokenStore, TenantRepoScope,
};

async fn insert_initial<S: RefreshTokenStore>(
    store: &S,
    scope: TenantRepoScope,
    initial: RefreshTokenRecord,
) -> Result<(), IdentityError> {
    store.insert(scope, initial).await
}

fn main() {}
