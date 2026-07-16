//! `PgRoleBindingReadRepo` —— identity RBAC binding read adapter。
//!
//! 该 adapter 只持有 tenant-scoped pool，不持有 clock、outbox 或 mutation 能力；finalized
//! LocalOnly authorizer 只能通过此窄 port 查询 subject bindings。

use identity::ports::{IdentityError, RoleBinding, RoleBindingReadRepo, TenantRepoScope};

use crate::cotx::PgTenantReadPool;
use crate::pool::VerifiedPgReadStore;

/// PostgreSQL 角色绑定只读仓储。
pub struct PgRoleBindingReadRepo {
    pool: PgTenantReadPool,
}

impl PgRoleBindingReadRepo {
    pub(crate) fn new(reader: &VerifiedPgReadStore) -> Self {
        Self {
            pool: PgTenantReadPool::new(reader),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            pool: PgTenantReadPool::from_unverified_for_test(store),
        }
    }
}

impl RoleBindingReadRepo for PgRoleBindingReadRepo {
    async fn list_for_subject(
        &self,
        scope: TenantRepoScope,
        subject: String,
    ) -> Result<Vec<RoleBinding>, IdentityError> {
        let tenant = scope.tenant();
        let rows: Vec<(String, String)> = self
            .pool
            .read(scope, move |conn| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT role_id, subject FROM role_bindings \
                         WHERE tenant_id = $1::uuid AND subject = $2 \
                         ORDER BY role_id ASC",
                    )
                    .bind(tenant.as_uuid().to_string())
                    .bind(&subject)
                    .fetch_all(conn)
                    .await
                })
            })
            .await
            .map_err(|error| IdentityError::Storage(Box::new(error)))?;

        rows.into_iter()
            .map(|(role_id, subject)| RoleBinding::hydrate(subject, &role_id, tenant))
            .collect()
    }
}
