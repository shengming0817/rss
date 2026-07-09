//! `PgRoleBindingLifecycle` —— identity RBAC binding lifecycle adapter（#1190 PR5b）。
//!
//! 最小生产闭环：assign / revoke 的 binding 行写删与 role event outbox append 同事务原子落库；不实现
//! audit consumer、不扩展授权查询模型。revoke 未命中时提交空事务并返回 `false`，不写 outbox，避免泄露存在性。

use consistency::Entry;
use diport::{Clock, OutboxEmitError, OutboxEnvelopeParts};
use identity::ports::{RoleBinding, RoleBindingLifecycle, RoleId, TenantId, TenantRepoScope};

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::outbox::{
    OutboxEnvelope, append_outbox_with_projection, metadata_with_ambient, unix_secs,
};
use crate::projection_events::ProjectionWriteRegistry;

/// PostgreSQL 角色绑定生命周期 adapter。
pub struct PgRoleBindingLifecycle {
    pool: PgTenantPool,
    clock: Box<dyn Clock>,
}

impl PgRoleBindingLifecycle {
    /// 由 [`PgStore`] 构造（clone 其 scoped pool）+ 注入 envelope 时间源。
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self::new_with_projection_registry(store, clock, ProjectionWriteRegistry::empty())
    }

    pub(crate) fn new_with_projection_registry(
        store: &PgStore,
        clock: Box<dyn Clock>,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            pool: PgTenantPool::with_projection_registry(store, projection_registry),
            clock,
        }
    }

    fn envelope(&self, envelope: OutboxEnvelopeParts) -> (TenantId, OutboxEnvelope) {
        let (contract, tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        (tenant, env)
    }
}

impl RoleBindingLifecycle for PgRoleBindingLifecycle {
    async fn assign_and_emit(
        &self,
        scope: TenantRepoScope,
        binding: RoleBinding,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        let tenant = binding.tenant();
        if scope.tenant() != tenant {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "role binding assign co-tx: scope tenant does not match binding tenant",
            )));
        }
        let (env_tenant, env) = self.envelope(envelope);
        if env_tenant != tenant {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "role binding assign co-tx: envelope tenant does not match binding tenant",
            )));
        }
        self.pool
            .co_tx_with_outbox(
                scope,
                &entry,
                &env,
                move |conn| {
                    Box::pin(async move {
                        sqlx::query(
                            r#"
                            INSERT INTO role_bindings (tenant_id, role_id, subject)
                            VALUES ($1::uuid, $2, $3)
                            ON CONFLICT (tenant_id, role_id, subject) DO UPDATE
                            SET assigned_at = now()
                            "#,
                        )
                        .bind(binding.tenant().as_uuid().to_string())
                        .bind(binding.role_id().as_str())
                        .bind(binding.subject())
                        .execute(conn.conn())
                        .await
                        .map_err(OutboxEmitError::new)
                        .map(|_| ())
                    })
                },
                OutboxEmitError::new,
            )
            .await
    }

    async fn revoke_and_emit(
        &self,
        scope: TenantRepoScope,
        role_id: RoleId,
        subject: String,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<bool, OutboxEmitError> {
        let tenant = scope.tenant();
        let (env_tenant, env) = self.envelope(envelope);
        if env_tenant != tenant {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "role binding revoke co-tx: envelope tenant does not match requested tenant",
            )));
        }
        let tenant_uuid = tenant.as_uuid().to_string();
        let projection_registry = self.pool.projection_registry();
        self.pool
            .write(
                scope,
                move |conn| {
                    Box::pin(async move {
                        let deleted = sqlx::query(
                            r#"
                            DELETE FROM role_bindings
                            WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3
                            "#,
                        )
                        .bind(&tenant_uuid)
                        .bind(role_id.as_str())
                        .bind(&subject)
                        .execute(conn.conn())
                        .await
                        .map_err(OutboxEmitError::new)?
                        .rows_affected();
                        if deleted == 0 {
                            return Ok(false);
                        }
                        append_outbox_with_projection(conn, &entry, &env, &projection_registry)
                            .await
                            .map_err(OutboxEmitError::new)?;
                        Ok(true)
                    })
                },
                OutboxEmitError::new,
            )
            .await
    }

    async fn list_for_subject(
        &self,
        scope: TenantRepoScope,
        subject: String,
    ) -> Result<Vec<RoleBinding>, identity::ports::IdentityError> {
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
            .map_err(|e| identity::ports::IdentityError::Storage(Box::new(e)))?;

        rows.into_iter()
            .map(|(role_id, subject)| RoleBinding::hydrate(subject, &role_id, tenant))
            .collect()
    }
}
