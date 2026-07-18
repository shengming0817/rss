//! `PgRoleBindingLifecycle` —— identity RBAC binding lifecycle adapter（#1190 PR5b）。
//!
//! 最小生产闭环：assign / revoke 的 binding 行写删与 role event outbox append 同事务原子落库；不实现
//! audit consumer、不扩展授权查询模型。revoke 未命中时提交空事务并返回 `false`，不写 outbox，避免泄露存在性。

use consistency::EventEntry;
use diport::{Clock, OutboxEmitError, OutboxEnvelopeParts};
use identity::ports::{
    ROLE_ASSIGNED_CONTRACT, ROLE_REVOKED_CONTRACT, RoleBinding, RoleBindingLifecycle, RoleId,
    RolesAssignProducerReceipt, RolesRevokeProducerReceipt, TenantId, TenantRepoScope,
};

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::{PgTenantWritePool, ProducerTxOutcome};
use crate::outbox::{OutboxEnvelope, metadata_with_ambient, unix_secs};
use crate::pool::VerifiedPgWriteStore;
use crate::projection_events::ProjectionWriteRegistry;

/// PostgreSQL 角色绑定生命周期 adapter。
pub struct PgRoleBindingLifecycle {
    pool: PgTenantWritePool,
    clock: Box<dyn Clock>,
}

impl PgRoleBindingLifecycle {
    /// integration-only 裸 store 测试 seam + 注入 envelope 时间源。
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self {
            pool: PgTenantWritePool::from_unverified_for_test(store),
            clock,
        }
    }

    pub(crate) fn new_with_projection_registry(
        writer: &VerifiedPgWriteStore,
        clock: Box<dyn Clock>,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            pool: PgTenantWritePool::with_projection_registry(writer, projection_registry),
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
        receipt: RolesAssignProducerReceipt,
        scope: TenantRepoScope,
        binding: RoleBinding,
        entry: EventEntry,
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
        let generated_fact = entry.generated_fact().ok_or_else(|| {
            OutboxEmitError::new(std::io::Error::other(
                "role binding assign entry lacks generated fact provenance",
            ))
        })?;
        self.pool
            .producer_tx(
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
                        .map(|_| ())?;
                        let authorization = receipt
                            .authorize(generated_fact, ROLE_ASSIGNED_CONTRACT)
                            .ok_or_else(|| {
                                OutboxEmitError::new(std::io::Error::other(
                                    "role binding assign co-tx: producer receipt does not authorize role-assigned",
                                ))
                            })?;
                        Ok(ProducerTxOutcome::Emitted((), authorization))
                    })
                },
                OutboxEmitError::new,
            )
            .await
            .into_result()
    }

    async fn revoke_and_emit(
        &self,
        receipt: RolesRevokeProducerReceipt,
        scope: TenantRepoScope,
        role_id: RoleId,
        subject: String,
        entry: EventEntry,
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
        let generated_fact = entry.generated_fact().ok_or_else(|| {
            OutboxEmitError::new(std::io::Error::other(
                "role binding revoke entry lacks generated fact provenance",
            ))
        })?;
        self.pool
            .producer_tx(
                scope,
                &entry,
                &env,
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
                            return Ok(ProducerTxOutcome::NoMutation(false));
                        }
                        let authorization = receipt
                            .authorize(generated_fact, ROLE_REVOKED_CONTRACT)
                            .ok_or_else(|| {
                                OutboxEmitError::new(std::io::Error::other(
                                    "role binding revoke co-tx: producer receipt does not authorize role-revoked",
                                ))
                            })?;
                        Ok(ProducerTxOutcome::Emitted(true, authorization))
                    })
                },
                OutboxEmitError::new,
            )
            .await
            .into_result()
    }
}
