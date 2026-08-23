//! `PgRoleBindingLifecycle` —— identity RBAC binding lifecycle adapter（#1190 PR5b）。
//!
//! 最小生产闭环：assign / revoke 的 binding 行写删与 role event outbox append 同事务原子落库；不实现
//! audit consumer、不扩展授权查询模型。revoke 未命中时提交空事务并返回 `false`，不写 outbox，避免泄露存在性。

use diport::{Clock, OutboxEmitError, OutboxEnvelopeParts};
use eventexec::event::ReviewedEvent;
use identity::ports::{
    ROLE_ASSIGNED_CONTRACT, ROLE_REVOKED_CONTRACT, RoleBinding, RoleBindingLifecycle, RoleId,
    RolesAssignProducerReceipt, RolesRevokeProducerReceipt, TenantRepoScope,
};
use rss_request_context::TenantId;

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::{ProducerTxOutcome, ServingWriteLane, TenantDb};
use crate::outbox::{OutboxEnvelope, metadata_with_ambient};
use crate::pool::VerifiedPgWriteStore;
use crate::projection_events::ProjectionWriteRegistry;

/// PostgreSQL 角色绑定生命周期 adapter。
pub struct PgRoleBindingLifecycle {
    pool: TenantDb<ServingWriteLane>,
}

impl PgRoleBindingLifecycle {
    /// integration-only 裸 store 测试 seam + 注入 envelope 时间源。
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(store: &PgStore, _clock: Box<dyn Clock>) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
        }
    }

    pub(crate) fn new_with_projection_registry(
        writer: &VerifiedPgWriteStore,
        _clock: Box<dyn Clock>,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::with_projection_registry(
                writer,
                projection_registry,
            ),
        }
    }

    fn envelope(
        &self,
        envelope: OutboxEnvelopeParts,
        occurred_at: rss_contract::Timepoint,
    ) -> (TenantId, OutboxEnvelope) {
        let (contract, tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(occurred_at.unix_seconds(), tenant, contract)
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
        event: ReviewedEvent,
    ) -> Result<(), OutboxEmitError> {
        let tenant = binding.tenant();
        if scope.tenant() != tenant {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "role binding assign co-tx: scope tenant does not match binding tenant",
            )));
        }
        let generated_fact = event.fact();
        let (entry, envelope, occurred_at, _fact) = event.into_parts();
        let (env_tenant, env) = self.envelope(envelope, occurred_at);
        if env_tenant != tenant {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "role binding assign co-tx: envelope tenant does not match binding tenant",
            )));
        }
        self.pool
            .identity_producer_tx(
                scope,
                &entry,
                &env,
                move |mut conn| {
                    Box::pin(async move {
                        conn.identity()
                            .upsert_role_binding(&binding)
                            .await
                            .map_err(OutboxEmitError::new)
                            ?;
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
        event: ReviewedEvent,
    ) -> Result<bool, OutboxEmitError> {
        let tenant = scope.tenant();
        let generated_fact = event.fact();
        let (entry, envelope, occurred_at, _fact) = event.into_parts();
        let (env_tenant, env) = self.envelope(envelope, occurred_at);
        if env_tenant != tenant {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "role binding revoke co-tx: envelope tenant does not match requested tenant",
            )));
        }
        self.pool
            .identity_producer_tx(
                scope,
                &entry,
                &env,
                move |mut conn| {
                    Box::pin(async move {
                        let deleted = conn
                            .identity()
                            .delete_role_binding(&role_id, &subject)
                            .await
                            .map_err(OutboxEmitError::new)?;
                        if !deleted {
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
