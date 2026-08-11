//! `PgRoleRepo` —— identity 角色仓储的 postgres adapter（#1250）。
//!
//! `PgRoleRepo` impl `RoleReadRepo`；`PgRoleDefinitionLifecycle` 是 actor-attributed append-only 写漏斗。
//! `#[cfg(test)]` `RoleRepoEdgeProof`（body `todo!()`
//! 的纯编译证明）。adapter→域 DIP 内向边（postgres 依赖 identity、native AFIT impl 其域形 port，经 deny.toml
//! identity wrapper + `allows(Adapter,Domain)` 放行；adapter 仍不被域依赖）。
//!
//! 持久化模型（`0009_create_roles.sql`）：`roles` 仅保存稳定 identity；`role_revisions` 保存 actor-attributed
//! 完整快照，permissions canonical 后序列化为 `text[]`。
//! `find` = [`tenant_scoped_read`] tenant-scoped 事务（SET LOCAL 注入 RLS policy `current_setting` 锚点，#1298）+
//! 显式 `WHERE tenant_id`（双重隔离）；mutation = tenant-scoped transaction 内调用唯一 SECURITY DEFINER
//! function，由数据库锁定 stable identity 并 append revision；应用角色没有两表直接 DML 权限。
//! storage 错误经 `IdentityError::Storage` 分层冒泡（保留 source 链；域 crate 不依赖 sqlx）。读出行经
//! `Role::hydrate` 受控重建——损坏持久化值（id / permission 复核失败）→ `Storage`（fail-closed，不静默接受脏数据）。
//!
//! ref: casbin/casbin-rs（RBAC 角色多租 domain-scoped 持久化模型）
//! ref: adapters/postgres/src/config_repo.rs（#1249，pool 注入 / SET LOCAL / storage 收口 / hydrate 范本）

use identity::ports::{
    IdentityError, Role, RoleId, RoleListResult, RolePage, RoleReadRepo, TenantRepoScope,
};
#[cfg(all(test, feature = "integration"))]
use identity::ports::{
    RoleDefinitionLifecycle, RoleMutationActor, RoleMutationOutcome, RoleRevision,
};

#[cfg(all(test, feature = "integration"))]
use crate::cotx::ServingWriteLane;
use crate::cotx::{ServingReadLane, TenantDb};
use crate::pool::VerifiedPgReadStore;

/// identity 角色仓储的 PostgreSQL adapter。
///
/// 仅由已验证 read capability 构造（同 [`crate::PgConfigRepo`]）。
pub struct PgRoleRepo {
    read_pool: TenantDb<ServingReadLane>,
}

impl PgRoleRepo {
    /// 由已验证 read capability 构造。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::role_repo` 收口。
    pub(crate) fn new(reader: &VerifiedPgReadStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(store),
        }
    }
}

/// Internal actor-attributed role definition mutation primitive.
///
/// No production bundle accessor exposes this type. Tests seed revisions through the explicit
/// `test-support` helper while the isolated function owner remains the only database executor.
#[cfg(all(test, feature = "integration"))]
pub(crate) struct PgRoleDefinitionLifecycle {
    write_pool: TenantDb<ServingWriteLane>,
}

#[cfg(all(test, feature = "integration"))]
impl PgRoleDefinitionLifecycle {
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
        }
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，故在 adapter 边界收口）。
fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

impl RoleReadRepo for PgRoleRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        id: RoleId,
    ) -> Result<Option<Role>, IdentityError> {
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 读闭包内仅 SQL fetch + try_get 返回原始值；Role::hydrate（复核 id / permission 白名单）在 tx 外，
        // 保持 IdentityError 语义不变（域错误不依赖 sqlx）。损坏持久化值 → Storage（fail-closed）。
        let id_str = id.as_str().to_owned();
        let query_id = id.clone();

        let raw = self
            .read_pool
            .identity_read(scope, move |mut conn| {
                Box::pin(async move { conn.identity().role_row(&query_id).await })
            })
            .await
            .map_err(storage)?;

        match raw {
            None => Ok(None),
            Some((name, permissions)) => {
                // 受控重建（WHERE 已锁 id = 入参，复用 `id_str` 即存储 id）；hydrate 复核 id / permission
                // 白名单，损坏值（脏行）→ Storage（fail-closed）。
                Ok(Some(Role::hydrate(&id_str, name, &permissions)?))
            }
        }
    }

    async fn list(
        &self,
        scope: TenantRepoScope,
        page: RolePage,
    ) -> Result<RoleListResult, IdentityError> {
        let after = page.after.clone();
        let limit = i64::from(page.limit.get()) + 1;
        let raw = self
            .read_pool
            .identity_read(scope, move |mut conn| {
                Box::pin(async move { conn.identity().role_rows(after.as_ref(), limit).await })
            })
            .await
            .map_err(storage)?;

        let requested = usize::from(page.limit.get());
        let has_more = raw.len() > requested;
        let roles = raw
            .into_iter()
            .take(requested)
            .map(|(id, name, permissions)| Role::hydrate(&id, name, &permissions))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RoleListResult { roles, has_more })
    }
}

#[cfg(all(test, feature = "integration"))]
impl RoleDefinitionLifecycle for PgRoleDefinitionLifecycle {
    async fn create_or_update(
        &self,
        scope: TenantRepoScope,
        actor: RoleMutationActor,
        role: Role,
    ) -> Result<RoleMutationOutcome, IdentityError> {
        if actor.tenant() != scope.tenant() {
            return Err(IdentityError::PermissionDenied);
        }
        self.write_pool
            .identity_write(
                scope,
                move |mut conn| {
                    Box::pin(async move {
                        let (revision, changed) = conn
                            .identity()
                            .record_role_revision(&actor, &role)
                            .await
                            .map_err(storage)?;
                        Ok(RoleMutationOutcome::new(
                            RoleRevision::hydrate(revision)?,
                            changed,
                        ))
                    })
                },
                storage,
            )
            .await
    }
}
