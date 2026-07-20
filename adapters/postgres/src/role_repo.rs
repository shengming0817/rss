//! `PgRoleRepo` —— identity 角色仓储的 postgres adapter（#1250）。
//!
//! impl `identity::ports::{RoleReadRepo, RoleWriteRepo}`（find/list 与 save 分口），替换原
//! `#[cfg(test)]` `RoleRepoEdgeProof`（body `todo!()`
//! 的纯编译证明）。adapter→域 DIP 内向边（postgres 依赖 identity、native AFIT impl 其域形 port，经 deny.toml
//! identity wrapper + `allows(Adapter,Domain)` 放行；adapter 仍不被域依赖）。
//!
//! 持久化模型（`0009_create_roles.sql`）：roles 表 PK (tenant_id, id)，permissions 序列化为 `text[]`。
//! `find` = [`tenant_scoped_read`] tenant-scoped 事务（SET LOCAL 注入 RLS policy `current_setting` 锚点，#1298）+
//! 显式 `WHERE tenant_id`（双重隔离）；`save` = tenant-scoped
//! 事务（SET LOCAL 锚点，与 config / session 写路径统一收口）内 upsert（`ON CONFLICT (tenant_id, id) DO UPDATE`）。
//! storage 错误经 `IdentityError::Storage` 分层冒泡（保留 source 链；域 crate 不依赖 sqlx）。读出行经
//! `Role::hydrate` 受控重建——损坏持久化值（id / permission 复核失败）→ `Storage`（fail-closed，不静默接受脏数据）。
//!
//! ref: casbin/casbin-rs（RBAC 角色多租 domain-scoped 持久化模型）
//! ref: adapters/postgres/src/config_repo.rs（#1249，pool 注入 / SET LOCAL / storage 收口 / hydrate 范本）

use identity::ports::{
    IdentityError, Role, RoleId, RoleListResult, RolePage, RoleReadRepo, RoleWriteRepo, TenantId,
    TenantRepoScope,
};
use sqlx::Row;

use crate::cotx::{PgTenantReadPool, PgTenantWritePool};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};

/// identity 角色仓储的 PostgreSQL adapter。
///
/// 仅由已验证 reader/writer capability 构造（同 [`crate::PgConfigRepo`]）。
pub struct PgRoleRepo {
    read_pool: PgTenantReadPool,
    write_pool: PgTenantWritePool,
}

impl PgRoleRepo {
    /// 由已验证 reader/writer capability 构造。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::role_repo` 收口。
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: PgTenantReadPool::new(reader),
            write_pool: PgTenantWritePool::new(writer),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: PgTenantReadPool::from_unverified_for_test(store),
            write_pool: PgTenantWritePool::from_unverified_for_test(store),
        }
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，故在 adapter 边界收口）。
fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

/// `TenantId` → SQL bind 参数（stringify UUID 绑 `$N::uuid` server-side cast；同 config_repo / auth_grant_lifecycle，
/// 不给 sqlx 加 uuid feature）。
fn tenant_param(tenant: TenantId) -> String {
    tenant.as_uuid().to_string()
}

impl RoleReadRepo for PgRoleRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        id: RoleId,
    ) -> Result<Option<Role>, IdentityError> {
        let tenant = scope.tenant();
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 读闭包内仅 SQL fetch + try_get 返回原始值；Role::hydrate（复核 id / permission 白名单）在 tx 外，
        // 保持 IdentityError 语义不变（域错误不依赖 sqlx）。损坏持久化值 → Storage（fail-closed）。
        let tenant_uuid = tenant_param(tenant);
        let id_str = id.as_str().to_owned();
        let tenant_uuid_q = tenant_uuid.clone();
        let id_str_q = id_str.clone();

        let raw = self
            .read_pool
            .read(scope, move |conn| {
                Box::pin(async move {
                    let row = sqlx::query(
                        r#"
                        SELECT name, permissions
                        FROM roles
                        WHERE tenant_id = $1::uuid AND id = $2
                        "#,
                    )
                    .bind(tenant_uuid_q)
                    .bind(id_str_q)
                    .fetch_optional(&mut *conn)
                    .await?;
                    match row {
                        None => Ok(None),
                        Some(r) => {
                            let name: String = r.try_get("name")?;
                            let permissions: Vec<String> = r.try_get("permissions")?;
                            Ok(Some((name, permissions)))
                        }
                    }
                })
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
        let tenant = scope.tenant();
        let tenant_uuid = tenant_param(tenant);
        let after = page.after.as_ref().map(|id| id.as_str().to_owned());
        let limit = i64::from(page.limit.get()) + 1;
        let raw = self
            .read_pool
            .read(scope, move |conn| {
                Box::pin(async move {
                    let rows = sqlx::query(
                        r#"
                        SELECT id, name, permissions
                        FROM roles
                        WHERE tenant_id = $1::uuid
                          AND ($2::text IS NULL OR id > $2)
                        ORDER BY id ASC
                        LIMIT $3
                        "#,
                    )
                    .bind(tenant_uuid)
                    .bind(after)
                    .bind(limit)
                    .fetch_all(&mut *conn)
                    .await?;

                    rows.into_iter()
                        .map(|r| {
                            let id: String = r.try_get("id")?;
                            let name: String = r.try_get("name")?;
                            let permissions: Vec<String> = r.try_get("permissions")?;
                            Ok((id, name, permissions))
                        })
                        .collect::<Result<Vec<_>, sqlx::Error>>()
                })
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

impl RoleWriteRepo for PgRoleRepo {
    async fn save(&self, scope: TenantRepoScope, role: Role) -> Result<(), IdentityError> {
        let tenant_uuid = tenant_param(scope.tenant());
        let permissions: Vec<String> = role.permission_ids().collect();
        self.write_pool
            .write(
                scope,
                move |conn| {
                    Box::pin(async move {
                        sqlx::query(
                            r#"
                            INSERT INTO roles (tenant_id, id, name, permissions)
                            VALUES ($1::uuid, $2, $3, $4)
                            ON CONFLICT (tenant_id, id) DO UPDATE
                            SET name = EXCLUDED.name, permissions = EXCLUDED.permissions
                            "#,
                        )
                        .bind(&tenant_uuid)
                        .bind(role.id().as_str())
                        .bind(role.name())
                        .bind(&permissions)
                        .execute(conn.conn())
                        .await
                        .map_err(storage)
                        .map(|_| ())
                    })
                },
                storage,
            )
            .await
    }
}
