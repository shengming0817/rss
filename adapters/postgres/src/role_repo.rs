//! `PgRoleRepo` —— identity 角色仓储的 postgres adapter（#1250）。
//!
//! impl `identity::ports::RoleRepo`（find / save），替换原 `#[cfg(test)]` `RoleRepoEdgeProof`（body `todo!()`
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

use identity::ports::{IdentityError, Role, RoleId, RoleRepo, TenantId};
use sqlx::Row;

use crate::PgStore;
use crate::cotx::{set_local_tenant, tenant_scoped_read};

/// identity 角色仓储的 PostgreSQL adapter。
///
/// 经 [`PgStore`] 的 `pool`（`pub(crate)`，share-pool 注入，同 [`crate::PgConfigRepo`]）clone 构造。
pub struct PgRoleRepo {
    pool: sqlx::PgPool,
}

impl PgRoleRepo {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::role_repo` 收口。
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
        }
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，故在 adapter 边界收口）。
fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

/// `TenantId` → SQL bind 参数（stringify UUID 绑 `$N::uuid` server-side cast；同 config_repo / session_lifecycle，
/// 不给 sqlx 加 uuid feature）。
fn tenant_param(tenant: TenantId) -> String {
    tenant.as_uuid().to_string()
}

impl RoleRepo for PgRoleRepo {
    async fn find(&self, tenant: TenantId, id: RoleId) -> Result<Option<Role>, IdentityError> {
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 读闭包内仅 SQL fetch + try_get 返回原始值；Role::hydrate（复核 id / permission 白名单）在 tx 外，
        // 保持 IdentityError 语义不变（域错误不依赖 sqlx）。损坏持久化值 → Storage（fail-closed）。
        let tenant_uuid = tenant_param(tenant);
        let id_str = id.as_str().to_owned();
        let tenant_uuid_q = tenant_uuid.clone();
        let id_str_q = id_str.clone();

        let raw = tenant_scoped_read(&self.pool, tenant, move |conn| {
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

    async fn save(&self, tenant: TenantId, role: Role) -> Result<(), IdentityError> {
        let tenant_uuid = tenant_param(tenant);
        let permissions: Vec<String> = role.permission_ids().map(str::to_owned).collect();
        // tenant-scoped 事务（SET LOCAL 锚点，与 config / session 写路径统一收口）内 upsert。
        // save 是本 adapter **唯一**写路径（find 为 plain read）⇒ 不抽 `tenant_scoped` helper，直接 inline。
        let mut tx = self.pool.begin().await.map_err(storage)?;
        set_local_tenant(&mut tx, tenant).await.map_err(storage)?;
        let result = sqlx::query(
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
        .execute(&mut *tx)
        .await;
        match result {
            Ok(_) => tx.commit().await.map_err(|e| {
                // commit 失败是运维高价值事件，补 warn 定位（与 cotx co-tx 分支对齐；error 经 redact 脱敏）。
                tracing::warn!(
                    target: "postgres",
                    tenant_id = tenant_uuid.as_str(),
                    error = %secure::redact_error(&e),
                    "role save: commit failed"
                );
                storage(e)
            }),
            Err(e) => {
                // rollback 失败是运维高价值事件（连接泄漏 / PG 断线），补 warn 定位（与 cotx co-tx 分支对齐）；
                // 不覆盖原写错误；Transaction Drop 亦兜底回滚。
                if let Err(rb) = tx.rollback().await {
                    tracing::warn!(
                        target: "postgres",
                        tenant_id = tenant_uuid.as_str(),
                        error = %secure::redact_error(&rb),
                        "role save: rollback failed after write error"
                    );
                }
                Err(storage(e))
            }
        }
    }
}
