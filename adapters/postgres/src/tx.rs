//! 全局表事务运行器：在单事务内跑一个闭包，成功 commit / 失败 rollback（eventexec 持久化基座，#1116）。
//!
//! 归属 postgres adapter（**不**进 diport，#1116 决策 1）——签名暴露 crate-private [`TxCapability`]，
//! 放 provider-agnostic 的 `diport` 会迫使其依赖 sqlx、破坏不变式。tenant 表不可使用本入口；必须经
//! `PgTenantReadPool` / `PgTenantWritePool` scoped methods 注入 `SET LOCAL rss.tenant_id`。
//!
//! `ref: sqlx examples/postgres/transaction/src/main.rs@v0.8.6` ·
//! `ref: sqlx sqlx-core/src/transaction.rs@v0.8.6`。

use futures::future::BoxFuture;

use crate::PgStore;
use crate::cotx::TxCapability;

impl PgStore {
    /// 在全局 infra 表事务内执行 `f`：`f` 返回 `Ok` → `commit`；返回 `Err` → `rollback` 并冒泡原错误。
    ///
    /// `f` 拿到 `&mut TxCapability` 执行查询。HRTB `for<'tx> FnOnce(&'tx mut TxCapability)
    /// -> BoxFuture<'tx, _>` 是绕过异步闭包借用规则的惯用写法（sqlx 0.8 未提供高阶 `transaction()`）。
    /// 错误类型 `E` 由调用方决定，须 `From<sqlx::Error>`——adapter 边界可把 `sqlx::Error` 包成域错误冒泡。
    ///
    /// **`pub(crate)`，非公开 API（fail-closed，#1116 review F2）**：本入口暴露**未做 tenant scope**的事务
    /// capability。它只允许用于无 `tenant_id` RLS 语义的 global infra 表；tenant 表生产路径必须
    /// 使用 typed read/write pool methods。`cargo xtask pg-tenant-tx-guard` 会拒绝 tenant
    /// 表 SQL 经本入口执行。
    // reason(dead_code): 基座事务原语，生产消费方（eventexec repo impl）落在 P4+；现仅 crate 内集成测试
    // 行使。保持 pub(crate)（不公开裸事务）优先于消除 dead_code——故 item-level allow + 业务理由。
    #[allow(dead_code)]
    pub(crate) async fn run_global_transaction<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
        E: From<sqlx::Error> + Send,
        T: Send,
    {
        let mut tx = self.pool.begin().await.map_err(E::from)?;
        let result = {
            let mut cap = TxCapability::from_transaction(&mut tx);
            f(&mut cap).await
        };
        match result {
            Ok(value) => {
                tx.commit().await.map_err(E::from)?;
                Ok(value)
            }
            Err(err) => {
                // reason: rollback 失败不覆盖业务原错误；Transaction Drop 亦兜底回滚（fire-and-forget）。
                let _ = tx.rollback().await;
                Err(err)
            }
        }
    }
}
