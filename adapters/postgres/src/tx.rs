//! 事务运行器：在单事务内跑一个闭包，成功 commit / 失败 rollback（eventexec 持久化基座，#1116）。
//!
//! 归属 postgres adapter（**不**进 diport，#1116 决策 1）——签名暴露 `&mut sqlx::PgConnection`（sqlx 类型），
//! 放 provider-agnostic 的 `diport` 会迫使其依赖 sqlx、破坏不变式；当前无任何域消费它，落为 `PgStore`
//! 的 inherent 方法最简洁（非 dynosaur DI port）。
//!
//! `ref: sqlx examples/postgres/transaction/src/main.rs@v0.8.6` ·
//! `ref: sqlx sqlx-core/src/transaction.rs@v0.8.6`。

use futures::future::BoxFuture;
use sqlx::PgConnection;

use crate::PgStore;

impl PgStore {
    /// 在单事务内执行 `f`：`f` 返回 `Ok` → `commit`；返回 `Err` → `rollback` 并冒泡原错误。
    ///
    /// `f` 拿到 `&mut PgConnection` 执行查询。HRTB `for<'tx> FnOnce(&'tx mut PgConnection)
    /// -> BoxFuture<'tx, _>` 是绕过异步闭包借用规则的惯用写法（sqlx 0.8 未提供高阶 `transaction()`）。
    /// 错误类型 `E` 由调用方决定，须 `From<sqlx::Error>`——adapter 边界可把 `sqlx::Error` 包成域错误冒泡。
    ///
    /// **`pub(crate)`，非公开 API（fail-closed，#1116 review F2）**：本入口暴露**未做 tenant scope**的裸
    /// `&mut PgConnection`，绕过 RLS（`tenancy.md` 要求 PG 租户 scope 经 `SET LOCAL` 注入）。因此**不**对域 /
    /// 组合根公开——仅供本 adapter 内部的 repo / store impl 使用（域 crate 经层规则本就够不到它，组合根亦无需裸事务）。
    /// 后续 eventexec repo port 落地时，crate 内 impl 须在 `f` 内先 `SET LOCAL` 注入租户；带 typed `TenantId` /
    /// `RowVisibility` 的 **tenant-scoped 事务公开抽象**是 P4+ 设计（见 backlog issue）。
    // reason(dead_code): 基座事务原语，生产消费方（eventexec repo impl）落在 P4+；现仅 crate 内集成测试
    // 行使。保持 pub(crate)（不公开裸事务）优先于消除 dead_code——故 item-level allow + 业务理由。
    #[allow(dead_code)]
    pub(crate) async fn run_in_transaction<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: for<'tx> FnOnce(&'tx mut PgConnection) -> BoxFuture<'tx, Result<T, E>> + Send,
        E: From<sqlx::Error> + Send,
        T: Send,
    {
        let mut tx = self.pool.begin().await.map_err(E::from)?;
        // &mut tx 经 DerefMut auto-deref 成 &mut PgConnection（闭包参数类型已知，编译器自动解引用）；
        // sqlx 0.8 起 Transaction 不再直接 impl Executor，须借出底层连接。
        match f(&mut tx).await {
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
