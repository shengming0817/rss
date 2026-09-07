# rss-ledger-postgres

`rss-ledger` 的 PostgreSQL 原子持久化，默认可独立消费。可选 `messaging` feature
使用既有消息 PG 事务借用能力，实现账本、业务状态和 inbox 完成同事务提交或回滚。

## 独立追加及业务事务

调用方配置 TLS pool、注入密钥和时钟，使用 `PgLedger::new(pool, auth, control)` 验证组件 schema。
库不执行 migration。`Control` 使用同一绝对预算覆盖连接获取、SQL 和结算；连接未确认结算时隔离关闭。
回滚失败同时保留原 operation 错误和 settlement 错误，避免结算失败覆盖业务失败原因。

```rust,no_run
use rss_ledger::AppendRequest;
use rss_ledger_postgres::{Control, Error, PgLedger, Timer};
async fn append<T: Timer>(store: &PgLedger, request: &AppendRequest, control: &Control<'_, T>) {
    store.append(request, control).await.fold(
        |receipt| { let _record = receipt.into_value(); }, // COMMIT ACK
        |error| { /* 未开始；结合错误分类恢复 */ },
        |error| { /* 已确认回滚；结合错误分类恢复 */ },
        |error| { /* 回滚未确认；隔离后恢复 */ },
        |error| { /* 提交未知：保留原稳定身份及字节，重新追加收敛 */ },
        |error| { /* 已失去 fencing authority */ },
    );
}
async fn business<T: Timer>(store: &PgLedger, request: AppendRequest, c: &Control<'_, T>) {
    let _attempt = store.local_tx(request.ledger().tenant(), c, move |tx| Box::pin(async move {
        let staged = tx.append(&request).await?;
        tx.with_connection(|connection| Box::pin(async move {
            // 真实业务表及其 RLS 由产品迁移提供。
            sqlx::query("SELECT 1").execute(connection).await?;
            Ok::<_, sqlx::Error>(())
        })).await?;
        Ok(staged)
    })).await;
}
```

结果直接使用 canonical `rss_transactional_messaging::transaction::LocalTxAttempt`，无第二套公开 outcome。
独立 PG 仅依赖该核心契约（关闭其默认 features），不需要消息 runtime 或 schema。
执行 race 超时/取消返回 `CommitUnknown` 并隔离连接；`Deadline/Cancelled` 携带 canonical 阶段。
只有实际尝试回滚但未获 ACK 才报告 `RollbackFailed`，其错误保留 operation 和 settlement。
业务 `with_connection` 原样返回调用方错误类型；调用方可检查 SQLSTATE/constraint 后再决定 operation 错误，
不会把业务唯一键冲突推断为账本稳定 ID 冲突。通用 SQL 错误转为 `Error` 时仅保留脱敏 Storage 原因。

`StagedAppend` 不是提交证明；只有外层 `Committed<T>` 回执确认独立事务提交。回执构造器私有。
独立重试按稳定身份返回原始记录和认证值，不增加序号；同身份不同 payload 冲突。
身份/配置检查和记录认证先于幂等返回。同链行锁、checked 分配、写入和链头更新保持在同一个事务。
PG 序号范围为 `0..=i64::MAX`，耗尽显式拒绝。

## 消息事务组合

启用 `messaging` 后调用 `append_in(tx, Arc<Authenticator>, request)`，无需构造独立 pool 或 PgLedger；不另开事务、不改变 tenant GUC 或预算、
不提交/回滚。实际借用连接的账本 schema/权限也会验证，不能用另一个 pool 的准入结果替代。

```rust,no_run
# #[cfg(feature="messaging")]
async fn message_effect(
    auth: std::sync::Arc<rss_ledger::Authenticator>,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    request: &rss_ledger::AppendRequest,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    rss_ledger_postgres::append_in(tx, auth, request).await?;
    Ok(())
}
```

`Error -> PgError` 穷尽分类：稳定 ID 冲突为 Conflict，非法输入/密钥、请求 scope 或序号耗尽为 Permanent；
认证、链间隙、持久 key/version 矛盾和准入契约违反为 Invariant；预算终止为 DeadlineElapsed；
存储故障或未确认回滚为 Transient。分类不构成提交或重试许可。

在 `PgConsumerEffect::apply` 中，确定的业务冲突可返回终态拒绝，避免无限基础设施重投。
以下例子先追加、再执行业务效果；仅在没有其它待提交业务写入时可选择终态拒绝。
完整性或基础设施错误必须传播失败，使既有 consumer owner 回滚，不能伪装成业务拒绝。

```rust,no_run
# #[cfg(feature="messaging")]
async fn consumer_effect(
    auth: std::sync::Arc<rss_ledger::Authenticator>,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    request: &rss_ledger::AppendRequest,
) -> Result<rss_transactional_messaging::transaction::TerminalDisposition,
            rss_transactional_messaging_postgres::PgConsumerEffectFailure> {
    use rss_transactional_messaging::transaction::{TerminalDisposition, RejectKind};
    use rss_transactional_messaging_postgres::{PgError, PgConsumerEffectFailure};
    match rss_ledger_postgres::append_in(tx, auth, request).await {
        Ok(_) => Ok(TerminalDisposition::Succeeded), // 业务 SQL 可在成功追加后执行
        Err(rss_ledger_postgres::Error::Conflict) =>
            Ok(TerminalDisposition::Rejected(RejectKind::Permanent)),
        Err(error) => Err(PgConsumerEffectFailure::infrastructure(PgError::from(error))),
    }
}
```

既有 consumer owner 核验 inbox lease、完成记录并结算。消息提交证据仍由该 owner 产生。

所有业务及追加错误必须传播到外层事务；吞掉错误可能提交业务调用者此前已执行的其它工作。
同一事务修改多个链时，按 tenant UUID 字节、chain UTF-8 字节的升序获取链锁，再获取业务行锁。
公开 SQL 借用是可信基础设施扩展点，不是 SQL 沙箱；禁止事务控制、修改租户或 session 设置。
库不授权用户指定租户，产品仍负责认证、多租户访问决策和业务表 RLS。

## Schema 与权限

组件提供唯一 fresh-install `MIGRATION_SQL`；产品以独立 `NOLOGIN NOSUPERUSER NOBYPASSRLS` owner 执行。
运行角色必须与 owner 分离，不可通过 SET ROLE/继承抵达 owner，不得拥有 CREATE、直接写入、TRIGGER 或 MAINTAIN 权限。
owner 只用于迁移及 SECURITY DEFINER 函数执行，所有表 FORCE RLS，函数固定 `pg_catalog,rss_ledger` search_path。
禁止 runtime/可达角色拥有对象 GRANT OPTION 或角色 ADMIN OPTION。PUBLIC 无组件权限。按消费角色授予：

```sql
GRANT USAGE ON SCHEMA rss_ledger TO application_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA rss_ledger TO application_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_ledger TO application_runtime;
```

准入核验角色可达权限、列类型/空值、约束、租户 policy、函数体和函数权限。拒绝未知 schema，不自动修补。`AdmissionViolation` 以 Schema/Role/Permissions/Rls/Functions/Columns/Constraints 区分漂移，诊断不包含 SQL、对象名或租户数据。
V1 是新的持久格式，无历史 audit migration 导入或双读兼容；必要后续升级由本 adapter 提供版本化 SQL，产品执行。
具有管理员或持钥权限的主体仍处于信任边界内；该模型不能宣称防管理员重写或 WORM。

## 窗口与资源

`read_window(ledger,start,limit,control)` 的 start inclusive，limit 为 1..=1024。
一条 SQL 在同一快照获取链尾、必要前驱及页内记录，验证连续性和预期页大小；缺必要前驱报错。
合法尾后空窗返回零条；返回链尾只反映数据库同一快照，不是防截尾证明。
每页最大约 1 GiB payload，消费方应选择满足内存预算的小 limit。

`close(control)` 同步关闭 pool 新借用，再有界等待已借用连接归还；取消等待后 pool 仍保持关闭。
传入 pool 及其所有 clone 共享这一生命周期。消息借用连接始终由消息 runtime 拥有。
`integration` feature 仅启用 fixture 结算故障注入，不改变默认一致性或权限规则。

## 验证与交付

T1：协议向量、篡改、边界、窗口和 SQL 转换；T2：`ledger-postgres-integration` 使用真实 TLS PostgreSQL，
验证并发、幂等、RLS、权限/结构篡改、连接终止、结算未知、取消及 inbox 原子性。
`hack/ledger-package-proof.py` 消费真实 archive，独立解析 core/PG/messaging/all 组合。

ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
ref: baseline 5b63e10 adapters/postgres/src/audit_repo.rs
#2312 接纳，0.1 实验版本线；构建/隔离消费与实际发布是不同事实，示例不是生产消费证明。
