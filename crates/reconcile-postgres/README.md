# rss-reconcile-postgres

PostgreSQL 16+ 的独立 Reconcile adapter。默认只需要 `rss_reconcile` schema 和调用方配置好的 SQLx `PgPool`；不依赖消息数据库安装。

`PgStore::new(pool, control)` 验证组件版本、必要结构、FORCE RLS、函数实现和运行角色。默认事务对每次实际借出的连接再次校验同一 canonical admission，构造后权限或 DDL 漂移会拒绝业务回调并隔离连接。它接管 pool 生命周期，`close(control)` 关闭该 pool 及其 clones 的 admission，并有界 drain；调用方先停止/join worker。连接的 TLS、凭据和认证由调用方配置。

## 安装与存储责任

`MIGRATION_SQL` 是新 schema 的版本化安装定义，由独立 NOSUPERUSER NOBYPASSRLS schema owner 执行。应用给 runtime 角色 schema USAGE、表 SELECT、函数 EXECUTE；不要授予组件表直接写权限、schema CREATE、owner membership 或 BYPASSRLS。所有租户表启用 FORCE RLS，函数固定 search_path，PUBLIC 权限撤销。迁移执行、角色配置和业务表由产品拥有。

首次发布只支持 fresh install，不读取、转换或接管历史 `public.reconcile_*`。历史表是否存在不参与新实现决策。后续组件 migration 只追加，维护新持久化 identity；不把“不兼容旧实现”解释为可以改写未来已发布存储格式。

唯一目标表持有 due time、wake version、失败状态、token 与递增 epoch。没有产品 snapshot、设备策略或历史审计账本。扫描用数据库时间和 `SKIP LOCKED`，claim、renew、release、finish 都限定 tenant/target/token/epoch。租户 setting 在可信应用内提供隔离，不认证持有数据库凭据的调用方。

## 受保护写入

`PgStore::protect(claim, control, context, callback)` 在一个事务内锁住并检查 claim，执行可信业务 SQL，再次检查租约并标记 Applied/需要重新观察，最后提交。它不释放 claim，worker 后续结算或 TTL 接管继续观察。`wake_with` 将业务写和登记工作原子组合；`local_tx` 可提供 tenant-scoped 观察查询。

目标行锁持有到事务结束。最终有效状态更新确定顺序；接管成功后旧 epoch 无法提交受保护写。若回调期间 lease 到期，末端校验导致全部回滚。保护不承诺物理 commit ACK 早于墙钟到期点，也不依赖全局 leader 或提交延迟触发器。

回调只借 transaction，不获得正常 commit/rollback 权限。原始 SQL 是可信应用代码，禁止 transaction/session control、改租户或绕过本组件保护。业务表需要自身 RLS；远端网络副作用不受此事务保护。

仅确认 commit/rollback 后复用连接。CommitUnknown、RollbackFailed 或 dropped future 隔离并关闭连接；无法确认提交不能当作已回滚重试。SQLx 负责数据库事务机制，adapter 只持有本组件的结算/错误语义。

## 可选消息组合

开启 `transactional-messaging` 才引入消息 core/PG 依赖。`messaging::protect` 和 `messaging::wake_with` 接受现有 `PgRuntime` 与显式 context，回调取得同一个消息 `PgTransaction`，可直接 `PgOutboxStore::append`。Reconcile 校验、业务 SQL、canonical Outbox 和调度状态同事务；消息 runtime 唯一拥有结算。它们返回 `LocalTxAttempt`，必须穷尽区分 committed、not-started、rolled-back、fenced、rollback-failed、commit-unknown。

消息模式需安装原消息 schema，并向同一 runtime 角色授予本组件最小权限。与默认路径共用本组件 SQL 和 fencing；不复制 Outbox/Inbox，不修改消息引擎依赖方向。回调的 context 可以直接借用业务字段，和 transaction 一起重借；不要求为借用额外包装 Arc。

## 验证

`cargo test -p rss-reconcile`；真实 provider 运行 `cargo nextest run -p reconcile-postgres-integration --all-features`（Docker、PostgreSQL TLS fixture）。该 suite 包含真实 COMMIT/ROLLBACK I/O 期间终止 backend、关闭取消/超时的行为证明，以及由父测试启动并 kill 的 worker 子进程；子测试单独标记 ignored，不代表恢复场景跳过。

`python3 hack/reconcile-package-proof.py` 验证真实 `.crate` 的独立解析、core-only、默认 PostgreSQL 和消息组合。candidate workflow 验证同提交上传 artifact 的 hash 与版本。

ref: launchbadge/sqlx `sqlx-core/src/transaction.rs@v0.9.0`；PostgreSQL 16 explicit-locking；固定历史 `5b63e10` 的 0041/0044/0084 仅提取通用 claim/wake 不变量。
