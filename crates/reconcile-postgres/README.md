# rss-reconcile-postgres

PostgreSQL 16+ 的独立 Reconcile adapter。默认只需要 `rss_reconcile` schema 和调用方配置好的 SQLx `PgPool`；不依赖消息数据库安装。

`PgStore::new(pool, control)` 一次验证组件版本、必要结构、FORCE RLS、函数实现和运行角色，并记录实际连接身份。业务操作只校验连接身份、绑定租户和 claim/lease/epoch，不重新扫描 catalog。受控 schema/ACL 变更必须先停流、排空、迁移，再重新构造 store；已准入对象不承诺即时发现带外 DDL 漂移。它接管 pool 生命周期，`close(control)` 关闭该 pool 及其 clones 并有界 drain；调用方先停止/join worker。TLS、凭据和认证由调用方配置。

## 安装与存储责任

`MIGRATION_SQL` 是新 schema 的版本化安装定义，由独立 NOSUPERUSER NOBYPASSRLS schema owner 执行。应用给 runtime 角色 schema USAGE、表 SELECT、函数 EXECUTE；不要授予组件表直接写权限、schema CREATE、owner membership 或 BYPASSRLS。所有租户表启用 FORCE RLS，函数固定 search_path，PUBLIC 权限撤销。迁移执行、角色配置和业务表由产品拥有。

只支持全新安装：`MIGRATION_SQL` 包含 `migrations/install.sql` 的唯一最终定义，无历史升级入口，不读取、转换或接管既有 schema。独立 owner 在新 schema 安装后配置角色，再构造 store。

目标表唯一持有 due time、wake version、失败状态、token 与递增 epoch。没有产品 snapshot、设备策略或历史审计账本。扫描用数据库时间和 `SKIP LOCKED`，claim、renew、release、finish 都限定 tenant/target/token/epoch。租户 setting 在可信应用内提供隔离，不认证持有数据库凭据的调用方。

## 存储损坏与恢复边界

准入精确校验组件 CHECK 的定义集合及 validated 状态；缺失、弱化、额外约束或
`NOT VALID` 均返回 `StorageContract`。定义顺序和约束名称不影响语义匹配。已准入操作复用该结构前提，借出连接时校验实际连接身份；
schema/ACL 变更必须停流并重新准入，空发现不重新扫描 catalog。规范 schema 禁止负数/超出 u32 的 failures、非法目标身份、
非正 wake version、负 epoch 和不合法 lease 形状；它不能证明任意外部存储破坏从未发生。

构造时的准入失败发生在 claim/业务回调前。若 claim SQL 或行转换失败，整批事务回滚，不返回部分成功 claim；
提交或回滚结果未知仍按原结算类别处理。worker 对 `StorageContract`、`Invariant` 和 `InvalidInput`
扫描错误直接返回，不热重试，也不自动跳过、删除或隔离目标。外部 owner 修复数据及规范约束后，
消费方重新构造所需 store 并重启 worker；正常邻接目标和后续扫描的恢复由真实 PG suite 验证。

计数耗尽是明确限制：schema 允许 `epoch=i64::MAX`，下一次批量 claim 的自增溢出返回
`InvalidInput`，整批回滚并阻断该 scope 的 worker，其他租户的独立 scope 仍可执行。
`wake_version=i64::MAX` 的下一次 wake 同样不能自增。库不重置 fencing 计数、不把耗尽目标
标为成功；外部 owner 负责处置。该证明不声称任意坏行均已自动隔离。

对标：Kubernetes v1.34.0 的 etcd3 `store.go` 在 LIST 解码失败时返回错误；`reflector.go`
由外层退避重试。RSS 返回非瞬态 worker 错误，将修复后重启交给消费方，不引入集群控制器。

## 受保护写入

`PgStore::protect(claim, control, context, callback)` 在一个事务内锁住并检查 claim，执行可信业务 SQL，再次检查租约并标记 Applied/需要重新观察，最后提交。它不释放 claim，worker 后续结算或 TTL 接管继续观察。`wake_with` 将业务写和登记工作原子组合；`local_tx` 可提供 tenant-scoped 观察查询。

目标行锁持有到事务结束。最终有效状态更新确定顺序；接管成功后旧 epoch 无法提交受保护写。若回调期间 lease 到期，末端校验导致全部回滚。保护不承诺物理 commit ACK 早于墙钟到期点，也不依赖全局 leader 或提交延迟触发器。

回调只借 transaction，不获得正常 commit/rollback 权限。原始 SQL 是可信应用代码，禁止 transaction/session control、改租户或绕过本组件保护。业务表需要自身 RLS；远端网络副作用不受此事务保护。

宿主已取得数据库准入许可时，使用 `store.with_permit(slot)?.renew(claim, lease, control).await` 或同一单次句柄的 local_tx、wake、bind_resources、claim_due、finish、release，以及组合业务 SQL 的 protect、wake_with、bind_with。许可在池等待、事务和连接收尾期间由 adapter 持有。已确认的结果立即返回；健康连接在 SQLx 归还探测完成后释放许可，探测最多等待 5 秒，隔离连接直接退出池容量。`close` 等待共享池排空，并等待本次构造实例及其 clones 接管的许可全部释放。若在同一池上独立构造多个 store，每个实例分别排空自己的许可。调用前应消费或丢弃尚未使用的句柄。

宿主配置 `min_connections` 时，SQLx 自行维护池的最小容量；补建连接可能在原操作释放其连接槽和宿主许可之后继续运行。

仅确认 commit/rollback 后复用连接。CommitUnknown、RollbackFailed 或 dropped future 隔离并关闭连接；无法确认提交不能当作已回滚重试。SQLx 负责数据库事务机制，adapter 只持有本组件的结算/错误语义。

## 可选消息组合

开启 `transactional-messaging` 才引入消息 core/PG 依赖。`PgMessagingStore::new(runtime, binding, deadline)` 在实际消息 runtime 上完成一次完整准入；其 `protect` 和 `wake_with` 方法接受本次 `ExecutionBinding` 及显式 context，回调取得同一个消息 `PgTransaction`。仅追加消息时，使用共享 runtime 与 domain 构造 `PgOutboxWriter`，在回调中通过 `OutboxWriter::append` 写入，无需 receipt 类型或投递预算。确实同时承担投递的消费者才组合使用 `PgOutboxStore<R>`。Reconcile 校验、业务 SQL、canonical Outbox 和调度状态同事务；消息 runtime 唯一拥有结算。它们返回 `LocalTxAttempt`，必须穷尽区分 committed、not-started、rolled-back、fenced、rollback-failed、commit-unknown。

`PgMessagingStore::protect_in` 借用调用方已经打开的 `PgTransaction`，供宿主先取得 Audit/Ledger 等上层锁，再锁 claim、执行业务并标记 Applied。它首先验证事务属于构造时绑定的同一 runtime，并核对实际连接身份；随后继承原连接和剩余预算，不改会话、不取得第二连接、不接管提交；成功只是 staged，错误必须交回原 owner 回滚。独立 `protect` 与该接口共用同一 claim 校验及写入实现。`PgMessagingStore::wake_in` 对称地在已有事务内登记 wake 并执行回调，与独立 `wake_with` 共用准入和 wake SQL，适用于上层锁必须先于调度目标锁的原子业务提交。

消息模式需安装原消息 schema，并向同一 runtime 角色授予本组件最小权限。与默认路径共用本组件 SQL 和 fencing；不复制 Outbox/Inbox，不修改消息引擎依赖方向。回调的 context 可以直接借用业务字段，和 transaction 一起重借；不要求为借用额外包装 Arc。

## 验证

`cargo test -p rss-reconcile`；真实 provider 运行 `make ci CI_PART=tests CI_FILTER='package(=reconcile-postgres-integration)'`（Docker、PostgreSQL TLS fixture）。该 suite 包含真实 COMMIT/ROLLBACK I/O 期间终止 backend、关闭取消/超时的行为证明，以及由父测试启动并 kill 的 worker 子进程；子测试单独标记 ignored，不代表恢复场景跳过。

`python3 hack/reconcile-package-proof.py --source` 验证独立源码 consumer 的解析与运行，包括 core-only、默认 PostgreSQL 和消息组合。candidate workflow 验证同提交上传 artifact 的 hash 与版本。

ref: launchbadge/sqlx `sqlx-core/src/transaction.rs@v0.9.0`；PostgreSQL 16 explicit-locking；固定历史 `5b63e10` 的 0041/0044/0084 仅提取通用 claim/wake 不变量。


执行示例和输入/结果说明见 [rss-examples](../examples/README.md)。独立源码使用
`python3 hack/reconcile-package-proof.py --source`；固定 artifact 使用
`python3 hack/reconcile-package-proof.py --artifacts DIR --revision SHA`。
两种模式实际运行公共 API 场景，正式验收绑定同一 clean revision、版本和 archive digest；
完整故障矩阵仍归本组件 T1/T2，不把示例通过解释为生产验收或实际发布。

SQLx 解码、列、配置与关闭池错误不会因缺少 SQLSTATE 被视为暂时故障；应用 SQL 将这些错误
归为 `Permanent`，组件结构错误归为 `StorageContract`。认证失败及缺数据库不自动重试。
锁不可用 `55P03` 为 `Transient`，仍须结合事务结果与剩余期限决定恢复。

Transient SQLSTATE classification uses an explicit allowlist. Undefined/duplicate files (`58P01`,
`58P02`), dropped databases (`57P04`), configuration limits (`53400`), protocol violations (`08P01`)
and disk exhaustion (`53100`) require correction, rather than automatic retries based on their class.
Condition names: https://www.postgresql.org/docs/16/errcodes-appendix.html .

## 资源协调

v3 使用 targets、target_resources（声明和可空等待票号）、resources（原 claim 的 owner）、scans 四张租户表。队列票号使用组件 sequence；运行角色不得直接使用/更新 sequence，也不得写组件表。只扩展已有 claim 事务，不增加每资源连接、线程或第二租约。

每个 claim 调用的领取量由宿主选择，能力上限由 `rss_reconcile::MAX_CLAIM_BATCH_SIZE` 持有。独立的 scan_budget 为正 u32，PostgreSQL 接受到 i32::MAX。
数据库先按有效到期时间取有界样本。样本完整时，在当前窗口内按票号领取。样本填满时，从持久游标流式读取票号，优先处理当前到期票；遇到未来票，可以用同一位置尝试窗口内更远的到期样本。每个位置至多尝试锁定一个目标，游标仅推进到实际检查的位置。尚未扫描的老票可能稍后领取，已登记的资源等待者由正常票号扫描复查，继续按老票优先。
前瞻票留给下一页，`more=true` 表示窗口中还有未检查的票，后续页可以为空。已越过游标的唤醒和新票可在下一轮发现。资源队头由部分索引点查，整个集合一次取得。所有资源占用绑定 target/token/epoch，TTL 直接引用 target；释放精确匹配 owner，旧 claim 不能清除接管者。

`protect` / `protect_in` callback 返回 `ProtectedStep::Ready(value)`、`Deferred(after)` 或 `Rebind(resources, after)`。Ready 才标记 Applied；Rebind 在原事务改声明，确认提交后返回 `ReconcileStep::Deferred`，runner 仍唯一负责 finish。`wake_with` / `wake_in` 显式带资源；`bind_with` / `bind_in` 提供保留调度事实的原事务绑定。消息 protect 发现绑定已变化时跳过 callback，返回 1ms 的 Deferred；这是 staged 结果，必须先等待原事务 owner 的已确认提交。实际资源排队仍由 claim 阶段持有。

`binding_revision=0` 表示首次资源绑定尚未完成；正常 wake 在同一事务完成首次绑定。Scope 中出现不完整绑定的待办时，claim 返回 StorageContract。`bind_resources/bind_with/bind_in` 用于当前资源重绑定，保留失败次数、wake version 和调度时间。

扫描最终游标和高水位没有变化时不 UPDATE `scans`，有实际窗口进展时仍持久化。扫描行锁及其可能产生的 WAL 保留。

重绑定保留旧 acquired owner，直到 Deferred finish/release 或 TTL 接管；两次事务间崩溃仍由原恢复机制处理。CommitUnknown/RollbackFailed 没有成功的 Deferred 回执，不凭客户端猜测继续释放。全部新增关系的结构、约束、索引、FORCE RLS、ACL 与当前函数定义在构造时精确准入。

租约与重试/延期时长使用正整毫秒，PostgreSQL interval 的微秒表示为有符号 64 位整数，
最多接受 9223372036854775 毫秒；实际时间戳加法溢出也会拒绝。
单次数据库操作的 statement/lock timeout 独立受 i32::MAX 毫秒限制，不截断配置。
