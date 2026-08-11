# Integration capability shards

> #1730：真集成 lane 按 capability 拆成七个 target-level shard。分类、资源和串并行调度的单一事实源是
> `xtask/src/integration_shards.rs` 的 catalog；本文只解释其运维语义。

## 入口与闭集

普通 PR 使用四个固定、显式且非 matrix 的 integration group carrier；直接复现必须选择一个 group：

```bash
cargo xtask ci run --job integration-critical --integration-group postgres --selection '<canonical SelectionPlan JSON>'
```

preflight 通过 plan 中的稳定 unit ID 选择 shard、batch 和 partition。闭合 group 映射为
`postgres = postgres-domain`、`transport = event-transport + consistency-fault`、
`runtime = runtime-http-auth + cdc-projection-saga`、`artifact = object-storage + production-runtime`。
`event-transport` 与
`runtime-http-auth` 分别登记 `1-of-2`、`2-of-2` 两个 partition；其余 shard 不分区。每次 invocation 的
JUnit/JSON、空 bucket 与重放语义见
[`202607111501-1731-nextest-test-evidence.md`](./202607111501-1731-nextest-test-evidence.md)。

`<shard>` 只能是 `postgres-domain`、`event-transport`、`runtime-http-auth`、
`consistency-fault`、`cdc-projection-saga`、`object-storage`、`production-runtime`。缺失、重复、未知 shard、
SelectionPlan 缺失、跨 owner、重复、乱序、未知 ID、额外尾参、自由 filter 和 `--all` 均 fail-closed。
旧的 shard-as-job、单进程全 shard 与无 group 入口均已删除，不提供 `all`、alias 或兼容 shim。

`ci run` 不提供缺工具宽限；缺少 nextest、Docker 或目标 shard 资源时 fail-closed。

## Target 归属、资源与调度

catalog 同时声明稳定 wire ID、primary owner、外部资源、影响 package 与 target；资源、Cargo target、filter
和批次都从单个 `IntegrationSelection` 投影，不维护独立 critical/resource 清单。`serial` 批次由 xtask 传
`--test-threads 1`；`parallel` 批次使用 nextest 默认并发。每个 shard 先跑
serial，再跑 parallel。`.config/nextest.toml` 不承载 integration shard 的 selector/test-group；集成调度只由 typed registry 派生。

| Shard | 所需资源 | Serial / Parallel |
|-------|----------|-------------------|
| `postgres-domain` | Postgres | 以 catalog `PostgresDomain` units 的 `Scheduling` / `LocalEligibility` 为准（含 RemoteOnly live-upgrade migration 与 LocalTx journey）；本文不枚举 target，避免与 `integration_shards.rs` 漂移 |
| `event-transport` | Postgres、Redis、AMQP、MQTT（Docker-only） | 以 catalog `EventTransport` units 为准 |
| `runtime-http-auth` | Postgres、Redis | 以 catalog `RuntimeHttpAuth` units 为准 |
| `consistency-fault` | Postgres、Redis、AMQP | 以 catalog `ConsistencyFault` units 为准 |
| `cdc-projection-saga` | Postgres | 以 catalog `CdcProjectionSaga` units 为准 |
| `object-storage` | MinIO / S3-compatible object storage | 以 catalog `ObjectStorage` units 为准 |
| `production-runtime` | Docker | 以 catalog `ProductionRuntime` units 为准 |

表中具体 `package:target`、串并行与 RemoteOnly/Affected 身份一律读
`xtask/src/integration_shards.rs` catalog；运维只需记住资源集合与「先 serial 后 parallel」批次序。
selector 只能由 typed execution unit 渲染为精确的
`package(=...) and binary(=...) and kind(=...)`；环境变量或 CLI 输入不会进入 selector。
两个 LocalTx journey 与 password-change 的 OutboxFact producer-transaction journey 必须保持在
`postgres-domain` 唯一 unpartitioned Serial batch；password-change 与 refresh 均不属于 LocalTx inventory，
`identity_password_security_event_journey` 验证 credential/account/grant/family/outbox 的 same-tx 原子性。
OutboxFact 的 `identity_logout_grant_journey` 由 Parallel batch 调度。各 batch 使用
`--no-tests=fail`；该 shard 的成功令牌只能在上述全部 batch 返回成功后生成。

`l2-dr-recovery-journey` 只在 `ReleaseCheck` 中拥有 `journeys-fault-matrix:l2_dr_recovery_journey`
这一枚 Serial、RemoteOnly execution unit；它使用 Postgres 与 AMQP 构造应用级等价 divergent state，
不执行外部 PITR 或 broker restore。该 unit 不带 impact marker，不能进入 `IntegrationCritical`、普通 PR
required selector 或 T3。完整 fault/recovery 仍只由 develop、nightly、release 或显式 `ci full` 选择；
需要在候选 revision 上定位时直接运行该 test target，不修改 canonical PR selection。

## 资源解析

缺少 shard 所需的任一可替代外部资源时才要求 Docker，以 testcontainers self-provision；无关资源不阻塞该
shard。MQTT 是显式例外：其 T2 必须同时证明 fixture-owned PKI、exact ACL、正式 broker plugin、persistence
和 restart，故 `event-transport` 运行 MQTT target 时始终要求 Docker，外部 URL 不能替代。其余外部资源的
就绪判据为：

- Postgres：非空 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES`，且 endpoint `PGHOST`、`PGPORT`、
  `PGDATABASE` 三项均非空。fixture 不读取 owner 凭据。只有声明
  `prepared-external-postgres` capability 的 unit 可消费该 endpoint；migration/owner-SQL unit 需要
  Docker-backed owned fixture。应用角色须以测试提供的用户名/密码预配，并精确满足 LOGIN、
  NOSUPERUSER、NOCREATEDB、NOCREATEROLE、NOREPLICATION、NOBYPASSRLS、NOINHERIT、无 role membership、
  密码未过期；免密认证端点会被拒绝。
- Redis：非空 `REDIS_TEST_URL`。
- AMQP：非空 `RSS_AMQP_TEST_URL`。
- MQTT：不接受外部资源输入；`RSS_MQTT_TEST_URL` 不再是配置面，测试始终使用 hermetic MQTTS fixture。
- Object storage：不接受外部资源输入；`object-storage` shard 始终使用 testkit 自建的 hermetic TLS MinIO。

例如 `postgres-domain` 不要求 Redis、AMQP 或 MQTT；`consistency-fault` 不要求 MQTT。外部 AMQP
用于 fault matrix 时仍须预建测试所需 vhost 并为 URL 用户授权。

## Coverage fail-closed

每次运行 shard 前，xtask 经 `CommandWorkspaceFacts` 单次加载
`cargo metadata --locked --all-features --format-version 1`。package、feature 与源码根均从
`LocalFeatureScope::ALL` 派生，不维护易漂移的平行 package/target 数量；每个 lib/test target 必须在 catalog
中恰好出现一次，每个 shard、catalog Test 集与 `RemoteOnly` 集必须非空。新增未分类 target、过期 target、
重复归属、源码路径 alias 或缺 package 都在编译/运行测试前失败。

Cargo manifest 是 test eligibility 的唯一事实源。每个 catalog Test 的 Cargo target 必须保持
`test = true`，其 `name` 与 `scope-root/tests/{target}.rs` 一一对应且源码路径不可复用。`RemoteOnly`
必须且只能声明 `LocalFeatureScope::feature()` 这一项 `required-features`；`Affected` 可默认构建，也可因
test-support 编译边界声明同一 typed feature，但不能声明其它或多余 feature。已由
`required-features` 门控的 target 不再保留同轴源码 `cfg(feature = ...)`；feature 缺失、错误、额外或恢复
双门都会触发 `INTEGRATION-SHARD-ELIGIBILITY-01`。

`s3:integration_object_store` 由 `object-storage` shard 强制执行；测试默认自建 MinIO，并在每轮创建启用
versioning、COMPLIANCE Object Lock 与有界 lifecycle 的独立 bucket，不存在 standalone 旁路。

`journeys:settingsonly_production_artifact` 对应 typed execution unit
`SettingsOnlyProductionArtifact`，只在 `ProductionRuntime` 的 Serial batch 运行；四条 exact case 及其 artifact
selector 的闭合映射由代码 gate 证明，本文不承担 enforcement。该 shard 继续使用既有
`production-runtime` 的 900 秒 runner timeout 和 develop/nightly 路由；本次 carrier 替换不新增 workflow、
scheduler 或 CI 路径。

MQTT production code 默认编译；`broker-tests` 只打开 Docker-backed T2，不控制 runtime 实现。typed shard
catalog 为 `mqtt:integration` 精确启用 `mqtt/broker-tests`，其它 package 继续使用各自的 `integration`
feature；缺 feature、改回通用 feature 或恢复 URL fallback 都会造成 catalog/behavior drift。

## 本地运行与故障定位

MQTT broker T2 的唯一直接复现命令是：

```bash
./hack/cargo.sh test -p mqtt --features broker-tests --test integration
```

该命令构建并启动 repository Dockerfile 所定义的 Mosquitto mTLS/plugin fixture，不读取外部 broker URL。

精确复现关键 PR 选择时，直接复制 preflight 输出的完整 canonical JSON，并选择 owning group：

```bash
cargo xtask ci run --job integration-critical --integration-group transport --selection '<canonical SelectionPlan JSON>'
```

定位顺序：

1. `integration shard coverage mismatch`：查看诊断中的 `unassigned` 或 `stale`，同步修改 Rust catalog；
   不用补通配 selector。
2. `required_features`、`src_path` 或 `test_by_default` eligibility mismatch：同步修正 Cargo target；不要用
   源码 `cfg`、`#[ignore]` 或第二份 metadata inventory 绕过。
3. `cargo metadata ... failed`：先确认 lockfile 和 workspace manifest 有效，再重跑相同 metadata 命令。
4. `docker daemon 不可达，且缺少 ...`：只补齐消息列出的 shard 资源，或启动 Docker；不要为无关资源设占位值。
5. nextest 的 `[n/m] serial|parallel` 失败：用输出中的精确 package/binary filter 定位 target；共享状态类失败先看
   serial 批次，hermetic 失败看 parallel 批次。
6. 固定 integration group 失败：按 group、selection 中的 unit ID 查 nextest sidecar 与独立
   lifecycle/log artifact；其它 group 并行执行，稳定 `integration-critical` aggregate 不会用诊断 artifact 覆盖失败。

缓存命中只影响耗时，不改变 catalog coverage、测试结论或 result-only gate verdict。
