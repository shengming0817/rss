# Integration capability shards

> #1730：真集成 lane 按 capability 拆成七个 target-level shard。分类、资源和串并行调度的单一事实源是
> `xtask/src/integration_shards.rs` 的 catalog；本文只解释其运维语义。

## 入口与闭集

唯一入口是闭合 `CiJobKey` executor：

```bash
cargo xtask ci run --job integration/<shard>[/<partition>]
```

`event-transport` 与 `runtime-http-auth` 分别登记 `1-of-2`、`2-of-2` 两个 job；其余 shard 的 job key
不带 partition。每次 invocation 的 JUnit/JSON、空 bucket 与重放语义见
[`202607111501-1731-nextest-test-evidence.md`](./202607111501-1731-nextest-test-evidence.md)。

`<shard>` 只能是 `postgres-domain`、`event-transport`、`runtime-http-auth`、
`consistency-fault`、`cdc-projection-saga`、`object-storage`、`production-runtime`。缺失、重复、未知 shard、
额外尾参、自由 filter 和 `--all` 均 fail-closed。旧 `cargo xtask integration` 与
`cargo xtask ci-integration` 均已删除，不提供 alias 或兼容 shim。

`ci run` 不提供缺工具宽限；缺少 nextest、Docker 或目标 shard 资源时 fail-closed。

## Target 归属、资源与调度

`serial` 批次由 xtask 传 `--test-threads 1`；`parallel` 批次使用 nextest 默认并发。每个 shard 先跑
serial，再跑 parallel。`.config/nextest.toml` 不承载 integration shard 的 selector/test-group；集成调度只由 typed registry 派生。

| Shard | 所需资源 | Serial targets | Parallel targets |
|-------|----------|----------------|------------------|
| `postgres-domain` | Postgres | `postgres:postgres` (lib)、`postgres-migration:postgres_migration` (lib)、`journeys:audit_list_tenant_entries_localtx_journey`、`journeys:identity_password_security_event_journey`、`journeys:settings_secret_publish_localtx_journey`、`runtime:settings_secret_e2e` | `postgres:feature_manifest`、`postgres:migration_ops_contract`、`postgres:tenant_transaction_trybuild`、`journeys:identity_logout_grant_journey` |
| `event-transport` | Postgres、Redis、AMQP、MQTT（Docker-only） | `amqp:integration`、`mqtt:integration`（`mqtt/broker-tests`）、`journeys:amqp_consumer_at_least_once_journey`、`journeys:identity_login_audit_durable_journey`、`runtime:event_transport_durable_e2e` | `amqp:amqp` (lib)、`mqtt:mqtt` (lib)、`journeys:eventtransport_journey`、`journeys:identity_login_audit_journey` |
| `runtime-http-auth` | Postgres、Redis | `runtime:runtime` (lib)、`runtime:configs_ready_e2e`、`runtime:identity_login_wire_e2e`、`runtime:service_token_replay_e2e`、`runtime:wire_contract_e2e` | `runtime:auth_e2e`、`runtime:infra_builders_api`、`runtime:refresh_mint_e2e`、`runtime:key_rotation_e2e`、`runtime:runtime_outputs_trybuild`、`runtime:runtime_serve_e2e` |
| `consistency-fault` | Postgres、Redis、AMQP | `redis-adapter:integration_claimer`、`journeys-fault-matrix:consistency_fault_matrix_journey` | `redis-adapter:redis` (lib)、`testkit:provider_catalog_trybuild` |
| `cdc-projection-saga` | Postgres | `runtime:settings_config_publish_durable_e2e` | `journeys:saga_projection_deps_journey`、`journeys:settings_config_publish_journey` |
| `object-storage` | MinIO / S3-compatible object storage | `s3:integration_object_store` | `s3:s3` (lib)、`s3:dlx_archive_store` |
| `production-runtime` | Docker | `journeys:two_replica_runtime`、`journeys:settingsonly_production_artifact` | `journeys:production_runtime`、`journeys:runtime_inventory` |

表中未标 `(lib)` 的项均为 Cargo test target。selector 只能由 typed execution unit 渲染为精确的
`package(=...) and binary(=...) and kind(=...)`；环境变量或 CLI 输入不会进入 selector。
两个 LocalTx journey 与 password-change 的 OutboxFact producer-transaction journey 必须保持在
`postgres-domain` 唯一 unpartitioned Serial batch；password-change 与 refresh 均不属于 LocalTx inventory，
`identity_password_security_event_journey` 验证 credential/account/grant/family/outbox 的 same-tx 原子性。
OutboxFact 的 `identity_logout_grant_journey` 由 Parallel batch 调度。各 batch 使用
`--no-tests=fail`；该 shard 的成功令牌只能在上述全部 batch 返回成功后生成。

## 资源解析

缺少 shard 所需的任一可替代外部资源时才要求 Docker，以 testcontainers self-provision；无关资源不阻塞该
shard。MQTT 是显式例外：其 T2 必须同时证明 fixture-owned PKI、exact ACL、正式 broker plugin、persistence
和 restart，故 `event-transport` 运行 MQTT target 时始终要求 Docker，外部 URL 不能替代。其余外部资源的
就绪判据为：

- Postgres：非空 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES`，且 `PGHOST`、`PGPORT`、`PGDATABASE`、
  `PGUSER`、`PGPASSWORD` 五项均非空。
- Redis：非空 `REDIS_TEST_URL`。
- AMQP：非空 `RSS_AMQP_TEST_URL`。
- MQTT：不接受外部资源输入；`RSS_MQTT_TEST_URL` 不再是配置面，测试始终使用 hermetic MQTTS fixture。
- Object storage：不接受外部资源输入；`object-storage` shard 始终使用 testkit 自建的 hermetic TLS MinIO。

例如 `postgres-domain` 不要求 Redis、AMQP 或 MQTT；`consistency-fault` 不要求 MQTT。外部 AMQP
用于 fault matrix 时仍须预建测试所需 vhost 并为 URL 用户授权。

## Coverage fail-closed

每次运行 shard 前，xtask 执行 `cargo metadata --locked --no-deps --format-version 1`，校验旧 integration
lane 的九个 package：`postgres`、`redis-adapter`、`amqp`、`mqtt`、`journeys`、`runtime`、
`journeys-fault-matrix`、`testkit`、`s3`。其中每个 lib/test target 必须在 catalog 中恰好出现一次，每个 shard 必须非空；
新增未分类 target、过期 target、重复归属或缺 package 都在编译/运行测试前失败。

`s3:integration_object_store` 由 `object-storage` shard 强制执行；测试默认自建 MinIO，并在每轮创建启用
versioning、COMPLIANCE Object Lock 与有界 lifecycle 的独立 bucket，不存在 standalone 旁路。

`journeys:settingsonly_production_artifact` 对应 typed execution unit
`SettingsOnlyProductionArtifact`，只在 `ProductionRuntime` 的 Serial batch 运行；四条 exact case 及其 artifact
selector 的闭合映射由代码 gate 证明，本文不承担 enforcement。该 shard 继续使用既有
`integration/production-runtime` 的 900 秒 SLO 预算和 develop/nightly 路由；本次 carrier 替换不新增 workflow、
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

精确复现 GitHub 九行 matrix：

```bash
cargo xtask ci run --job integration/postgres-domain
cargo xtask ci run --job integration/event-transport/1-of-2
cargo xtask ci run --job integration/event-transport/2-of-2
cargo xtask ci run --job integration/runtime-http-auth/1-of-2
cargo xtask ci run --job integration/runtime-http-auth/2-of-2
cargo xtask ci run --job integration/consistency-fault
cargo xtask ci run --job integration/cdc-projection-saga
cargo xtask ci run --job integration/object-storage
cargo xtask ci run --job integration/production-runtime
```

定位顺序：

1. `integration shard coverage mismatch`：查看诊断中的 `unassigned` 或 `stale`，同步修改 Rust catalog；
   不用补通配 selector。
2. `cargo metadata ... failed`：先确认 lockfile 和 workspace manifest 有效，再重跑相同 metadata 命令。
3. `docker daemon 不可达，且缺少 ...`：只补齐消息列出的 shard 资源，或启动 Docker；不要为无关资源设占位值。
4. nextest 的 `[n/m] serial|parallel` 失败：用输出中的精确 package/binary filter 定位 target；共享状态类失败先看
   serial 批次，hermetic 失败看 parallel 批次。
5. CI 单 shard 失败：下载名称含 shard 的 evidence，并按 [#1731 测试证据主文档](./202607111501-1731-nextest-test-evidence.md)
   的完整 context 模板查看 `Integration Tests / integration / <shard> / <partition-label> / cargo xtask ci run`；
   未分区行的 `<partition-label>` 明确为 `unpartitioned`，最终以对应 run 的实际 check-run context 为准。其它
   shard 因 matrix `fail-fast: false` 会继续运行。

Integration matrix 只读恢复共享 Rust cache，不写 target cache；因此 cache miss 影响耗时，不应通过给五个
并发 shard 恢复 writer 权限来修复。
