# Integration capability shards

> #1730：真集成 lane 按 capability 拆成六个 target-level shard。分类、资源和串并行调度的单一事实源是
> `xtask/src/integration_shards.rs` 的 catalog；本文只解释其运维语义。

## 入口与闭集

唯一入口是：

```bash
cargo xtask ci-integration --shard <name>
```

`event-transport` 与 `runtime-http-auth` 在 CI 中分别追加 `--partition 1/2`、`--partition 2/2`；其余
shard 不传 partition。每次 invocation 的 JUnit/JSON、空 bucket 与重放语义见
[`202607111501-1731-nextest-test-evidence.md`](./202607111501-1731-nextest-test-evidence.md)。

`<name>` 只能是 `postgres-domain`、`event-transport`、`runtime-http-auth`、
`consistency-fault`、`cdc-projection-saga`、`object-storage`。缺失、重复、未知 shard、额外尾参、自由 filter 和 `--all`
均 fail-closed。旧 `cargo xtask integration` 已删除，不提供 alias 或兼容 shim。

本地确需在缺少 nextest 或 Docker 时跳过，可显式追加 `--allow-missing-tools`；CI 不使用该宽限。

## Target 归属、资源与调度

`serial` 批次由 xtask 传 `--test-threads 1`；`parallel` 批次使用 nextest 默认并发。每个 shard 先跑
serial，再跑 parallel。`.config/nextest.toml` 不承载 selector/test-group；所有调度只由 typed registry 派生。

| Shard | 所需资源 | Serial targets | Parallel targets |
|-------|----------|----------------|------------------|
| `postgres-domain` | Postgres | `postgres:postgres` (lib)、`runtime:settings_secret_e2e` | `postgres:tx_capability_trybuild` |
| `event-transport` | Postgres、Redis、AMQP、MQTT | `amqp:integration`、`mqtt:integration`、`journeys:amqp_consumer_at_least_once_journey`、`journeys:identity_login_audit_durable_journey`、`runtime:event_transport_durable_e2e` | `amqp:amqp` (lib)、`mqtt:mqtt` (lib)、`journeys:eventtransport_journey`、`journeys:identity_login_audit_journey` |
| `runtime-http-auth` | Postgres、Redis | `runtime:runtime` (lib)、`runtime:configs_ready_e2e`、`runtime:identity_login_wire_e2e`、`runtime:wire_contract_e2e` | `runtime:auth_e2e`、`runtime:infra_builders_api`、`runtime:refresh_mint_e2e`、`runtime:runtime_serve_e2e` |
| `consistency-fault` | Postgres、Redis、AMQP | `redis-adapter:integration_claimer`、`journeys-fault-matrix:consistency_fault_matrix_journey` | `redis-adapter:redis` (lib)、`journeys:device_command_ack_timeout_journey` |
| `cdc-projection-saga` | Postgres | `runtime:settings_config_publish_durable_e2e` | `journeys:journeys` (lib)、`journeys:saga_projection_deps_journey`、`journeys:settings_config_publish_journey` |
| `object-storage` | MinIO / S3-compatible object storage | `s3:integration_object_store` | `s3:s3` (lib)、`s3:dlx_archive_store` |

表中未标 `(lib)` 的项均为 Cargo test target。selector 只能由 typed execution unit 渲染为精确的
`package(=...) and binary(=...) and kind(=...)`；环境变量或 CLI 输入不会进入 selector。

## 资源解析

缺少 shard 所需的任一外部资源时才要求 Docker，以 testcontainers self-provision；无关资源不阻塞该 shard。
外部资源的就绪判据为：

- Postgres：非空 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES`，且 `PGHOST`、`PGPORT`、`PGDATABASE`、
  `PGUSER`、`PGPASSWORD` 五项均非空。
- Redis：非空 `REDIS_TEST_URL`。
- AMQP：非空 `RSS_AMQP_TEST_URL`。
- MQTT：非空 `RSS_MQTT_TEST_URL`。
- Object storage：`RSS_S3_TEST_ENDPOINT`、`RSS_S3_TEST_ACCESS_KEY`、`RSS_S3_TEST_SECRET_KEY` 均非空；未提供时 testkit 自建 MinIO。

例如 `postgres-domain` 不要求 Redis、AMQP 或 MQTT；`consistency-fault` 不要求 MQTT。外部 AMQP
用于 fault matrix 时仍须预建测试所需 vhost 并为 URL 用户授权。

## Coverage fail-closed

每次运行 shard 前，xtask 执行 `cargo metadata --locked --no-deps --format-version 1`，校验旧 integration
lane 的九个 package：`postgres`、`redis-adapter`、`amqp`、`mqtt`、`journeys`、`runtime`、
`journeys-fault-matrix`、`testkit`、`s3`。其中每个 lib/test target 必须在 catalog 中恰好出现一次，每个 shard 必须非空；
新增未分类 target、过期 target、重复归属或缺 package 都在编译/运行测试前失败。

`s3:integration_object_store` 由 `object-storage` shard 强制执行；测试默认自建 MinIO，并在每轮创建启用
versioning、COMPLIANCE Object Lock 与有界 lifecycle 的独立 bucket，不存在 standalone 旁路。

## 本地运行与故障定位

精确复现 GitHub 七行 matrix：

```bash
cargo xtask ci-integration --shard postgres-domain
cargo xtask ci-integration --shard event-transport --partition 1/2
cargo xtask ci-integration --shard event-transport --partition 2/2
cargo xtask ci-integration --shard runtime-http-auth --partition 1/2
cargo xtask ci-integration --shard runtime-http-auth --partition 2/2
cargo xtask ci-integration --shard consistency-fault
cargo xtask ci-integration --shard cdc-projection-saga
cargo xtask ci-integration --shard object-storage
```

定位顺序：

1. `integration shard coverage mismatch`：查看诊断中的 `unassigned` 或 `stale`，同步修改 Rust catalog；
   不用补通配 selector。
2. `cargo metadata ... failed`：先确认 lockfile 和 workspace manifest 有效，再重跑相同 metadata 命令。
3. `docker daemon 不可达，且缺少 ...`：只补齐消息列出的 shard 资源，或启动 Docker；不要为无关资源设占位值。
4. nextest 的 `[n/m] serial|parallel` 失败：用输出中的精确 package/binary filter 定位 target；共享状态类失败先看
   serial 批次，hermetic 失败看 parallel 批次。
5. CI 单 shard 失败：下载名称含 shard 的 evidence，并按 [#1731 测试证据主文档](./202607111501-1731-nextest-test-evidence.md)
   的完整 context 模板查看 `Integration Tests / integration / <shard> / <partition-label> / cargo xtask integration`；
   未分区行的 `<partition-label>` 明确为 `unpartitioned`，最终以对应 run 的实际 check-run context 为准。其它
   shard 因 matrix `fail-fast: false` 会继续运行。

Integration matrix 只读恢复共享 Rust cache，不写 target cache；因此 cache miss 影响耗时，不应通过给五个
并发 shard 恢复 writer 权限来修复。
