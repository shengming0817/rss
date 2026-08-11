# RSS 对标框架参考（framework-comparison）

> **入口单一事实源** · `explorer` / `developer` / `ship` / `fix` 查「当前模块对标哪个开源项目」的入口。
>
> 本文件是「当前模块对标哪个开源项目」的**单一事实源**：概念映射 + **repo 坐标 + 关键源码起点路径** + primary/secondary
> 优先级。`CLAUDE.md` §参考框架 只保留 `ref:` 工作流并指回本文件，不再持表。供 `WebFetch` 拉 raw 源码对比；新建 / 重构
> 层内模块前，explorer 按下表 step 1 确定 primary / secondary 对标。
> 路径列是**起点**，explorer 用 `WebSearch` 校准具体文件与行号（仓库布局会变）。

## 模块对标表

> 本表只列**读源码优先的 Rust 工业对标 + 生态 crate**：每格 `·` / `/` 分隔的引用按 **primary（加粗，读源码首选）→ secondary（参考，可偏离）** 排序。
> Go / Java / .NET 等架构范式 / 概念出处见文末「概念谱系」附录（优先级远低于本表，仅作设计意图参考）。
> 下文「按模块扩展对标」表用 `primary | secondary` 列表达同一套语义；「Rust 标准库参考」表等权强制遵循、不分 primary/secondary。

| RSS 模块 / 层 | Rust 工业对标 + 生态（owner/repo · 起点） |
|---------------|------------------------------------------|
| 域 crate 生命周期 / init + 契约校验（`bootstrap`） | **`kube-rs/kube`**（`kube-runtime/src/controller/mod.rs`）· `oxidecomputer/omicron`（`Cargo.toml` 组合根） |
| 域 crate 运行时 / 依赖注入（组合根 `assemblies` / `bins`） | 构造器注入 · **`oxidecomputer/omicron`** / `risingwavelabs/risingwave`（手工接线范本）· `AzureMarker/shaku` |
| 代码生成（`generated` / build.rs / proc-macro） | **`oxidecomputer/typify`**（`typify/src/lib.rs`）· `prettyplease` · `oxidecomputer/dropshot`(代码→OpenAPI) / `oxidecomputer/progenitor`(OpenAPI→client) |
| 中间件（`httpserve` tower 层） | **`tower-rs/tower`**（`tower/src/builder/`）/ `tower-http` · `linkerd/linkerd2-proxy`（Layer / mTLS 工业标杆） |
| HTTP server（`httpserve`） | **`tokio-rs/axum`**（`axum/src/routing/`）· `oxidecomputer/dropshot`（`dropshot/src/lib.rs`） |
| 事件驱动（`eventexec` / EventBus） | **`serverlesstechnology/cqrs`**（crate `cqrs-es`，`src/lib.rs`，CQRS/ES）· `oxidecomputer/steno`（`src/lib.rs`，saga 编排） |

raw 拉取 URL 形态：`https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}`
（branch 多为 `master` 或 `main`，404 时换分支重试；大文件先 `Grep`/`WebSearch` 定位行号再局部拉取）。
默认分支为 `master` 的：`AzureMarker/shaku` · `tikv/tikv` · `tikv/raft-rs` · `vectordotdev/vector` ·
`dtolnay/thiserror` · `shepmaster/snafu` · `rust-lang/rust-analyzer` · `casbin/casbin-rs`；其余多为 `main`。

## 按模块扩展对标（主表 6 行之外）

> 主「模块对标表」6 行之外的模块；以下 owner/repo 坐标只在本文件维护。`crate` 列是 RSS 侧归属。
> `primary` 列 = 读源码首选，`secondary` 列 = 参考、可偏离（与主表「加粗 = primary」同一套语义）。

| RSS 模块 / 关注点 | crate | primary 对标（owner/repo · 起点） | secondary |
|-------------------|-------|----------------------------------|-----------|
| reconcile L4 控制环 | `consistency`（引擎）· `deviceloop`（设备 L4 消费者）· `assemblies/deviceidentity`（#1904 draft library composition） | `kube-rs/kube`（`kube-runtime/src/controller/mod.rs`） | `oxidecomputer/omicron`。RSS #1904 偏离：仅以 `Demo + Identity + Demo`、closed five-role provider catalog 证明 library composition；六份 proposal contract 保持 draft，且不声明 binary/listener/image/journey/production activation。provider inventory 仍只由 assembly manifest + closed registry 持有。 |
| saga L3 编排 | `consistency` / `eventexec` | `oxidecomputer/steno`（`src/lib.rs`） | `temporalio/sdk-rust`（`crates/sdk-core/src/lib.rs`） |
| Postgres LocalTx transaction runner | `adapters/postgres` | `launchbadge/sqlx`（`sqlx-core/src/transaction.rs`，消费式 commit/rollback + Drop rollback safety net；`sqlx-core/src/pool/connection.rs`，`close_on_drop` 隔离 pooled connection） | `launchbadge/sqlx`（`sqlx-postgres/src/transaction.rs`，Postgres BEGIN/COMMIT/ROLLBACK manager） |
| Postgres mutable outbox 原子 batch claim / lease deadline | `consistency` / `eventexec` / `adapters/postgres` | `geofmureithi/apalis`（`packages/apalis-sql/migrations/postgres/20250307001101_add_job_priority.sql@49f90e1304f8f218eb08ce6ca0f1b4934f3ed011`，`UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED) RETURNING` 原子 batch claim；RSS 由 `PgOutbox::claim_batch` 铸造 provider-owned opaque `PgClaimedOutboxEntry`，lease/durable context 不进 `consistency` 公开可 hydrate 面） | `Diggsey/sqlxmq`（`migrations/20220208120856_fix_concurrent_poll.up.sql@79cbd3091ab39178d5de65d14416dad6067ac067`，显式持久化 `attempt_at` deadline；RSS 偏离为 UUID token + 精确 deadline 严格 CAS） |
| AMQP publisher confirm / 有界发布 | `adapters/amqp` / `adapters/postgres` | `amqp-rs/lapin`（`src/generated/channel.rs@v4.10.0` 的 `basic_publish` 返回 `PublisherConfirm`；`src/publisher_confirm.rs@v4.10.0` 的 unresolved-confirm `Drop` 会注册给 `Channel::wait_for_confirms()`；`src/returned_messages.rs@v4.10.0` 只在 drain/channel-error 清 dropped confirms。RSS 以单一 deadline 覆盖两次 await；timeout 先以 generation CAS 退休旧 channel，再由 single-flight owned recovery 在同一 absolute recovery deadline 内 drain/close/create 新 confirm channel，恢复期间 fail-fast，且始终视为 broker 可能已接收） | RabbitMQ publisher confirms（at-least-once 下 confirm 丢失允许稳定 ID 重投；RSS 另以 Postgres typed watchdog/lease preflight/settle deadline 收口） |
| Postgres mutable outbox 终态生命周期 / retention | `adapters/postgres` | `spring-projects/spring-modulith`（`spring-modulith-events/spring-modulith-events-jdbc/src/main/java/org/springframework/modulith/events/jdbc/JdbcEventPublicationRepositoryV2.java`，原子写 `COMPLETED + completion_date`、按终态时间清理；Rust 生态无同成熟度实现，故采用实现级开源对标） | `spring-projects/spring-modulith`（`spring-modulith-events/spring-modulith-events-jdbc/src/main/resources/org/springframework/modulith/events/jdbc/schemas/v2/schema-postgresql.sql`，终态时间索引） |
| 分布式锁 / fencing / 共识 | `distributed` | `tikv/tikv`（`Cargo.toml`，raft / fencing） | `databendlabs/openraft`（`openraft/src/lib.rs`）· `tikv/raft-rs`（`src/raft.rs`） |
| 证书 / PKI L4 | `deviceloop` | `rustls/rcgen`（`rcgen/src/lib.rs`）· `djc/instant-acme`（`src/lib.rs`） | `maxlambrecht/rust-spiffe`（`spiffe/src/lib.rs`）· cert-manager（概念，provider-agnostic 范式） |
| 可观测性 | `observ` | tokio `tracing` · `vectordotdev/vector`（`src/lib.rs`，管道范式） | `open-telemetry/opentelemetry-rust`（`opentelemetry/src/lib.rs`） |
| 健康分级聚合 / 系统元信息（sysinfo） | `syshealth` | `aegis-monitoring`（`docs.rs/aegis-monitoring/0.1.3`，`health/`，critical/non-critical 分级聚合；**仅 crates.io/docs.rs，无 GitHub raw 拉取路径**——读源码经 docs.rs `[src]`）· `danielschemmel/build-info`（`build-info-common/src/lib.rs`，`SystemInfo` 字段对标 `CrateInfo.name`/`.version`/`GitInfo.commit_short_id`；偏离 build.rs 自采集 → 组合根注入） | spring-boot-actuator `/info`（概念，服务元信息端点） |
| 授权 PDP / ABAC | `vocab` / `authn` | `casbin/casbin-rs`（`src/lib.rs`，RBAC/ABAC enforcer）· `eclipse-biscuit/biscuit-rust`（`biscuit-auth/src/lib.rs`，能力令牌） | `osohq/oso`（**已弃用**，Oso 转 SaaS；仅作 Polar / ABAC 概念参考，**勿读源码实现**） |
| 状态机 FSM | `consistency` / `deviceloop` | `mdeloof/statig`（`statig/src/lib.rs`） | typestate 模式 |
| workspace 组织 | （根 workspace） | `oxidecomputer/omicron`（`Cargo.toml`）· `risingwavelabs/risingwave`（`Cargo.toml`） | `zed-industries/zed`（`Cargo.toml`） |
| 错误模型 | `vocab` | `dtolnay/thiserror`（`src/lib.rs`，库错误枚举） | `shepmaster/snafu`（`src/lib.rs`，带 context，TiKV / GreptimeDB 在用） |
| xtask / 内部 codegen + lint 范本 | `xtask` | `rust-lang/rust-analyzer`（`xtask/src/main.rs`） | `matklad/cargo-xtask`（`README.md`，约定 spec） |
| 内部 CLI 表层（subcommand / flags / help） | `xtask`、`assemblies/runtime` operator | `clap-rs/clap`（`clap_derive` / `examples/derive_ref`；typed `Parser`/`Subcommand`） | `rust-lang/rust-analyzer`（`xtask/src/flags.rs`，`xflags` 声明式范式对照；RSS 有意选 clap 覆盖 operator 面） |
| Cargo workspace package graph / root build facts | `crates/workspacefacts`（`xtask` command-scope loader） | `guppy-rs/guppy`（`guppy/src/graph/graph_impl.rs`、`build_targets.rs`、`query.rs`、`cargo/cargo_api.rs`、`feature/resolve.rs`、`platform/platform_spec.rs` @ 0.17.26；完整 metadata JSON → `PackageGraph` catalog，闭合 selection → `CargoSet` target/host closure） | RSS 仅保留 owned package/path/target/build DTO；all-features catalog 与 root-specific selection 分型，只将 selected CargoSet links 投影为稳定 activation path，不自建第二套 feature/platform resolver，也不使用 guppy `MetadataCommand` 绕过 xtask command funnel |
| CI 覆盖率门（绝对地板 + per-diff 增量） | `xtask`（`coverage.rs`/`diffcov.rs`） | `taiki-e/cargo-llvm-cov`（`src/json.rs` export JSON + `report --lcov` 复用 profdata；绝对地板门 `data[].files[].summary.lines`） | `Bachmann1234/diff_cover`（`README.rst`：per-diff 增量门——三点式 compare-branch + lcov + 「diff coverage = % of new/modified lines covered」定义） |
| CI 固定 Job 委托 / result-only 聚合 | 根 CI（reusable workflow / `xtask` typed preflight 与 executor） | GitHub reusable workflows（官方 `reuse-workflows`；采纳薄 caller、闭合 typed input 与固定 `workflow_call` Job 实现）· GitHub Actions job result context（固定 `preflight`、`check`、`test-affected` 与四个闭合 integration carrier；稳定 `integration-critical` 和 `ci-gate` 只聚合结果；LocalOnly required evidence 由 `test-affected` producer 拥有） | cargo-nextest（组件测试选择、JUnit 与 replay sidecar 仅作执行/诊断；不得作为第二个 gate verdict owner） |
| redis adapter — 幂等 claimer / kv 去重（`InboxStore` provider）+ 连接池 `ManagedResource` | `adapters/redis` | `redis-rs/redis-rs`（`redis/src/cmd.rs` — `cmd("SET").arg(..).arg("NX").arg("PX") + query_async`）· `deadpool-rs/deadpool`（`deadpool-redis/src/lib.rs` — `Pool`/`Config`/`Runtime`；`Pool::close` ⇒ `ManagedResource::shutdown`） | — |
| s3 adapter — 对象存储（`ObjectStore` provider: put/get/delete）+ `ManagedResource`；runtime S3 canary consumer（真实 put/get/delete/get-miss → `s3_object_store_ready`） | `adapters/s3` / `assemblies/runtime` | `awslabs/aws-sdk-rust`（`sdk/s3/src/client.rs` — `Client::{put_object,get_object,delete_object}`；对标 gocell `s3.ObjectUploader`@aws-sdk-go-v2；`default-features=false` 关 `default-https-client` 收 TLS license，runtime 用 `aws-smithy-http-client` 显式 rustls+ring） · `awslabs/smithy-rs`（`aws-smithy-mocks`，canned 响应单测 mock；`aws-smithy-http-client` `Builder::tls_provider(Rustls(Ring)).build_https()` / `build_http()`） | `apache/arrow-rs`（`object_store/src/aws`，provider-agnostic 概念参考） |
| vault adapter — RSS profile-bound Transit JWS 签名（`Signer` provider: sign）+ `ManagedResource` | `adapters/vault` | HashiCorp Vault Transit Sign API（`POST {mount}/sign/{name}`、base64 `input`、ECDSA `marshaling_algorithm=jws`；`ref: hashicorp/vault api-docs/secret/transit#sign-data`）· `jmgilman/vaultrs`（`vaultrs/src/api/transit/requests.rs` / `responses.rs`） | RSS 偏离通用 SDK：只暴露接收 `JwtSigningBinding<RssAccessProfile>` 的构造器，HTTP 前精确拒绝 key/purpose 漂移；startup 与周期 readiness 用固定 challenge 对 active `kid` 的当前 P-256 JWKS 公钥做本地验签，T2 mint→verify round-trip 继续证明外部 material 行为。 |
| oidc adapter — 三个互斥 typed token profile 入站验签（RSS/Federated ES256-only；Service HS256-only）+ profile-specific `ManagedResource` | `adapters/oidc` | RFC 8725 §3.11–3.12（显式 typing + 互斥验证规则）· RFC 9068 §2.1（`typ=at+jwt`）· RFC 7515 §4.1.11（`crit`）· `RustCrypto/elliptic-curves`（P-256 ES256）· `RustCrypto/MACs`（HS256） | `maxlambrecht/rust-spiffe` JWT-SVID 验签链范式。RSS **偏离**：sealed profile marker + `OidcProvider<P>`，listener/issuer/audience/key-source 隔离；RSS/Service/Projection 的 tenant/kind claim 名由 `TokenPolicy` 固定且无 operator override，Federated 独占 extension-claim 映射与 kind allowlist；exact `kid`，无 blind-scan；任何 `crit` 拒绝；16/4/12/1 KiB encoded bounds 先于 decode/JSON/key lookup/crypto/replay。 |
| authn — typed token profile 签发（RSS Access ES256、Service Token HS256；Federated 无 issuer） | `authn`（`src/mint.rs`：`JwtIssuer<P>` / `JwtIssuerConfig<P>` / `MintedJwt`；`src/grant.rs`：`AuthGrant` / `RssAccessIssueInput`） | RFC 7515 §7.1（JWS Compact Serialization）· RFC 8725 §3.11–3.12（显式 profile 与互斥 validation）· RFC 9068 §2.1（access token `typ`）· RFC 7519（registered claims） | `Keats/jsonwebtoken` encoding flow。RSS **偏离**：`JwtSigningBinding<P>` 从 sealed profile + active key 派生 algorithm/canonical purpose/request；claim 序列化直接读取 `TokenPolicy` tenant/kind wire names；RSS Access 只从 `AuthGrant` 借出私有 issue input，固定 User 并签入 `sid/jti/auth_time/authn_epoch`，TTL `1..=900s` 且不越过 grant expiry；Service TTL `1..=300s`；裸 purpose 与错误 profile 构造在编译期不存在。 |
| grpc adapter — gRPC 传输 scaffold（tonic 0.14 plaintext server + 标准健康服务 `tonic-health`，`grpc.health.v1` 协议）+ `ManagedResource` graceful shutdown | `adapters/grpc` | `hyperium/tonic`（`examples/src/health/server.rs` — `tonic_health::server::health_reporter()` → `Server::builder().add_service(health_service).serve_with_incoming_shutdown(..)`；tonic 0.14 拆 `tonic-prost` 使 core codec-agnostic；本切片 server+router、不启 tls，TLS 三模式/拦截器/proto-codegen = P2-6/P2-7 follow-up） | `hyperium/tonic`（`tonic-health/src/server.rs` — `HealthReporter` / `health_reporter` 实现） |
| mqtt adapter — MQTT v5 设备传输（单一 mTLS persistent `MqttSession`：exact publish/subscribe、manual ACK、readiness/reload）+ `ManagedResource` | `adapters/mqtt` | `bytebeamio/rumqtt`（`rumqttc/examples/async_manual_acks_v5.rs` — `MqttOptions` / `set_manual_acks(true)` / 单 `EventLoop::poll` / `AsyncClient::ack`；RSS 同一 driver 另固定 `clean_start=false`、bounded expiry 与 explicit rustls）· `eclipse-mosquitto/mosquitto`（`include/mosquitto_plugin.h` — v5 plugin lifecycle；`include/mosquitto_broker.h` — `MOSQ_EVT_MESSAGE` / `mosquitto_evt_message` / `mosquitto_client_certificate`；`plugins/message-timestamp/mosquitto_message_timestamp.c` — message property mutation；`src/plugin.c` — event callback rejection/propagation） | `testcontainers/testcontainers-rs`（`testcontainers/src/buildables/generic.rs` — `GenericBuildableImage` 从 repository Dockerfile 构建正式 Mosquitto mTLS/plugin fixture；RSS 偏离通用 Mosquitto module 的 anonymous 1883 默认，不接受外部 URL fallback） |
| `secure`(blind_index) at-rest 字段加密 / blind index / deterministic opt-in（HMAC keyed-hash 旁路等值查询索引；随机化 AEAD 主密文不变；sub-key 派生 / filterBits 截断 / Transform 规范化 / lookup_set 轮换） | `crates/secure` | `paragonie/ciphersweet`（`src/EncryptedRow.php@master` per-(table,col,index) HMAC-SHA256 子密钥；`src/BlindIndex.php@master` filterBits 截断 + transformations[]；`src/Backend/BoringCrypto.php@master` bit-mask 截断） | `rails/rails`（`activerecord/lib/active_record/encryption/encryptable_record.rb@main` previous: 轮换窗口）· `tink-crypto/tink-go`（`daead/subtle/aes_siv.go@main`，威胁矩阵「leaks plaintext equality」否决论据） |
| testkit `containers` feature — 真集成测试 fixture（testcontainers self-provision postgres/redis/rabbitmq；MQTT 自建正式 mTLS/plugin image；与 #1136 HTTP 契约 harness 同 crate） | `crates/testkit` | `testcontainers/testcontainers-rs-modules-community`（`src/postgres/mod.rs` / `src/redis/mod.rs` / `src/rabbitmq/mod.rs` — module image + `AsyncRunner::start().await → ContainerAsync` + `get_host_port_ipv4`）· `testcontainers/testcontainers-rs`（`testcontainers/src/core/containers/async_container.rs` — lifecycle/restart；`testcontainers/src/buildables/generic.rs` — `GenericBuildableImage` + repository Dockerfile 构建 exact Mosquitto plugin image） | gocell `integration-test` lane（testcontainers Go，概念出处）；MQTT 明确不采用 community Mosquitto module 的 anonymous/plaintext 默认。 |
| nextest CI partition、组件测试唯一所有权与 invocation evidence（#1731、#1883） | `xtask/src/nextest.rs` | `cargo-nextest/nextest`（`nextest-runner/src/partition.rs@cargo-nextest-0.9.137`，commit `75ddba7e911b44c5c0700dac0415d824403de9bd`；hash partition 文法与确定性分桶） | GitHub Actions 官方 `store-and-share-data-from-a-workflow`（artifact upload/download 与 retention；本 PR 仅产 v3 manifest，不做 archive；仅当 retention 后仍需长期合规留存时另启不可变归档）· typed component selection/feature closure、partition、JUnit + JSON sidecar 与 workflow topology 守卫 |

## Rust 标准库参考

> `fix` 技能（标准库 / 核心生态优先）查此表：有既定做法时遵循，不自创。语言层细则见 `docs/rules/rust-standards.md`。

| 场景 | 标准库 / 核心生态做法 |
|------|----------------------|
| 错误类型 | `thiserror`（库错误枚举）/ `anyhow`（应用边界），见 `error-handling.md` |
| 时间 | `Clock` trait 注入（构造器位置参），禁止默认系统时钟 |
| 集合 / 迭代 | 入参优先 `&[T]` / `impl Iterator`，避免无谓 `clone` |
| 序列化 | 仅 contract / DTO derive `serde`，domain 类型不 derive |
| 并发 | tokio task + `CancellationToken`，资源 RAII 清理 |
| HTTP 测试 | `tower::ServiceExt::oneshot` + `axum::http` 驱动 handler |

## 概念谱系（设计范式出处 · 多生态）

> 各模块的**架构范式发源地**（跨 Go / Java / .NET 生态）。RSS 借其设计意图、用上「模块对标表」的 Rust 工业对标实现。
> 各行按范式**真实发源地**标注生态，不强求每行覆盖三生态（如 reconcile / codegen 范式主源自 Go，无同级 Java/.NET 锚点）。
> **本附录优先级远低于上「模块对标表」**——只作概念出处参考，故只列框架名、不带源码起点路径。

| RSS 模块 | 概念范式出处（Go / Java / .NET） | 借鉴的概念 |
|----------|----------------------------------|-----------|
| 域生命周期 / reconcile | `kubernetes/kubernetes`（Go） | 控制器 / desired-state 收敛环 |
| 依赖注入 / 组合根 | `uber-go/fx`（Go）· Spring / Spring Boot（Java）· ASP.NET Core DI（.NET） | DI 容器 + 生命周期（**Rust 无同级框架**，唯一概念锚点）|
| 代码生成 | `zeromicro/go-zero` goctl（Go） | API spec → code 工具链 |
| 中间件 | `go-kratos/kratos`（Go）· ASP.NET Core middleware pipeline（.NET） | 中间件链 / pipeline |
| 事件驱动 / saga | `ThreeDotsLabs/watermill`（Go）· Axon Framework（Java）· MassTransit（.NET） | 消息路由 / pubsub / CQRS-saga 编排 |

## 维护

模块新增 / 对标变更时**只改本文件**——本文件是对标的**单一事实源**（Rust 工业对标主表 + 完整 owner/repo + 起点路径 +
扩展模块 + primary/secondary 优先级 + 多生态概念谱系附录）。`CLAUDE.md` §参考框架 不持表、只留 `ref:` 工作流并指回本文件，故无第二份表
需同步（单源化消除了原「两表逐行同序」漂移面）。表中无匹配模块时，explorer 须
fail-loud（见 `.claude/agents/explorer.md` step 1），不静默吐空结论。
