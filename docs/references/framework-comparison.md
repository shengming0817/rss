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
| reconcile L4 控制环 | `consistency`（引擎）· `deviceloop`（设备 L4 消费者） | `kube-rs/kube`（`kube-runtime/src/controller/mod.rs`） | `oxidecomputer/omicron` |
| saga L3 编排 | `consistency` / `eventexec` | `oxidecomputer/steno`（`src/lib.rs`） | `temporalio/sdk-rust`（`crates/sdk-core/src/lib.rs`） |
| Postgres LocalTx transaction runner | `adapters/postgres` | `launchbadge/sqlx`（`sqlx-core/src/transaction.rs`，消费式 commit/rollback + Drop rollback safety net） | `launchbadge/sqlx`（`sqlx-postgres/src/transaction.rs`，Postgres BEGIN/COMMIT/ROLLBACK manager） |
| 分布式锁 / fencing / 共识 | `distributed` | `tikv/tikv`（`Cargo.toml`，raft / fencing） | `databendlabs/openraft`（`openraft/src/lib.rs`）· `tikv/raft-rs`（`src/raft.rs`） |
| 证书 / PKI L4 | `deviceloop` | `rustls/rcgen`（`rcgen/src/lib.rs`）· `djc/instant-acme`（`src/lib.rs`） | `maxlambrecht/rust-spiffe`（`spiffe/src/lib.rs`）· cert-manager（概念，provider-agnostic 范式） |
| 可观测性 | `observ` | tokio `tracing` · `vectordotdev/vector`（`src/lib.rs`，管道范式） | `open-telemetry/opentelemetry-rust`（`opentelemetry/src/lib.rs`） |
| 健康分级聚合 / 系统元信息（sysinfo） | `syshealth` | `aegis-monitoring`（`docs.rs/aegis-monitoring/0.1.3`，`health/`，critical/non-critical 分级聚合；**仅 crates.io/docs.rs，无 GitHub raw 拉取路径**——读源码经 docs.rs `[src]`）· `danielschemmel/build-info`（`build-info-common/src/lib.rs`，`SystemInfo` 字段对标 `CrateInfo.name`/`.version`/`GitInfo.commit_short_id`；偏离 build.rs 自采集 → 组合根注入） | spring-boot-actuator `/info`（概念，服务元信息端点） |
| 授权 PDP / ABAC | `vocab` / `authn` | `casbin/casbin-rs`（`src/lib.rs`，RBAC/ABAC enforcer）· `eclipse-biscuit/biscuit-rust`（`biscuit-auth/src/lib.rs`，能力令牌） | `osohq/oso`（**已弃用**，Oso 转 SaaS；仅作 Polar / ABAC 概念参考，**勿读源码实现**） |
| 状态机 FSM | `consistency` / `deviceloop` | `mdeloof/statig`（`statig/src/lib.rs`） | typestate 模式 |
| workspace 组织 | （根 workspace） | `oxidecomputer/omicron`（`Cargo.toml`）· `risingwavelabs/risingwave`（`Cargo.toml`） | `zed-industries/zed`（`Cargo.toml`） |
| 错误模型 | `vocab` | `dtolnay/thiserror`（`src/lib.rs`，库错误枚举） | `shepmaster/snafu`（`src/lib.rs`，带 context，TiKV / GreptimeDB 在用） |
| xtask / 内部 codegen + lint 范本 | `xtask` | `rust-lang/rust-analyzer`（`xtask/src/main.rs`） | `matklad/cargo-xtask`（`README.md`，约定 spec） |
| CI 覆盖率门（绝对地板 + per-diff 增量） | `xtask`（`coverage.rs`/`diffcov.rs`） | `taiki-e/cargo-llvm-cov`（`src/json.rs` export JSON + `report --lcov` 复用 profdata；绝对地板门 `data[].files[].summary.lines`） | `Bachmann1234/diff_cover`（`README.rst`：per-diff 增量门——三点式 compare-branch + lcov + 「diff coverage = % of new/modified lines covered」定义） |
| CI 资源证据 / 磁盘低水位门 / cache writer | 根 CI（`.github/scripts` / reusable workflow / `xtask` 守卫） | `seaweedfs/seaweedfs`（`weed/util/minfreespace.go@5c511c4894c9f6fcbc0e3b7a5d9338628356aeca`；采纳“可用空间低于明确阈值则 fail-fast”，偏离为 CI 单次 `df` 门而非服务持续 min-free 监控）· `actions/cache`（`action.yml@55cc8345863c7cc4c66a329aec7e433d2d1c52a9` + `restore/action.yml` + `save/action.yml`；采纳显式 restore/save、primary/matched key 与 exact-hit 输出；RSS 对 executable cache 禁止 restore prefix，tool 只在 repository execution 前保存，target 绑定 Git tree）· GitHub reusable workflows（官方 `reuse-workflows`：同仓 `./.github/workflows/*.yml` 从 caller 同一 commit 加载；采纳薄 caller + literal lane，完整 job 单源在 `workflow_call`） | `taiki-e/install-action`（钉版 release installer；采纳其 SHA-256/可用 attestation/signature 的下载验证边界，`--version` 只验证 fresh install 版本，不让 cached binary 自证来源）· `Swatinem/rust-cache`（`src/cleanup.ts@c19371144df3bb44fab255c43d04cbc2ab54d1c4`；采纳 `CARGO_INCREMENTAL=0` 与 metadata 驱动清理，偏离为 download/target 物理拆分 + repository-owned schema v2 evidence）· `gradle/actions`（`docs/setup-gradle.md@6550634d3eb14a20275549de1588a83267023d42`；采纳 cache/build 前后诊断与 artifact 可运维性，偏离为 RSS 使用闭合 JSON + 原子 append + 5 GiB 硬门） |
| redis adapter — 幂等 claimer / kv 去重（`InboxStore` provider）+ 连接池 `ManagedResource` | `adapters/redis` | `redis-rs/redis-rs`（`redis/src/cmd.rs` — `cmd("SET").arg(..).arg("NX").arg("PX") + query_async`）· `deadpool-rs/deadpool`（`deadpool-redis/src/lib.rs` — `Pool`/`Config`/`Runtime`；`Pool::close` ⇒ `ManagedResource::shutdown`） | — |
| s3 adapter — 对象存储（`ObjectStore` provider: put/get/delete）+ `ManagedResource`；runtime S3 canary consumer（真实 put/get/delete/get-miss → `s3_object_store_ready`） | `adapters/s3` / `assemblies/runtime` | `awslabs/aws-sdk-rust`（`sdk/s3/src/client.rs` — `Client::{put_object,get_object,delete_object}`；对标 gocell `s3.ObjectUploader`@aws-sdk-go-v2；`default-features=false` 关 `default-https-client` 收 TLS license，runtime 用 `aws-smithy-http-client` 显式 rustls+ring） · `awslabs/smithy-rs`（`aws-smithy-mocks`，canned 响应单测 mock；`aws-smithy-http-client` `Builder::tls_provider(Rustls(Ring)).build_https()` / `build_http()`） | `apache/arrow-rs`（`object_store/src/aws`，provider-agnostic 概念参考） |
| vault adapter — Transit 数据签名（`Signer` provider: sign）+ `ManagedResource` | `adapters/vault` | `jmgilman/vaultrs`（`vaultrs/src/api/transit/requests.rs` — `SignDataRequest`：`POST {mount}/sign/{name}` + base64 `input`；`vaultrs/src/api/transit/responses.rs` — `SignDataResponse.signature`；最小自写 reqwest 客户端复刻该请求/响应形状，不依赖 vaultrs SDK） | `hashicorp/vault`（Transit API 文档，provider 范式概念参考；gocell `vault.transit_provider`@hashicorp/vault-go） |
| oidc adapter — JWT / 服务-token 入站验签（`diport::Pdp` provider：ES256+HS256，静态 KeySource）+ `ManagedResource` | `adapters/oidc` | `RustCrypto/elliptic-curves`（`p256/src/ecdsa.rs` — `VerifyingKey=ecdsa_core::VerifyingKey<NistP256>` + `Verifier::verify(msg,&sig)`，定长 r‖s 签名、`DigestAlgorithm=sha2::Sha256` 即 ES256）· `RustCrypto/MACs`（`hmac/src/lib.rs` — `Hmac<D>` + `Mac`/`KeyInit`，HS256 MAC；常数时间比对复用 `primitives::crypto::constant_time_eq`←`subtle`）· `RustCrypto/hashes`（`sha2`） | `maxlambrecht/rust-spiffe`（`spiffe/src/svid/jwt/mod.rs` — JWT-SVID 验签链范式：3 段 split→base64url→`alg` 白名单→按 `kid` 选 key→验签→exp/aud 校验。RSS **偏离**：白名单收窄至 ES256〔JWT 路径〕+HS256〔service-token 路径〕+ alg-key 路径隔离、加 iss 校验 + **注入 `diport::Clock`** 的 leeway/nbf、纯 RustCrypto **不**经 jsonwebtoken/ring（守卫 INVARIANT: OIDC-ALG-KEYPATH-01 @ adapters/oidc/src/verify.rs））；cert-manager/SPIFFE（provider-agnostic 验签器概念）。**JWKS key 源（#1197）**：`maxlambrecht/rust-spiffe`（`spiffe/src/jwt_source/mod.rs` — `JwtSource`：本地缓存 JWK bundle + 自动刷新 + 按 kid 查找 + 离线验签）+ cert-manager/k8s（controller/kubelet 拉取后写本地 Secret/挂载文件、应用读本地文件）。RSS **采纳本地文件源 + 外部 agent 刷新**（in-app 零 HTTP/TLS provider——无 license-clean 成熟 rustls provider + in-app HTTPS 是零信任生产规避的少数派，见 `docs/spec/003-pdp-verify-wiring/research.md` R3）；闭合 `enum KeySource` 统一 Static/Jwks，后台 poll 重载 + kid 索引轮转 + fail-closed + `ManagedResource` 关闭刷新句柄 |
| authn — JWT 签发（mint/sign）：claims 组装（sub/tenant/kind/exp/iat/iss/aud）+ ES256/HS256 紧凑 JWS 序列化（复用 `diport::Signer` + 注入 `diport::Clock`，纯计算零 crypto/I-O；真实 JWS-兼容 signer adapter〔ES256 定长 r‖s / HS256 HMAC〕+ httpserve 接线留 W） | `authn`（`src/mint.rs`：`JwtIssuer`/`JwtAccessPrincipal`/`JwtAlg`/`JwtIssueError`/`MintedJwt`） | `RFC 7515 §7.1`（JWS Compact Serialization：`base64url(header)."."base64url(payload)` 为 signing input、签名段 base64url 无填充；authn `JwtIssuer::issue_access` **直接实现**access-token 组装，与 `adapters/oidc/src/jws.rs` 验签侧**同 RFC 反方向**——verify=解析 / mint=组装）· `RFC 7519`（JWT registered claims：sub/exp/iat/iss/aud 名与语义） | `Keats/jsonwebtoken`（`src/encoding.rs` — `encode<T: Serialize>(&Header, &claims, &EncodingKey) -> String`：serialize header/claims→base64url→拼 signing input→`try_sign`→拼签名段，与 `JwtIssuer::issue_access` **同形**的工业 mint 流程；RSS **不依赖**——手写 base64+serde_json + 签名委托 `diport::Signer`，并用 `JwtAccessPrincipal` 在类型层区分 scoped 主体与 super-admin）；`JwtAlg` 闭枚举 = OIDC-ALG-WHITELIST-01 的 **mint 侧镜像**（alg=none/RS256 类型层不可 mint） |
| grpc adapter — gRPC 传输 scaffold（tonic 0.14 plaintext server + 标准健康服务 `tonic-health`，`grpc.health.v1` 协议）+ `ManagedResource` graceful shutdown | `adapters/grpc` | `hyperium/tonic`（`examples/src/health/server.rs` — `tonic_health::server::health_reporter()` → `Server::builder().add_service(health_service).serve_with_incoming_shutdown(..)`；tonic 0.14 拆 `tonic-prost` 使 core codec-agnostic；本切片 server+router、不启 tls，TLS 三模式/拦截器/proto-codegen = P2-6/P2-7 follow-up） | `hyperium/tonic`（`tonic-health/src/server.rs` — `HealthReporter` / `health_reporter` 实现） |
| mqtt adapter — MQTT v5 设备传输（`Publisher`/`Subscriber` provider：publish/subscribe）+ `ManagedResource`（driver task 泵 `EventLoop`） | `adapters/mqtt` | `bytebeamio/rumqtt`（`rumqttc/examples/asyncpubsub_v5.rs` — `MqttOptions`→`AsyncClient::new`→循环 `eventloop.poll()` 驱动 + `client.publish_with_properties`〔v5 `PublishProperties.correlation_data`=event_id，订阅侧流回 `Message.id`，对标 amqp `message_id` 传播〕/ `Packet::Publish` 收取；对标 gocell `mqtt` adapter@paho.mqtt.rust；`default-features=false` 关 TLS 收 crypto license——本 PR 仅明文 `mqtt://`，`mqtts://`/设备 mTLS〔依赖 softca〕+ app-level `$dead` DLT/`SupportsRequeue=false`/HoL〔P1-8，对标 amqp 推 P7〕= follow-up） | `eclipse/mosquitto`（broker fixture 镜像，testcontainers self-provision；MQTT 无 vhost ⇒ 跨域隔离经 per-domain 凭据+ACL，非命名前缀） |
| `secure`(blind_index) at-rest 字段加密 / blind index / deterministic opt-in（HMAC keyed-hash 旁路等值查询索引；随机化 AEAD 主密文不变；sub-key 派生 / filterBits 截断 / Transform 规范化 / lookup_set 轮换） | `crates/secure` | `paragonie/ciphersweet`（`src/EncryptedRow.php@master` per-(table,col,index) HMAC-SHA256 子密钥；`src/BlindIndex.php@master` filterBits 截断 + transformations[]；`src/Backend/BoringCrypto.php@master` bit-mask 截断） | `rails/rails`（`activerecord/lib/active_record/encryption/encryptable_record.rb@main` previous: 轮换窗口）· `tink-crypto/tink-go`（`daead/subtle/aes_siv.go@main`，威胁矩阵「leaks plaintext equality」否决论据） |
| testkit `containers` feature — 真集成测试 fixture（testcontainers self-provision postgres/redis/rabbitmq/mosquitto；adapter 集成 lane #1137；与 #1136 HTTP 契约 harness 同 crate） | `crates/testkit` | `testcontainers/testcontainers-rs-modules-community`（`src/postgres/mod.rs` / `src/redis/mod.rs` / `src/rabbitmq/mod.rs` / `src/mosquitto/mod.rs` — `Image` 默认镜像 + `AsyncRunner::start().await → ContainerAsync` + `get_host_port_ipv4`；`with_db_name` 满足 pg 守卫；mosquitto 默认 1883 anonymous）· `testcontainers/testcontainers-rs`（`testcontainers/src/core/containers/async_container.rs` — `ContainerAsync::exec(ExecCommand)` 跑 `rabbitmqctl add_vhost` 建 per-domain vhost） | gocell `integration-test` lane（testcontainers Go，概念出处；gocell-rust-ci-plan.md 已规划同形 lane） |
| nextest CI partition 与 invocation evidence（#1731） | `xtask/src/nextest.rs` | `cargo-nextest/nextest`（`nextest-runner/src/partition.rs@cargo-nextest-0.9.137`，commit `75ddba7e911b44c5c0700dac0415d824403de9bd`；hash partition 文法与确定性分桶） | GitHub Actions 官方 `store-and-share-data-from-a-workflow`（artifact upload/download 与 retention；本 PR 仅产 v2 manifest，不做 archive；仅当 retention 后仍需长期合规留存时另启不可变归档）· typed profile/partition、JUnit + JSON sidecar 与 workflow topology 守卫 |

## Rust 标准库参考

> `fix` 技能（标准库 / 核心生态优先）查此表：有既定做法时遵循，不自创。语言层细则见 `.claude/rules/rss/rust-standards.md`。

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
