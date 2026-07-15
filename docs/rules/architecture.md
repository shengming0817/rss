# RSS 架构与 workspace 规则

> 本文件是 RSS **架构单一事实源**,并且是**扁平 workspace 结构树的唯一持有者**。
> 所有规则、CLAUDE.md、agent、skill 在涉及"目录 / crate / 层 / contract / 一致性等级 / 命名"时以本文件为准。
> (GoCell→RSS 迁移对照归档见 `docs/prd/rust-mapping.md`,历史快照、非现行规则。)

## 架构风格(domain-native)

RSS 采用 **domain-native 治理**:bounded context 之间只经 **contract** 通信、操作按 **L0–L4 一致性等级**分类、
**journeys** 为验收单源。结构上是惯用扁平 Rust workspace(见 §扁平 workspace 结构)。

适配原则:**能用 Cargo/rustc/官方工具链直接强制的约束,就不自己写治理机器**——目录因此收缩成常规 Rust
workspace(见 §扁平 workspace 结构、§Rust 原生强制)。

## 命名(单源,全仓统一)

- **架构风格**称 **`domain-native`**:bounded context 只经 contract 通信 + L0–L4 分类 + journeys 验收。
- **单元一律叫「域 crate（domain）」**——一个 bounded context = 一个域 crate(identity/settings/audit/contractreg/syshealth)。
  派生表述统一为 **跨域 / per-domain / `domain` metric label / `RSS_<DOMAIN>_*` env / `Domain*` 类型**。
- 域 crate 内的 **feature 模块**(`pub(crate)` 封装)承载更细的边界,不是独立 crate。
- crate 名一律 **concat 无 dash、不加 `rss-` 前缀**——路径已表达分层与归属,产品名 `rss` 只保留在 `bins/rss` 一处。
  仅当扁平 `crates/` 与外部依赖 crate 真重名又缺路径语境时才加限定:`httpserve`(避开 `http`)、`authn`(避开 `auth`)、
  `settings`(避开 `config`);`adapters/` 用裸后端名(目录 `adapters/redis`)。与自身依赖的 crates.io crate 同名的
  (`redis`/`prometheus`)——尤其经传递依赖引入(如 deadpool-redis 拉 `redis@1.x`,无法 `package=` 重命名传递包)——
  其 **package 名加 `-adapter` 后缀**(`name = "redis-adapter"`)避免 `cargo -p` 与 package-id 歧义,**`[lib] name` 保留裸名**
  (`use redis::…` 不污染导入面);deny.toml ban 按 package 名(`redis-adapter`)照常守,无需 source-centric 豁免。

## 核心载体

| 概念 | Rust/Cargo 载体 | 说明 |
|------|----------------|------|
| bounded context | **域 crate**(library) | identity/settings/...;跨域只经 contract |
| feature 模块 | 域 crate 内 `pub(crate)` 模块 | intra-crate 边界;不是独立 crate |
| Contract | `contracts/{kind}/{domain}/{version}/` 的 `contract.toml` + `*.schema.json` 声明源 | typify/xtask 派生 Rust 进 `generated/` crate;跨边界唯一 wire 载体 |
| Contract 归属 | `owner` = 域 crate 名 / `_framework`(sentinel) | provider-agnostic 中立契约归框架 |
| Assembly | `assemblies/{name}/` 的 `assembly.toml`(+ `bins/server` / bin crate) | 依赖闭包 = 物理打包；static assembly intent + DI provider 声明源 |
| 一致性等级 L0–L4 | `contract.toml` 的 `consistencyLevel` 字段 + typed `[capabilities.*]` 证据块；L4 另需顶层 `[reconcile]` block；active HTTP 同源派生 `ROUTE: vocab::HttpRouteBinding<RouteMarker, ConsistencyMarker>`，`HttpSpec::route` 由 `ROUTE.evidence()` 擦除供元数据查询 | `ConsistencyMarker` 由 manifest codegen 单源选择，不可手写替换；非 L0 state 经 `.with_state`闭合，L0 只允许 stateless 或 `.with_classified_state` 的 Read/Auth + LocalPrivilege；`xtask` R22 强制等级、能力证据与 L4 reconcile 声明一致；endpoint 构造要求 binding marker 与 handler `ContractMarker` 相同，request extension 传播同一 evidence |
| context 控制流值(tenant/principal) | `runctx::RequestCtx`/`AppCtx`(`task_local` 传播);tenant payload = `vocab::tenant::TenantId` | sealed 构造 + redacted Debug + fail-closed 取用(决策 #2 → ADR-002);base intra-base DAG `runctx → vocab` |
| 层 | 扁平 `crates/` 分组 + `deny.toml` 强制 | 见 §扁平 workspace 结构、§分层 |

一句话:cargo 的 **crate ≈ 域 / 服务 / adapter / contract 派生体**,**workspace ≈ assembly**;
Rust 的**类型系统 + crate 依赖图原生强制了大部分静态架构约束**(见 §Rust 原生强制)。

## 扁平 workspace 结构(结构树唯一持有者)

```
rss/
├── Cargo.toml            # [workspace] members + [workspace.dependencies] 统一版本
├── deny.toml             # cargo-deny：分层禁依赖 + license + advisory（分层强制载体）
├── clippy.toml           # disallowed-methods/types/macros（clock/panic/import 纪律）
├── rust-toolchain.toml
├── .config/nextest.toml  # cargo-nextest（进程隔离 / 重试）
├── crates/               # 全部库 crate，扁平（Rust 惯例，非分层目录）
│   ├── vocab/            # error(thiserror) / authz / tenant / query（基础词汇）
│   ├── ids/              # sealed newtype（私有字段 = 硬封）
│   ├── securederive/    # proc-macro：#[derive(Redact)] 字段级脱敏（intra-base DAG 低于 secure）
│   ├── secure/           # redaction（字段级 Redact 策略模型）/ aead / cookie / pathsafe
│   ├── support/          # http / pg / validation 杂项
│   ├── runctx/           # 请求上下文(tenant/principal)；可观测 ID 走 tracing span
│   ├── diagctx/          # 诊断信道 fail-open correlation（ADR-002 §D1-bis）
│   ├── consistency/      # outbox / saga / reconcile / projection / command_journal / idempotency（纯态机 + trait，L0–L4）
│   ├── primitives/       # crypto / authplan / healthz / circuitbreaker（引擎纯计算原语）
│   ├── tracewire/        # W3C traceparent capture/restore 单源（outbox→consumer trace 续传，唯一 otel 桥落点，#1224）
│   ├── diport/           # DI-infra：可替换 provider 的 DI port trait 单源；动态消费用 dynosaur，跨 Send+Sync 多次调用用静态泛型（ADR-003 #1095）
│   ├── httpserve/        # axum router / middleware / health
│   ├── authn/            # jwt / session / refresh / PDP / Principal
│   ├── bootstrap/        # composition / config / shutdown / worker
│   ├── eventexec/        # outbox relay / eventbus / saga executor·tailer / command
│   ├── deviceloop/       # cert lifecycle·signing（L4）
│   ├── observ/           # metrics / logging / grpc interceptor / websocket（audit sink 迁 diport，#1075）
│   ├── distributed/      # distlock / cas / transport
│   ├── testkit/          # 服务层 test-support：HTTP 契约测试 oneshot harness（经 [dev-dependencies] 被域/组合根消费，零 adapter 依赖，不进生产 shipped 图）
│   ├── identity/         # 域：身份 / 会话 / RBAC / ABAC
│   ├── settings/         # 域：版本化配置 / flag（避开 config 重名）
│   ├── audit/            # 域：审计链
│   ├── contractreg/      # 域：运行时契约 submit / list
│   └── syshealth/        # 域：健康聚合
├── adapters/             # 一 adapter 一 crate + feature 门控；裸后端名（adapters/ 路径消歧）
│   ├── postgres/ redis/ amqp/ mqtt/ s3/
│   ├── oidc/ grpc/ httpd/ otel/ prometheus/ vault/   # httpd = HTTP 传输（HttpServer bind+serve+ManagedResource，对标 grpc，#1320）
│   ├── softca/ ratelimit/
│   └── memory/           # in-mem DI port provider（测试 / demo 注入；被 journeys 组合根消费）
├── bins/
│   ├── server/           # 部署二进制
│   └── rss/              # 薄 cli：只放 xtask/cargo 干不了的运行时命令（产品/二进制名仅此处保留）
├── contracts/            # ★ 跨边界单源：{kind}/{domain}/{version}/contract.toml + *.schema.json（typify 消费）
├── assemblies/           # ★ 物理打包（runtime/settingsonly/identityaudit；assembly.toml 声明 static intent + DI provider）
├── composition/          # ★ 可复用的域组合根接线（依赖域 + adapter；不承载 assembly intent）
│   ├── settings/         # settings PG/KeyProvider typed wiring + readiness 生命周期
│   ├── identity/         # identity PG/Signer/JWT typed wiring
│   └── audit/            # audit PG/MacVerifier typed wiring
├── journeys/             # ★ 验收规格（*-journey.toml）+ status-board.toml；亦承载验收 journey 组合根 crate（demo 组装根 + 集成测试，RW-G1）
├── fixtures/             # ★ 测试夹具（fixture-*.toml）
├── examples/             # ssobff / todoorder / iotdevice / corebundlestarter
├── xtask/                # codegen + golden + 契约/一致性治理校验
├── generated/            # 契约派生的 committed crate（一等审查材料）；其余 codegen 走 build.rs OUT_DIR + insta
└── actors.toml           # 外部 Actor 注册（参与 contract 但不属于域模型的系统）
```

## 分层(crate 图 + deny.toml 编译期强制)

- **基础** `vocab`/`ids`/`securederive`/`secure`/`support`/`runctx`/`diagctx`:依赖 std + 外部 crate(serde/thiserror/uuid…),**不依赖引擎/DI-infra/服务/域/adapters**。基础层内部按 enumerated intra-base DAG 单向依赖:`diagctx（独立根）◁ vocab ◁ ids ◁ securederive ◁ secure ◁ support ◁ runctx`(右可依赖左 = **DAG 前向边均 sanctioned**、反向 / 同 crate 禁止)；`diagctx` 为独立根，不依赖其它基础 crate，不被其它基础 crate 依赖，仅向上被服务/域/adapters/组合根消费（诊断信道 fail-open，ADR-002 §D1-bis）。现有 sanctioned 前向边:`runctx → vocab`(`AppCtx` 的 tenant payload 收敛为具体 `vocab::tenant::TenantId`,ADR-002 §D3,决策 #2)与 `secure → securederive`(字段级脱敏 `#[derive(Redact)]` proc-macro,#1360；`securederive` 是编译期纯工具 crate,出边全外部,非 SemVer 库面 ⇒ public-api baseline 经 `layers::is_proc_macro` 排除)。`INVARIANT: BASE-INTRADAG-01`:无环由 cargo 天然守(反向 2-crate 边即成环被拒);前向 / 反向方向守由 `cargo xtask layer-deps` 的 `layers::basis_intra_dag_allows` 机器强制(#1022 已落，本 PR 加 intra-base 前向例外)。
- **引擎/原语** `consistency`/`primitives`/`tracewire`:依赖基础(或仅外部 crate);不依赖 DI-infra/服务/域/adapters。`tracewire`(W3C traceparent capture/restore 单源,#1224)出边全是外部 `opentelemetry`/`tracing-opentelemetry`、无内部边,被服务 `eventexec`(consume 还原)+ adapter `postgres`(emit 捕获)依赖——otel 收口在此 + `adapters/otel`,二者外不直接 import otel(结构性收口,机器硬化待 follow-up dylint)。
- **DI-infra** `diport`:依赖基础+引擎;**被服务/域/adapter/组合根消费**,自身不依赖服务及以上(无 back-path)。
  **provider-agnostic** DI port trait 单源(Clock/Signer/Publisher/Subscriber/AuditSink/ManagedResource/DlxLifecycleRepository/DlxArchiveStore…,签名只引基础/wire/port-owned/associated types)。需要运行期动态消费的 async port 使用 dynosaur Dyn wrapper；跨 `Send + Sync` worker 多次调用且 provider 由组合根静态选择的 port 使用 ADR-003 #1095 静态泛型（DLX 两 port），不为无消费方的动态能力生成 wrapper。**服务/域 互不依赖,但都可向下依赖 diport** ——
  服务层 crate(bootstrap/deviceloop/eventexec/authn…)消费 DI port 须经此层,故 diport 不能与它们同层(服务→服务禁)。
  注:**域形** repo/service port(签名引用域内实体)**不归 diport**,归所属域 crate `pub mod ports`(ADR-005 Option 2,见下「域」行 + category line ADR-005 §2.1)。
- **服务** `httpserve`/`authn`/`bootstrap`/`eventexec`/`observ`/`distributed`/`deviceloop`:依赖基础+引擎+DI-infra;不依赖域/adapters。**服务→服务横向默认禁(同 diport 行所述),唯一受控例外 = ADR-009 sanctioned `bootstrap → httpserve` 单向路由类型边**(组合根 typed route funnel:`bootstrap::finalize_routes` 产 `httpserve::UnfinalizedRoutes` → 经 `httpserve::finalize_auth` 换可 bind 的 `AuthenticatedRoutes`;反向 `httpserve → bootstrap` 及其它任意 `服务→服务` 边仍禁),由 `xtask layers::route_funnel_allows` 机器守(INVARIANT LAYER-DEPS-ROUTE-FUNNEL-01,见下「静态强制」表 + ADR-009)。跨层另有且仅有 **`eventexec → generated`** command seam 编译边：eventexec 实现 generated 的 `CommandEmit`/`CommandJournal`，再在自身 crate 内构造私有 reviewed DTO；由 `command_generated_seam_allows` 精确 crate pair 守，不能推广成一般 Service→Generated。`testkit` 是同层 **test-support 库**(HTTP 契约测试 oneshot harness,#1136):出边全外部 crate(axum/tower/serde…,无内部边),经 `[dev-dependencies]` 被域/组合根消费写 per-contract 测试——**零 production-adapter、零 workspace 依赖**(满足「域单测不依赖平台 adapter crate」),分层登记在 `xtask layers.rs` `SERVICE_CRATES`。另带 `containers` feature(#1137):testcontainers self-provision postgres/redis/rabbitmq 容器 fixture,供 adapter 集成测试 + journeys durable journey 经 `[dev-dependencies]` 消费(testcontainers 树 feature-gated + dev-dep-only 不进产物)。机器边界拆为正交两面：LAYER-DEPS-08 `check_test_support_confinement` 守任一 shipped 入边指向 testkit 均失败；LAYER-DEPS-10 `check_test_support_internal_dependencies` 守 testkit 任一 shipped 出边指向 workspace 成员均失败，保证其只依赖外部 crate。
- **域** `identity`/`settings`/`audit`/`contractreg`/`syshealth`:依赖基础+引擎+DI-infra+服务+`generated`(contract 派生);
  **互不依赖**(跨域只经 contract);不依赖 adapters。**定义自身域形 repo/service DI port**(`pub mod ports`,签名引用域内实体,由 adapter 经 DIP 实现,ADR-005);为此可依赖 dynosaur/trait-variant(DIPORT-MACRO-CONFINE-02 白名单)。
- **adapters/**:实现基础/引擎/DI-infra/服务定义的 trait(DI port 的 provider impl 在此);**不被域依赖**(组合根注入)。**可依赖域 crate 以 impl 其域形 repo/service port**(`adapter→域` = DIP 内向边,`allows(Adapter,Domain)=true` + deny.toml 该域 wrapper 放行 + 真实 source edge 校验,ADR-005;反向「域→adapter」仍禁,依赖反转方向保持)。通用 `Adapter→Service` 合法；#1676 仅对 provider output 边界增加精确 deny：`adapters/redis|s3|vault → bootstrap` 禁止（package 名为 `redis-adapter|s3|vault`），postgres→bootstrap 与目标 adapter→diport 不受影响（`LAYER-DEPS-PROVIDER-BOOTSTRAP-01`）。`postgres` 的域形实现由无默认值的 `domain-settings` / `domain-identity` / `domain-audit` Cargo feature 精确启用；assembly 必须显式选择，未选择的域依赖不进入目标 package 图。`adapters/memory` 是 **dev/test-only** in-mem DI port provider(测试 / demo)——**禁生产 bin(server/rss)依赖**,只准验收 journey + tooling(`xtask layers.rs` `DEV_ADAPTER_ROOTS`)依赖,机器边界由 `layer-deps` LAYER-DEPS-07(正向收窄 + 反向排除生产 bin)+ deny.toml 收窄 wrapper 守。
- **bins/**、**xtask/**、**assemblies/**、**composition/**、**journeys/**:组合根,可依赖所有库 crate(`journeys` 为验收 journey 组合根——demo 组装根 + 端到端集成测试；`composition/*` 为多个 assembly 复用的 typed domain wiring，不含 manifest 或启动入口)。**examples/** 为收窄示例层,只准依赖基础/引擎/DI-infra/服务,不直接依赖域、adapters 或 generated。`assemblies/{name}/assembly.toml`
  是 static assembly intent + DI provider 声明源：`name`/`profile`/`domains`/`topology`/`listeners`
  声明组合根 intent/surface，`listeners.domains` 以闭合 domain/listener enum 声明 route surface 归属；
  `[[diportProviders]]` 声明 provider 的 port / providerCrate / requiredFeatures / consumer / lifecycle /
  durability / purpose，并以闭合 `outputs = [probes|resources|workers]` 声明 lifecycle channel 贡献；字段细则见 `docs/rules/runtime-assembly-plan.md`
  Phase 3。`cargo xtask assembly validate` 守 manifest intent 非空/闭值/去重、active provider 的依赖 /
  feature 与安全边界（例如 production `diport::RevocationStore` 必须持久）。assembly intent / provider 声明不替代
  `contracts/**/contract.toml`、env/secrets、listener bind 配置或 Rust 构造器接线；跨域 wire contract 单源仍是 contracts。
  `cargo xtask graph assembly` 从该 manifest、匹配的 committed `modules_gen.rs` carrier 与 active event
  contract/subscription 派生同一 typed model 的 Mermaid/JSON。默认 runtime 双产物提交在
  `docs/architecture/generated/runtime-assembly.{mmd,json}`，`--check` 作为字节级漂移门；显式
  `--assembly <name>` 的临时图只写 `target/xtask/`。`modules_gen.rs` 同时携 typed domain-listener / provider-output
  evidence；runtime 将 observed domain route registration 与 colocated provider output metadata 对照该 carrier，漂移 fail-closed。
  图证明 domain→listener surface 与 provider→lifecycle channel kind，不证明具体 route path、授权、网络可达性、
  provider 实例数量、资源名、关停次序或运行健康状态，也不读取环境变量、endpoint 或 secret。
- **generated/**:contract 派生,被域依赖。
- 强制:cargo 拒绝循环依赖(分层无环天然成立);`cargo-deny`(deny.toml) 表达禁依赖;`cargo-udeps` 抓多余/未声明;
  `cargo public-api` 守封装面。

> 关键:**"域只经 contract 通信" 由 crate 依赖图自动守住**——域 crate 没在 Cargo.toml 声明就 import 不到,
> 且 `deny.toml` 禁止声明对兄弟域 crate 的依赖,无需运行期 import 扫描。

## Rust 原生强制(三档载体)

约束优先上移到编译期。三档载体按"越靠前越接近编译期、越免费"排;能编译期免费成立的约束,绝不退化成运行期治理测试。

### 一档(Hard)· rustc/Cargo 直接吸收(整类约束编译期免费成立)

| 约束 | Cargo/rustc 原生载体 |
|---|---|
| 分层依赖隔离 | workspace 成员 + 依赖图:不在 Cargo.toml 声明就 import 不到 |
| 必填依赖 | 非 `Option` 字段 + 构造器签名,缺了编不过 |
| sealed / marker / newtype funnel | 模块可见性 + 私有字段 + sealed trait |
| 值集冻结(HandleResult/Disposition/Status/result label) | `#[non_exhaustive]` enum + 穷尽 `match`,漏 case 编不过 |
| 错误 message const | `thiserror` enum variant(const `&'static str`,非格式化字符串) |
| 数据竞争 | `Send`/`Sync` 编译期 |
| wire struct 字段/tag 冻结 | serde derive 单源生成 |
| active LocalOnly receipt target | codegen 只为 active LocalOnly 生成 `LocalOnlyConformanceMarker` + `LOCAL_ONLY_SPECS`；失活/改级后 canonical callsite 编译失败，opaque receipt 仅由成功 post-check 铸造（LOCAL-ONLY-RECEIPT-TARGET-01） |
| Identity finalized authorizer capability exclusion | `RoleBindingReadRepo` / `ResourceAttributeReadRepo` 仅为 `AuthEffect + LocalPrivilege`；mutation 分别封入 `RoleBindingLifecycle(OutboxEffect)` / `ResourceAttributeWriteRepo(WriteEffect)`，旧混合接口删除；`ContractAuthorizer` / `IdentityDomainDeps` 只能接收窄读 dyn port，危险能力不可注入 LocalOnly authorizer |
| 进程隔离测试 | `cargo-nextest`(每测试独立进程,原生) |

### 二档(Medium)· Cargo 生态既有工具(配置 / 少量代码)

| 约束 | Rust 载体 |
|---|---|
| clock 注入强制 / 禁直调 `time` / 禁特定 import | `clippy.toml` `disallowed-methods`/`disallowed-types` + `cargo clippy -D warnings` |
| panic 纪律 | clippy `panic`/`unwrap_used`/`expect_used` deny + 行级 `#[allow]` carve-out |
| codegen funnel | `build.rs` + `typify`/`prettyplease`(或 `xtask` 生成 committed crate) |
| golden 漂移 | `insta` 快照(`cargo insta review`) |
| 库 API / authoring-schema SemVer | `cargo-semver-checks` + `cargo-public-api` |
| DB migration 命名空间 | `sqlx::migrate!` |
| 依赖图导出 | `cargo tree` / `cargo-depgraph` |
| mock(同模块)/ table-driven | `mockall` / `rstest` |
| 残留真要 AST 级的少数 funnel(某 callsite) | `dylint`（自写 clippy lint）。实际注册清单以根 `Cargo.toml [workspace.metadata.dylint]` 与 `lints/Cargo.toml` 为准，当前同步为：`rss_domain_no_serialize`、`rss_spawn_missing_scope`、`rss_crosstenant_callsite`、`rss_dlq_operator_callsite`、`rss_diport_impl_allowlist`、`rss_principal_facet_impl_allowlist`、`rss_authplan_callsite`、`rss_authenticated_callsite`、`rss_handler_local_principal_authz`、`rss_diport_error_debug_redacted`、`rss_diport_dto_debug_redacted`、`rss_pdp_impl_adapter_only`、`rss_projection_append_only`、`rss_partition_serial_allowlist`、`rss_diport_envelope_reserved_writer`、`rss_redact_debug_required`。其中 `rss_handler_local_principal_authz` 是 typed route permission 的 Medium backstop：除既有 `Authenticated` getter 禁用外，也禁止非 allowlist 的 `PrincipalKind::{Admin,SuperAdmin,...}` / role-name 字面量授权分支。符号/红例/盲区见各 `lints/<lint>/` rustdoc 与 `lints/README.md`；`cargo dylint --all` 已是 `cargo xtask verify` / `ci` 一步并经 `DYLINT_RUSTFLAGS=-D warnings` fail-closed。 |
| 治理脚本入口 | `cargo` + `xtask/` |
| 错误码前缀所有权 golden | `cargo xtask` 前缀所有权治理测试（与 `error-handling.md` 一致） |
| DI port + dynosaur 收敛到定义点白名单 | `deny.toml` wrapper：`dynosaur`/`trait-variant` 只准 **DI port 定义点 crate** 依赖——白名单 = `diport`（provider-agnostic infra port）+ 定义自身 repo/service port 的域 crate（域形 port，ADR-005 Option 2，INVARIANT DIPORT-MACRO-CONFINE-02；`layer-deps` `EXTERNAL_CONFINEMENT_WRAPPERS` 守白名单条目属 DiPort/Domain 层 + wrapper⟷源集合相等）。注：dynosaur 0.3 生成的 unsafe 经 def-site hygiene **不触发** consumer forbid（实测，ADR-003 §8），无 forbid 例外、无 unsafe carve-out——本约束是「DI port 定义点集中」架构守卫，非 unsafe 收敛；ADR-005 把原 `-01`「单一依赖点」放宽为白名单（域形 repo port 必然多点定义，前提失效，零安全代价） |
| `adapter→域` DIP 内向边（impl 域形 repo port） | `xtask/src/layers.rs` `allows(Adapter,Domain)=true`（source-centric `layer-deps`，矩阵红/绿 case anti-vacuity；反向 `域→adapter` 仍 `false`）+ `deny.toml` 该域 ban 的 wrappers 加该 adapter（LAYER-DEPS-06 反向② 放行）。INVARIANT 随 `allows` 矩阵单源（LAYER-DEPS-00），ADR-005 |
| 受控 `bootstrap → httpserve` 路由类型边（组合根 typed route funnel；服务→服务唯一例外） | `xtask/src/layers.rs` `route_funnel_allows`（**只**放行 `bootstrap → httpserve` 这一对有向边，`check_layers` 在 `!allows(Service,Service)` 时叠加；反向 `httpserve → bootstrap` 及其它任意 `服务→服务` 仍禁；rstest + 端到端 `check_layers` 正反例 anti-vacuity）。INVARIANT LAYER-DEPS-ROUTE-FUNNEL-01，ADR-009 |
| command sealed seam 编译边 | `xtask/src/layers.rs` `command_generated_seam_allows` 只放行 `eventexec → generated`；`authn/bootstrap/其它 Service → generated` 与反向边均保持 `GeneratedScope` 红。`deny.toml` generated wrapper 同步只增加 eventexec；正例、其它 Service 反例与真实 workspace green 三重 anti-vacuity。类型/可见性 Hard seal 见 ADR-016。 |
| Redis/S3/Vault provider output 不反向依赖 bootstrap | `xtask/src/layers.rs` `provider_adapter_bootstrap_forbidden` 精确拒绝 `redis-adapter|s3|vault → bootstrap`，并在 `layerdeps::check_layers` 通用 `allows` 前应用；三目标 synthetic red、postgres→bootstrap 与目标→diport green、真实 workspace green。INVARIANT LAYER-DEPS-PROVIDER-BOOTSTRAP-01，**Medium（xtask + CI 门）**，ADR-010 |
| PG lifecycle owner/module 单一路径 | `PgRuntimeDeps` non-Clone owner 只包 cloneable `PgRuntimeHandle`；handle 无 lifecycle API，owner/factory 均按值消费，并直接生成既有 `DomainModuleResult` batch（Hard；无平行 output type）。`RUNTIME-PROVIDER-OUTPUTS-LIVE-01` 以 synthetic red + anti-vacuity green 锁唯一 PG helper/生产调用、禁止 PG 实现通用 `ProviderOutput`、禁止 helper 外调用 lifecycle primitives，并锁定 PG batch 经公共 helper 在统一 domain module 前注册（AcceptedMedium）。ADR-010 #1677 amendment |
| Event transport output 单一路径 | crate-private `wire_event_transport` 直接返回 owned `DomainModuleResult`，使旧 `.module/.infra_guards` 拆包不可编译（`EVENT-TRANSPORT-OUTPUT-TYPE-01`，Hard）；`EVENT-TRANSPORT-OUTPUT-FUNNEL-01` 以 synthetic red + anti-vacuity green 锁定 AMQP resources 只进入 module channel、run 恰好一次 merge、launch 只走公共注册 helper（AcceptedMedium）。ADR-010 #1678 amendment |
| defer/follow-up 结构化完整性（governed docs + 根 config） | governed scope（`docs/rules`/`docs/architecture`/`.claude/rules` + 根 `deny.toml`/`clippy.toml`/`CLAUDE.md`）内 `DEFER(#NNNN)` 标签须 `owner=`/`blocked-by=<#NNNN｜trigger:..>`/`closes-when=` 齐全 + 禁裸 TODO/FIXME/XXX/HACK 注解（注解位）；`cargo xtask defer-gate`（接 verify/ci no-compile meta 步，synthetic red + anti-vacuity green）。INVARIANT DEFER-GATE-01；符号/盲区/红例见 `xtask/src/defergate.rs` rustdoc + ADR-010；v1 守结构化标签 + 经典注解，自由词散文 + 代码注释扩域 = ratchet follow-up |

### 三档 · Cargo 替不了,框架自建(RSS 真差异化)

| 机制 | 载体 | 评级 |
|---|---|---|
| contracts 跨边界单源 + 扇出闭环 | `xtask` 校验器 | Medium(CI 门) |
| L0–L4 一致性声明 + typed capability evidence + L4 `[reconcile]` block(拓扑/引用完整性/active producer readiness/格式/能力门) | `xtask` | Medium(CI 门) |
| wire contract 版本目录(轴 B) | `xtask` | Medium(CI 门) |
| 分层依赖残留(无 back-path 反向边 / 兄弟域互斥 / adapter·generated scope / test-support 双向 shipped confinement / wrappers⟷源一致) | `cargo xtask layer-deps`(source-centric：读各成员 Cargo.toml shipped 依赖表按 §分层矩阵及 LAYER-DEPS-08/10 校验；接入 `verify`；符号/规则/盲区见 `xtask/src/layerdeps.rs` rustdoc 的 LAYER-DEPS-01..10) | Medium(CI 门) |
| `SharedRuntimeDeps` 字段仅基础设施 / value object（禁域 service / repo） | `cargo xtask runtime-deps guard`(syn 字段扫描 + `xtask/runtime-deps-guard.toml` 配置单源 + synthetic red；接入 `verify`) | Medium(CI 门) |
| active LocalOnly ↔ source receipt exact-set、唯一性与逐 site marker/ID/mounted ROUTE proof/三维 observers/同一 routes finalize+tuple factory/generated GET operation 闭合 AST 证书 | `cargo xtask consistency local-only-effects`（LOCAL-ONLY-RECEIPT-COVERAGE-01；module/cfg-aware synthetic red + real 5/6 anti-vacuity；仅 `settings.config-get` missing，仍为 report-only） | Medium(CI 门) |
| 组合根 DI 接线(SharedDeps / `module()`) | 手工 `main` + `bootstrap` crate | — |
| outbox/saga/reconcile/projection/command_journal 引擎 + topology-gated resolver | tokio 自写(`consistency` 态机 + `eventexec` 执行 + 各 deps resolver) | — |

**残留运行期/CI 检查**(类型系统 / crate 图管不到)的机器载体显式为 **Medium(xtask/CI 门)**，不得用文档或
人工约定替代：active subscriber
存在性、active HTTP outbox producer 目标 readiness、consistency capability evidence、contract 扇出完整性、migration 只增不改、覆盖率阈值、no-op 业务理由、分层依赖残留(crate 图仅 Hard
守已声明边的「下层依赖上层成环」；不成环的反向边 / 兄弟域互斥 / adapter·generated scope 由 `cargo xtask layer-deps`
source-centric 补，免疫裸名×crates.io 命名冲突)。治理重心在 "crate-graph lint + clippy + 类型系统"(见
`.claude/rules/rss/ai-robust.md`)。Medium gate 必须进入稳定的 repository aggregate，并在 aggregate 执行时
fail-closed；这仍不等同于 active PR 已自动调度该 aggregate 或以其阻断合入。

这些 Medium gate 的 **GitHub Actions typed CI** carrier 由 `.github/workflows/ci.yml` 定义：workflow 只保留
`ci-plan`、一个从闭合 `CiJobKey` 派生的动态 matrix executor 与稳定 `ci-gate`；被运维策略接纳的事件统一经
planner 决定选择性执行或 full fallback，不在规则文档复制触发/激活状态。
INVARIANT CI-ADAPTIVE-WORKFLOW-01 以结构化 YAML 闭集校验、synthetic red 与 anti-vacuity 锁定 planner、
matrix、always gate、只读权限和唯一 reusable 委托，不允许 workflow 重列路径/job 策略。gate registry 的闭枚举、穷举 dispatch 与唯一/完整断言由
Rust 编译期证明（Hard），YAML carrier 边界由 xtask/CI 守卫证明（Medium）。workflow 存在性不得外推成
active PR 的 Medium enforcement；运行时激活状态、required-check 状态与升级条件只在 CI 运维文档维护，
避免规则文档复制易漂移的运维事实。
本地差异 preflight 统一使用 `make ci CI_BASE=<remote>/develop`；显式全量使用 `cargo xtask ci full`。
门集包含 `verify` 全门（build/clippy 升 `--all-features --all-targets`）、覆盖率门
(`cargo llvm-cov`,引擎-基础 ≥90%、无 ratchet 例外)、`public-api --check`
(轴 A;`cargo-semver-checks` 因全 crate `publish=false` 空转、本轮 deferred) 与 cargo-audit(供应链漏洞,#1133)。
**供应链门**(#1133):`cargo deny check`(advisories/RustSec+licenses+bans+sources)+ cargo-audit 通过 typed
`cargo xtask ci run --job audit` 暴露 advisory-scoped 定时刷新能力，覆盖「未变依赖」后来披露 CVE 的时间维度。
实际 schedule、forge 与 required-check 状态以
[CI 运维状态](../ops/202607130824-1765-diff-adaptive-ci.md) 为准，设计见
[`202606231530-001-ci-lane.md`](../ops/202606231530-001-ci-lane.md)。

L0/L1 验证沿用同一 typed plan，不在规则文档维护第二份 gate inventory：`verify --fast` 闭合声明、codegen
与静态证据，完整 `verify` 增加编译和默认行为测试并仅编译 integration targets，真实 Postgres LocalTx matrix
与 active L1 journey 由 `cargo xtask ci run --job integration/postgres-domain` 执行。具体采用顺序与失败边界分别见
[`consistency-l0.md`](./consistency-l0.md) 和 [`localtx.md`](./localtx.md)。

ArchRules 反向索引由 `cargo xtask archrules list` 从真实 carrier 的 `INVARIANT:` 锚点派生，展示
rule id → carrier → source → fixture/baseline → gate；`cargo xtask archrules verify` 接入 verify/ci 的
no-compile meta gate。本文档只描述载体原则，不维护落地实例清单。
11 个持久化 funnel 的强度与证据由
[`202607091830-015-persistence-funnel-ai-robust-matrix.md`](../architecture/202607091830-015-persistence-funnel-ai-robust-matrix.md)
派生展示；`cargo xtask archrules matrix --check` 与同一 ArchRules gate 一起进入 verify/ci。

## 关键模式的 Rust 形态

- **组合根 / `module()`**:当前 `bootstrap` 已落私有字段 `DomainBinding` + `DomainBinding::new` +
  `compose_bindings(&mut Vec<DomainBinding>)`;该受控出口只在 compose 成功后返回聚合 `DomainModuleResult`,失败保持
  bindings/outputs 原样。runtime 的 settings/identity/audit 统一返回 `Future<Result<DomainBinding>>`；
  identity/audit 的 provider-to-binding 构造由 `composition/*` 必填 typed deps 单源承载，runtime 仅保留
  env/provider 适配与 generated module 薄入口。
  generated list 已由 #1672 接入 live `compose_bindings`；`assembly.toml` 顺序是唯一域构造、声明注册与生命周期输出聚合顺序。
  adapter↔域绑定在 `bins/server` / assembly / reusable `composition/*` 用构造器注入完成。
  topology-gated resolver(`eventtransport`/`replaydeps`/`sagaprojectiondeps`)
  是 `bootstrap` 子模块(按 `Topology` 单源选型 eventbus / claimer / nonce / saga instance/journal 依赖)。
- **持久化能力分层**:`DomainBinding`(域实例+生命周期输出的单一 owner) / `DomainModuleResult`(仅聚合
  probes/resources/workers,不承载 domain service/routes/generic bag) / Pg
  capability bundle(`PgRuntimeDeps` owner · `PgRuntimeHandle` capability · `PgDomainDeps`) / adapter bundle / defer gate 实施顺序的**设计单源**见 **ADR-010**
  (`docs/architecture/202606270148-010-persistence-capability-layering.md`);执行体随 #1419(runtime base) / #1421(settings
  闭环) / W 阶段落地,本处不复制未强制细节。
- **运行时接线契约首切([PERSIST-001] #1422,ADR-010 §2.6 step 2 的 `DomainModuleResult` + `SharedRuntimeDeps` 聚合)**:
  `bootstrap::DomainModuleResult`(probes/resources/workers 可聚合产物流出,组合根 `merge` 聚合后排空到 `Registry::probe`
  / `ShutdownStack`,**归属 ADR-010 §2.2 = `bootstrap`**) + `assemblies/runtime` 的 `SharedRuntimeDeps`(infra 流入,持
  `Arc<PgStore>` 故必留组合根层);`wire_settings` 首用。**INVARIANT WIRING-DEPS-NO-HANDOFF-01(Hard)**:
  async `module(source: &impl XModuleSource) -> Result<DomainBinding>` 的 per-domain source trait sealed，且 typed
  `wire_X` 入口均无参数可塞别域 result ⇒ 跨
  module value handoff 编译期不可表达。`DomainModuleResult` 固定为 `DomainBinding.output` 的生命周期三出口；`name/domain` 属 binding，
  domain service 留在 typed domain 内经 route 闭包捕获、不出向。live `wire_X` 切换 binding 属 runtime assembly Phase 4，
  不改变当前运行时顺序。
  **INVARIANT: WIRING-DEPS-INFRA-ONLY-01 { level = "Medium", exec = "verify", source = "code" }**:
  `cargo xtask runtime-deps guard` 解析字段类型，按 `xtask/runtime-deps-guard.toml` 读取 provider bundle / infra
  value object 允许根与精确 `Arc<dyn distributed::DomainTransport>` 例外，拒绝域 service / repo 经 deps bag 跨
  module handoff。规则细节 / 盲区 / 扩展流程见 `docs/rules/runtime-wiring.md`。
- **Transaction retry policy([PERSIST-018] #1439)**:`consistency::tx_retry` 持有闭值集
  `TxRetryClass::{Transient, Conflict, Permanent, OwnershipLost}` + `TxRetryPolicy` + runtime-neutral
  `run_tx_retry`。adapter 只在明确 UoW 边界套 retry（当前 postgres `settings.config` /
  `settings.secret` / `identity.credential` / `identity.session` 写边界），每次 attempt 必须重建完整事务；仅注册的
  config commit、`PgSecretUnitOfWork` mutation、credential password change 与 session logout 是 adapter UoW
  入口，其余 repo 方法、handler、outbox
  publish/settle、
  consumer commit/release 内部不得隐式 retry 带副作用写入。分类规则：`Transient`
  （如 PG `40001`/`40P01`/连接瞬断/池获取超时）可在预算内重试；`Conflict`（CAS/version 冲突）必须向上返回，
  由 command 层显式 refetch/recompute；`Permanent`（约束/解码/租户 envelope mismatch/损坏行）fail-closed；
  `OwnershipLost`（lease lost/fencing miss/stale owner）是终态围栏，不得把当前 side effect 当 transient 重跑。
  settings secret 的 HTTP `publish`、identity password change 与 logout 只能消费 domain typed command 携带的
  generated LocalTx observation 并使用 LocalTx runner；marker 经 crate-private `PgLocalTxOperation` 唯一映射到
  retry boundary，调用方不能另传 boundary。`publish_internal` / rollback `republish` 使用 generic runner，二者
  不得借用 HTTP contract telemetry。只读 `SecretRepo` 不暴露 mutation，四个 settings 写入口集中在
  `SecretUnitOfWork`。
  backoff 使用 full jitter；Postgres retry attempt 的 pool acquire 与 lock wait 均有上限，有限 attempt 数构成总等待
  上界，调用 future 被请求 deadline 取消时不得在后台继续重放。durable command 的 request-side 幂等不靠重试包自动重放：
  `command_journal` 先 claim request fingerprint；
  需要业务写共提交时，由 Postgres/domain-shaped UoW 在同一 tenant transaction 内提交业务写与 outbox
  append；重复请求只按 journal 结果回放，same-key different-fingerprint 返回 conflict。
  **INVARIANT: TX-RETRY-BOUNDARY-01 { level = "Medium", exec = "manual/opt-in", source = "code" }**:
  闭枚举 + postgres SQLSTATE 单源映射 + `testkit::repo_conformance::assert_retry_boundary_policy` 防止
  retry 规则散落为 bool/string 约定。
- **Init fail-fast**:`fn init(&self, reg: &mut Registry) -> Result<(), KernelError>`;必填依赖走构造器必填参数
  (编译期);init 内不做 I/O、不 spawn task。
- **Assembly manifest intent + provider declaration**:`assemblies/{name}/assembly.toml` 声明组合根的静态 intent
  （`name`/`profile`/`domains`/`topology`/`listeners`）以及选择了哪个 DI provider 及其生命周期 / 持久性，不生成运行时接线，
  也不驱动 live topology、route mounting、auth scheme、provider construction 或 readiness；真实接线仍在 assembly Rust
  代码里经构造器注入完成。active provider 必须与 assembly `Cargo.toml [dependencies]` + required features 对齐，且安全关键 port 可追加专门约束。
  `ASSEMBLY-DOMAIN-CLOSURE-01` 对每个 assembly 的目标 package 独立执行 normal-edge Cargo tree（含该 package 全 features），active domain 必须是同名直接依赖，inactive domain 不得进入该 artifact 闭包；workspace 联合 all-features 编译由 CI 另行覆盖，不作为单个部署 artifact 的裁剪事实
  （当前 production `diport::RevocationStore` provider 必须 `durability=persistent`；draft/ephemeral 只允许
  demo/test assembly）。Phase 3 字段边界与验证 carrier 见 `docs/rules/runtime-assembly-plan.md`。
- **Adapter sealed marker**:unit sealed-marker(`struct PgStore;`)以 native AFIT impl diport 已冻 DI port
  trait(`ManagedResource` 普适 + `Signer`/`Publisher` 按职责);DI port **不**跨 crate sealed(ADR-003 §4.2
  方案②——impl-sealing 未机器强制、待 #1060);raw client(如 `PgPool`,`pub(crate)` 不泄漏)的字段延迟到 W 阶段接后端时填入。
- **DTO 作用域**:域内 = `pub(crate)` 模块类型;跨域 wire = contract(`contracts/` 声明 → `generated/` crate)。
- **错误**:`vocab`(error) + `thiserror`(库错误枚举);应用边界可 `anyhow`。错误码命名空间注册 + golden。
- **代码生成**:`build.rs` / proc-macro / `xtask` 作为 codegen funnel,产物入 `generated/`(committed,一等审查材料)
  或 `OUT_DIR` + `insta`。
