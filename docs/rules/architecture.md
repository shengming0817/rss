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

### 公开发布命名

上述 concat/no-dash/no-`rss-` 规则只约束仓内 workspace identity。进入正向 Release Surface 的公开 registry
package 使用品牌 **RSS** 与 `rss-` 前缀；当前 Release Surface 已接纳的 internal → public 映射固定为：

| repository path / internal dependency key | public Cargo package | registry owner |
|---|---|---|
| `diagctx` | `rss-diag-context` | `github:shengming0817:rss-maintainers` |
| `tracewire` | `rss-trace-context` | `github:shengming0817:rss-maintainers` |
| `conformance` | `rss-conformance` | `github:shengming0817:rss-maintainers` |
| `contract` | `rss-contract` | `github:shengming0817:rss-maintainers` |
| `request-context` | `rss-request-context` | `github:shengming0817:rss-maintainers` |
| `platform` | `rss-platform` | `github:shengming0817:rss-maintainers` |
| `crates/devicesecuritycontracts` / `devicesecuritycontracts`（candidate，尚未物化） | `rss-device-security-contracts` | `github:shengming0817:rss-maintainers` |

规范源码仓库是 [`shengming0817/rss`](https://github.com/shengming0817/rss)。2026-08-09 UTC 的 crates.io
检查确认精确名称 `rss` 已被无关的 RSS feed 读写 crate 占用，而 `rss-diag-context`、
`rss-trace-context` 与 `rss-platform` 当时未登记；2026-08-12 UTC 的 Cargo registry 精确查询对
`rss-device-security-contracts` 也未返回登记项。未登记只是一项带时间的冲突检查，不构成名称保留、ownership 或发布授权；首次
发布前必须重新查询精确名称，并在 crate 创建后验证 registry owner 列表。`crates/diagctx` / `diagctx` 与
`crates/tracewire` / `tracewire` 分别是仓内路径与 dependency rename key，不构成旧 package alias。Cargo closure
PBI 直接采用上表公开 package identity。未完成最终 API 与同 revision artifact proof 的 package 保持
`publish = false` 且不得选择进 Release Surface；完成者可以进入正向 candidate selection，但仍不得据此声明
RC、registry upload 或 published。

## 核心载体

| 概念 | Rust/Cargo 载体 | 说明 |
|------|----------------|------|
| bounded context | **域 crate**(library) | identity/settings/...;跨域只经 contract |
| feature 模块 | 域 crate 内 `pub(crate)` 模块 | intra-crate 边界;不是独立 crate |
| Contract | `contracts/{kind}/{domain}/{version}/` 的 `contract.toml` + `*.schema.json` 声明源 | typify/xtask 派生 Rust 进 `generated/` crate;跨边界唯一 wire 载体 |
| Contract 归属 | `owner` = 域 crate 名 / `_framework`(sentinel) | provider-agnostic 中立契约归框架 |
| Assembly | `assemblies/{name}/` 的 `assembly.toml`(+ `bins/server` / bin crate) | 依赖闭包 = 物理打包；static assembly intent + DI provider 声明源 |
| 一致性等级 L0–L4 | `contract.toml` 的 `consistencyLevel` 字段 + typed `[capabilities.*]` 证据块；L4 另需顶层 `[reconcile]` block；active HTTP 同源派生 `ROUTE: vocab::HttpRouteBinding<RouteMarker, ConsistencyMarker>`，`HttpSpec::route` 由 `ROUTE.evidence()` 擦除供元数据查询 | `ConsistencyMarker` 由 manifest codegen 单源选择，不可手写替换；非 L0 state 经 `.with_state`闭合，L0 只允许 stateless 或 `.with_classified_state` 的 Read/Auth + LocalPrivilege；`xtask` R22 强制等级、能力证据与 L4 reconcile 声明一致；endpoint 构造要求 binding marker 与 handler `ContractMarker` 相同，request extension 传播同一 evidence |
| context 控制流值(tenant/principal) | `rss-request-context` canonical value/read view；仓内 ambient carrier 为 `runctx::RequestCtx`/`AppCtx` | Foundation 值不是 evidence；production trusted concrete 仅由 AuthZ 后的 assembly bridge 私有构造，`runctx → rss-request-context` |
| Foundation 公共原语 owner | 当前 `rss-contract` 唯一拥有 contract identity/descriptor，`rss-request-context` 唯一拥有 authority-free request values；Timepoint/PageCursor/DataClass/SafeError 的 planned owner 为 `rss-contract` | [ADR-029](../architecture/202608191635-029-foundation-public-primitives-ownership.md) 只冻结 owner 与 carrier handoff；planned API 在 #2150/#2151/#2152/#2153 落地前不构成当前 Release API，禁止 facade、镜像或跨 owner re-export |
| 层 | 扁平 `crates/` 分组 + `deny.toml` 强制 | 见 §扁平 workspace 结构、§分层 |

active HTTP L2 producer 的 route 绑定必须走 move-only typed 链：`HttpProducerBinding<RouteMarker>` →
`ProducerMarker` / `ProducerAssuranceReceipt` / `ProducerAuthorization<M>`。provider 侧只允许受控
producer transaction 入口消费同一个 crate-private capability，并由 typed outcome 闭合
emitted / no-mutation。跨文件 residual 由 Medium fail-closed execution graph 加 production-composition
join 与 in-process L2 typed closure 证明；不存在 committed assurance artifact、旧 co-tx API、reader、
alias、shim 或双写。

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
│   ├── contract/         # FoundationPublic：canonical contract identity/descriptor；ADR-029 planned 公共原语 owner（std-only）
│   ├── request-context/  # FoundationPublic：authority-free request values/read-only views
│   ├── platform/         # PlatformPublic：typed async waist；精确依赖两个 Foundation package
│   ├── assembly-schema/  # assembly / contract authoring schema；依赖 vocab canonical 类型
│   ├── ids/              # sealed newtype（私有字段 = 硬封）
│   ├── securederive/    # proc-macro：#[derive(Redact)] 字段级脱敏（intra-base DAG 低于 secure）
│   ├── secure/           # redaction（字段级 Redact 策略模型）/ aead / cookie / pathsafe
│   ├── support/          # http / pg / validation 杂项
│   ├── runctx/           # 请求上下文(tenant/principal)；可观测 ID 走 tracing span
│   ├── diagctx/          # 诊断信道 fail-open correlation（ADR-002 §D1-bis）
│   ├── authmint/         # Authenticated production evidence mint capability token（AUTH-EVIDENCE-MINT-01）
│   ├── dlqauthmint/      # DLQ operator authorization mint capability（DLQ-OPERATOR-MINT-01）
│   ├── requestidmint/    # HTTP middleware-owned wire request-id capability（HTTP-REQUEST-ID-AUTHORITY-01）
│   ├── runtimeinventorymint/ # runtimeexec-only inventory observation mint capability（RUNTIME-INVENTORY-MINT-01）
│   ├── consistency/      # outbox / saga / reconcile / projection / command_journal / idempotency（纯态机 + trait，L0–L4）
│   ├── primitives/       # crypto / authplan / healthz / circuitbreaker（引擎纯计算原语）
│   ├── conformance/      # provider-neutral LocalTx assertion primitive（Release API）
│   ├── tracewire/        # W3C Trace Context capture/remote-parent restore 单源（HTTP + outbox，唯一 otel 桥落点）
│   ├── tracewiretest/    # publish=false、dev-dependency-only 的 OTel subscriber/exporter 测试脚手架
│   ├── workspacefacts/   # Tooling/Verification：guppy PackageGraph/CargoSet 薄适配；owned Cargo facts
│   ├── diport/           # DI-infra：可替换 provider 的 port 单源；dynosaur 默认非 Sync，async_sync 闭集（KeyProvider/Pdp/SecretResolver/ServiceTokenReplayStore）是共享例外（ADR-003 · DIPORT-DYN-CONCURRENCY-01）
│   ├── httpserve/        # axum router / middleware / health
│   ├── authn/            # jwt / AuthGrant / security vocabulary / refresh / PDP / Principal
│   ├── bootstrap/        # composition / config / shutdown / worker
│   ├── runtimeexec/      # provider-independent runtime 启动/信号/逆序关闭内核（不拥有 HTTP/DTO/provider）
│   ├── eventexec/        # outbox relay / eventbus / saga executor·tailer / command
│   ├── deviceloop/       # cert lifecycle·signing（L4）
│   ├── observ/           # metrics / logging / grpc interceptor / websocket（audit sink 归 diport）
│   ├── distributed/      # distlock / cas / transport
│   ├── testkit/          # 服务层 test-support：HTTP 契约测试 oneshot harness（经 [dev-dependencies] 被域/组合根消费，零 adapter 依赖，不进生产 shipped 图）
│   ├── identity/         # 域：身份 / 凭据与账户安全编排 / RBAC / ABAC
│   ├── settings/         # 域：版本化配置 / secret 引用（避开 config 重名）
│   ├── audit/            # 域：审计链
│   ├── contractreg/      # 域：运行时契约 submit / list
│   └── syshealth/        # 域：健康聚合
├── adapters/             # 一 adapter 一 crate + feature 门控；裸后端名（adapters/ 路径消歧）
│   ├── postgres/ redis/ amqp/ mqtt/ s3/
│   ├── oidc/ grpc/ httpd/ otel/ prometheus/ vault/   # httpd = HTTP 传输（只消费 budget-sealed ServerService；HttpServer bind+serve+ManagedResource）
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
├── journeys/             # ★ 验收规格（*-journey.toml）+ status-board.toml；亦承载 tests-only 验收 journey 组合根（RW-G1）
├── fixtures/             # ★ 测试夹具（fixture-*.toml）
├── examples/             # ssobff / todoorder / iotdevice / corebundlestarter
├── xtask/                # codegen + golden + 契约/一致性治理校验
├── generated/            # 契约派生的 committed crate（一等审查材料）；其余 codegen 走 build.rs OUT_DIR + insta
└── actors.toml           # 外部 Actor 注册（参与 contract 但不属于域模型的系统）
```

## 分层(crate 图 + deny.toml 编译期强制)

- **FoundationPublic** `rss-contract` / `rss-request-context`：全 workspace 最低位公开层；前者 std-only，后者
  只依赖外部 `uuid` 且公共签名不泄漏该类型，二者均无 internal workspace 出边。它们分别唯一拥有 contract
  identity/descriptor 与 authority-free request values/read-only views；不拥有 registry、generated catalog、crypto、
  trusted mint、cancel authority 或跨租户 capability。[ADR-029](../architecture/202608191635-029-foundation-public-primitives-ownership.md)
  另将 planned Timepoint/PageCursor/DataClass/SafeError 公共 owner 分配给 `rss-contract`；在对应 Hard/Medium carrier、
  Release API 与 external consumer 落地前，该分配不是当前 API 或完成声明，也不允许 Platform/generated/内部 crate
  建镜像、alias 或 re-export 路径。
- **PlatformPublic** `rss-platform`：位于 Foundation 之上，normal/build workspace 出边精确限定为两个 Foundation
  package。它只拥有 typed async application/module/dispatch waist、闭合 dispatch 结果与只读 `HostView`；不拥有
  JWT/JWKS/token verifier、listener/provider、进程 lifecycle、RuntimePlan、inventory publisher 或 drain authority。
  RuntimeExec 经必填只读 bridge 投影 readiness/drain/live inventory，production assembly 是唯一接线点。

- **基础** `vocab`/`assembly-schema`/`ids`/`securederive`/`secure`/`support`/`runctx`/`diagctx`/`authmint`/`sagaauthmint`/`dlqauthmint`/`requestidmint`/`runtimeinventorymint`:依赖更低位 FoundationPublic + std + 外部 crate(serde/thiserror/uuid…),**不依赖引擎/DI-infra/服务/域/adapters**。基础层内部按 enumerated intra-base DAG 单向依赖:`diagctx（独立根）◁ runtimeinventorymint ◁ vocab ◁ assembly-schema ◁ ids ◁ securederive ◁ secure ◁ support ◁ runctx`(右可依赖左 = **DAG 前向边均 sanctioned**、反向 / 同 crate 禁止)；capability crate `diagctx`、`authmint`、`sagaauthmint`、`dlqauthmint` 与 `requestidmint` 为独立根，不依赖其它基础 crate，也不被其它基础 crate 依赖。`dlqauthmint` 的 exact wrapper 仅为 `diport`（proof owner）与 `runtime`（唯一生产 mint owner）；`eventexec`、adapter 与其它 assembly 均不能命名 token（DLQ-OPERATOR-MINT-01 Hard）。`diport::DlqOperatorAuthorization<A>` 以 sealed action marker、私有字段和 move-only proof 将 caller、已验证 operator subject、tenant、durable start audit ID 与五类 DLQ action 绑定；runtime 内部铸造时序另由 `rss_operator_authorization_callsite` 精确 funnel 守（Medium）。`requestidmint` 仅由 deny.toml wrappers `httpserve`（mint）与 `generated`（consume）持有（HTTP-REQUEST-ID-AUTHORITY-01 Hard），因此业务 crate 不能伪造 typed response 的 request ID。`runtimeinventorymint` 无出边，deny.toml wrapper exact-set 仅准 `assembly-schema` 在 receipt 签名中命名 token、`runtimeexec` 实际持有 token；assembly roots 不能依赖它（RUNTIME-INVENTORY-MINT-01 Hard）。`diagctx` 仅向上被服务/域/adapters/组合根消费（诊断信道 fail-open，ADR-002 §D1-bis）；`authmint` 仅由既有 deny.toml wrappers 持有（AUTH-EVIDENCE-MINT-01 Hard）；assembly 内 exact mint + proof-consuming 另由 `rss_authenticated_callsite` Medium 守。`assembly-schema::runtime_inventory` 拥有 wire-neutral parts、invariant 与私有 observation fields；`runtimeexec::inventory::InventoryReader` 独占 live source 和 mint，generated 只消费 observation，不存在 generated↔runtimeexec 编译边。现有有语义 owner 的前向边包括:`assembly-schema → runtimeinventorymint|vocab`（runtime inventory receipt token 与 contract authoring 的 canonical `StepName` / `DomainName` 类型边界）、`runctx → rss-request-context`（`AppCtx` tenant payload = canonical `rss_request_context::TenantId`，ADR-029）与`secure → securederive`(字段级脱敏 `#[derive(Redact)]` proc-macro；`securederive` 是编译期纯工具 crate,出边全外部,非 SemVer 库面 ⇒ public-api baseline 经 `layers::is_proc_macro` 排除)。`INVARIANT: BASE-INTRADAG-01`:无环由 cargo 天然守(反向 2-crate 边即成环被拒);前向 / 反向方向守由 `cargo xtask layer-deps` 的 `layers::basis_intra_dag_allows` 机器强制。
- **引擎/原语** `consistency`/`primitives`/`conformance`/`tracewire`:依赖基础(或仅外部 crate);不依赖 DI-infra/服务/域/adapters。`conformance` 是公开的 provider-neutral LocalTx assertion primitive，零 workspace 出边；支持面不含 adapter/provider driver、fixture、scheduler、CI/T3 或产品成熟度。`tracewire`(W3C Trace Context capture/remote-parent restore 生产单源)出边全是外部 `opentelemetry`/`tracing-opentelemetry`、无内部边,被服务 `eventexec`(consume 还原)+ adapters `httpd`(HTTP ingress 还原)/`postgres`(emit 捕获)依赖。生产 OTel 桥只在此与 `adapters/otel` 收口；publish=false 的 `tracewiretest` 只提供 dev-dependency 测试装配。
- **DI-infra** `diport`:依赖基础+引擎;**被服务/域/adapter/组合根消费**,自身不依赖服务及以上(无 back-path)。
  产品面定位是 `publish = false` 的 **Internal Provider Contract**：仓内 `pub` 只使 official adapter、服务/域与组合根
  能跨 crate 实现或消费统一接缝，不构成 Platform Public / Release API。official adapter 继续直接实现该 internal seam，
  并由静态 composition root 经封闭 provider catalog 构造；无需绕尚不存在的公共 Provider SPI。
  **provider-agnostic** DI port trait 单源(Clock/Signer/Publisher/Subscriber/AuditSink/DlxLifecycleRepository/DlxArchiveStore…,签名只引基础/wire/port-owned/associated types)。`ManagedResource` / `ManagedResourceLocal` 是为复用 async dyn 派发而同置于本层的 lifecycle seam，adapter resource、服务 worker 与 runtime wrapper 均可实现，不受 provider impl-site allowlist 限制。需要运行期动态消费的 async port 使用 dynosaur Dyn wrapper；默认 dyn wrapper 是 Send 非 Sync（`async_send`），跨 `Send + Sync` worker 多次调用且 provider 由组合根静态选择的 port 改用 ADR-003 静态泛型。共享 Sync 例外是 `classify_ports!` 的 `async_sync` 闭集四端口（`KeyProvider` / `Pdp` / `SecretResolver` / `ServiceTokenReplayStore`，base trait 显式 `Send + Sync`；INVARIANT DIPORT-DYN-CONCURRENCY-01：Hard = native `assert_send_sync_bound`，Medium = `ui_assert_*` trybuild），其中 PDP 由正向/负向 compile gate 锁定并供 HTTP serving 跨 await 共享。不为无消费方的动态能力生成 wrapper。**服务/域 互不依赖,但都可向下依赖 diport** ——
  服务层 crate(bootstrap/deviceloop/eventexec/authn…)消费 DI port 须经此层,故 diport 不能与它们同层(服务→服务禁)。
  注:**域形** repo/service port(签名引用域内实体)**不归 diport**,归所属域 crate `pub mod ports`(ADR-005 Option 2,见下「域」行 + category line ADR-005 §2.1)。
- **服务** `httpserve`/`authn`/`bootstrap`/`eventexec`/`observ`/`distributed`/`deviceloop`:依赖基础+引擎+DI-infra;不依赖域/adapters。**服务→服务横向默认禁(同 diport 行所述),唯一受控例外 = ADR-009 sanctioned `bootstrap → httpserve` 单向路由类型边**(组合根 typed route funnel:`bootstrap::Registry::admit_writes` 按值进入 `WriteAdmittedRegistry`，仅该状态可 `finalize_routes` 产 `httpserve::UnfinalizedRoutes` → 经 `httpserve::finalize_auth` 换可 bind 的 `AuthenticatedRoutes`;反向 `httpserve → bootstrap` 及其它任意 `服务→服务` 边仍禁)。`ROUTE-WRITE-ADMISSION-01` 是 native compile **Hard**：裸 `Registry` 无 `finalize_routes`，一次 registry finalization 把其存储的同一 gate 注入所有 listener accumulator，无 optional install/fallback；由 trybuild 反例守。该 Hard 范围只证明 registry 状态转换与同次 finalization 的 gate 传播，不声称 workspace 全局不可创建独立 admission controls，也不证明 OS process singleton；后者由 canonical runtime assembly owner 负责。受控依赖边由 `xtask layers::route_funnel_allows` 机器守(INVARIANT LAYER-DEPS-ROUTE-FUNNEL-01,见下「静态强制」表 + ADR-009)。跨层另有且仅有两个 **Service → Generated** sealed bridge owner：`eventexec → generated` 实现 command/event authoring与 workflow seam，`bootstrap → generated` 实现 typed subscription registry seam；由 `generated_seam_allows` 精确守这两个有向 crate pair，且 `LAYER-DEPS-GENERATED-BOOTSTRAP-REGISTRAR-01` 进一步把 bootstrap production item surface 收窄到 exact registrar vocabulary，不能推广成一般 Service→Generated 或 generated authoring/catalog 消费。`testkit` 与 `tracewiretest` 是同层 **test-support 库**：前者提供 HTTP 契约/容器 fixture，后者只提供 OTel subscriber/exporter 脚手架；两者只经 `[dev-dependencies]` 消费。机器边界拆为正交两面：LAYER-DEPS-08 `check_test_support_confinement` 守任一 shipped 入边指向 test-support 均失败；LAYER-DEPS-10 `check_test_support_internal_dependencies` 守 test-support shipped 出边，唯一精确例外为 `testkit → rss-conformance`，使内部 harness 复用同一公开分类 owner，其余内部出边仍失败。`eventexec/test-support` 还可从中性 Projection identity 铸造 source/operator authority，因此与其它 scoped-construction feature 一样由 LAYER-DEPS-09 禁止进入任一 shipped feature closure。
- **RuntimeExec** `runtimeexec`:provider-independent 的 runtime 启动、信号等待与逆序关闭内核，并拥有 runtime inventory 的 live reader/source sampling、唯一 production mint 与 `Starting → Ready → Draining → Stopped` 的只读 Platform 投影；只可依赖公开 Foundation/Platform 与基础/引擎/DI-infra/服务。shipped direct dependency 的实际集合以 `crates/runtimeexec/Cargo.toml` 为源，并由 `cargo xtask layer-deps` 的 RUNTIMEEXEC-DEPS-01 executable allowlist 收敛；本文不复制该集合。它不拥有 HTTP transport、wire DTO、域模型或具体 provider。分层矩阵只允许 Root 入边，`deny.toml` target wrapper 再收窄为 `assemblies/runtime|settingsonly|identityaudit` 三个 assembly 的集合相等白名单，禁止 bins/composition/journeys/xtask 直接消费（RUNTIMEEXEC-LAYER-01）。
  `runtimeexec/test-support` 暴露绕过 launch lifecycle funnel 的 ready-host fixture，只准由测试图消费；LAYER-DEPS-09 禁止它进入任一 shipped feature closure。
- **Tooling/Verification** `workspacefacts`:非发布 Cargo workspace facts owner；shipped 合法链路精确为
  `xtask → workspacefacts → guppy`，dev 图只准 `xtask` 与 `workspacefacts` 自测消费。xtask 只经 command-scoped `CommandWorkspaceFacts` 注入（同命令
  metadata 成功/失败至多一次），不得绕过 façade 直依赖 guppy，也不得自读成员 `Cargo.toml` 判定
  package / dependency identity。公开面是 owned catalog DTO（字段级语义见 crate rustdoc），不泄漏
  Guppy 类型与 lifetime。`deny.toml` wrappers 与 `cargo xtask layer-deps` 的 WORKSPACEFACTS-CONFINEMENT-01
  守集合相等及真实 source edge，业务、provider、production assembly 不得消费。`WORKSPACEFACTS-COMMAND-FUNNEL-01`
  另外以 production AST 协议守住 metadata 唯一执行点并拒绝任何 Cargo tree 进程；测试 fixture 不计作
  production evidence。
- **域** `identity`/`settings`/`audit`/`contractreg`/`syshealth`:依赖基础+引擎+DI-infra+服务+`generated`(contract 派生);
  **互不依赖**(跨域只经 contract);不依赖 adapters。该边界同样适用于 `[dev-dependencies]`：域测试可复用下层、generated 与 test-support，但不得依赖兄弟域或具体 adapter；Cargo 允许表达此类测试边，故由 `layer-deps` 的确定性 Medium 子集校验。**定义自身域形 repo/service DI port**(`pub mod ports`,签名引用域内实体,由 adapter 经 DIP 实现,ADR-005);为此可依赖 dynosaur/trait-variant(DIPORT-MACRO-CONFINE-02 白名单)。
- **adapters/**:实现基础/引擎/DI-infra/服务定义的 trait(DI port 的 provider impl 在此);**不被域依赖**(组合根注入)。**可依赖域 crate 以 impl 其域形 repo/service port**(`adapter→域` = DIP 内向边,`allows(Adapter,Domain)=true` + deny.toml 该域 wrapper 放行 + 真实 shipped source edge 校验,ADR-005;反向「域→adapter」仍禁,依赖反转方向保持)。通用 `Adapter→Service` 合法；provider output 边界另有精确 deny：`adapters/redis|s3|vault → bootstrap` 禁止（package 名为 `redis-adapter|s3|vault`），postgres→bootstrap 与目标 adapter→diport 不受影响（`LAYER-DEPS-PROVIDER-BOOTSTRAP-01`）。`postgres` 的域形实现由无默认值的 `domain-settings` / `domain-identity` / `domain-audit` Cargo feature 精确启用；assembly 必须显式选择，未选择的域依赖不进入目标 package 图。`adapters/memory` 是 **dev/test-only** in-mem DI port provider(测试 / demo)——**禁生产 bin(server/rss)依赖**，当前真实 consumer 只有验收 `journeys`；机器边界由 `layer-deps` LAYER-DEPS-07 反向排除生产 bin，精确 wrapper 闭集由 cargo-deny 守。
- **bins/**、**xtask/**、**assemblies/**、**composition/**、**journeys/**:组合根,可依赖所有普通库 crate；收窄例外有两处：`runtimeexec` 只准上述三个 assembly 直接消费（`deny.toml` target wrapper 集合相等），`workspacefacts` shipped 只准 `xtask → workspacefacts → guppy`，dev 只准 xtask 与自身测试消费（`deny.toml` wrappers + WORKSPACEFACTS-CONFINEMENT-01）。`journeys` 为 tests-only 验收 journey 组合根；`composition/*` 为多个 assembly 复用的 typed domain wiring，不含 manifest 或启动入口。**examples/** 为收窄示例层,只准依赖基础/引擎/DI-infra/服务,不直接依赖 RuntimeExec、域、adapters 或 generated。`assemblies/{name}/assembly.toml`
  是 static assembly intent + DI provider 声明源：`name`/`profile`/`domains`/`topology`/`listeners`
  声明组合根 intent/surface，`listeners.domains` 以闭合 domain/listener enum 声明 route surface 归属；
  `[[diportProviders]]` 声明 provider 的 port / providerCrate / requiredFeatures / consumer / lifecycle /
  durability / purpose，并以闭合 `outputs = [probes|resources|workers]` 声明 lifecycle channel 贡献；字段细则见 `docs/rules/runtime-assembly-plan.md`
  Phase 3。`cargo xtask assembly validate` 守 manifest intent 非空/闭值/去重、active provider 的依赖 /
  feature 与安全边界（例如 production `diport::RevocationStore` 必须持久）。assembly intent / provider 声明不替代
  `contracts/**/contract.toml`、env/secrets、listener bind 配置或 Rust 构造器接线；跨域 wire contract 单源仍是 contracts。
  `assembly.toml → private generated provider catalog → AssemblyLock → RuntimePlan` 是已接纳 provider 的唯一事实链；
  未来候选 package metadata 即使存在，也必须先经同一 governance/compiler 验证，不能自动注册或建立平行 registry。
  assembly graph 从该 manifest、匹配的 committed `modules_gen.rs` carrier 与 active event
  contract/subscription 按需构造 typed presentation model；构造过程复用 canonical source 校验并防御性拒绝
  node ID 冲突或悬空 edge，但不注册独立 verify/CI gate。需要人工阅读时运行
  `cargo xtask graph assembly [--assembly <name>]`，Mermaid/JSON 只覆盖写入 `target/xtask/`，不参与
  identity、equality 或 gate verdict。`modules_gen.rs` 同时携 typed domain-listener / provider-output
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
| 值集冻结(Disposition/Status/result label，可演进) | `#[non_exhaustive]` enum + 稳定 label 映射 |
| 结算协议闭合(Settled；HandleResult 三构造器 funnel) | 闭合 enum + 穷尽 `match`，漏 case 编不过（禁 `#[non_exhaustive]`） |
| 错误 message const | `thiserror` enum variant(const `&'static str`,非格式化字符串) |
| 数据竞争 | `Send`/`Sync` 编译期 |
| wire struct 字段/tag 冻结 | serde derive 单源生成 |
| active LocalOnly receipt target | codegen 只为 active LocalOnly 生成 `LocalOnlyConformanceMarker` + `LOCAL_ONLY_SPECS`；失活/改级后 canonical callsite 编译失败，opaque receipt 仅由成功 post-check 铸造（LOCAL-ONLY-RECEIPT-TARGET-01） |
| Identity finalized authorizer capability exclusion | `RoleBindingReadRepo` 仅为 `AuthEffect + LocalPrivilege`，role mutation 封入 `RoleBindingLifecycle(OutboxEffect)`；`ResourceSecurityFactReadRepo` 只能进入接受 sealed `DeviceCertificateScope` 的 `DeviceResourceFactPip`，不得进入通用 `ContractAuthorizer` / `IdentityDomainDeps`。Fact authoring 完全留在 External bootstrap DB funnel 且无 Rust write port |
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
| 残留真要 AST/HIR 级的少数 funnel(某 callsite) | `dylint`（自写 clippy lint）。注册以根 `Cargo.toml [workspace.metadata.dylint]` 为准，members 以 `lints/Cargo.toml` 为准；派生反向索引用 `cargo xtask archrules list` / `verify`；符号/红例/盲区见各 `lints/<lint>/src/lib.rs` rustdoc。`lints/README.md` 只作操作指引（前置/运行/逃生门/新增步骤），不维护 inventory。`cargo dylint --all` 已是 `cargo xtask verify` / `ci` 一步并经 `DYLINT_RUSTFLAGS=-D warnings` fail-closed。 |
| 治理脚本入口 | `cargo` + `xtask/` |
| 错误码前缀所有权 golden | `cargo xtask` 前缀所有权治理测试（与 `error-handling.md` 一致） |
| DI port + dynosaur 收敛到定义点白名单 | `deny.toml` wrapper：`dynosaur`/`trait-variant` 只准 **DI port 定义点 crate** 依赖——白名单 = `diport`（provider-agnostic infra port）+ 定义自身 repo/service port 的域 crate（域形 port，ADR-005 Option 2，INVARIANT DIPORT-MACRO-CONFINE-02；`layer-deps` `EXTERNAL_CONFINEMENT_WRAPPERS` 守白名单条目属 DiPort/Domain 层 + wrapper⟷源集合相等）。注：dynosaur 0.3 生成的 unsafe 经 def-site hygiene **不触发** consumer forbid（实测，ADR-003 §8），无 forbid 例外、无 unsafe carve-out——本约束是「DI port 定义点集中」架构守卫，非 unsafe 收敛；ADR-005 把原 `-01`「单一依赖点」放宽为白名单（域形 repo port 必然多点定义，前提失效，零安全代价） |
| `adapter→域` DIP 内向边（impl 域形 repo port） | `xtask/src/layers.rs` `allows(Adapter,Domain)=true`（source-centric `layer-deps`，矩阵红/绿 case anti-vacuity；反向 `域→adapter` 仍 `false`）+ `deny.toml` 该域 ban 的 wrappers 加该 adapter（LAYER-DEPS-06 反向② 放行）。INVARIANT 随 `allows` 矩阵单源（LAYER-DEPS-00），ADR-005 |
| 受控 `bootstrap → httpserve` 路由类型边（组合根 typed route funnel；服务→服务唯一例外） | `xtask/src/layers.rs` `route_funnel_allows`（**只**放行 `bootstrap → httpserve` 这一对有向边，`check_layers` 在 `!allows(Service,Service)` 时叠加；反向 `httpserve → bootstrap` 及其它任意 `服务→服务` 仍禁；rstest + 端到端 `check_layers` 正反例 anti-vacuity）。INVARIANT LAYER-DEPS-ROUTE-FUNNEL-01，ADR-009 |
| generated sealed bridge 编译边 | `xtask/src/layers.rs` `generated_seam_allows` 只放行 `eventexec → generated` 与 `bootstrap → generated`；`LAYER-DEPS-GENERATED-BOOTSTRAP-REGISTRAR-01` 以 source-aware AST exact allowlist 只准 bootstrap production 使用 `EventSubscribe`/`EventSubscription`/`EventContract`/`SubscriptionExecution`/`SubscriptionEffect`，glob、宽 module、per-event、authoring/command/workflow/catalog synthetic-red；其它 Service → generated 与反向边均保持 `GeneratedScope` 红。`deny.toml` generated wrapper 同步精确增加这两个 owner；正例、其它 Service 反例与真实 workspace green 三重 anti-vacuity。Command/event authoring 类型与可见性 Hard seal 见 ADR-016/022；subscription 由 generated marker + typed wrapper 收口。 |
| Redis/S3/Vault provider output 不反向依赖 bootstrap | `xtask/src/layers.rs` `provider_adapter_bootstrap_forbidden` 精确拒绝 `redis-adapter|s3|vault → bootstrap`，并在 `layerdeps::check_layers` 通用 `allows` 前应用；三目标 synthetic red、postgres→bootstrap 与目标→diport green、真实 workspace green。INVARIANT LAYER-DEPS-PROVIDER-BOOTSTRAP-01，**Medium（xtask + CI 门）**，ADR-010 |
| ProviderPlan / output transaction 单一路径 | `PgRuntimeDeps`、factory permit 与 `ProviderBuild` 均按值消费；generated catalog 与 RuntimePlan exact-join 后，每项 role-specific typed accessor 只能消费一次，并由 sealed batch 从真实 `DomainModuleResult` 推导 lifecycle channels（Hard；无 trait/static binding/string lookup/平行 output）。`RUNTIME-PROVIDER-BIJECTION-LIVE-01` 以真实 workspace green + catalog/permit/finish/rollback synthetic red 锁 output batch 精确集合、唯一 completion/handoff、失败异步 LIFO 回滚与 provider-before-domain 注册（AcceptedMedium）。ADR-010 |
| Event transport output 单一路径 | crate-private `wire_event_transport` 直接返回 owned `DomainModuleResult`，使旧 `.module/.infra_guards` 拆包不可编译（`EVENT-TRANSPORT-OUTPUT-TYPE-01`，Hard）；receipt 完整性与 partial rollback 由 `provider_output` 行为测试拥有，`RUNTIME-PROVIDER-BYPASS-01` 仅拒绝跨文件 raw/legacy provider 与 receipt 绕过（AcceptedMedium）。ADR-010 |
| defer/follow-up 结构化完整性（根 config） | 仅机器拥有的根 `deny.toml`/`clippy.toml` 内 `DEFER(#NNNN)` 标签须 `owner=`/`blocked-by=<#NNNN｜trigger:..>`/`closes-when=` 齐全 + 禁裸 TODO/FIXME/XXX/HACK 注解（注解位）；`cargo xtask defer-gate`（接 verify/ci no-compile meta 步，synthetic red + anti-vacuity green）。INVARIANT DEFER-GATE-01；Markdown 与 `CLAUDE.md` 不作 enforcement carrier，只由周期、非阻塞 advisory grep 提示。 |
| canonical 本地 CI executable 入口 | `cargo xtask ci-entry-guard` 只校验 Makefile 中唯一、600 秒有界的 `ci` 与精确 `ci-full` recipe；skill、template、CLAUDE 等 Markdown 不作 enforcement carrier，只由周期、非阻塞 advisory grep 提示。CI-LOCAL-ENTRY-01，synthetic red + workspace anti-vacuity。 |
| Release Surface `.crate` artifact correctness | `cargo xtask package-proof` 从 validated Release Surface 动态派生 package/version exact-set，在 clean committed checkout 生成 same-head `.crate`，校验内容、VCS revision、checksum、default/no-default/all-features、MSRV、docs/doctest，并通过 invocation-local ephemeral registry 在 workspace 外执行每包 locked/offline archive consumer；portable candidate bundle 在原子发布前复算 archive checksum、重定位 registry 并复用同一 consumer proof。RELEASE-PACKAGE-PROOF-COVERAGE-01 / RELEASE-PACKAGE-SAME-HEAD-01，synthetic red + derived exact-set anti-vacuity。跨包联合 product-consumption correctness 由外部 `rss-incubator` canonical candidate CI 拥有，RSS 不保存其源码拓扑、workspace 或 lock。 |
| production Rustdoc 语义与 token profile trust chain | `cargo xtask source-semantic-guard` 只扫描 production `.rs` 的 Rustdoc，拒绝 outbox exactly/at-most-once、旧 LocalOnly effect 语义，并守四个 token-profile Rustdoc carrier；不读取 `.md`。SOURCE-RUSTDOC-SEMANTICS-01 / TOKEN-PROFILE-RUSTDOC-01，synthetic red + workspace anti-vacuity，verify/ci no-compile meta。 |

### 三档 · Cargo 替不了,框架自建(RSS 真差异化)

| 机制 | 载体 | 评级 |
|---|---|---|
| contracts 跨边界单源 + 扇出闭环 | `xtask` 校验器 | Medium(CI 门) |
| L0–L4 一致性声明 + typed capability evidence + L4 `[reconcile]` block(拓扑/引用完整性/active producer readiness/格式/能力门) | `xtask` | Medium(CI 门) |
| wire contract 版本目录(轴 B) | `xtask` | Medium(CI 门) |
| 分层依赖残留(无 back-path 反向边 / 兄弟域互斥 / adapter·generated scope / test-support 双向 shipped confinement / RuntimeExec、authmint、workspacefacts/guppy 特殊精确闭包 / wrapper source 分类) | `cargo xtask layer-deps`(source-centric：单次读取各成员 Cargo.toml 全部 shipped/dev 与 target-specific 依赖表；普通 wrapper 的 all-features resolved exact-set 只由 `cargo-deny -D unused-wrapper` 证明，layer-deps 不复制依赖解析器；符号/规则见 `xtask/src/layerdeps.rs` rustdoc) | Medium(CI 门；Cargo/rustc 允许 dev 边，无低成本 Hard 上移路径) |
| `SharedRuntimeDeps` 字段仅基础设施 / value object（禁域 service / repo） | `cargo xtask runtime-deps guard`(syn 字段扫描 + `xtask/runtime-deps-guard.toml` 配置单源 + synthetic red；接入 `verify`) | Medium(CI 门) |
| active LocalOnly ↔ compiled `LOCAL_ONLY_SPECS` exact-set、canonical receipt/marker/SPEC/ROUTE association、production mount、state/port/auth/privilege、receipt namespace 防伪造、module/cfg/macro reachability、runtime observer API/record mutation provenance 与 anti-vacuity | `cargo xtask consistency local-only-effects`（LOCAL-ONLY-RECEIPT-COVERAGE-01；Cargo facts 经 command-scoped `WorkspaceFacts`；不含 provider helper lineage / 字段字面量 / helper pairing / fixed site count / 局部顺序 bait；posture report 只输出 schema v4，**不是** enforcement carrier） | Medium(CI 门) |
| active LocalTx ↔ compiled `LOCAL_TX_SPECS` exact-set、typed route/test/journey marker、production mount、backend required-probe enrollment / provider-bound action dataflow、board/spec/fixture/runner exact-set、module/cfg/macro reachability 与 anti-vacuity | `cargo xtask localtx-coverage`（LOCALTX-COVERAGE-CLOSURE-01 / BACKEND-PROFILE-CLOSURE-01 / JOURNEY-CLOSURE-01；Cargo facts 经 command-scoped `WorkspaceFacts`；不含 probe-body AST / helper-name-launder / 非协议 call-order bait；`localtx report` **不是** enforcement carrier） | Medium(CI 门) |
| PostgreSQL tenant transaction / exact lane 与 reader / RLS catalog | Hard sealed `TenantDb<Lane>` + private-mint `TenantTx<Lane>` 绑定 tenant identity 与 transaction lifecycle；原始事务只在 `cotx` 内核可见，closure 仅获得不可互换的 `IdentityTx` / `SecretTx` / `EventingTx<Concern>` / `ReconcileTx` 等 operation set。类型层拒绝跨 concern、raw executor/connection/settlement、parallel tenant bind 及 lane 交叉（POSTGRES-TX-TYPE-01 / PG-TX-CONCERN-CAPABILITY-01 / `PG-TX-CAPABILITY-SEAL-01`）。`cargo xtask pg-tenant-tx-guard` 只保留类型无法证明的 raw-pool/tenant-table（精确列 `tenant_id` 与 `schema-rls` 共享 `tenant_migration_tables`）、SQL owner、GUC/RLS 与 settlement/quarantine 语义漏斗（#1988 已删除 refresh-legacy / exact-shape / 本门 DLX 副本）；DLX FIXED_FUNCTIONS 存在性归 `dlx-lifecycle-funnel`。合入前无 PG：`cargo xtask schema-rls`（`TENANCY-RLS-FORCE-01` / `TENANCY-PG-READER-ACL-01`）。迁移后 live catalog proof（`TENANCY-PG-CATALOG-PROOF-01`）与直连 `rss_app` A/B behavior proof（`TENANCY-PG-BEHAVIOR-PROOF-01`）由 `integration-critical:postgres-lib` 承载（激活 forge CI 时）；`setlocal-funnel` 已删除且不恢复 | Hard + Medium(schema-rls + integration-critical) |
| 组合根 DI 接线(SharedDeps / `module()`) | 手工 `main` + `bootstrap` crate | — |
| outbox/saga/reconcile/projection/command_journal 引擎 + topology-gated resolver | tokio 自写(`consistency` 态机 + `eventexec` 执行 + 各 deps resolver) | — |

**残留运行期/CI 检查**(类型系统 / crate 图管不到)的机器载体显式为 **Medium(xtask/CI 门)**，不得用文档或
人工约定替代：active subscriber
存在性、active HTTP outbox producer 目标 readiness、consistency capability evidence、contract 扇出完整性、migration 只增不改、覆盖率阈值、no-op 业务理由、分层依赖残留(crate 图仅 Hard
守已声明边的「下层依赖上层成环」；不成环的反向边 / 兄弟域互斥 / adapter·generated scope 由 `cargo xtask layer-deps`
source-centric 补，免疫裸名×crates.io 命名冲突)。治理重心在 "crate-graph lint + clippy + 类型系统"(见
`docs/rules/ai-robust.md`)。Medium gate 必须进入稳定的 repository aggregate，并在 aggregate 执行时
fail-closed；这仍不等同于 active PR 已自动调度该 aggregate 或以其阻断合入。

LocalTx / LocalOnly residual scanner 的 rule→carrier 分工：Cargo inventory 只认 `workspacefacts`；
active exact-set 只认 compiled `LOCAL_TX_SPECS` / `LOCAL_ONLY_SPECS`；行为结果认 typed testkit +
Postgres T2 / sealed receipt + runtime conformance；scanner 只守跨文件 reachability、production
binding、exact-set 与 anti-vacuity。细则见 [`localtx.md`](./localtx.md) 与
[`consistency-l0.md`](./consistency-l0.md)，本文不复制闭表。

这些 Medium gate 的 **GitHub Actions typed CI** carrier 由 `.github/workflows/ci.yml` 定义。
**PR job 拓扑固定**（`preflight` 生成规范 `SelectionPlan` 并早筛、执行 Job 不重列路径策略、两级
result-only gate 只聚合执行结果）：具体 Job 名与闭集以 `.github/workflows/ci.yml` 为真源，运维激活状态见
[CI 运维状态](../ops/202607130824-1765-diff-adaptive-ci.md) 与
[`202606231530-001-ci-lane.md`](../ops/202606231530-001-ci-lane.md)；本文不手抄 Job 名单。
`test-affected` 除 affected 组件测试外始终持有并生产 LocalOnly required evidence；其唯一公开直接入口是
`cargo xtask ci localonly-evidence --output <path>`。高影响根、影响分析失败和保守 rename 可升级为
`PrComplete`，但不得把 PR 扩成 `ReleaseCheck`。完整验证只属于 develop、nightly、release 与显式
`cargo xtask ci full`。
`CI-FIXED-WORKFLOW-01` 以结构化 YAML 闭集校验、synthetic red 与 anti-vacuity 锁定固定拓扑、
只读权限和唯一 reusable 委托，不允许 workflow 重列路径/job 策略；`CI-RESULT-GATE-01` 锁定 result-only
聚合。固定 Job 枚举、穷举 dispatch 与唯一/完整断言由 Rust 编译期证明（Hard），YAML carrier 边界由
xtask/CI 守卫证明（Medium）。workflow 存在性不得外推成
active PR 的 Medium enforcement；运行时激活状态、required-check 状态与升级条件只在 CI 运维文档维护，
避免规则文档复制易漂移的运维事实。
本地差异 preflight 统一使用 `make ci CI_BASE=<remote>/develop`：10 分钟有界、unknown 默认本地忽略并留痕，
只跑受影响 package 与定向治理测试；显式全量 `cargo xtask ci full` 仅供人工诊断，不是 PR 完成条件。
nightly/develop 重型门集包含 `verify` 全门（build/clippy 升 `--all-features --all-targets`）、覆盖率门
（引擎-基础 ≥90%，无 ratchet 例外）、唯一 `public-api` gate（internal/release exact-set、逐包 SemVer、
公共依赖与结构化类型泄漏）与供应链门。
**供应链门**必须同时覆盖依赖内容与时间维度：`cargo deny check`（advisories/licenses/bans/sources）
守当前依赖集，advisory-scoped 定时刷新覆盖「未变依赖」后来披露 CVE。
实际 schedule、forge 与 required-check 状态以
[CI 运维状态](../ops/202607130824-1765-diff-adaptive-ci.md) 为准，设计见
[`202606231530-001-ci-lane.md`](../ops/202606231530-001-ci-lane.md)。

L0/L1 验证沿用同一 typed policy，不在规则文档维护第二份 gate inventory：affected `make ci` 按
Consistency domain 选择声明、codegen 与静态证据；`verify --fast` 门集以 `xtask/src/verify.rs` 为真源，
不拥有 L0/L1 证明。完整 `verify` 增加编译和默认行为测试并仅编译 integration targets，真实 Postgres
LocalTx matrix 与 active L1 journey 由
`cargo xtask ci run --job integration-critical --integration-group postgres --selection '<canonical SelectionPlan JSON>'`
执行；selection 必须包含其稳定 integration unit ID。具体采用顺序与失败边界分别见
[`consistency-l0.md`](./consistency-l0.md) 和 [`localtx.md`](./localtx.md)。

ArchRules 反向索引由 `cargo xtask archrules list` 从真实 carrier 的 `INVARIANT:` 锚点派生，展示
rule id → carrier → source → fixture/baseline → gate；`cargo xtask archrules verify` 接入 verify/ci 的
no-compile meta gate。Hard 只接纳 Cargo-reachable production Rust、build script 与 production 类型边界；
trybuild/external compile 是 support evidence，JSON/Markdown/Mermaid/golden/report
漂移是 Medium presentation evidence。索引 identity 与稳定输出使用 carrier path，不使用仅供诊断的行号。
本文档只描述载体原则，不维护落地实例清单。持久化 funnel 的单一真源是
[`xtask/src/archrules.rs`](../../xtask/src/archrules.rs) 的 typed catalog；`cargo xtask archrules verify`
在内存中完成语义校验并随同一 ArchRules gate 进入 verify/ci。需要阅读派生展示时运行
`cargo xtask archrules matrix`，报告仅写入 `target/xtask/`，不参与 identity、equality 或 gate verdict。

## 关键模式的 Rust 形态

### 组合根与域装配

- 域实例与其生命周期输出由 `bootstrap::DomainBinding` 单一持有，只经私有构造器与受控 `compose_bindings`
  出口聚合；compose 失败必须保持 bindings/outputs 原样。
- `DomainModuleResult` 固定为 `DomainBinding.output` 的生命周期三出口（probes / resources / workers），
  **不得**承载 domain service、routes 或 generic bag；`name` / `domain` 属 binding。
  domain service 留在 typed domain 内经 route 闭包捕获，不向外流出。
- `assembly.toml` 的顺序是唯一的域构造、声明注册与生命周期输出聚合顺序。
- 各域的 provider-to-binding 构造由 `composition/*` 的必填 typed deps 单源承载；assembly 只保留
  env/provider 适配与薄入口。adapter↔域绑定一律在组合根用构造器注入完成。
- topology-gated resolver 是 `bootstrap` 子模块，按 `Topology` 单源选型，不散落到各域。
- 载体：`WIRING-DEPS-NO-HANDOFF-01`（Hard）——per-domain source trait sealed 且 typed 装配入口无参数可塞
  别域 result，跨 module value handoff 在类型层不可表达。
- `SharedRuntimeDeps` 只能放共享基础设施 / provider value object，**禁止**放 domain service / repo。
  允许根由 `xtask/runtime-deps-guard.toml` 单源配置。
  载体：`WIRING-DEPS-INFRA-ONLY-01`（Medium，`cargo xtask runtime-deps guard`）；
  规则细节与盲区见 `docs/rules/runtime-wiring.md`。
- 持久化能力分层（binding / module result / provider capability bundle / adapter bundle）的设计单源是
  **ADR-010**（`docs/architecture/202606270148-010-persistence-capability-layering.md`），本文不复制。

### Assembly manifest

- `assemblies/{name}/assembly.toml` 只声明静态 intent（`name`/`profile`/`domains`/`topology`/`listeners`）
  与 DI provider 选择及其 lifecycle / durability。它**不**生成运行时接线，也不驱动 live topology、
  route mounting、auth scheme、provider construction 或 readiness——真实接线仍在 Rust 里经构造器注入完成。
- active provider 必须与该 assembly `Cargo.toml [dependencies]` + required features 对齐；
  安全关键 port 可追加专门约束（例如 production 撤销 store 必须持久，draft/ephemeral 只允许 demo/test assembly）。
- 载体：`ASSEMBLY-DOMAIN-CLOSURE-01` 对每个 assembly 的目标 package消费同一 command-scoped
  `WorkspaceFacts`，以 CargoSet Resolver-v2 Target-side All/Default selection证明 normal direct edge、
  active domain 与 inactive artifact 闭包；Host edge、包经其它路径被选中、rename 或 unresolved declaration
  均不能伪装成 direct dependency。
  workspace 联合 all-features 编译由 CI 另行覆盖，**不**作为单个部署 artifact 的裁剪事实。
- 字段边界与验证 carrier 见 `docs/rules/runtime-assembly-plan.md`。

### Transaction retry

- retry 分类是闭值集 `TxRetryClass::{Transient, Conflict, Permanent, OwnershipLost}`，
  与 runtime-neutral 的 retry 执行体一起定义在 `consistency`；不得散落成 bool / string 约定。
- 只有 adapter 的明确 UoW 边界可以套 retry，且每次 attempt 必须重建完整事务。
  repo 方法、handler、outbox publish/settle、consumer commit/release 内部**不得**隐式 retry 带副作用的写入。
- 分类语义：`Transient`（序列化失败 / 死锁 / 连接瞬断 / 池获取超时）可在预算内重试；
  `Conflict`（CAS 或版本冲突）必须向上返回，由 command 层显式 refetch/recompute；
  `Permanent`（约束 / 解码 / 租户 envelope mismatch / 损坏行）fail-closed；
  `OwnershipLost`（lease lost / fencing miss / stale owner）是终态围栏，不得当 transient 重跑。
- LocalTx contract 的写入口只能消费 domain typed command 携带的 generated observation 并使用 LocalTx runner；
  marker 经 crate-private operation 类型唯一映射到 retry boundary，调用方不能另传 boundary。
  内部 / rollback 路径使用 generic runner，二者不得借用 HTTP contract telemetry。
- 只读 repo 不暴露 mutation；同一域的写入口集中在一个 UoW 类型。
- backoff 使用 full jitter；pool acquire 与 lock wait 均有上限，有限 attempt 数构成总等待上界；
  调用 future 被请求 deadline 取消时不得在后台继续重放。
- durable command 的 request-side 幂等**不靠**重试包自动重放：先 claim request fingerprint；
  需要业务写共提交时由同一 tenant transaction 提交业务写与 outbox append；
  重复请求只按 journal 结果回放，same-key different-fingerprint 返回 conflict。
- 载体：`TX-RETRY-BOUNDARY-01`（Medium）——闭枚举 + SQLSTATE 单源映射 + testkit conformance 断言。

### 其它

- **Init fail-fast**：必填依赖走构造器必填参数（编译期）；init 内不做 I/O、不 spawn task。
- **Adapter sealed marker**：unit sealed-marker（如 `struct PgStore;`）以 native AFIT impl 已冻结的 DI port
  trait；DI port **不**跨 crate sealed（ADR-003 §4.2 方案②，impl-sealing 未机器强制）。
  raw client 字段一律 `pub(crate)`，不泄漏到 API 面。
- **DTO 作用域**：域内 = `pub(crate)` 模块类型；跨域 wire = contract（`contracts/` 声明 → `generated/` crate）。
- **错误**：`vocab`(error) + `thiserror`（库错误枚举）；应用边界可 `anyhow`。错误码命名空间注册 + golden。
- **代码生成**：`build.rs` / proc-macro / `xtask` 作为 codegen funnel，产物入 `generated/`（committed，
  一等审查材料）或 `OUT_DIR` + `insta`。
