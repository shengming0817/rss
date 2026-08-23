---
description: "Task list — 全 crate 签名冻结 (#997 / RW-G0.2)"
---

# Tasks: 全 crate trait/type 签名冻结（#997 / RW-G0.2）

**Input**: Design documents from `docs/spec/001-crate-signature-freeze/`

**Prerequisites**: plan.md ✓, spec.md ✓, research.md ✓, data-model.md ✓, contracts/ ✓

**Tests**: 本 feature 的"测试"= 签名冻结期的 **mock 可构造性 / dyn-compatible（dynosaur）/ DI 接线 shape 测试**（PORT-SHAPE-01/02/03）+ build smoke，**不含行为测试**。每个 crate 任务**内含**其 shape 测试件。

**全局铁律**：所有方法体 `todo!()`，**只冻签名不实现行为**。每个 crate 任务的"完成"= `cargo build -p <crate>` 绿 + shape 测试编译过 + 遵守 conventions（单源 ADR-004，`contracts/conventions.md` 薄引用）。

## Format: `[ID] [P?] [Story] Description`

- **[P]**: 可并行（不同 crate、无未完成依赖）
- **[Story]**: US1=基础+引擎(P1) / US2=服务(P2) / US3=域+adapters(P3)
- 标注约定：`PR-N` 所属 PR · `门:` 上游依赖 · `spike:` spike 门 · `ref:` 对标 · `测试:` shape 测试件

---

## Phase 1: Setup —— PR-0 conventions 地基

**Purpose**: 落地签名编写约定单源，作为全部签名 PR 的 review 基准。

- [x] T001 [PR-0] 落地签名 conventions 单源为 **ADR-004** `docs/architecture/202606220106-004-signature-conventions.md`（dynosaur async/dyn 二分、mock、ctx 范式 ADR-002、关闭逆序 ADR-001、必填依赖/Clock、serde 边界、sealed/newtype 方案②、unsafe 收敛、dynosaur pin、覆盖率豁免、对标 ref）；`contracts/conventions.md` 改薄引用 ADR-004
- [x] T002 [P] [PR-0] 增 typed `cargo xtask public-api internal|release` 子命令（`xtask/src/main.rs` Command enum + `xtask/src/publicapi.rs`，包装外部 `cargo-public-api`，未装/缺 nightly 给指引）。baseline 快照在 PR-1/PR-2 产出
- [x] T003 [P] [PR-0] 在 epic 评论登记 spike 依赖门矩阵（ADR-002/ADR-003 横切、ADR-001 局部、diport 落地门、#998 软、dynosaur 回退路径），引用 `data-model.md` 实体4 + diport 落地待决项

---

## Phase 2: Foundational （阻塞门 —— 全部 user story 前置）

**⚠️ CRITICAL**: 下列门未过，任何层签名**实施**不得开始（规划已完成，不受此门约束）。

- [x] T004 [PR-0] 核验 spike ADR 落地门：**ADR-002(#994 context) + ADR-003(#995 dynosaur 派发) 已落地**（横切，gate 全部签名）；**ADR-001(#996 关闭逆序) 已落地**（gate ManagedResource + bootstrap::shutdown）。三 ADR 均 Accepted → 门已过。⚠️ ADR-003 dynosaur **可行性待 PR-diport 验证**（§8）；DI port 实质冻结门于 PR-diport，未过 → 不开工 DI port 实施

**Checkpoint**: T001–T004 完成 → conventions(ADR-004) 就绪 + spike 门已过 → 放行 US1。

---

## Phase 3: User Story 1 — 基础+引擎层接缝冻结 (Priority: P1) 🎯 MVP

**Goal**: 冻结分层依赖根（基础 5 + 引擎 2 crate）的 trait/type 签名，解锁上层一切引用。

**Independent Test**: `cargo build -p vocab -p ids -p secure -p support -p runctx -p consistency -p primitives` 绿；L0 引擎/策略 trait 泛型静态分发编译过；不依赖任何上层 crate。（DI port 如 Clock 推荐迁 diport，dyn-compatible 验证在 PR-diport，见待决项#2）

### PR-1 基础层（门: T004；同层 5 crate 并行）

- [ ] T005 [P] [US1] 冻结 `vocab` 公开签名于 `crates/vocab/src/lib.rs`：error 枚举(thiserror, message `&'static str` const, `#[non_exhaustive]`)、authz/tenant/query 词汇 type、`ContractOwner`(sealed enum)。测试: build smoke + public-api baseline。覆盖率豁免
- [ ] T006 [P] [US1] 冻结 `ids` 于 `crates/ids/src/lib.rs`：sealed newtype ID（私有字段）+ 构造 funnel。测试: build smoke + public-api baseline
- [ ] T007 [P] [US1] 冻结 `secure` 于 `crates/secure/src/lib.rs`：redaction/aead/cookie/pathsafe trait + 值类型。测试: build smoke + PORT-SHAPE-01（如有 dyn trait）
- [ ] T008 [P] [US1] 冻结 `support` 于 `crates/support/src/lib.rs`：http/pg/validation helper 签名。测试: build smoke
- [ ] T009 [P] [US1] 冻结 `runctx` 于 `crates/runctx/src/lib.rs`：`RequestCtx`(tenant/principal 载体)。spike: #994 决定 struct vs task_local 形态。可观测 ID 走 tracing span 不入签名。测试: build smoke
- [ ] T010 [US1] PR-1 验收（门: T005–T009）：`cargo build -p vocab -p ids -p secure -p support -p runctx` + `cargo clippy -D warnings` 绿；deny.toml 绿（无内部分组依赖）；commit public-api baseline。**开 PR-1，body 标覆盖率豁免 + ref**

### PR-2 引擎层（门: T010；同层 2 crate 并行）

- [ ] T011 [P] [US1] 冻结 `consistency` 于 `crates/consistency/src/lib.rs`：outbox/saga/reconcile/projection/idempotency 纯态机 + trait（L0–L4），如 `InboxStore`/`OutboxRelay`/`Reconciler`。**L0 引擎策略 → native AFIT + 泛型静态分发**（零开销，不引 dynosaur）；`Reconciler` 函数式接缝。ref: kube-rs kube-runtime/src/controller/mod.rs@main + watcher.rs@main（L0 native AFIT）。测试: build smoke + 泛型静态分发编译 + public-api baseline
- [ ] T012 [P] [US1] 冻结 `primitives` 于 `crates/primitives/src/lib.rs`：crypto/authplan/healthz/circuitbreaker 等纯计算/原语。`Clock`(构造器位参, 禁默认系统时钟) 与 `ManagedResource`(LIFO) 是 **DI port → 推荐迁 diport**（待决项#2#4，`ManagedResource` inter-ADR 暂遵 ADR-001）；primitives 仅留非 DI 纯计算接缝。ref: uber-go/fx lifecycle.go@master。测试: build smoke + public-api baseline
- [ ] T013 [US1] PR-2 验收（门: T011–T012）：`cargo build -p consistency -p primitives` + clippy 绿；不依赖服务/域/adapters（deny 绿）；commit public-api baseline。**开 PR-2**

**Checkpoint**: US1 完成 → 基础+引擎接缝冻结，上层可引用。

---

## Phase 3.5: PR-diport — DI port trait 收敛 + dynosaur 可行性落地

> **重排单元（ADR-003）**：ID 前缀 **TD** 以免打乱既有 T0NN。gate PR-3/PR-4/PR-5。**实施门**：dynosaur 可行性（ADR-003 §8 三风险）；不可接受 → 回退 async-trait（§5）+ spec 再 reconcile。

**Goal**: 建 `crates/diport`，把全部 DI 注入 port trait（Store/Signer/Publisher/Subscriber/PDP/Clock/ManagedResource/域 repo…）以 dynosaur 收敛，unsafe 限定本 crate；完成结构单源回写。

**Independent Test**: `cargo build -p diport` 绿；首 port trait dyn-compatible（`trybuild` compile-pass/fail）；`deny.toml` wrappers 绿（dynosaur 仅 diport——PR-diport 彼时仅 infra port；**ADR-005 后白名单扩 = diport + 定义域形 repo port 的域 crate**，DIPORT-MACRO-CONFINE-01′）；adapter crate 保持 forbid 编译过。

- [ ] TD01 [PR-diport] 建 `crates/diport`（继承 workspace forbid，**无 deny 覆盖、无生成点 `#[allow]` carve-out**——#1049 实测 def-site hygiene 不触发 consumer forbid）；定义 DI port trait 全集 + `#[trait_variant::make(X: Send)]` + `#[dynosaur(pub DynX = dyn(box) X, bridge(dyn))]` wrapper（native AFIT，body=todo!()）。ref: spastorino/dynosaur releases/v0.3.0。测试: build smoke + PORT-SHAPE-01/02/03（`Box/Arc<DynX>`）
- [ ] TD02 [PR-diport] **结构单源回写（同 PR 三处）**：`Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`、`Cargo.toml [workspace] members`（加 `crates/diport`）、`deny.toml` wrappers（`dynosaur`/`trait-variant` **依赖**仅 diport——彼时仅 infra port；**ADR-005 后扩白名单 + 定义域形 repo port 的域 crate**；限依赖非 impl，impl-allowlist 待 #1060）+ dynosaur pin `=0.3.x`
- [ ] TD03 [PR-diport] 验证 ADR-003 §8 三开放风险（#1049 落地结论）：① unsafe carve-out **不需要**——def-site hygiene 不触发 consumer forbid（无 `#[allow(unsafe_code)]`、无 carve-out 登记）；② 跨 crate sealing 采方案②（deny.toml wrapper 限宏**依赖**非 impl；impl-allowlist 待 #1060/PR-5）；③ dynosaur v0.3 API pin `=0.3.0` + 审 changelog
- [ ] TD04 [PR-diport] 回写 Cargo workspace 分层与 `deny.toml` wrappers（DI port 集中 + sealing 改 cargo-deny）；加首 port trait `trybuild` dyn-compatible compile-pass/fail（Medium 回归锁）；解决 mockall × dynosaur/native-AFIT 形态（待决项#6）
- [ ] TD05 [PR-diport] PR-diport 验收（门: TD01–TD04 + bootstrap shutdown 框架前置）：`cargo build -p diport` + clippy + `cargo deny check` 绿；dyn-compatible trybuild 绿；§8 三风险已结论；架构/规则单源已回写。**开 PR-diport，body 标 ref: dynosaur + ADR-003 §8 验证结论 + 覆盖率豁免**

**Checkpoint**: PR-diport 完成 → DI port 接缝冻结 + dynosaur 可行性确证 → 放行 PR-3/PR-4/PR-5。

---

## Phase 4: User Story 2 — 服务层接缝冻结 (Priority: P2)

**Goal**: 冻结 7 个服务 crate 的**非 DI 接缝**（type/穷尽 enum/sync Fn/生命周期编排）；DI 注入 port（PDP/Publisher/Subscriber/store/distlock/signer…）已迁 diport（PR-diport）。

**Independent Test**: 7 服务 crate `cargo build` 绿（依赖已冻 P1 + diport）；`Domain::init` 返回 Result 不 panic；`Disposition`/`HandlerFn`/`RouteGroup` 等非 DI 接缝冻结；不依赖域/adapters。

### PR-3 服务层（门: TD05（PR-diport）；同层 7 crate 并行）

- [x] T014 [P] [US2] 冻结 `httpserve` 于 `crates/httpserve/src/lib.rs`：`RouteGroup`/`Route`/`ListenerKind`(穷尽 enum)；复用 `tower::Layer`/`Service`；register=同步 `Fn(Router)->Result<Router>`（非 DI 接缝）。ref: tower tower-layer/src/lib.rs@master + axum axum/src/routing/mod.rs@main。测试: build smoke
- [x] T015 [P] [US2] 冻结 `authn` 于 `crates/authn/src/lib.rs`：jwt/session/refresh 值类型、`Principal`(RowScope 派生) 类型；ctx 遵 ADR-002 显式传 `&RequestCtx`。authplan 类型引 primitives::authplan。**PDP/session store dyn port → diport**。测试: build smoke
- [x] T016 [P] [US2] 冻结 `bootstrap` 于 `crates/bootstrap/src/lib.rs`：`Domain::init(&self,&mut Registry)->Result`、`Registry`、`module()->DomainModule`、shutdown 编排（持 `ManagedResource` LIFO，遵 ADR-001；trait 归属待 diport 拍板）。init=sync 不 I/O 不 spawn。ref: kube-rs controller + uber-go/fx module.go@master。测试: build smoke + PORT-SHAPE-01/02
- [x] T017 [P] [US2] 冻结 `eventexec` 于 `crates/eventexec/src/lib.rs`：非 DI 接缝 `Disposition`(穷尽 enum)、`HandlerFn`/`ConsumerFn` 类型、`SubscribeInitializer`、saga executor·tailer/command。**Publisher/Subscriber dyn port → diport**（subscribe 返回 `impl Stream+Send`）。ref: watermill message/pubsub.go@master + router.go@master。测试: build smoke
- [x] T018 [P] [US2] 冻结 `observ` 于 `crates/observ/src/lib.rs`：metrics/logging 值类型（metrics label 闭值集）。**audit sink/interceptor dyn port → diport**。测试: build smoke
- [x] T019 [P] [US2] 冻结 `distributed` 于 `crates/distributed/src/lib.rs`：distlock/cas/transport 值类型。**dyn port → diport**。测试: build smoke
- [x] T020 [P] [US2] 冻结 `deviceloop` 于 `crates/deviceloop/src/lib.rs`：cert lifecycle·signing(L4) 态机类型。**signer dyn port → diport**。测试: build smoke
- [x] T021 [US2] PR-3 验收（门: T014–T020）：7 服务 crate `cargo build` + clippy 绿；不依赖域/adapters（deny 绿）；listener auth chain 显式（无 None）；DI port 已在 diport。**开 PR-3，body 标覆盖率豁免 + ref**

**Checkpoint**: US2 完成 → 服务接缝冻结，域与 adapters 可实现/注册。

---

## Phase 5: User Story 3 — 域层+adapters 层接缝冻结 (Priority: P3)

**Goal**: 冻结 5 域 crate 的**域内 DTO + 非 DI 域逻辑 + 域形 repo/service port（`pub mod ports`，ADR-005）** + 12 adapters 的 sealed-marker + native AFIT impl（diport infra port + 域形 repo port）。扇出面最宽，冻结后即逐单元放行 W。（provider-agnostic infra DI port 在 diport；域形 repo port 归域 crate，ADR-005 #1083）

**Independent Test**: 每个域 crate `cargo build` 绿且域间无 import（deny 绿）；每个 adapter sealed newtype native AFIT impl diport trait 且 raw client `pub(crate)`、保持 forbid；`cargo build --workspace` 绿。

### PR-4 域层（门: T021；软门 #998 generated；同层 5 crate 并行，与 PR-5 并行）

- [x] T022 [P] [US3] 冻结 `identity` 于 `crates/identity/src/`：身份/会话/RBAC/ABAC 域内 DTO + 值对象 + 非 DI 域逻辑。domain 类型不 derive Serialize（ADR-004 C6）。**repo/领域服务 DI port → diport**（dynosaur，PR-diport）。软门: #998(wire 类型)。测试: build smoke + 域内类型编译
- [x] T023 [P] [US3] 冻结 `settings` 于 `crates/settings/src/`：版本化配置 **域内值对象 + 非 DI 纯逻辑**（ConfigEntry/ConfigVersion + diff）。feature flag 占位产品面已移除并 deferred 至 #2070。**repo/服务 DI port → diport（归属待决 #1083，本轮 Scope A 不含）**。测试: build smoke（显式 `fn(..)->..` 签名断言）
- [x] T024 [P] [US3] 冻结 `audit` 于 `crates/audit/src/`：审计链 **域内值对象 + 非 DI 纯逻辑**（AuditEntry/EntryHash/AuditChainLink + link_hash/verify_chain）。**repo/append 服务 DI port → diport（归属待决 #1083，本轮不含）**。测试: build smoke（显式签名断言）
- [x] T025 [P] [US3] 冻结 `contractreg` 于 `crates/contractreg/src/`：运行时契约 **域内值对象 + 非 DI 纯逻辑**（ContractRecord/Kind/Status/ConsistencyLevel + can_transition/validate_metadata）。**submit/list repo+服务 DI port → diport（归属待决 #1083，本轮不含）**。测试: build smoke（显式签名断言）
- [x] T026 [P] [US3] 冻结 `syshealth` 于 `crates/syshealth/src/`：健康聚合 **域内值对象 + 非 DI 纯逻辑**（复用 primitives::healthz + ProbeRegistry/ProbeDescriptor + aggregate_with_criticality）。**聚合服务 DI port → diport（归属待决 #1083，本轮不含）**。测试: build smoke（显式签名断言）
- [x] T027 [US3] PR-4 验收（门: T022–T026）：5 域 crate `cargo build` + clippy 绿；域间无 import + 不依赖 adapters（deny 绿）；domain 类型未 derive Serialize（核）。**开 PR-4，body 标覆盖率豁免 + ref + #998 软依赖说明**
  - 落地说明（PR #1051，**Scope A**）：本 PR 冻**域内值对象 + 非 DI 纯域逻辑**（对标 authn），全 `todo!()`、域类型落 `mod domain` 经 dylint `rss_domain_no_serialize` 守 C6，smoke 用显式 `fn(..)->..` 断言 Hard 锁签名。**勾选 [x] 仅代表 Scope A（域内非 DI 接缝）已交付**——上列 T023–T026 中 **repo port / repo 型领域服务 / PORT-SHAPE 部分未在本 PR 落地**（归属阻塞于 `data-model.md` 待决项#1：diport 不得引域实体，与 layer-diport.md SessionRepo→diport 矛盾 → **跟踪 #1083**）；待 #1083 拍板后另起单元补 repo/服务接缝 + PORT-SHAPE。#998 虽 closed 但 `generated/` 仅 seed stub、无真实域 wire 类型，故只冻非 wire 接缝。依赖精简 → #1084。`cargo xtask verify`（含 build/clippy/nextest/deny/dylint）全绿。
  - **✅ #1083 已拍板（ADR-005，Option 2）**：域形 repo/service port 归**所属域 crate `pub mod ports`**（非 diport），`adapter→域` 经 DIP 内向边 impl（`allows(Adapter,Domain)=true`）。两份 spec 矛盾（layer-diport.md ↔ data-model.md 待决项#1）已消解。本轮落 1 个代表性 `identity::ports::RoleRepo` + `postgres` impl 作编译证明；**T023–T026 各域剩余 repo/service port + PORT-SHAPE 随 W 阶段行为单元逐域补**（机械复制本范式，按需扩 deny.toml 域 wrapper + dynosaur 白名单）。

### PR-5 adapters 层（门: TD05（PR-diport）；与 PR-4 并行；同层 12 crate 并行）

- [x] T028 [P] [US3] 冻结 `adapters/postgres`：`PgStore` sealed-marker + **native AFIT** impl diport `ManagedResource`(todo!())。crate 保持 forbid(unsafe_code)（不 invoke dynosaur 宏）。测试: build smoke
- [x] T029 [P] [US3] 冻结 `adapters/redis`：sealed-marker `RedisStore` + native AFIT impl `ManagedResource`。测试: build smoke
- [x] T030 [P] [US3] 冻结 `adapters/amqp`：sealed-marker `AmqpPublisher` + native AFIT impl `Publisher` + `ManagedResource`。测试: build smoke
- [x] T031 [P] [US3] 冻结 `adapters/mqtt`：sealed-marker `MqttPublisher` + native AFIT impl `Publisher` + `ManagedResource`。测试: build smoke
- [x] T032 [P] [US3] 冻结 `adapters/s3`：sealed-marker `S3Store` + native AFIT impl `ManagedResource`。测试: build smoke
- [x] T033 [P] [US3] 冻结 `adapters/oidc`：sealed-marker `OidcProvider` + native AFIT impl `ManagedResource`。测试: build smoke
- [x] T034 [P] [US3] 冻结 `adapters/grpc`：sealed-marker `GrpcServer` + native AFIT impl `ManagedResource`。测试: build smoke
- [x] T035 [P] [US3] 冻结 `adapters/otel`：sealed-marker `OtelExporter` + native AFIT impl `ManagedResource`。测试: build smoke
- [x] T036 [P] [US3] 冻结 `adapters/prometheus`：sealed-marker `PromExporter` + native AFIT impl `ManagedResource`。测试: build smoke
- [x] T037 [P] [US3] 冻结 `adapters/vault`：sealed-marker `VaultSigner` + native AFIT impl `Signer` + `ManagedResource`。测试: build smoke
- [x] T038 [P] [US3] 冻结 `adapters/softca`：sealed-marker `SoftCaSigner` + native AFIT impl `Signer` + `ManagedResource`。测试: build smoke
- [x] T039 [P] [US3] 冻结 `adapters/ratelimit`：sealed-marker `RateLimiter` + native AFIT impl `ManagedResource`。测试: build smoke
- [x] T040 [US3] PR-5 验收（门: T028–T039）：12 adapter `cargo build` + clippy 绿；adapter crate 保持 forbid(unsafe_code)；不被任何域 crate 依赖（deny 绿）。**开 PR-5，body 标覆盖率豁免 + ref**

> **PR-5 实施决策（与原任务文本的偏离，记录于此保持 spec tracker 诚实）**
>
> 1. **raw client 字段统一延迟到 W 阶段**（含 postgres）：diport 现仅冻 4 个 DI port trait（`Clock`/`Signer`/`Publisher`/`ManagedResource`），无 repo/store/transport/metrics/限流 trait——原任务文本里的这些 trait 名不存在，故 adapter 只 impl 已冻的 4 个。sealed-marker 均为 **unit struct**（无 raw client 字段）；「raw client `pub(crate)` 不泄漏」作为 W 阶段约定记录在每个 crate 的 rustdoc，字段在接后端时填入。原计划 postgres 用 `sqlx::PgPool` 做唯一范例，但其 `tls-rustls` 树拉入 `webpki-roots`（`CDLA-Permissive-2.0`，不在 license allowlist）触 `cargo deny licenses` 红——为不扩 allowlist / 不引入整棵 sqlx 供应链树（仅为 todo!() 范例），postgres 亦改 unit 标记，与其余 11 一致（决策见 PR 说明）。
> 2. **trait 映射**：全部 12 impl `ManagedResource`（生命周期 shutdown 通用）；vault/softca 另 impl `Signer`，amqp/mqtt 另 impl `Publisher`。
> 3. **implementer-allowlist（#1060）仍 deferred**：cargo-deny 限依赖非 impl，无干净静态载体（见 ADR-003 落地结论 2 / deny.toml 注释）。本 PR 让 adapter 成为 port trait 首批真实 impl，allowlist 强制待 #1060。

**Checkpoint**: US3 完成 → 全部接缝冻结。

---

## Phase 6: Polish & 收口 GATE

**Purpose**: 全 workspace 编译 + 签名 review → 放行 W 宽扇出。

- [ ] T041 全量编译门：`cargo build --workspace` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo deny check`（含 diport wrappers）全绿
- [ ] T042 签名 review 门：全部 PR-0/PR-1/PR-2/PR-diport/PR-3/PR-4/PR-5 合并 + 接缝签名 review 通过 → **放行 W 宽扇出 (#1000–#1016)**，并在 epic #991 评论登记 #997 完成、W 单元解锁

---

## Dependencies & 执行序

```
Phase1 Setup(PR-0: T001-T004)               ← 本次 ship 已实施（ADR-004 + xtask public-api + epic 评论 + 门核验）
  └─ US1(P1): PR-1(T005-T010) → PR-2(T011-T013)
      └─ Phase3.5 PR-diport(TD01-TD05)        ← DI port 收敛 + dynosaur 可行性验证（gate 下游）
          └─ US2(P2): PR-3(T014-T021，非 DI 接缝)
              └─ US3(P3): PR-4(T022-T027) ∥ PR-5(T028-T040)   ← 两组并行
                  └─ Phase6 GATE(T041-T042) → 放行 W
```

- **跨层严格串行**：US1 → PR-diport → US2 → US3（DI port 未冻下游无法 impl/mock，非 DI 接缝待 diport 后冻）。
- **层内并行**：PR-1 内 T005-T009、PR-2 内 T011-T012、PR-3 内 T014-T020、PR-4 内 T022-T026、PR-5 内 T028-T039 各组 `[P]` 全并行；PR-diport(TD01-TD05) 串行单元（建 crate + 回写 + 验证）。
- **PR-4 ∥ PR-5**：域与 adapters 触不同 crate，可同时跑（均门于 PR-diport）。
- **spike 门（实施前置）**：ADR-002+ADR-003 阻塞 T004 后全部；ADR-001 阻塞 T012/T016 的 ManagedResource；**PR-diport(dynosaur 可行性) 阻塞 PR-3/4/5 的 DI port impl**；#998 软阻塞 T022-T026 的 wire 引用部分。

## 并行执行示例

- **PR-1（基础层）**：同时派 5 个 agent 跑 T005/T006/T007/T008/T009（各自独立 crate，零文件重叠）。
- **PR-3（服务层）**：同时派 ≤4 个 agent 跑 T014-T020（cap 4/批，分两批）。
- **US3**：PR-4 的 T022-T026（5 域）与 PR-5 的 T028-T039（12 adapter）可在 ≤4 并发下同时推进。

## MVP 范围

**MVP = US1（PR-0 + PR-1 + PR-2）**：基础+引擎接缝冻结即可独立交付价值——它是分层依赖根，冻结后 W 阶段的引擎/基础消费单元（#1000 RW-W-base）即可开工，无需等 diport/服务/域层。后续 PR-diport → US2/US3 增量交付（PR-diport 是 DI port 消费方 PR-3/4/5 的硬前置）。

## 覆盖率说明（全任务统一）

所有签名冻结 PR body=`todo!()` 不可达 → 每个 PR body **必须**声明"覆盖率延迟到对应行为 PR（W 阶段）兑现"，避免 80%/90% 门触发 CI 红（conventions C8）。
