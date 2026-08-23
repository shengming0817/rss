# ADR-003：DI trait 的 async + dyn 派发策略与 Arc 样板范式

- **状态**：Accepted + **Landed**（PR-diport #1049，2026-06-22）。派发策略（dynosaur）已落地；§8 三项开放风险已实测，结论见下「落地结论」——**dynosaur 可行，且比本 ADR 原设更简**（无 unsafe 例外）。
- **日期**：2026-06-21（落地回写：2026-06-22）
- **关联**：issue #995 [RW-G0.5] · epic #991 · 落地单元 #1049 · `docs/migration-from-gocell/gocell-rust-crate-mapping.md`
- **后续修订**：**ADR-005**（#1083，2026-06-23）把「所有 DI port 收敛 diport」部分化——域形 repo/service port 归域 crate（§6 偏离 2 + §7 行 1 已就地重写并重评威胁矩阵）。
- **后续修订**：**Amendment（#1095，2026-06-23）**——async DI port 注入形态收口（`make(X: Send)` 的 `DynX` 是 Send 非 Sync ⇒ `Arc<DynX>` 是 `!Send`；多次调用 async 消费者用泛型静态分发而非 `Arc<DynX>`）。§4.3 / §4.5 冲突段就地重写、§7 威胁矩阵补行、Option A defer。见下「Amendment」节。
- **后续修订**：**Amendment（#1142，2026-06-25）**——新增 ack-capable delivery seam（`Acker` / `AckableSubscriber` 两个 async DI port + `Delivery`/`AckAction` 值类型），照本 ADR 既定 `make(X: Send)`+dynosaur 范式扩端口（**非新机制**），使 AMQP 消费达成 at-least-once。§7 补行、威胁矩阵重评。见下「Amendment（#1142）」节。
- **后续修订**：**Amendment（#1168，2026-07-14）**——DLX lifecycle 两个 provider-neutral port 归 `diport`，按 #1095 的多次 `Send + Sync` 调用形态使用 `trait_variant` Send 变体 + 静态泛型；不生成无消费方的 dyn wrapper。第三个 cipher port 删除，eventexec 直接静态消费既有 `KeyProvider`。见下「Amendment（#1168）」节。
- **后续修订**：**Amendment（#1828，2026-07-16）**——HTTP serving 的 PDP 必须跨 Pending 共享，故 `PdpLocal` / `Pdp` 收紧为 `Send + Sync`，成为 #1095 默认规则的窄例外；同步轮询路径删除并由机器门禁止。
- **后续修订**：**Amendment（#1153，2026-08-11）**——`ManagedResource` / `ManagedResourceLocal` 明确分类为 lifecycle seam，不属于 provider impl-site allowlist；其合法实现面覆盖 adapter resource、service worker 与 runtime wrapper。见下「Amendment（#1153）」节。
- **归属**：framework（DI 接缝是 provider-agnostic 基础设施，不绑单一域）
- **AI-robust 评级**：见 §7（本 ADR 引入的 enforcement 逐条 Hard/Medium）

---

## 落地结论（PR-diport #1049，覆盖 §3/§4/§7/§8）

dynosaur 0.3 落地 spike 实测，三项开放风险结论 + 对原 ADR 的修订（**冲突段落以本节为准**）：

1. **§8 风险 1（unsafe carve-out）→ 不存在**：实测 dynosaur 0.3 宏生成的 `unsafe transmute` 经 **def-site
   hygiene** 不触发 consumer crate 的 `unsafe_code` lint——`diport` 即便 `#![forbid(unsafe_code)]` 也编译通过
   （anti-vacuity 已验证 forbid 对 `diport` 手写 unsafe 仍生效）。故 **§3 的「必须把 forbid 降为 deny」例外
   不需要**：`diport` 与其它 crate 一致 `[lints] workspace = true`（继承 forbid），无 forbid→deny 例外、
   无 `#[allow(unsafe_code)]`、无 error-handling §Carve-out 登记项。**威胁重评**：原 §3「unsafe 注入消费 crate」
   的威胁前提在 0.3 不成立；`diport` 的存在理由降为纯架构（DI port 集中 + 单一 dyn-dispatch 依赖点），
   unsafe 收敛不再是动机。dynosaur exact-pin `=0.3.0`，升级须复测本不变式（`diport` rustdoc DIPORT-UNSAFE-HYGIENE-01）。
2. **§8 风险 2（跨 crate sealing）→ 方案 ②**：DI port trait 不带 sealed supertrait；「谁可 impl」由 `deny.toml`
   wrapper 限定可依赖 `dynosaur`/`trait-variant`/`diport` 的 crate 集（cargo-deny Medium，INVARIANT
   DIPORT-MACRO-CONFINE-01，`layer-deps` 守 wrapper⟷源一致）。cargo-deny 限「依赖」非「impl」的残余缺口
   （域 crate 也依赖 diport 来消费端口）由 dylint 自写 lint `rss_diport_impl_allowlist`（AST 级，Medium，
   INVARIANT DIPORT-IMPL-ALLOWLIST-01）补齐：非 adapter / 组合根路径下 impl 任一 diport port trait 即报，#1060 闭环。
3. **§8 风险 3（v0.3 API）→ 修订**：真实构造 API = `DynX::new_box` / `new_arc` / `from_box` / `from_mut`
   （§4 示例 `new_box`/`new_arc` 正确；README 的 `boxed` 形态为旧版）。**新增**：`dyn(box)` 默认 boxed future
   **非 Send**；DI port 须在多线程 runtime 跨 spawn → 用 `#[trait_variant::make(X: Send)]` 生成 Send 变体 +
   `#[dynosaur(DynX = dyn(box) X, bridge(dyn))]` 据此生成 Send 的 `DynX`（需 `trait-variant` crate，同 exact-pin）。
   公开 Send 变体 `X` + `DynX`；非 Send 基 trait `XLocal` 不在 crate 根 re-export（避免方法解析歧义）。
4. **§4.3 Clock 修订**：`Clock` 是 **sync** trait（`fn now(&self) -> SystemTime`），天然 dyn-compatible →
   经 `Box<dyn Clock>` 注入，**不需** dynosaur / 无 `DynClock`（dynosaur 仅为 async fn in trait 的 dyn 派发）。
5. **ManagedResource（§7 末条 + 跨 ADR-001 冲突）→ 已收敛**：迁入 `diport` 改 dynosaur Send 变体；`bootstrap`
   `ShutdownStack` 以 `Box<DynManagedResource<'static>>` 持有并 `tokio::spawn` 隔离 panic——`Box` 仅需 `Send`
   （免 `Arc` 的 `Send+Sync`），并去掉原 `Arc::clone`。ADR-001 威胁矩阵同步重评（见 ADR-001 落地回写）。

---

## Amendment（2026-08-11，#1153）：ManagedResource lifecycle seam 分类

**触发**：DIPORT-IMPL-ALLOWLIST-01 最初以“`diport` 只包含 provider port”为前提，把 crate 中任一 trait 的
production impl 都限制到 adapter / 组合根。`ManagedResource` 实际是由 `ShutdownStack` 驱动的进程内生命周期
协议；relay、saga、blocking worker 等 service-owned resource 必须在其行为所有者处实现，继续复制 item-level
escape hatch 只会掩盖分类错误。

**决策**：`ManagedResource` 与 trait-variant 基 trait `ManagedResourceLocal` 保持位于 `diport`，作为跨 crate
lifecycle seam；它们不属于 provider impl-site allowlist。adapter resource、service worker 与 runtime wrapper
均可在各自 crate 实现。其余 `diport` trait 仍 fail-closed 受原 package allowlist 约束，不改公开 trait、dyn
wrapper、`ShutdownStack` 或 provider 实现位置规则。

### 威胁矩阵 / AI-robust 重评

- **provider impl 面**：不退化。Dylint 以 trait `DefId` 的 canonical DefPath 精确排除两个 lifecycle 身份；
  其它 `diport` trait 默认受限（Medium，DIPORT-IMPL-ALLOWLIST-01）。按名称、源文件或 consumer crate 放宽均不成立。
- **lifecycle impl 面**：允许行为所有者实现是目标能力，不是绕过。Rust sealing 会同时禁止独立 adapter 的合法
  实现，故不存在低成本 Hard 载体；UI synthetic red/green 与 workspace Dylint 提供 anti-vacuity（Medium）。
- **运行期与依赖面**：无新增攻击面或依赖边。生命周期关闭顺序、panic 隔离及 timeout 仍由 ADR-001 与
  `ShutdownStack` 约束；本 amendment 只修正静态治理分类。

> 上方「落地结论」第 2 项“任一 diport port trait”是 #1060 时的历史表述；自本 amendment 起仅指
> provider port，不包含上述两个 lifecycle trait。

---

## Amendment（2026-06-23，#1095）：async DI port 注入形态收口（`Arc<DynX>` 是 `!Send`）

**触发**：RW-G1（PR #186）内置 review（架构维度 Cx3）发现 §4.3 的 `Arc<Dyn*>` 注入示例与**落地结论 3** 矛盾。
落地用 `#[trait_variant::make(X: Send)]` 只生成 **Send（非 Sync）** 变体——冒号后的 bound 既作变体 trait 的
supertrait、又作 async 返回 future 的 bound，且**只取所列 bound、不隐式补 `Sync`**
（`ref: rust-lang/impl-trait-utils trait-variant/src/lib.rs@main`：`make(IntFactory: Send)` ⇒ `trait IntFactory: Send`
+ `impl Future + Send`）。dynosaur 据此生成的 `DynX` 内部 `dyn ErasedX` **无 `Sync`**。后果链：

- `Box<DynX>: Send` 成立（`Box<T>: Send ⟸ T: Send`）；
- 但 `Arc<DynX>: Send` 需 `DynX: Send + Sync`，`DynX` 非 Sync ⇒ **`Arc<DynX>` 是 `!Send`**；
- 故任何**多次调用、且把依赖 clone 进每次调用的 Send `'static` future** 的 async 消费者（典型订阅 handler
  `handle() -> BoxFuture<'static>`）**无法持有 `Arc<DynX>`**——§4.3 的 `Arc<DynEventPublisher>` + `tokio::spawn`
  示例在落地形态下编不过。

in-repo 编译期证据：负例 `crates/diport/tests/ui/arc_dyn_ports_not_send.rs`（`classify_ports!`
`async_send` 闭集 / macro-expanded exact set ⇒ 每个 `Arc<DynX>` 非 Send，trybuild compile-fail）。

### 窄例外（2026-07-16，#1828 / #1331）：共享 Sync 闭集必须 `Send + Sync`

HTTP serving / 多线程共享路径上的少数 async DI port 必须跨 await 持有 `Arc<DynX>`。闭集（`classify_ports!`
`async_sync` bucket，Hard 单源）：

- `Pdp` / `DynPdp`（#1828）
- `ServiceTokenReplayStore` / `DynServiceTokenReplayStore`
- `KeyProvider` / `DynKeyProvider`
- `SecretResolver` / `DynSecretResolver`（#1331：与上三者同桶，不再靠手列 UI）

各 port 经 base / `trait_variant` 显式 `Send + Sync`，使 `Arc<DynX>: Send + Sync`。这不是其余端口
Option A 的兼容扩张：生产 bridge 仍以 `Arc<P>` 泛型静态分发持有实际 provider；其余 dyn wrapper 维持
#1095 默认（`async_send` ⇒ `Arc<DynX>: !Send`）。

Hard 证据：`classify_ports!` 展开的 sealed `DiPortConcurrency` + `async_sync` 臂内
`assert_send_sync_bound::<Arc<DynX>>()`（native-compile，INVARIANT DIPORT-DYN-CONCURRENCY-01）。
Medium 回归锁：`ui_assert_async_sync_arc_send_sync!` / `ui_assert_async_send_arc_not_send!`
trybuild + PDP non-Sync provider compile-fail（anti-vacuity，**不得**把 trybuild 标成 Hard）。旧同步轮询
另由 Clippy `disallowed-methods` 和 runtime async bridge 结构守卫（Medium）禁止。终止预算不属于 PDP port
或 bridge：runtime 从必填非零 snapshot 配置解析 `ServerRequestBudget`，httpserve 唯一 bindable funnel 用它
包住完整 request future，httpd plaintext/mTLS 只接受 budget-sealed `ServerService`。耗尽 drop 整条 future
并返回统一 503（outcome 未知，`retryable=false`）；局部 verifier timeout 由结构门明确拒绝。

四处同源（rustdoc「注入形态」+ trybuild UI + 本节 + xtask `collect_diport` Dyn* export exact-set）须同步：
新增共享 Sync 例外只改 `classify_ports!` `async_sync` 标签，不得手改 UI 端口列表；Dyn* 根 re-export
须与 `async_sync∪async_send` exact-set 对齐。

### 决策（sanctioned 注入形态，三分）

| 消费场景 | 注入形态 |
|----------|----------|
| 单 owner、非跨 Send-future（如 `ShutdownStack` 顺序关闭，落地结论 5） | `Box<DynX>`（仅需 Send） |
| **多次调用 + 把依赖 clone 进每次 Send `'static` future**（订阅 handler 等） | **泛型静态分发**：消费者 `<S: X + Send + Sync + 'static>` 持 `Arc<S>`（静态分发 DI——provider 经 trait bound 仍可互换、产出 Send future、零运行期成本、不碰冻结端口） |
| 单线程 / 不跨 Send-future 持有 | `Arc<DynX>`（窄场景） |

范例（已落地）：`audit::application::SessionCreatedAuditHandler<S: AuditSink + Send + Sync + 'static>` 持
`Arc<S>`，`handle()` 内 `Arc::clone` 进 `Box::pin(async move {…})`（Send `'static` future）。§4.3 / §4.5 冲突
段落已就地加 ⚠ 修订 banner。

### Option A（已评估 → defer，跟踪 issue #1152）

把 6 个 async DI port（AuditSink / Publisher / Subscriber / Signer / RateLimiter / ManagedResource）的 Dyn wrapper 改 `Send + Sync`（`#[trait_variant::make(X: Send + Sync)]` 或手写
`DynX: Send + Sync`），使 `Arc<DynX>` 可 dyn 注入运行期多态消费者。**defer 理由**：① 改 ADR-005 冻结的端口
签名（触 `cargo public-api` 复核）；② 须重验 12 个 adapter impl 全 `Sync` + boxed-future Sync 语义；③
trait-variant / dynosaur 是否接受 / 传递 `Send + Sync` 在 pinned pre-1.0（`=0.3.0` / `=0.1.2`）上未验证；④
当前无 `Arc<DynX>` 运行期多态 / 异构 sink 集合消费方。触发条件（出现上述需求）记于 issue #1152。

### 威胁矩阵 / 安全模型重评（ai-robust：amendment 须同步重评）

- **新增攻击面**：无。本 amendment 不改运行期行为，仅收口注入形态选择。
- **错误形态可表达性**：默认 `Arc<DynX>` 跨 Send future = **编译期不可表达（Hard）**——`Arc<DynX>: !Send` 使
  `tokio::spawn` 处直接 `E0277`，不依赖人记规范。负例 `arc_dyn_ports_not_send.rs`（trybuild compile-fail，
  **Medium** anti-vacuity，INVARIANT DIPORT-ASYNC-ARC-SEND-01）锁该事实：若改 Send+Sync（Option A）此例转可
  编译，强制有意识更新本 ADR + 负例。
- **PDP / 共享 Sync 反向约束**：`async_sync` 闭集 `Arc<DynX>: Send + Sync` 与 PDP non-Sync provider
  不可实现均为 **Hard**；macro-expanded trybuild + 独立 non-Sync fail fixture 防止假绿。共享能力只开放给
  闭集端口，不改变其它端口威胁面。
- **provider 可互换性**：泛型静态分发经 `S: X` trait bound 保持（与 dyn 注入同等可换 provider、同样经构造器
  必填参注入），未削弱 §2「可替换 provider」与 §7 其余行——安全模型不退化。
- INVARIANT: DIPORT-ASYNC-ARC-SEND-01（`diport` crate rustdoc「注入形态」节 + 负例 + 本节，三处同源）。

---

## Amendment（2026-06-25，#1142）：ack-capable delivery seam（`Acker` / `AckableSubscriber`）

**触发**：#1142（P7）——AMQP subscriber P6 用 `no_ack=true`（auto-ack，at-most-once），`eventexec::run_consumer`
只做 idempotency/DLX bookkeeping、**从不触达 broker**，崩溃窗口在途消息丢失。要 at-least-once，须把 broker 的
ack/requeue/reject 接到消费侧。

**决策**：在 `diport` 新增**两个 async DI port** + 两个值类型，**完全照本 ADR 既定范式扩端口**（`#[trait_variant::make(X: Send)]`
+ `#[dynosaur(pub DynX = dyn(box) X, bridge(dyn))]`，re-export Send 变体 + `DynX`）——**不引入任何新机制 / 新范本**：

- `Acker`（`async fn settle(&self, action: AckAction) -> Result<(), AckError>`）+ `DynAcker`：单条投递的 broker
  结算句柄（provider-agnostic）。注入形态走「单 owner、move 进终态」= `Box<DynAcker<'static>>`（Amendment #1095
  三分表第 1 行），由 [`Delivery`] 携带、`run_consumer_ackable` 每条终态恰 `settle` 一次。
- `AckableSubscriber`（`subscribe_ackable(..) -> Result<DeliveryStream, _>`）+ `DynAckableSubscriber`：at-least-once
  订阅端口，与既有 `Subscriber`（at-most-once，`MessageStream`）**对偶并存**（双端口拆分，按投递保证拆，不删旧路径）。
- `AckAction { Ack, Requeue, Reject }`（typed enum，非 `requeue: bool`——typed function choice，§7 范本）+
  `Delivery { message: Message, acker: Box<DynAcker<'static>> }`（acker 与 message **并置**，不挂 `Message`）。

`AckAction` 是 provider-agnostic 的 broker 词汇，**不复用** `consistency::outbox::Disposition`——「引擎 disposition + DLX
写结果 → `AckAction`」的映射在 `eventexec::run_consumer_ackable` 完成（终态映射表见 `contracts/**/contract.toml`、`generated` 与 `crates/consistency`
§Acker / 投递结算 seam）。

### 威胁矩阵 / 安全模型重评（ai-robust：amendment 须同步重评）

- **新增攻击面**：无。新端口是既有 dyn-port 范式的实例，攻击面与 `Subscriber` / `DeadLetterStore` 同构。
- **`Message` 冻结值类型不变式保持（关键）**：acker 落**独立 seam**（`Delivery` 并置 `Box<DynAcker>`），**不**给
  `Message` 加 Ack/Nack 字段或方法——`Message` 的 ADR-003 冻结（无 metadata setter、payload Debug 脱敏，
  DIPORT-DTO-PII-DEBUG-REDACT-01）与 `contracts/**/contract.toml`、`generated` 与 `crates/consistency`「subscriber 层扩展信息放 `DeliveryOutcome`，不污染业务结果」
  规约**不退化**。本 amendment 正是该 `DeliveryOutcome` 规约的落地。
- **PII 边界**：`AckError` 经 `RedactedSource`（DIPORT-ERR-SOURCE-REDACT-01，与 `SubscriberError` 同范式），
  broker 原始错误不经 `Error` 接口暴露。
- **定义面 / impl 面守卫复用**：两个新端口的 dynosaur/trait-variant 宏依赖落在 `diport`（DIPORT-MACRO-CONFINE-01′
  白名单已含 `diport`，`deny.toml` **无需改**）；production impl（`adapters/amqp` 的 `AmqpAcker` / `AckableSubscriber`）
  受 dylint `rss_diport_impl_allowlist`（DIPORT-IMPL-ALLOWLIST-01，adapter 路径放行）守；test-cfg 替身（`eventexec`
  `#[cfg(test)]` `FakeAcker`）与既有 `FakeDeadLetterStore` 同位置、同豁免。
- **provider 可互换性**：`AckableSubscriber` / `Acker` 经 trait bound + 构造器必填参注入，与 §2 一致，未削弱安全模型。
- **范围边界**：consumer worker 生命周期（`run_consumer_ackable` spawn + `ManagedResource`/`ShutdownStack` + probe）
  与 MQTT manual-ack（#1265）不在本 amendment——前者派生 follow-up issue 跟踪、后者已有 open issue。

---

## Amendment（2026-07-14，#1168）：DLX lifecycle 静态 Send port 与 cipher seam 删除

**触发**：`DlxLifecycleRepository` / `DlxArchiveStore` 是 provider-neutral 基础设施 port，却曾定义在
`eventexec`；同时 `DlxArchiveCipher` 把既有 `KeyProvider` 再包装成第三个可替换 seam，并用
`Arc<Mutex<Box<DynKeyProvider>>>` 补偿 `DynKeyProvider: Send + !Sync`。前者违反 ADR-005 category line，后者扩大
能力面且把 #1095 已确认的 dyn 限制转化为运行期锁。

**决策**：两个 port 迁入 `diport`。它们由 `trait_variant` 生成 Send future 变体，但不生成 `Dyn*`：DLX worker
持有单一组合根静态选择的 provider，跨 tick 多次通过 `&self` 调用，所需形态正是 #1095 三分表的
`P: Port + Send + Sync + 'static` 静态分发。`DlxLifecycle<R, S, K>` 直接约束既有 `K: KeyProvider`；archive
AAD、typed archive key 与 seal/open 编排留在 eventexec 私有具体 service。不存在 cipher port、dyn wrapper、
兼容 re-export 或 provider fallback。

repository 的 candidate / verified receipt / expired receipt / missing proof 仍由 eventexec 拥有，并通过 port 的
associated types 表达；eventexec 在 `DlxLifecycle` bound 中把 associated types 精确绑定到四个 sealed 类型。
`diport` 的 trait 签名不命名也不依赖 eventexec，依赖方向保持单向。

### 威胁矩阵 / 安全模型重评

- **错误 proof/provider 组合**：associated-type equality + 私有 proof 构造器使错误 receipt/proof 类型无法注入
  `DlxLifecycle`（Hard）；`DlxArchiveStore::ObjectKey` 同样精确绑定 typed `DlxArchiveObjectKey`。
- **archive/hot key 混用**：eventexec 私有 crypto service 只接收 `DlxArchiveKeyName`，并在 encrypt/decrypt 边界
  校验 `KeyRef.name`；运行时另以独立 Vault workload token 限权。删除 cipher port不削弱该边界。
- **运行期替换能力**：无退化。组合根仍可用 trait bound 选择任一 production/test provider；当前不存在运行期
  异构 provider 集合，故无消费方的 dyn wrapper 不是能力。
- **治理载体**：port 定义归属由 crate 图 + `diport` 无 eventexec 依赖守（Hard）；生产 impl 站点复用
  `rss_diport_impl_allowlist`，旧 eventexec port/cipher token 由 `DLX-LIFECYCLE-FUNNEL-01` synthetic red +
  recursive anti-vacuity 拒绝（Medium）。无 Soft 例外。

---

## 1. 背景

GoCell→Rust 迁移的 G0「接缝冻结」阶段需要先定下一个贯穿所有后续单元的基础决策：**依赖注入（DI）
trait 的 async 方法如何做动态派发**。

根因（`gocell-rust-crate-mapping.md` §三）：组合根（`bins/`、assembly）重度持有
`Arc<dyn Authorizer / Signer / Store / Publisher / ...>` 这类可替换 provider 接缝。而 Rust 的
**async fn in trait（AFIT，1.75 起稳定）静态分发 OK、`dyn` 不行**——`async fn` 脱糖成 RPITIT，返回
每个 impl 各异的 opaque type，尺寸不定，无法进 vtable，trait 因此非 dyn-compatible（object-unsafe）。
直接写 `Arc<dyn Store>` 会得到 `error[E0038]: the trait cannot be made into an object`。

当前 workspace 为骨架：`crates/` 全部仅 `lib.rs`、无任何 trait 定义——本 ADR（**编号 003**）属 G0「接缝冻结」批次，是 greenfield 决策，不存在向后兼容包袱。

本 ADR 产出：① 派发策略决策；② 可被下游直接套用的「Arc 样板范式」；③ 与 RSS 既有 Hard/Medium 治理
规则的契合 / 偏离登记；④ 落地前须验证的开放风险与 follow-up。

---

## 2. 决策

按接缝性质分两档，**单一策略、不留双路径 / 兼容 shim**：

| 接缝 | 策略 | 形态 |
|------|------|------|
| **可替换 provider 的 DI port trait**（`Store` / `Signer` / `Publisher` / `Authorizer` / `Clock`，含 I/O、L1–L4） | **dynosaur**（native AFIT trait + 宏生成 dyn-compatible wrapper） | `#[dynosaur::dynosaur(DynXxx = dyn(box) Xxx)]`，组合根经 `Box<DynXxx>` / `Arc<DynXxx>` 注入 |
| **L0 域内纯计算 / 单实现**（`consistency` / `primitives` / `vocab` 内部，无运行时替换需求） | **native AFIT + 泛型静态分发** | `fn f<S: Xxx>(s: &S)` / `impl Xxx`；零开销、`pub(crate)` 封住类型签名扩散 |

**为何选 dynosaur 而非 async-trait**：dynosaur 是 rust-lang 生态（Santiago Pastorino）官方推进、瞄准取代
async-trait 的新派范式——**静态分发路径零开销、仅 dyn 路径才 box**；而 `#[async_trait]` 无条件把每个
方法体 `Box::pin`，即便静态调用也付一次堆分配。选 dynosaur 即选「静态零成本、动态才付费」的成本模型，
代价是接受其 `unsafe` 偏离（§3、§6、§8）。

**明确拒绝**（备选矩阵见 §5）：

- **async-trait**：每调用 box（含静态路径），与上面成本模型相悖。其**零 unsafe** 仅作为 dynosaur 在
  发 1.0 前若实测不达标时的**复评对照**，**不是**当前并行维护的退路。
- **native AFIT + `dyn`**：Rust **1.96 仍非 stable**（RTN / async-fn-in-dyn 实验性；RTN 稳定化
  PR #138424 因新 trait solver 顾虑被 blocked）。不可用。
- **trait-variant**：`#[trait_variant::make(T: Send)]` 只生成 Send-bounded 变体解 Send bound 问题，
  **不解 dyn**（返回仍是 opaque type）。不满足需求。
- **纯静态泛型铺满**：组合根「满天飞 `Arc<dyn>`」场景会造成单态膨胀 + bin crate 编译时间爆炸 +
  类型参数漏到组合根难写。仅用于 L0。

---

## 3. unsafe 收敛：专用 `diport` crate（边界决策）

> ⚠ **本节原设前提已被落地实测推翻——以顶部「落地结论」为准**：dynosaur 0.3 的 unsafe 经 def-site
> hygiene **不触发** consumer forbid，故 `diport` **无需** forbid→deny 例外、无 `#[allow]` carve-out。
> 下文「必须把 forbid 降为 deny」「目标 `#[allow]`」仅存原始推理记录，不代表落地形态。

dynosaur 宏展开会把 `unsafe { core::mem::transmute(...) }`（把 trait object 的局部 lifetime 擦除到
`'static`，layout 不变、仅编译期成立）注入到调用宏的消费 crate。原设：RSS 默认
`#![forbid(unsafe_code)]`（rust-standards §工程护栏，**Hard**），且 `forbid` 无法被内层 `#[allow]`
覆盖——故曾推断承载 dynosaur trait 的 crate 须把 `forbid` 降为 `deny`（**实测不需要**，见落地结论 1）。

**决策**：DI port trait 定义 + 其 dynosaur `Dyn*` wrapper **集中到一个专用服务层 crate `diport`**
（命名待评审）。**只有 `diport`** 在自己的 `Cargo.toml [lints]` 中把 `unsafe_code` 设为 `deny`（覆盖
workspace 默认的 `forbid`）并对 dynosaur 生成点做目标 `#[allow(unsafe_code)]`；其余所有 crate 继续
`[lints] workspace = true` 继承 `forbid`。

**收敛的真正守卫是 crate 依赖图 + cargo-deny（Medium），不是 per-crate forbid（后者可被覆盖）。**
准确说：① 要 invoke `#[dynosaur::dynosaur(...)]` 宏，crate 必须**声明对 `dynosaur` 的依赖**；
② `deny.toml` wrappers 把「可依赖 `dynosaur`」限定到 `diport` 一个 crate（cargo-deny，**Medium**，CI 门）——
没有依赖就 import 不到宏、也就展开不出 unsafe。per-crate `#![forbid(unsafe_code)]` 只是**可被成员
`[lints]` 覆盖的纵深防御默认**（workspace lints 是 opt-in 继承、非硬上限，见 Cargo workspace 文档），
**不**单独构成编译期 Hard——故本约束按 **Medium** 登记（§7），不夸大为 Hard。

> 收敛的代价是偏离「port trait 属域 crate `internal/ports`」（§6 偏离 2）。DI infra port 不是跨域 wire——
> 跨域通信仍只经 contract，本偏离不触碰「契约是跨域通信单源」。

---

## 4. Arc 样板范式

### 4.1 port trait 定义（在 `diport`）

> ⚠ **本节示例代码已被落地实测替换——落地形态以顶部「落地结论」+ `crates/diport/src/signer.rs` 为准**：
> ① `diport` **用** `[lints] workspace = true`（无 forbid→deny 例外、无 `#![deny(unsafe_code)]` 覆盖、无目标
> `#[allow]`，见落地结论 1）；② 单 `#[dynosaur(...)]` 生成的 boxed future **非 Send**，DI port 须改
> `#[trait_variant::make(X: Send)]` + `#[dynosaur(pub DynX = dyn(box) X, bridge(dyn))]`（落地结论 3），下方
> `pub trait UserStore: Send + Sync` 单宏模板会产出非 Send `DynX`、在 `tokio::spawn` 处编不过。下文仅存原始推理。

`diport` 的 `Cargo.toml`（**原设**，已废）**不**写 `[lints] workspace = true`，而是显式
`[lints.rust] unsafe_code = "deny"`（覆盖 workspace 默认 `forbid`，使 crate 根 / 生成点的目标 `#[allow]`
能生效——`forbid` 下 `#[allow]` 无效，`deny` 下有效）：

```rust
// crates/diport/src/lib.rs
#![deny(unsafe_code)] // crate 根：deny（非 forbid），仅本 crate；其余 crate 继承 workspace forbid

// crates/diport/src/store.rs
use std::sync::Arc;

/// dynosaur 生成 dyn-compatible 的 `DynUserStore` wrapper；static 路径零开销，dyn 路径才 box。
/// 实现方限制：本模板按方案 ②（adapter 独立 crate 实现）——port trait **不带** sealed supertrait，
/// 「谁可 impl」由 dylint lint `rss_diport_impl_allowlist`（AST 级，Medium，DIPORT-IMPL-ALLOWLIST-01）限定到
/// adapter / 组合根（见 §4.2 / §8 风险 2）；`deny.toml` wrappers 守「谁可定义 port」（DIPORT-MACRO-CONFINE-01）。
/// 仅当改选方案 ①（adapter impl 收回 `diport`）才加 `mod private { pub trait Sealed {} }` + `private::Sealed` supertrait。
#[dynosaur::dynosaur(DynUserStore = dyn(box) UserStore)]
pub trait UserStore: Send + Sync {
    async fn find_by_id(&self, id: UserId) -> Result<User, StoreError>;
    async fn save(&self, user: &User) -> Result<(), StoreError>;

    // 无 async Drop（Rust Drop 只能同步）：infra 资源（PgPool flush 等）显式异步关闭。
    // reason: no async Drop in Rust; infra teardown is async — see §4.4
    async fn shutdown(&self) -> Result<(), StoreError>;
}
```

### 4.2 adapter 实现（在 adapter crate）

raw adapter client 先 newtype 包成 `pub(crate)`，再实现 port trait——adapter crate
**保持 `#![forbid(unsafe_code)]`**（只 import `diport` 的 trait + `Dyn*`，自己不 invoke dynosaur 宏）：

```rust
// adapters/postgres/src/user_store.rs  （forbid(unsafe_code) 不变）
use diport::UserStore;

pub(crate) struct PgUserStore(sqlx::PgPool); // raw client 保持 pub(crate)

impl UserStore for PgUserStore {            // native AFIT impl，无 #[async_trait]
    async fn find_by_id(&self, id: UserId) -> Result<User, StoreError> { /* sqlx ... */ }
    async fn save(&self, user: &User) -> Result<(), StoreError> { /* ... */ }
    // reason: sqlx::PgPool::close() 返回 ()，无错误路径——其它有错误路径的 port（Signer/Publisher）须用 `?`
    async fn shutdown(&self) -> Result<(), StoreError> { self.0.close().await; Ok(()) }
}
```

> **sealing 的根本张力（§8 风险 2）**：sealed-trait（`private::Sealed` supertrait）只能在**定义 crate（`diport`）
> 内**封闭；而 adapter 是**独立 crate**——sealed-trait 无法「只放行某个外部 crate impl」。故集中到 `diport`
> 后，DI port trait **无法**对其 adapter 实现方 sealing。落地二选一（本 ADR 倾向 ②，保持 adapter crate 独立）：
> **①** port impl 收回 `diport` 内（sealing 成立，但 adapter 逻辑入 diport）；**②** 放弃跨 crate sealing——
> 定义面由 `deny.toml` wrappers 限定（只准 `diport` 定义 port，cargo-deny **Medium**），impl 面由 dylint lint
> `rss_diport_impl_allowlist` 限定到 adapter / 组合根 crate 集（AST 级 **Medium**，DIPORT-IMPL-ALLOWLIST-01，#1060 落地）。
> §4.1 trait 模板 + 上方 adapter 骨架**统一按 ② 写**（trait 无 sealed supertrait、adapter 不 `impl Sealed`），
> 可直接复制编译，**单一可执行路径**；若改选 ①，§4.1 加回 `private::Sealed` supertrait + `mod private` 且 adapter impl 收回 `diport`。

### 4.3 构造器必填注入（Clock 同范式）

DI 依赖是**非 `Option` 构造器位置参**，缺失即编译错误（ai-robust Hard 范本）。`Clock` 走同一
`Box<DynClock>` 范式，**不**经 builder option / Config 字段：

```rust
// crates/identity/src/application/session_service.rs  （forbid(unsafe_code) 不变）
pub(crate) struct SessionService {
    store: Box<DynUserStore>,        // 非 Option，缺失即编不过（Hard）
    clock: Box<DynClock>,            // Clock 同范式：构造器位置参，不走 Config
    publisher: Box<DynEventPublisher>,
}

impl SessionService {
    pub(crate) fn new(
        store: Box<DynUserStore>,
        clock: Box<DynClock>,
        publisher: Box<DynEventPublisher>,
    ) -> Self {
        Self { store, clock, publisher }
    }
}
```

> ⚠ **本段已被 Amendment（2026-06-23，#1095）修订——原设错误**：落地 `make(X: Send)` 变体的 `DynX` 是
> **Send 非 Sync**，故 `Arc<DynX>` 是 `!Send`，**不能** move / clone 进 `tokio::spawn` 的 Send `'static` task；
> 下方 `Arc<DynEventPublisher>` + spawn 示例在落地形态下编不过（多次调用 async 消费者改用泛型静态分发
> `<S: X + Send + Sync>` + `Arc<S>`，见 Amendment §决策）。`Box<DynX>` 仍是单 owner 缺省。下文仅存原始（已废）推理。
>
> `Box<Dyn*>` 还是 `Arc<Dyn*>`？单一所有者 → `Box`；需要跨 `tokio::spawn` / 多 service 共享同一 provider
> → `Arc`（`Box` 不能 clone 共享）。两者都满足 `Send + Sync + 'static`（trait 定义处已声明 `Send + Sync`）。
> 共享场景示例：
>
> ```rust
> let publisher: Arc<DynEventPublisher> = Arc::new(DynEventPublisher::new_box(AmqpPublisher::..));
> let p = Arc::clone(&publisher);
> tokio::spawn(async move { p.publish(evt).await }); // Arc 可 move 进 'static task；Box 不行
> ```

### 4.4 组合根装配 + 逆序关闭（无 async Drop）

```rust
// bins/server/src/main.rs  （forbid(unsafe_code) 不变）
// CAUTION: new_box / from_box 是 dynosaur pre-1.0（=0.3.x）API，升级前先查 changelog（§8 风险 3）
let store = DynUserStore::new_box(PgUserStore(pool));        // dynosaur v0.3 API：new_box
let clock = DynClock::new_box(SystemClock);                  // prod clock 只在组合根构造
let publisher = DynEventPublisher::new_box(AmqpPublisher::connect(...).await?);

let svc = SessionService::new(store, clock, publisher);
// ... bootstrap / serve ...

// 显式逆序关闭（构造顺序的反向）——由 bootstrap shutdown 框架统一编排（§7 Medium），
// 不靠组合根手记顺序。
```

### 4.5 静态 ↔ 动态判定准则

| 选 `Box<Dyn*>` / `Arc<Dyn*>`（动态） | 选 `impl Trait` / `<S: Trait>`（静态） |
|---|---|
| provider 在 prod/test/staging 会换（PgStore vs InMem vs Mock） | 总是同一实现，无运行时替换 |
| 在组合根跨 crate 注入的依赖 | 同 crate 内调用、无跨界 |
| 一致性等级 L1–L4（I/O / 事务 / 远程） | L0 纯计算、域内、无副作用 |
| 传给 `tokio::spawn` 的依赖需 `'static` | crate 内直接持有泛型参 |
| 用 `mockall` mock 注入测试 | 测试直接 monomorphize |

具体：`UserStore`/`SessionStore`/`CertSigner`/`EventPublisher`/`Pdp`/`Clock` → 动态；`vocab` 错误格式化、
`ids` 校验、`consistency` 状态机转移、`tower::Layer` 中间件 → 静态。

> 表中「用 `mockall` mock 注入测试」**只适用于已经走 `Box<Dyn*>`/`Arc<Dyn*>` 的动态依赖**——可 mock
> 不是选动态的理由。L0 静态依赖的单测用 `#[cfg(test)]` 模块内的直接 impl 替身，不引入 dynosaur wrapper、
> 不破坏「L0 保持 forbid 干净」。
>
> **Amendment（#1095）补充**：左列「动态」并非都用 `Arc<DynX>`。async DI port 的 `DynX` 是 Send 非 Sync ⇒
> `Arc<DynX>` 是 `!Send`，故**把依赖 clone 进每次调用的 Send `'static` future** 的多次调用消费者（订阅 handler
> `handle() -> BoxFuture<'static>`）**不能**用 `Arc<DynX>`，改用**泛型静态分发** `<S: X + Send + Sync + 'static>`
> + `Arc<S>`（Amendment §决策）。三分：`Box<DynX>`（单 owner move 进 spawn）/ `Arc<S>`（多次调用克隆）/
> `Arc<DynX>`（单线程窄场景）。

### 4.6 dyn 对象安全 dos / don'ts（port trait 写法约束）

**禁**（破坏 dyn-compatible）：泛型方法 `fn f<T>(..)`、返回 `Self`、返回 `impl Trait`、`where Self: Sized`、
`Clone` supertrait（`dyn` 不能 Clone）、未在 `dyn` 处指定的关联类型。
**须**：每方法 `&self`/`&mut self`、参数 / 返回为具体类型或 `Box<dyn _>`、supertrait 仅
`Send + Sync`（方案 ② 默认；实现方 crate 集由 `deny.toml` wrappers 限定，见 §4.2——选方案 ① 时再加 `private::Sealed`）、带 `async fn shutdown`。

---

## 5. 备选权衡矩阵

| 方案 | dyn 兼容 | 堆分配/调用 | Send+Sync | MSRV | unsafe | 编译开销 | 成熟度(2026) | 裁决 |
|------|---------|-----------|-----------|------|--------|---------|------------|------|
| **dynosaur 0.3** | ◎ 经 `Dyn*` wrapper | dyn 时 box / 静态 0 | ◎ wrapper 处理 | 1.75+ | **有**（生成 transmute） | proc-macro 中 | △ pre-1.0 | **选** |
| async-trait 0.1 | ◎ 天然 | **每调用 box**（含静态） | ◎ 默认 +Send | 全版 | 无 | proc-macro 中 | ◎ 生态标准 | 拒（成本模型）/复评对照 |
| native AFIT + dyn | ✗ stable 不可 | — | △ RTN 未稳 | — | — | 最小 | 1.96 ✗ | 拒 |
| trait-variant 0.1 | ✗ 不解 dyn | 0（静态） | ◎ 生成变体 | 1.75+ | 无 | proc-macro 小 | △ helper | 拒（不解 dyn） |
| 纯静态泛型 | 不适用 | 0 | ◎ where 显式 | 全版 | 无 | **单态膨胀大** | ◎ 语言特性 | 仅 L0 |

---

## 6. 与 RSS 既有规则的契合 / 偏离

**契合**（范式不破坏既有 Hard）：构造器必填参（ai-robust Hard）；raw client `pub(crate)` 封装
（`PgUserStore(PgPool)`）；Clock 构造器位置参（rust-standards）；Init fail-fast（`Arc/Box<Dyn*>` 由组合根
构造后注入，`init()` 不做 I/O / 不构造连接）；跨域只经 contract（DI port ≠ 跨域 wire，不触碰）。

**偏离 1**：`#![forbid(unsafe_code)]` 全局默认 → **`diport` 例外**（`deny` + 目标 `allow`）。理由：dynosaur
生成点的 transmute 无法在 `forbid` 下编译；收敛到单一 crate 使其余全仓保持 `forbid`（§3）。

**偏离 2**：domain-patterns「port trait 属域 crate `internal/ports`」→ **DI port trait 集中到 `diport`**。
理由：unsafe 收敛要求宏调用集中（§3）。澄清：DI infra port 是 provider-agnostic 基础设施 trait，**不是**
跨域 wire 类型；跨域通信单源仍是 contract，本偏离不削弱该不变式。

> ⚠ **ADR-005 修订（2026-06-23，#1083）——本偏离部分化**：「**所有** DI port 收敛 diport」对
> provider-agnostic infra port 成立，但对**域形 repo/service port over-reach**（其签名必引域内实体，放
> diport 即 diport→域 反向依赖、层序倒置、deny 红）。修订：infra port 收敛 `diport`；**域形 repo/service
> port 归所属域 crate `pub mod ports`**（ADR-005 §2 category line：port 签名是否引用域内实体）。dynosaur
> 派发范式**不变**，仅扩定义点集合（diport + 定义自身 repo port 的域 crate）。详见 ADR-005。

**偏离 3（部分）**：domain-patterns「port trait 用 sealed-trait 封闭」在**同 crate**内仍成立，但 DI port
trait 集中到 `diport` 后**无法对独立 adapter crate sealing**（§4.2）——本 ADR 放弃跨 crate sealing：定义面由
cargo-deny wrappers 守（只准 `diport` 定义 port），impl 面由 dylint lint `rss_diport_impl_allowlist`（AST 级
Medium，DIPORT-IMPL-ALLOWLIST-01）限定实现方到 adapter / 组合根。即「外部无法 impl」从类型系统 Hard 降为
dylint Medium（#1060 闭环）。

> 三条偏离须在 `diport` crate 实落时**同步回写** `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与
> workspace lint 配置，登记 `diport` 服务层 crate（见 §8 follow-up）。本 doc-only PR 不提前声明尚不存在的 crate。

---

## 7. AI-robust 分级（本 ADR 引入的 enforcement 逐条评级，Soft 禁止立项）

| 约束 | 评级 | 载体 |
|------|------|------|
| **dynosaur / trait-variant 只能被 DI port 定义点 crate 依赖**（原「unsafe 只能出现在 `diport`」） | **Medium（cargo-deny）** | `deny.toml` wrapper + `layer-deps` 把「可依赖 `dynosaur`/`trait-variant`」限定到 DI port 定义点白名单（INVARIANT DIPORT-MACRO-CONFINE-01**′**）。**落地修订（结论 1）**：dynosaur 0.3 的 unsafe 不触发 consumer forbid，故本约束动机是 **DI port 定义点集中**（架构），**非** unsafe 收敛。**ADR-005 威胁重评（#1083）**：原「单一 dyn-dispatch 依赖点」前提随域形 repo port 必然多点定义（各域 crate）而**失效**——白名单放宽为 `diport`（DiPort）+ 定义自身 repo port 的域 crate（Domain）；残余威胁（宏被非 port-定义 crate 滥用）由「白名单条目须属 DiPort/Domain 层」守，unsafe 维度更早已被结论 1 中和，故放宽**零安全代价**、安全模型不退化。 |
| **DI port trait 必须 dyn-compatible** | **Hard（编译器）** | 写出非 dyn-safe trait，`Box<Dyn*>`/`Arc<Dyn*>` 直接编不过。`trybuild` compile-fail 用例仅作 **Medium 回归锁**（锁错误形态），列 §8 follow-up。 |
| **必填 DI 依赖非 Option** | **Hard（类型系统）** | 构造器必填位置参 `Box<Dyn*>`，缺失即编译错误（ai-robust 范本）。 |
| **dynosaur 版本 pin** | **Medium（cargo-deny）** | `deny.toml` 注释 ID：dynosaur `=0.3.x`。列 §8 follow-up（`diport` 落地时加）。 |
| **shutdown 逆序关闭** | **Soft（当前）→ Medium（`bootstrap` 框架落地后）** | 逆序类型系统管不到（无 async Drop）。`bootstrap` shutdown 框架（§8 follow-up，**尚未落地**）按注册逆序统一执行 `shutdown()` 后升 Medium；在此之前为 Soft，故该框架是 `diport` 实落的**前置项**而非可选 follow-up——**禁止**长期停留在「组合根手记顺序」的 Soft 纪律。 |
| **provider port impl-site allowlist**（Amendment #1153：lifecycle seam 不属于 provider port） | **Medium（Dylint）** | `rss_diport_impl_allowlist` 以 canonical trait DefPath 精确排除 `ManagedResource` / `ManagedResourceLocal`；其余 `diport` trait fail-closed，package manifest parent allowlist 与 item-level escape hatch 不变。UI synthetic red/green + workspace Dylint 锁 anti-vacuity。 |
| **多次调用 async 消费者注入形态收口**（Amendment #1095：`Arc<DynX>` 跨 Send future 不可表达，改泛型静态分发） | **Hard（类型系统）+ Medium 回归锁** | `Arc<DynX>: !Send`（`DynX` Send 非 Sync）使误用 `tokio::spawn` 处 `E0277`（Hard，不依赖人记）；负例 `tests/ui/arc_dyn_ports_not_send.rs`（trybuild compile-fail，**Medium** anti-vacuity，INVARIANT DIPORT-ASYNC-ARC-SEND-01）锁事实，改 Send+Sync（Option A）即破。详见 Amendment（#1095）。 |
| **Dyn* Arc Send/Sync concurrency buckets**（Amendment #1331 / #1319：`async_sync` / `async_send` / `sync_obj` 闭集） | **Hard（类型系统）+ Medium 回归锁** | Hard：`classify_ports!` + sealed `DiPortConcurrency` + `async_sync` 臂 `assert_send_sync_bound::<Arc<DynX>>()`（native-compile，INVARIANT DIPORT-DYN-CONCURRENCY-01）。Medium：`ui_assert_*` trybuild anti-vacuity（同 INVARIANT，`source=trybuild`）。四处同源含 xtask `collect_diport` Dyn* export vs `async_sync∪async_send` exact-set。详见 Amendment（#1828 / #1331）。 |
| **ack seam 不挂 `Message` 冻结值类型**（Amendment #1142：acker 落 `Delivery` 独立 seam） | **Hard（类型系统）** | `Acker` 句柄经 `Delivery { message, acker }` 与 `Message` 并置，`Message` 无 ack/nack 字段或方法——给 `Message` 加 acker 即触其冻结（无 setter / Debug 脱敏 DIPORT-DTO-PII-DEBUG-REDACT-01）。`AckAction` 用 typed enum 而非 `requeue: bool`（typed function choice 范本）。新端口宏依赖/impl 面复用 DIPORT-MACRO-CONFINE-01′ + DIPORT-IMPL-ALLOWLIST-01（`deny.toml` 无需改）。详见 Amendment（#1142）。 |

---

## 8. 落地前须验证的开放风险 + follow-up

**开放风险（`diport` crate 实落前必须验证，dynosaur pre-1.0 的不确定面）**：

1. **目标 `#[allow]` 可达性 + carve-out 登记**：dynosaur 是否自带 `#[allow(unsafe_code)]` 于生成点？若否，
   需 item-level 包裹机制把 allow 局限到生成项——**不得**用 module/crate-level carve-out，否则与
   §Carve-out「carve-out 只能 item-level」冲突。须实测 `cargo expand` 确认。**无论自带或手写**，只要 unsafe
   出现在 `diport`，即构成一次 carve-out 事件——必须映射到 lint 配置，
   并在展开点提供 `// SAFETY:`（或 `diport` rustdoc INVARIANT 集中登记）阐明 transmute 的
   lifetime-擦除安全假设（rust-standards §工程护栏「unsafe 必须带 `// SAFETY:`」）。
2. **跨 crate sealing 不可行（见 §4.2）**：sealed-trait 只能在定义 crate `diport` 内封闭，adapter 是独立
   crate → DI port trait 无法对其 adapter 实现方 sealing。落地选 §4.2 ②（放弃跨 crate sealing）：定义面由
   cargo-deny wrappers 守、impl 面由 dylint lint `rss_diport_impl_allowlist`（Medium，DIPORT-IMPL-ALLOWLIST-01，#1060）守。
3. **dynosaur v0.3 API 稳定性**：`new_box` / `from_box` / bridge impl 仍在破坏式演进；pin `=0.3.x` 并在
   升级时审 changelog。供应链 advisory 由 `deny.toml [advisories]`（全量 advisory 扫描 + `yanked = "deny"`）
   自动覆盖，无需显式 ignore。

**follow-up（本 doc-only PR 不做；归属下游 `diport` 落地单元——epic #991 的 G1/W/Join 子项跟踪，不在此重复建 issue）**：

- **结构单源回写（`diport` 落地同 PR，三处一并改防漂移）**：`Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`
  + §分层（登记 `diport` 服务层 crate）、`Cargo.toml [workspace] members`（加 `crates/diport`）、`deny.toml` wrappers。
- `deny.toml` wrappers（Medium）：「可依赖 `dynosaur`」限定到 `diport`（定义面）；impl 面（「谁可 impl port
  trait」限定到 adapter / 组合根）由 dylint lint `rss_diport_impl_allowlist`（DIPORT-IMPL-ALLOWLIST-01，#1060）守。
- 首个 port trait 落地：加 `trybuild` dyn-compatible compile-pass / compile-fail 用例（Medium 回归锁）。
- `bootstrap` shutdown 框架：按注册逆序执行 `shutdown()`（把 §7 末条从 Soft 升 Medium）——**前置项**，先于
  port trait 大规模落地。
- 回写 Cargo workspace 分层与 `deny.toml` wrappers（DI port 集中例外 + port trait sealing 由 sealed-trait 改 cargo-deny wrappers）。
- **复评触发**：dynosaur 发 1.0 时复评（破坏式 API / unsafe 收口 / forbid 兼容）；若 1.0 前实测三项开放
  风险任一不可接受，按 §5 以 async-trait 为对照重评。

---

## 对标证据（ref）

- `ref: spastorino/dynosaur releases/v0.3.0` — 选定方案：`dyn(box)` 生成、`new_box`/`from_box` API、pre-1.0。
- `ref: rust-lang/impl-trait-utils trait-variant/src/lib.rs@main` — Amendment（#1095）依据：`make(X: Send)` 把冒号后 bound 作变体 trait supertrait + async 返回 future bound，只取所列 bound（不隐式补 Sync）⇒ `DynX` Send 非 Sync ⇒ `Arc<DynX>` `!Send`。
- `ref: tower tower-service/src/lib.rs@master` — `poll_ready + type Future` 规避 async-fn-in-trait 的 pre-AFIT 范式。
- `ref: kube-rs kube-runtime/src/watcher.rs@main` — 内部 trait 用 native AFIT + 泛型静态分发（L0 档对标）。
- `ref: linkerd2-proxy linkerd/stack/src/arc_new_service.rs@main` — `Arc<dyn NewService>` 同步工厂 + 异步 call 的 DI 接缝。
- `ref: sqlx sqlx-core/src/executor.rs@main` — 手工 `BoxFuture` + 泛型 `impl Executor` 的库级取舍。
- `ref: dtolnay/async-trait README@master` — 被拒方案：每调用 `Box::pin` 的成本模型。
