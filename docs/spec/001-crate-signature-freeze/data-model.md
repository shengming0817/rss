# Phase 1 Data Model — 冻结单元 / Trait 分类 / Conventions

> 本 feature 无运行时数据实体。这里的"实体"= 规划域对象：**freeze unit（PR 粒度）**、**trait 分类**、**conventions 项**、**spike 门**。tasks.md 直接消费本清单。
> 派发范式以 **ADR-003（dynosaur）** 为单源；签名约定单源 = ADR-004。

## 实体 1：Freeze Unit（签名冻结单元 = PR 粒度）

字段：`id` · `层` · `crate 集` · `上游门(crate)` · `spike 门` · `软门` · `是否同层可并行`

| unit | 层 | crate 集 | 上游门 | spike 门 | 软门 | 同层并行 |
|---|---|---|---|---|---|---|
| **PR-0** | conventions | 文档/ADR-004（+ public-api 工具入口） | — | ADR-002 + ADR-003 + ADR-001（已落地） | — | — |
| **PR-1** | 基础 | vocab, ids, secure, support, runctx | PR-0 | ADR-002（runctx ctx 范式） | — | ✅ 5 crate 互不依赖 |
| **PR-2** | 引擎 | consistency, primitives | PR-0, PR-1 | ADR-001（lifecycle，待 diport 拍板归属） | — | ✅ 2 crate 互不依赖 |
| **PR-diport** | 服务（DI infra） | **diport（新建）** | PR-1, PR-2 | ADR-003（dynosaur 落地 + §8 三风险验证） | — | — |
| **PR-3** | 服务 | httpserve, authn, bootstrap, eventexec, observ, distributed, deviceloop | PR-diport | ADR-001（bootstrap::shutdown） | — | ✅ 7 crate 互不依赖（非 DI 接缝） |
| **PR-4** | 域 | identity, settings, audit, contractreg, syshealth | PR-3 | — | #998（generated wire 类型） | ✅ 5 crate 互不依赖（deny 强制）；与 PR-5 并行 |
| **PR-5** | adapters | postgres, redis, amqp, mqtt, s3, oidc, grpc, otel, prometheus, vault, softca, ratelimit | PR-diport（被实现的 DI port trait 已冻） | — | — | ✅ 12 crate 互不依赖；与 PR-4 并行 |

> generated/ 不在任何 unit：契约派生（#998 产物），不手写签名。
> **重排说明**：ADR-003 把 DI 注入 port trait（Store/Signer/Publisher/Subscriber/PDP/Clock/ManagedResource…）收敛进新 `diport` crate（dynosaur 宏 + unsafe 收敛，§3）。故新增 **PR-diport** 单元（PR-2 后、PR-3/4/5 前）；PR-3 只冻服务层**非 DI 接缝**、PR-4 只冻域内 DTO/非 DI 域逻辑。具体归属边界见下「diport 落地待决项」（由 PR-diport 拍板）。
> 同层 unit 在 tasks 中可进一步拆"子 PR"以增并行度（见 quickstart §并行拆分建议）。

## 实体 2：Trait 分类（决定 async/dyn 范式 + mock 方式）

| 分类 | 典型 crate | 派发范式（ADR-003） | mock | 备注 |
|---|---|---|---|---|
| **纯计算 trait**（无 async / 无 dyn） | vocab, ids, secure, support | native（sync）/ 泛型静态分发 | `#[cfg_attr(test, automock)]` | 错误枚举、ID newtype、redaction |
| **引擎策略 trait**（L0 静态分发） | consistency, primitives | native AFIT + 泛型 `<S: Trait>` | 同 crate `#[cfg(test)]` 替身 | 幂等/outbox/saga 态机；零开销、不引 dynosaur wrapper |
| **DI port trait**（provider-可换、dyn 注入） | **diport**（收敛 Store/Signer/Publisher/Subscriber/PDP/Clock…） | **dynosaur**（native AFIT + `dyn(box)` wrapper） | automock（形态待验证#5） | 注入 `Box/Arc<DynX>`；adapter native AFIT impl |
| **生命周期 trait** | diport / bootstrap | `ManagedResource`（**inter-ADR 待决**：ADR-001=async_trait vs ADR-003=dynosaur，见待决项） | automock | LIFO 由 bootstrap 显式 await，无 async Drop |
| **服务非 DI 接缝**（type/enum/sync） | httpserve, eventexec, observ… | type/enum + sync `Fn`（非 trait object） | — | RouteGroup/Route/ListenerKind/Disposition/HandlerFn |
| **域内类型**（pub(crate)） | identity, settings… | DTO + 非 DI 域逻辑（DI port 已迁 diport） | — | domain 不 derive Serialize |
| **adapter sealed-marker** | adapters/* | native AFIT impl diport 已冻 DI port trait（ManagedResource 普适 + Signer/Publisher 按职责；无新 trait、不 invoke dynosaur 宏，保持 forbid） | 不 mock | `struct PgStore;`（unit；raw client 字段延迟 W） |

## 实体 3：Conventions 项（单源 = ADR-004，被全部签名引用）

详见 ADR-004 C1–C12（`docs/architecture/202606220106-004-signature-conventions.md`）。要点：

1. **async/dyn 二分**：DI port → dynosaur（`#[dynosaur::dynosaur(DynX = dyn(box) X)]`，定义于 diport）；L0 → native AFIT + 泛型静态分发。
2. **mock**：同 crate `#[cfg(test)]`；dynosaur/native-AFIT 下 mockall 形态待验证（待决项#6）。
3. **ctx 传播**：`RequestCtx<T,P>`（sealed struct + task_local!，ADR-002 D2）；需 ctx 处显式传 `&RequestCtx`。
4. **关闭逆序**：`ManagedResource` LIFO + 显式 `async fn shutdown`，无 async Drop（ADR-001）。
5. **必填依赖/Clock**：`Box<DynX>` 构造器必填位置参；Clock 同范式，禁默认系统时钟（ADR-003 §4.3）。
6. **serde 边界**：domain 不 derive Serialize/Deserialize；仅 contract/DTO。
7. **sealed/newtype**：DI port trait 不跨 crate sealed（deny.toml wrappers，ADR-003 §4.2 方案②）；adapter raw client `pub(crate)` newtype。
8. **覆盖率豁免**：签名 PR body=todo!() 声明覆盖率延迟到行为 PR。
9. **每 PR 对标 ref** / 10. **错误（vocab+thiserror const literal）** / 11. **unsafe 收敛（仅 diport）** / 12. **dynosaur pin =0.3.x**。

## 实体 4：Spike 门（实施前置，非规划前置）—— 均已落地为 ADR

| spike / 单元 | 主题 | ADR | 影响范围 | gate 的 unit |
|---|---|---|---|---|
| #994 | context 传播（RequestCtx + task_local!） | **ADR-002**（Accepted） | 横切（每个含 ctx 的 trait 方法形态） | PR-0 + 全部含 ctx 签名 |
| #995 | DI async + dyn 派发（**dynosaur**） | **ADR-003**（Accepted 方向，可行性待验证） | 横切（每个 DI port 声明语法 + diport 收敛） | PR-0 + PR-diport + 全部 DI port |
| #996 | 关闭逆序（ManagedResource LIFO） | **ADR-001**（Accepted） | 局部 | PR-2/PR-diport(lifecycle) + PR-3(bootstrap::shutdown) |
| **diport 落地** | dynosaur 可行性验证 + 建 crate + 规则回写 | ADR-003 §8（下游单元） | DI port 全集归属 | **PR-diport**（gate PR-3/4/5） |
| #998 | contract codegen → generated | — | 软（仅 wire 引用） | PR-4(域层) |
| #993 | workspace 骨架 | — | 已满足（closed） | 全部（已解锁） |

## diport 落地待决项（由 PR-diport 拍板，不在 PR-0 解决）

计划层重排引入 diport 后浮现的真实开放点（ADR-003 §8 亦留为开放风险）—— 此处显式登记 + 给推荐方向：

1. **实体引用与分层序（架构约束，非选项）**：diport 是**服务层 crate**，按分层规则 **MUST NOT 依赖域 crate**（deny.toml 编译期强制）。故 diport port trait 的参数/返回实体类型 **MUST** 定义在基础层（`ids`/`vocab`）或 `generated`（wire 类型），**不得**引用域内实体（`User`/`Session` 等域专属类型）——否则 diport→域 反向依赖、层序倒置、deny.toml 红。ADR-003 §4.1 示例中的 `User` 须按此约束落在基础层/generated，或由 PR-diport 决定其归属（但不得让 diport 依赖域 crate）。这是设计约束，PR-diport 实施者不得将域实体引入 diport。
2. **Clock / ManagedResource 归属**：ADR-003 §2/§4.3 把 Clock 列为 DI port→diport；原 spec 把 Clock 放 primitives（引擎）。**推荐**：`Clock`+`DynClock`、`ManagedResource`+`DynManagedResource` 迁入 diport；primitives 只留纯计算/静态引擎 trait。PR-diport 确认。
3. **域 repo `pub(crate)`→`pub`**：DI port 迁 diport 即跨 crate → 失去 `pub(crate)` 封装；改由 deny.toml wrappers 限定实现方 crate 集（ADR-003 §4.2 方案②，Hard→Medium）。登记该偏离。
4. **inter-ADR 冲突（ManagedResource）**：**ADR-001** 把 `ManagedResource` 定为 `#[async_trait]` + `Arc<dyn>`；**ADR-003** 通则是 DI 注入→dynosaur。二者对 `ManagedResource` 冲突。**推荐**：随 bootstrap shutdown 框架落地时统一为 dynosaur 并**同步重评 ADR-001 威胁矩阵**（ai-robust「ADR amendment 同步」）；在此之前 `ManagedResource` 暂遵 ADR-001（async_trait）。
5. **diport 落地 = ADR-003 §8 可行性验证单元**：建 crate + 验三开放风险（`#[allow(unsafe_code)]` 可达性 + carve-out 登记 / 跨 crate sealing 取舍 / dynosaur v0.3 API）+ 完成 §8 全部 follow-up（architecture.md/deny.toml/rust-standards/domain-patterns 回写、trybuild、bootstrap shutdown 框架前置）。**若 dynosaur 实测不可接受 → 按 ADR-003 §5 回退 async-trait，本 spec 需再 reconcile**。
6. **mockall × dynosaur/native-AFIT**：PORT-SHAPE-01/02/03 假设 mockall mock 可构造；native-AFIT/dynosaur 下兼容性 ADR-003 未覆盖 → PR-diport 验证（mock 是 native trait 还是 `DynX` wrapper）。

## 验证不变式（测试件）

- **PORT-SHAPE-01**：`let _: Box<DynT> = DynT::new_box(MockT::new());`（或 `Arc<DynT>`）编译通过（dynosaur dyn-compatible）。
- **PORT-SHAPE-02**：`Svc::new(DynRepo::new_box(MockRepo::new()))` 编译通过（DI 必填位置参注入）。
- **PORT-SHAPE-03**：`#[tokio::test]` 中 mock async 方法 `.await` 且 Future `Send`。
- **BUILD-SMOKE**：每 unit `cargo build -p <crate...>` 通过。
- **PUBLIC-API**：基础/引擎层 `cargo public-api` baseline 可 commit（PR-0 落工具入口，PR-1/PR-2 产快照）。

> PORT-SHAPE 的 dynosaur 具体形态（`new_box`/`from_box` API、mock 装入路径）随待决项#6 在 PR-diport 验证后定稿。
