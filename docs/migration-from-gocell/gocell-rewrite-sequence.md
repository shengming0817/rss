# GoCell 重写实施顺序分析

> **归档·冻结** · 2026-06-21 GoCell→Rust 迁移评估快照（target 命名已对齐 RSS）· **非现行规则**。
> 现行架构单源见 `docs/rules/architecture.md`；本批只读冻结，仅供迁移评估溯源。
>
> 生成日期：2026-06-21 · 依据 git 历史（1589 commits，2026-04-04 起）+ 分层依赖推导
> 配套文档：[gocell-package-overview.md](./gocell-package-overview.md) · [gocell-rust-tradeoff.md](./gocell-rust-tradeoff.md) · [gocell-rust-crate-mapping.md](./gocell-rust-crate-mapping.md) · [gocell-rust-directory-structure.md](./gocell-rust-directory-structure.md) · [gocell-rust-ci-plan.md](./gocell-rust-ci-plan.md) · [gocell-rust-eval-checklist.md](./gocell-rust-eval-checklist.md)

## 数据校正（避免误读 git）

`framework/kernel|pkg|runtime` 的首次出现都显示 2026-06-15，**这不是诞生日**——是把 `kernel/` 等提升为独立 `framework/` Go module 的大重构（`git log --diff-filter=A` 把"重命名/移动"当成"新增"）。同理 `corecells` 的 2026-06-11 是从 `cells/` 改名（#1560），`cellmodules` 的 2026-06-02 是组合根分层抽出。

**真正没被重命名污染、最干净的时序信号 = ADR 文件名时间戳 + 早期 commit 的 Phase/Wave 标记。** 下文据此推导。

---

## 一、git 历史揭示的真实建造顺序

剥掉后期重命名噪声，实际是**严格自底向上、且声明模型先行**：

| 时期 | 实际在做什么（ADR / commit 为证） |
|---|---|
| 4 月初 | **元数据模型 + validator + CLI 骨架**：`metadata v3 skeleton`、`Phase 0 Cell/Slice 接口`、`Phase 1 Wave1-4 = parser/validate/catalog/scaffold/registry/depcheck/outbox 接口` |
| 4 月底–5 月初 | **kernel 纯原语 + 出 wire 边界 + codegen 漏斗**：clock 注入、wrapper/metrics 抽象、panic 白名单、errcode-PII、wire-format-out-of-kernel、cellmeta 单源、markergen/cellgen 统一、pg-outbox-fencing |
| 5 月中 | **协议层 + archtest 成熟**：credential-session / audit-ledger / CAS 协议、sealed-marker、distlock-lock-as-resource、relay-isolation、archtest process-isolation/carveout/funnel |
| 5 月底 | **DI 接缝 + gRPC + L3/L4 harness**：capability-provider-interface、grpc-transport、cqrs-projection-lifecycle、reconcile-design(#661)、cellmodule-composition-public-api(#1085) |
| 6 月 | **高阶能力**：saga-L3、http-idempotency、tenant/RLS/ABAC 接线(#1348)、device-cert-pivot(#1895)、framework-owned-contract(#1939)、topology-gated-transport(#1940)、cross-cell-mTLS(#2263)、runtime-contract-registry(#303)、authz-default-abac(#2020) |

corecells（accesscore/auditcore/configcore）是**贴着 journey 增量长出来的**——15 个 `J-*.yaml`（ssologin→sessionrefresh→accessdecision→accountlockout→auditlogintrail→config…→deviceidentity→systemhealth）就是验收切片清单。

### 历史里代价最大的"晚做"（重写要提前定型的教训）

1. `framework/` module 拆分拖到 6-15（移动整棵树）；
2. `cells → corecells` 改名到 6-11；
3. `cellmodules` 组合根到 6-02 才抽出；
4. topology-gated resolver（eventtransport / replaydeps / sagaprojectiondeps）到 6 月中才统一。

这四样都是**边界**，越晚改越贵，重写里应从第一天就定型。

---

## 二、重写推荐实施顺序（9 阶段，语言无关）

每阶段给「为什么是这个位置」+「验证里程碑」。

### P0 · 声明模型 + 治理 + codegen 骨架 + 边界定型
- `metadata`(解析 cell/slice/contract/assembly/journey) + `cellvocab`(枚举单源) + `governance`(校验规则) + `cell`/`contractspec`(运行时模型)
- `tools/codegen`(contractgen/cellgen) + golden harness + `cmd/gocell`(validate/scaffold/generate/verify)
- **此刻确立 module/crate 边界**（framework 独立模块、corecells vs examples 命名）+ 立起 archtest/AI-robust 漏斗骨架
- pkg 落位：`pathsafe`/`fspath`(写文件防护) + `cmdrun`(跑 goimports/gofumpt) + `yamlsafe`/`contractpath`/`scaffoldid`(单源类型) + `testutil`(TDD)
- 为什么最先：GoCell 一切都从 yaml 派生，声明模型 + 生成管道是脊柱；历史也确实从这里开局。

### P1 · kernel 纯原语（无 I/O）
`clock` / `lifecycle` / `healthz` / `fsm` / `circuitbreaker` / `crypto`(接口)。叶子依赖，谁都要用；ADR 证据是这批最早。
- pkg 落位：`errcode`/`authz`/`tenant`/`query`/`projection`(核心数据词汇) + `ctxkeys`/`ctxutil`/`ctxcancel`/`validation`(context 与错误转译) + `idutil`/`redaction`/`panicregister`(sealed 标识/脱敏/panic 纪律)

### P2 · 装配骨架 + 最小 listener
`composition`(Builder/App/SharedDeps/CellModule) + `bootstrap`(分阶段生命周期) + `config`/`shutdown`/`worker` + `http/router|middleware|health` + `auth`(JWT/Principal/PDP 骨架) + `observability`。目标：能起进程、能 serve `/healthz`，组合根接缝**此刻就在**。
- pkg 落位：`httputil`(响应/分页) + `securecookie`(BFF session) + `netutil`/`logutil`/`observability`/`secutil` + `csvparam`(query 闭值集)

### P3 · L1/L2 持久化与事件主干
`adapters/postgres`(Pool/TxManager/Migrator) + `outbox`+`Relay`+`idempotency`+`CAS` + 事件 transport。**先 in-memory 分支，再 PG/Redis**，topology-gated resolver 从这第一次 adapter 绑定就建好，不留后补。
- pkg 落位：`pgquery`(keyset SQL) + `pgrepoapproved`(批准直执 SQL token) + `migration`(命名空间) + `aeadutil`(config/secrets 加密)；`spiffeid`(cross-cell mTLS sealed 身份)留到 P8

### P4 · 第一颗追踪弹：J-ssologin 端到端（L2）
只打通**一条** journey：contract → 生成 handler → cell/slice → service → repo → outbox 事件 → audit 消费。accesscore(sessionlogin+identity) + auditcore(ledger+一个 append)。这一步把契约扇出闭环和分层全验一遍，是后面横向铺开的模板。

### P5 · 横向铺开核心 cell + authz 接线
configcore(CRUD/publish/featureflag/CAS) + accesscore 全量(refresh/logout/rbac/policy/decide) + auditcore 全量(双链/query) + tenant/RLS/ABAC 接线。复用 P4 模式。

### P6 · L3 编排 harness
`projection`(CQRS) + `saga`+`executor`+`tailer`+`journal`。高阶一致性，依赖 outbox + composition。历史顺序也是 projection → reconcile → saga。

### P7 · L4 设备闭环
`reconcile` + `certsigning`+`certlifecycle` + `command` 队列 + `softca`/`deviceidentity`(EST)/`mqtt` + framework-owned 契约。最专精、依赖最多，放最后。

### P8 · 多进程 / 拓扑生产化
sagaprojectiondeps、distlock(Redis)、cross-cell mTLS transport、registrycore、syscore、adapters(otel/prometheus/vault/s3/websocket/grpc 全量)、`cmd/corebundle`、examples。在"单进程已跑通"之上的生产硬化。

### 贯穿全程（不要留到最后）
archtest/治理规则随每阶段同步长；契约扇出闭环从 P0 起强制；每个决策落 ADR。历史的教训正是治理 harness 早立（5 月中就成熟），而非事后补。

---

## 二之补 · pkg 层怎么排（叶子，just-in-time）

`framework/pkg/` 是依赖图的叶子（只依赖 stdlib），被所有层消费，所以**不是独立阶段**，而是「谁先用到就地建」，集中落在 P0–P3（各阶段「pkg 落位」行已标注）。它同时是「让错误不可表达」的载体层——几乎每个 pkg 都是某一概念的唯一 sanctioned 类型/实现（`contractpath`/`idutil`/`spiffeid`/`migration`/`yamlsafe`/`pgrepoapproved`/`panicregister`/`fspath`）。

**4 个「宪法级」pkg —— 必须 P0/P1 锁死，晚改全库返工：**

| 包 | 决定什么 | 晚改的代价 |
|---|---|---|
| `errcode` | 所有错误的形态（三通道 + PII 边界） | 每个 handler/service/repo 改签名 |
| `tenant` | 多租户怎么穿透（typed 参数 + RowScope） | 每个 repo/service API 改签名 |
| `ctxkeys` | context 载荷（cell/trace/correlation） | 可观测性与属性传播全线返工 |
| `panicregister` | panic 纪律（唯一批准入口） | 满地裸 panic 要回收 |

> Rust 重写时此层大幅变薄：sealed newtype 包（`idutil`/`scaffoldid`/`spiffeid`/`migration`/`yamlsafe`/`pgrepoapproved`/`tenant`/`authz.Decision`）变成私有构造器的 newtype/enum，「单源 + 不可伪造」是语言原生属性。两个例外更难：`ctxkeys`（无 ambient context）、`panicregister`（Rust panic 非 recover-as-控制流，语义模型不同）。

---

## 三、若用 Rust 重写，顺序的三处位移

接 [gocell-rust-tradeoff.md](./gocell-rust-tradeoff.md) 的分析，整体顺序不变，但：

- **P0 变轻**：codegen funnel + golden → proc-macro（折进编译期）；archtest 贯穿线里很大一块塌进类型系统，治理工作量前移且缩小。
- **新增 P1.5「context 传播 + DI 策略」设计 spike**：Rust 没有 `context.Context`，而 P2 组合根重度依赖 ctxkeys 全程穿透 + `dyn Trait` DI——**必须在动 P2 之前先定**任务本地存储 / 显式 Context struct 的方案，否则 P2 之后到处返工。（**已决议**：落为 `runctx` crate——可观测 ID 走 `tracing` span、控制流值走显式 `RequestCtx`，不再是开放二选一。）
- **P3/P6/P7 后台环**（relay/sweeper/reconcile fan-out）要预留 tokio 结构化并发 + CancellationToken 的设计预算，比 Go 的 `go func()` 重。

---

## 附：阶段依赖速览

```
P0 声明模型/codegen/边界
        ↓
P1 kernel 纯原语 ──────────────┐
        ↓                      │
P2 装配骨架 + listener         │ (都依赖 P1)
        ↓                      │
P3 持久化 + 事件主干 ←─────────┘
        ↓
P4 追踪弹 J-ssologin (L2 端到端)
        ↓
P5 横向铺开核心 cell + authz
        ↓
P6 L3 projection/saga
        ↓
P7 L4 reconcile/cert/command
        ↓
P8 多进程拓扑 + registry + operator + examples
```
