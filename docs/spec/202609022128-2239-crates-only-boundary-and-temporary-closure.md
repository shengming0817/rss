# RSS M1 crates-only 边界与临时 library closure

- **Status**：M1 temporary implementation baseline
- **Date**：2026-09-02
- **Tracking**：#2239、#2240；Epic #2238
- **Observed revision**：`origin/develop@8f6061a5c7890c22e65cf4eb1e5ffa8e724348c5`
- **Historical recovery**：`baseline/pre-community-core-20260902`

## 1. 目的与有效期

本文冻结第一里程碑的 crates-only 目标边界，并把当前 Cargo graph 投影为后续删除可以消费的临时 library closure。
它是过渡规格，不是最终范围 ADR、Release Surface、package inventory 或删除完成证明。

本文只回答三件事：

1. 最终仓库允许和禁止什么；
2. 五个候选职责如何形成无环的临时依赖上限；
3. 后续删除 PBI 用什么机器事实判定完成。

代码清理期间不得以本文为理由迁移、归档或复制消费者与旧实现。历史回溯只使用上述 Git tag。文档重建阶段删除本
过渡规格；完成 crates-only 机器验收后，再从最终 Cargo metadata、公开 API 和真实消费者证据编写最终 ADR。

## 2. #2239：crates-only 目标边界

### 2.1 可保留

| 类别 | 保留判据 | 最终证据 |
|---|---|---|
| Library crate | 具有唯一公共消息一致性职责，并被最终候选或真实外部消费者直接需要 | Cargo package/target facts、公开 API、外部 consumer |
| T1 | 直接保护候选 crate 的类型、状态机、错误、API 或 package 不变量 | rustc、crate tests、standard lint/package/doc tools |
| 最低充分 T2 | 证明 T1 无法观察的公共 transaction/delivery/runtime seam，且不拥有 provider 基础设施 | provider-neutral conformance 与外部 consumer receipt |
| 发布证明 | 证明候选可独立打包、解析、编译、测试和生成文档 | registry candidate、locked/offline external build |
| 文档与法律文件 | 只描述最终 crate、公共语义、使用、测试和发布 | 最终工作树与 package docs |

### 2.2 必须清零

最终仓库不得存在以下产品面或其改名、facade、fixture、snapshot、兼容读取和治理副本：

- domain、认证/设备/设置/审计/注册/系统健康等消费方业务能力；
- provider adapter、provider 管理脚本、业务 SQL migration 和 migration operator；
- composition、assembly、artifact/profile selector、process lifecycle、binary、image、Dockerfile、deploy；
- executable product example、product journey、T3、production profile 与 production acceptance evidence；
- 业务 contracts、generated domain binding、消费者源码、gitlink/submodule 或 vendored consumer；
- 只保护上述已删除产品面的 xtask、custom CI scheduler、lint、gate、fixture、report 与 compatibility path。

“暂时仍被另一个旧 crate 依赖”不是保留判据。需要的中立语义必须进入下节某个唯一候选 owner；否则随原 owner 删除。

## 3. #2240：临时五候选 closure

### 3.1 职责和最大允许直接依赖

下表是删除阶段的依赖上限，不是最终 exact-set。后续真实消费者可以合并、改名或删除候选，也可以移除表中的边；
不得为了迁移便利增加第六个 facade、prelude、shared、provider 或 compatibility crate。

| 临时候选 | 唯一职责 / 公共 API 类别 | 最大允许直接内部依赖 | 明确排除 |
|---|---|---|---|
| `rss-contract` | provider/domain-neutral contract identity、version/digest 与候选间共享的安全值 | 无 | authority、provider handle、业务 DTO、runtime behavior |
| `rss-eventing` | envelope/metadata、publication/consumption outcome、ambiguity、delivery budget、低基数 observation 与窄 event port | `rss-contract` | topic registry、通用 Provider SPI、broker 管理、generated routing、L3/L4 |
| `rss-consistency` | LocalTx、Outbox/Inbox、幂等、settlement、lease/fencing、bounded retry model 与窄 transaction/store port | `rss-contract`、`rss-eventing` | command journal、projection、Saga、reconcile、provider persistence 实现 |
| `rss-runtime` | provider-neutral author/consume sequencing、commit/commit-unknown、ACK-after-commit、取消、bounded drain 与 settlement callback | `rss-eventing`、`rss-consistency` | transport client、process startup、config、listener、health/readiness、assembly、operator |
| `rss-conformance` | 前四个候选公共语义的黑盒 assertion library | `rss-contract`、`rss-eventing`、`rss-consistency`、`rss-runtime` | provider/driver、broker/DB fixture、scheduler、artifact selector、CI receipt |

依赖方向固定为：

```text
rss-contract
  └─ rss-eventing
       └─ rss-consistency
            └─ rss-runtime
                 └─ rss-conformance
```

图表示上层可依赖左侧已列的直接 owner；所有边单向，Core 不依赖 conformance，任何候选都不依赖 provider 或消费方。
候选只可暴露其算法签名和 conformance 所需的最小 semantic trait/callback；provider registry、动态发现、配置、生命周期、
选择逻辑和具体实现始终由仓外 owner 持有。

### 3.2 当前物理载体与处置

以下事实来自 observed revision 的 Cargo manifests/metadata，只用于指导抽取，不授予最终 package 身份：

| 临时候选 | 当前载体 | 当前直接内部生产依赖 | 处置 |
|---|---|---|---|
| `rss-contract` | `crates/contract` | 无 | 暂留并按公共消息语义裁剪；当前额外 Foundation API 不自动保留 |
| `rss-eventing` | `crates/eventing` | `rss-contract`、`rss-request-context`、`rss-diag-context` | 暂留；后两项需要的中立值归入唯一候选 owner 后删除原 crate |
| `rss-consistency` | `crates/consistency`（当前 package `consistency`） | `ids`、`rss-request-context`、`runctx`、`secure`、`support`、`vocab` | 只把 LocalTx/Outbox/Inbox/幂等/lease/retry 视为抽取源；不整体改名 |
| `rss-runtime` | `crates/eventexec` 的窄处理算法 | `assembly-schema`、`consistency`、`diport`、`generated`、`primitives`、`rss-contract`、`rss-diag-context`、`rss-eventing`、`rss-request-context`、`rss-trace-context`、`secure`、`vocab` | 只抽取 provider-neutral sequencing；不得保留整个旧 crate 或其产品模块 |
| `rss-conformance` | `crates/conformance` | 无 | 暂留 LocalTx assertion；后续扩展只消费候选公共 API，不引入 provider fixture |

`crates/runtimeexec` 以 `assembly-schema`、`authn`、`bootstrap`、`diport`、`eventexec`、listener lifecycle、platform、
runtime inventory 和 process-global behavior 为职责中心，整体属于 assembly/process 抽取反例。它不得通过改 package name、
re-export 或薄 façade 成为 `rss-runtime`。

### 3.3 待删除依赖

`request-context`、`diagctx`、`vocab`、`ids`、`secure`、`support`、`runctx`、`primitives`、`diport`、
`assembly-schema`、`generated`、`tracewire` 及其它 current internal package 均不在临时五候选集合。每项只有两种合法结局：

1. 被公共消息语义直接需要的最小值/算法原子进入一个唯一候选 owner，所有旧 consumer 同时切换并删除旧 owner；
2. 随领域、provider、装配或治理 consumer 删除。

禁止把它们作为额外发布 package、兼容 shim、internal-but-permanent helper 或测试便利继续保留。外部依赖同样按实际公共
API 与实现需要重算，现有 workspace pin 不构成保留依据。

## 4. 可执行删除清单与 owner

每个 PBI 必须从最新 Cargo/tracked-tree 事实重新计算范围；本表只固定 outcome 和判据，不保存实时状态或数量。

| Owner | 删除 outcome | 完成判据 |
|---|---|---|
| #2241 | 删除 consumer repository coupling 与产品专属 fixture/config | 无 consumer gitlink/submodule/vendor，也无位于领域 owner 之外的 consumer-owned source、fixture、配置或接线 |
| #2242 | 删除 binary、Docker/部署与可执行产品 example | Cargo target 无产品 bin；`bins/`、Dockerfile、deploy 与进程型 example 清零 |
| #2243 | 删除 T3、production profile、artifact journey 与专用 evidence | 无 T3 selector/profile/artifact journey、product fault matrix 或其 fixture/report |
| #2244 | 删除 composition 与 assembly | Cargo members/graph 和 tracked tree 无 composition、assembly、artifact manifest 或装配测试 |
| #2245 | 解除并删除领域/provider adapter 依赖 | 候选图不依赖 adapter；provider-specific trait/type/config 不泄漏公共 API，旧 adapter 无业务残留 |
| #2246 | 删除业务 SQL migration 与 migration operator | tracked tree、build target 和 package artifact 中无 migration SQL、embedded inventory 或 operator |
| #2247 | 删除 Identity、AuthN 与 Device Security | package/API/dependency graph 无相应领域类型、策略、服务和测试 |
| #2248 | 删除 Settings、Audit、Contract Registry 与 Syshealth | package/API/dependency graph 无相应领域类型、服务、配置、观测和测试 |
| #2249 | 删除业务 contracts、generated crate 与领域 codegen | 无业务 schema/manifest/generated binding；候选 package 不依赖 generated/internal contract path |
| #2250 | 删除 xtask 中产品与旧架构治理能力 | 每个保留检查只保护候选公共不变量；其余 command/gate/lint/snapshot/fixture 清零 |
| #2251 | 删除 xtask binary 与 custom CI scheduler | workspace 无 xtask/custom scheduler；标准 Cargo/lint/package 工具拥有验证入口 |
| #2252 | 裁剪孤立 crate、adapter、feature、script 与治理残留 | 每个保留 package/feature 均被最终候选直接需要；Cargo 反向闭包无孤立或 workspace-only helper |
| #2253 | 删除旧文档并从最终 crate 事实重建 | 旧 product/domain/assembly/T3 语料及本文清零；最小文档只描述最终实现 |
| #2254 | 验证 crates-only 与可消费性 | Cargo metadata/targets/graph、tracked-path audit、package/doc 和 registry-only locked/offline consumer 全绿 |
| #2255 | 从最终实现固化范围 ADR | ADR 引用 final Cargo/API/consumer evidence，记录最终职责/DAG/排除项/tag；不保留临时闭包 |

## 5. 最终验证算法

最终验收 owner 使用一次性交付脚本或 CI 命令组合产生 final-HEAD evidence；除非能证明长期公共不变量需要，
不把它升级为新治理平台。

1. `cargo metadata` 证明所有 production package root 都是最终允许的 library crate，无 `bin` 或进程 target，内部依赖
   exact closure 闭合且无 path/git/workspace-only 发布缺口；crate-local test/bench/doc example 仅在直接保护公共不变量时保留。
2. Cargo dependency graph 证明 Core 不依赖 provider/consumer，候选间无环，package artifact 不包含 internal 或业务生成物。
3. tracked-path audit 证明第 2.2 节禁止类别及 archive/legacy/compatibility 副本为零。
4. 每个最终 package 独立执行 package、解析、check、test、clippy 与 doc；registry candidate consumer 只通过 registry source、
   精确版本与独立 lock 在 locked/offline 模式消费。
5. 验证结果绑定 final commit；失败只回到对应删除 owner，不通过 alias、忽略项、空 inventory 或 Markdown 断言放行。

## 6. 对标与取舍

- [`cqrs-es` public core](https://github.com/serverlesstechnology/cqrs/blob/main/src/lib.rs) 展示公共 trait/algorithm 与 persistence
  扩展边界；RSS 采用更严格的 provider 外置，不把内存或数据库 store 放进核心候选。
- [`SQLx Transaction`](https://github.com/transact-rs/sqlx/blob/v0.8.6/sqlx-core/src/transaction.rs) 是 LocalTx
  commit/rollback 与 drop safety 的 provider 参考；RSS 公共面保留显式 commit-unknown 和 no-replay 语义，不公开 SQLx 类型。
- [`Tokio JoinHandle`](https://github.com/tokio-rs/tokio/blob/master/tokio/src/runtime/task/join.rs) 的 drop-detach 行为说明
  bounded cancellation/drain 必须由 `rss-runtime` 算法显式拥有，不能靠裸 task handle 或 process assembly 隐式保证。
- [`Steno`](https://github.com/oxidecomputer/steno/blob/main/src/lib.rs) 将 Saga 建模为独立 coordinator/store/DAG；M1 因而不把
  现有 Saga、projection 或 reconcile 作为消息一致性核心的迁移便利项。

## 7. 本 PR 的非目标

- 不删除、移动、重命名或新增 crate/module；不修改 Cargo manifest、lock、deny、Release Surface 或 public-api baseline。
- 不改变 Rust API、package identity、publish eligibility、版本、wire schema、SemVer 或运行行为。
- 不执行后续 PBI 的抽取、consumer first-green、registry publish、文档重建、最终 crates-only 验收或 ADR 固化。
- 不新增 Markdown scanner、目录 allowlist、永久 inventory、兼容 gate、runner、report schema 或 evidence database。
