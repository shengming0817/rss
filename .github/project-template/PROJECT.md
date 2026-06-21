# RSS 项目管理真源

> **唯一真源 = 激活 forge 的 issue/work-item tracker + 看板（当前 azure → Azure Boards；github → Project v2；gitlab → Issues/Boards）**。
> 不再有 `docs/backlog/` markdown 副本。所有 backlog 条目、epic、状态、优先级、评级活在激活 forge 的 issue/work-item tracker。
>
> 本文件是 label 体系 / 看板字段 / 评级 rubric 的单源参考。

---

## 1. 真源与入口

| 维度 | 载体 | 写入方 |
|------|------|--------|
| 条目内容 / 状态描述 | forge issue/work-item body | 人 / 自动化 |
| 领域 / 类型 / 优先级 / 复杂度 | Issue label（area / type / pri / cx） | CLI 显式 `--label` |
| 进度状态 | 激活 forge 看板字段（Status；azure=Boards 状态列 / github=Project v2 Status / gitlab=board 列） | 看板 UI / 自动化 |
| epic 实施顺序 | 最新 `<!-- pm:epic-wave -->` issue 评论 | `issues` 技能 |
| 父子关系 | 激活 forge 的父子关系（azure work-item parent/child / github sub-issue / gitlab parent），经 `forge.sh subissue-link` | 人 / 自动化 |

> 本仓 issue/PR 全程经 forge 适配器 / 技能创建，body 读 `.github/project-template/` 下对应模版（`--body-file`）。

**新建 backlog**：`bash hack/automation/forge.sh issue-create "[<ID>] ..." <填好的 backlog.md> "backlog,pri-pX,area-XX,type-XX,cx-X"`。area/type/pri/cx 四轴必须显式贴（cx 取值见 §2.6/§3.2，无 unknown sentinel）；建单前先经 `hack/automation/issue-labels.sh validate` 校验完整性（`issues` B1 强制门）。

**新建 epic**：`bash hack/automation/forge.sh issue-create "[EPIC] ..." <填好的 epic.md> "epic,backlog,pri-pX,area-XX"`；子任务用激活 forge 的父子关系关联（azure work-item parent/child / github sub-issue / gitlab parent），经 `forge.sh subissue-link`。epic 不贴 cx（跨多 PR、无单一 diff）。

---

## 2. Label 体系（3 维 + 条件标记 + 工具 label + PR label）

### 2.1 area-XX（领域，1 个，8 选）

| Label | 领域 | 主要 crate |
|-------|------|--------|
| `area-kernel` | 底座/生命周期 + Bootstrap 启停编排 | `crates/bootstrap` `crates/primitives` `crates/runctx` `crates/ids` |
| `area-auth` | 认证 + 授权 | `crates/authn` `crates/identity` `adapters/oidcadapter` |
| `area-http` | Contract 注册/发现 + HTTP 入站 | `crates/httpserve` `crates/contractreg` `adapters/grpcadapter` |
| `area-eventing` | Outbox producer + Subscriber/Claimer + Saga L3 | `crates/consistency` `crates/eventexec` `crates/deviceloop` `adapters/amqpadapter` `adapters/mqttadapter` |
| `area-data` | Config 热更新 + 持久化/加密 + 分布式锁 | `crates/settings` `crates/secure` `crates/support` `crates/distributed` `adapters/pgadapter` `adapters/redisadapter` `adapters/vaultadapter` `adapters/s3adapter` |
| `area-observability` | Metrics / Tracing / Logging | `crates/observ` `crates/audit` `adapters/oteladapter` `adapters/promadapter` |
| `area-tooling` | 分层治理/crate 依赖图 + deny.toml + codegen/工具链 | `xtask/` `bins/rss` `deny.toml` `clippy.toml` `contracts/`（治理） |
| `area-cross` | 跨 ≥4 领域 / 无明确归属 | `crates/vocab` `crates/syshealth` + 跨 ≥4 域 |

### 2.2 type-XX（类型，1 个，8 选）

`type-feat`（新功能）/ `type-bug`（缺陷）/ `type-refactor`（重构）/ `type-arch-opt`（架构优化）/
`type-doc`（文档）/ `type-test`（测试）/ `type-debt`（技术债）/ `type-fu`（PR follow-up）

### 2.3 pri-XX（优先级，1 个，CLI 显式贴）

`pri-p0` / `pri-p1` / `pri-p2` / `pri-p3`（语义见 §3 rubric）。建 issue 时必须显式 `--label pri-pX`。复杂度 label（cx）见 §2.6。

### 2.4 工具 / 标记 label

- `backlog`（automation trigger，必贴，新 issue 入看板）/ `epic`（跨多 PR 父 issue）/ `pr-fu`（PR review 派生）
- `flag-cond`（**条件延后**：该条目 gated 在某触发条件，body `## Trigger` 必填）。`flag-hard` / `flag-soft` /
  `flag-planned` 已删——分别与 `pri-p0/p1` / `pri-p3` / 看板 Status 语义重叠；`flag-cond` 保留是因为它携带
  pri/Status 表达不了的"触发门控"信息。

### 2.5 PR 状态 label（两正交轴）

| 轴 | Label | 含义 |
|----|-------|------|
| **pr-status**（流转） | `pr-status/in-progress` | ship 实施 + 内置 review/fix 中 |
| | `pr-status/needs-review-again` | 仅 ship 交接后首审一次（review 出 changes-requested 后转 needs-fix） |
| | `pr-status/needs-fix` | review 出 changes-requested（非首审），待 `/fix` 修复 |
| | `pr-status/needs-check-fix` | `/fix` 已修，待 `/pr-review --check` 验证修复是否到位 |
| | `pr-status/ready` | `--check` 验证全修复，可合并 |
| **pr-review**（审查结论） | `pr-review/approved` | review 无需改 |
| | `pr-review/changes-requested` | review 提出需改项 |

流转见 §5。PR 始终恰好一个 `pr-status/*`，pr-review 轴 `approved` XOR `changes-requested`（切一侧必清同轴对侧）。`/fix` 不能直接到 `ready`——必过 `/pr-review --check` 验证（fix 不能自证完成）。`needs-review-again` 仅用于 ship 首次交接；review 出 changes-requested 后始终切 `needs-fix`（5-state）。

### 2.6 cx-XX（复杂度，1 个，必填 CLI 贴）

`cx-1` / `cx-2` / `cx-3` / `cx-4`（语义见 §3.2 rubric）。与 pri 同为评级两轴之一、载体对称（都是 label），cx **必填**：建 issue 时必须定级并显式 `--label cx-X`（与 pri 对称，无 unknown sentinel——定不到级也要在 §3.2 rubric 里就近取一档）；review/fix finding 派生的 issue 从 finding 的 `[…Cx…]` tag 自动带上对应 cx。epic 不贴（跨多 PR、无单一 diff）。非 epic backlog issue 的 area/type/pri/cx 完整性由 `hack/automation/issue-labels.sh validate` 守卫（`issues` B1 建单前强制门 + `make verify` 经 `verify-automation-selftest.sh` selftest 回归）。

---

## 3. 评级 rubric（P + Cx，**单源在此**）

> P + Cx 评级 rubric 的**单源在此节**；评级处直接引用，不复制。

### 3.1 P 严重程度

| 级 | 含义 | 用法 |
|----|------|------|
| **P0** | 发布阻塞 / 数据丢失 / 安全 CVE / 编译失败 | **红线**，仅 incident-driven；body 须写 incident ID 或 CVE 编号 |
| **P1** | 架构/安全/正确性关键 + 抽象/去重/funnel 闭环关键 | 架构 refactor 的上限（即使跨 ≥3 领域也顶 P1，不进 P0） |
| **P2** | 常规债务、影响维护性但不阻塞功能 | 默认档 |
| **P3** | 触发型 / 可延后 / 性能微调 / 文档完善 | |

**架构/去重/抽象命中信号**（任一即命中 → P3 升 P2、P2 升 P1，P1 维持）：type ∈ {arch-opt/refactor/debt} 且描述含
*统一/合并/拆分/抽象/converge/unify/dedup/single source/funnel/sealed/Hard 升级* ；或触及 `crates/primitives` / `crates/consistency` 等多个核心 crate /
crate 依赖图·deny.toml·clippy/dylint typed funnel / ≥3 域 crate；或 AI-robust Soft→Hard / Funnel 双向锁未闭合；或影响 ≥3 领域。

**触发型例外**：`flag-cond` 风格触发型条目，若其守护的 invariant 已被 Medium clippy lint/cargo-deny/governance 守住（CI 绿），
架构信号升级**封顶 P2**。**反向降级**：纯 feat/bug 触发型无业务推动、或"推测性/无 benchmark/待审视"无明确 outcome
的 P2 → 降 P3。

### 3.2 Cx 复杂度（= 改动量/实现风险，以 PR diff 为单位）

| 级 | 文件域 | 类型加载 | 典型 |
|----|--------|---------|------|
| **Cx1** | 单文件 / 同文件 ≤3 处 | 不需类型推导 | 改字面量、补 rustdoc、加单测 |
| **Cx2** | 同 crate ≤5 文件 | 可能需 clippy/dylint lint / deny.toml 单条 | 加方法、抽 helper、补 governance 守卫单条 |
| **Cx3** | 跨 crate 5–15 文件 | 需 sealed trait / 类型系统强制 | trait 扩字段 + 多实现同步、funnel 双向锁、ADR amendment |
| **Cx4** | ≥15 文件 / ≥3 领域 | 跨 crate 类型变更 + build.rs/proc-macro codegen | trait ctx 透传、域 crate 接口重构、codegen 链路改造 |

> Cx 由 `cx-1`..`cx-4` label 承载（§2.6）。Cx5+ 必须拆为多 item / 多 wave。

---

## 4. 激活 forge 看板字段

| 字段 | 类型 | 取值 | 写入方 |
|------|------|------|--------|
| **Status** | single-select | Backlog / Ready / In progress / In review / Done | 人（看板内置 workflow + 手动） |
| **Wave** | single-select | Wave 1 / 2 / 3 / 4（**仅 4 档**） | 保留字段；epic 排序结果只写 issue 评论（算法见 `issues` Part A），不再由技能写字段 |
| **Parent issue** | built-in | 自动派生（激活 forge 父子关系） | forge |
| **Sub-issues progress** | built-in | 自动派生（子 issue close 比例） | forge |

> Priority 不是看板字段，是 `pri-pX` label（单源）；复杂度（Cx）同理改用 `cx-X` label（§2.6）。已删字段：Iteration（原 daily-planner 每日调度，技能已退役）、
> Size（XS-XL）、Estimate（原承载 Cx1-Cx4，已改 `cx-X` label）。

---

## 5. PR 流程（ship → review → fix → check）

**外部 app handoff contract**：外部 app 是 `needs-review-again` / `needs-check-fix` 的实时消费者；`/pr-monitor` 是 ship/fix 收尾约 10min 后必跑的一次性兜底检查器。消费者只能在同仓、非 draft、可信作者、same-head、无已记录失败、未重复领取的前提下 dispatch，并且必须同时满足 live label 与最新 fresh canonical 机器块：

| live label | latest block | allowed dispatch |
|------|------|------|
| `pr-status/needs-review-again` | `kind=ship` + `verdict=needs-review-again` + `next.triggerLabel=pr-status/needs-review-again` | `codex review` |
| `pr-status/needs-check-fix` | `kind=fix` + `verdict=needs-check-fix` + `next.triggerLabel=pr-status/needs-check-fix` | `/pr-review --check` |
| `pr-status/needs-fix` | `kind=pr-review` + `verdict=changes-requested` + `next.triggerLabel=pr-status/needs-fix` | `/fix`（仅 `/pr-monitor` 在 Cx1/Cx2 window 内自动接力；Cx3+ 转人工） |

离线契约测试：`bash hack/automation/pr-handoff-contract-selftest.sh`，已由 `hack/verify-automation-selftest.sh` 接入 `make verify`。

```
/ship <issue>
  实施 → PR 创建 → 贴 pr-status/in-progress
  → ship：内置 6 维 reviewer + /fix Cx1/Cx2 → 贴 pm:ship → 冲突预检 + CI 绿（capability-gated：激活 forge=azure 无 CI，ci-* 返回 no-ci，CI 收敛降级本地 make verify，不贴 pm:ci）
  → 切 pr-status/needs-review-again（首审唯一使用点）→ 外部 app 实时监听并执行 review
  → 延迟 ~10min 必须启动 pr-monitor --mode=auto 监听交接（needs-fix 自动 /fix；单次跑完即止）

[review 轮] codex review 或 /pr-review <PR#>
  → 贴 findings 评论（codex / pm:pr-review）
  → 有需改 → 切 pr-review/changes-requested + pr-status/needs-fix
  → 无需改（无 findings）→ 切 pr-review/approved + pr-status/ready（无需 fix/check 的终态）

/fix <PR#>（pr-status/needs-fix 时；可多次跑，≤3 轮自动循环）
  → bash hack/automation/pr-comments.sh latest <N> pr-review（最新 pm:pr-review findings）→ 过滤最新一轮
  → triage + 修复 → 贴 pm:fix → 冲突预检 + CI 绿（capability-gated，同上）
  → 切 pr-status/needs-check-fix + 移除 pr-status/needs-fix（待验证）
  → 外部 app 实时监听并执行 /pr-review --check
  → 延迟 ~10min 必须启动 pr-monitor --mode=auto 监听 check 交接

/pr-review <PR#> --check（验证上一轮 findings 是否修复 + 抓回归）
  → 逐条核对当前代码：✅已修复 / ❌未修复 / ⚠️回归 / 🔧部分 → 贴 pm:pr-review（--check）
  → 全 ✅ → 切 pr-status/ready + pr-review/approved
  → 有 ❌/⚠️/🔧 → 切 pr-review/changes-requested + pr-status/needs-fix
              + 移除 pr-review/approved + 移除 pr-status/needs-check-fix → 回 /fix
```

> 不变式：PR 始终恰好一个 `pr-status/*`、pr-review 轴 `approved` XOR `changes-requested`（切换时同步移除同轴对侧）；每阶段结束都贴评论留痕（约定，无 CI 机器门），标记按来源不编 round 号。`needs-review-again` 只在 ship 首次交接后出现一次；所有后续 review→changes-requested 均切 `needs-fix`（5-state 不变式）。
> `/fix` 不能直接到 `ready`——必过 `/pr-review --check` 独立验证（fix 不能自证完成）。
> **输出纪律**（ship/review/fix/check 各阶段共用单源）：每阶段**窗口完整打印是主输出、PR 评论是无损留痕，两者都做缺一不可**——评论是 `/fix` 与再审（codex / `/pr-review`）提取 findings 的唯一来源（每条带 `file:line`、无损详表入 `<details>`，无损约定见 `pr-comment.md`）。skill 不重述此纪律，引用本条。
> 评论格式模板单源 = `.github/project-template/pr-comment.md`。

---

## 6. 常用查询

# 按 label/tag 维度筛 open backlog（运维便捷查询）。`forge issue-list <search> <state>`
# 是关键字 + 状态查询，不做 label 过滤；label/tag 过滤经激活 forge 的原生 issue 查询
# （当前 azure → Azure Boards 查询按 System.Tags 过滤；github → issue label 过滤；
# gitlab → issue label 过滤）。需筛的标签组合：
#   主线队列（P0/P1 未关）：backlog + pri-p0 / backlog + pri-p1
#   按领域：backlog + area-eventing      按类型：backlog + type-bug
#   按复杂度：backlog + cx-3              epic：epic

```bash
# 某 PR 最新一轮 review findings（fix 入口；最新 pm:pr-review body）
bash hack/automation/pr-comments.sh latest <N> pr-review
```

> label 维度（area/type/pri/cx）经激活 forge 的原生 issue 查询按 label/tag 筛；Status/Wave
> 仅看板 UI 可见。cx 改 label 后，wave 内 Cx tiebreaker 不再依赖看板 UI。
