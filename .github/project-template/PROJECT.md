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
| epic 实施顺序 | 最新 `pm:epic-wave`（可见 token）issue 评论 | AI / 自动化 |
| 父子关系 | 激活 forge 的父子关系（azure work-item parent/child / github sub-issue / gitlab parent），经 `forge.sh subissue-link` | 人 / 自动化 |

> 本仓 issue/PR 全程经 forge 适配器 / 技能创建，body 读 `.github/project-template/` 下对应模版（`--body-file`）。

**新建 backlog**：area/type/pri/cx 四轴必须显式贴（cx 取值见 §2.6/§3.2，无 unknown sentinel），同一份标签先校验、再创建：

```bash
LABELS="backlog,pri-pX,area-XX,type-XX,cx-X"
bash hack/automation/issue-labels.sh validate --labels "$LABELS"
bash hack/automation/forge.sh issue-create "[<ID>] ..." <填好的 backlog.md> "$LABELS"
```

**新建 epic / feature**（容器层）：见 §1.1 三层映射。Epic / Feature 按当前流程在 Azure Boards UI 手工建（脚本化时 `issue-create` 第 4 参传 Work Item Type，body 读 `epic.md` / `feature.md`）；子任务经 `forge.sh subissue-link` 关联原生父子关系。容器不贴 `cx` / `type`（跨多 PR、无单一 diff）。

---

### 1.1 Work Item Type 三层映射（Azure：Epic ▷ Feature ▷ PBI）

work-item **类型层级**是结构轴（容器 vs 叶子 / 归属），与 §2 的 `type-XX` 标签（变更性质轴）**正交**——勿混用：

| 层 | Azure Work Item Type | 含义 | parent | 允许的标签轴 |
|----|---------------------|------|--------|------------|
| 顶 | **Epic** | 能力工程聚合（如整个 Rust 重写迁移） | — | `epic` `backlog` `area` `pri` |
| 中 | **Feature** | 能力块 / 门控阶段（**跨多 PR**） | Epic | `backlog` `area` `pri` |
| 叶 | **Product Backlog Item** | 可交付增量（**≈ 一个 PR**） | Feature（无则挂 Epic） | `backlog` `area` `pri` **`cx` `type`** |

- **`cx` 与 `type-XX` 是叶子（PBI）专属轴**：Epic / Feature 是跨多 PR 的容器、无单一 diff，**不贴** `cx` / `type-XX`（§2.6 / §3.2 同源）。
- **父子链 = Epic→Feature→PBI**（经 `forge.sh subissue-link` 写原生父子关系）；同层（PBI↔PBI / Feature↔Feature）不互作父子。
- 容器层（Epic / Feature）按当前流程在 Azure Boards UI 手工建；`forge.conf` 的 `AZURE_WI_TYPE_EPIC` / `AZURE_WI_TYPE_FEATURE` 供脚本化建容器时指定类型。建单门 `issue-labels.sh validate` 经 `--tier pbi|feature|epic` 区分结构层（Work Item Type 是验证器输入，不靠标签集推断容器/叶子）：PBI 叶子（默认 `--tier pbi`）要求 area+type+pri+cx；Epic / Feature 容器（`--tier epic|feature`）要求 area+pri、**禁止** type/cx。

---

## 2. Label 体系（3 维 + 条件标记 + 工具 label + PR label）

### 2.1 area-XX（领域，1 个，8 选）

| Label | 领域 | 主要 crate |
|-------|------|--------|
| `area-kernel` | 底座/生命周期 + Bootstrap 启停编排 | `crates/bootstrap` `crates/primitives` `crates/runctx` `crates/ids` |
| `area-auth` | 认证 + 授权 | `crates/authn` `crates/identity` `adapters/oidcadapter` |
| `area-http` | Contract 注册/发现 + HTTP 入站 | `crates/httpserve` `crates/contractreg` `adapters/grpcadapter` `adapters/ratelimit` |
| `area-eventing` | Outbox producer + Subscriber/Claimer + Saga L3 | `crates/consistency` `crates/eventexec` `crates/deviceloop` `adapters/amqpadapter` `adapters/mqttadapter` `adapters/softca` |
| `area-data` | Config 热更新 + 持久化/加密 + 分布式锁 | `crates/settings` `crates/secure` `crates/support` `crates/distributed` `adapters/pgadapter` `adapters/redisadapter` `adapters/vaultadapter` `adapters/s3adapter` |
| `area-observability` | Metrics / Tracing / Logging | `crates/observ` `crates/audit` `adapters/oteladapter` `adapters/promadapter` |
| `area-tooling` | 分层治理/crate 依赖图 + deny.toml + codegen/工具链 | `xtask/` `bins/rss` `deny.toml` `clippy.toml` `contracts/`（治理） |
| `area-cross` | 跨 ≥4 领域 / 无明确归属 | `crates/vocab` `crates/syshealth` + 跨 ≥4 域 |

### 2.2 type-XX（类型，1 个，8 选）

`type-enhancement`（新功能）/ `type-bug`（缺陷）/ `type-refactor`（重构）/ `type-arch-opt`（架构优化）/
`type-doc`（文档）/ `type-test`（测试）/ `type-debt`（技术债）/ `type-fu`（PR follow-up）

> `type-XX` 是 **PBI 叶子专属轴**（§1.1），与 Work Item Type 层级轴正交；`type-enhancement`（变更性质=新功能）与 Azure 的 `Feature` 类型（容器层级）是两个轴，勿混。

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

`cx-1` / `cx-2` / `cx-3` / `cx-4`（语义见 §3.2 rubric）。与 pri 同为评级两轴之一、载体对称（都是 label），cx **必填**：建 issue 时必须定级并显式 `--label cx-X`（与 pri 对称，无 unknown sentinel——定不到级也要在 §3.2 rubric 里就近取一档）；review/fix finding 派生的 issue 从 finding 的 `[…Cx…]` tag 自动带上对应 cx。epic / feature 容器不贴（跨多 PR、无单一 diff，§1.1）。PBI 叶子的 area/type/pri/cx 完整性由 `hack/automation/issue-labels.sh validate` 守卫；selftest 直接运行 `bash hack/automation/issue-labels.sh selftest`。

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
| **Wave** | single-select | Wave 1 / 2 / 3 / 4（**仅 4 档**） | 保留字段；epic 排序结果只写 issue 评论，不写本字段 |
| **Parent issue** | built-in | 自动派生（激活 forge 父子关系） | forge |
| **Sub-issues progress** | built-in | 自动派生（子 issue close 比例） | forge |

> Priority 不是看板字段，是 `pri-pX` label（单源）；复杂度（Cx）同理改用 `cx-X` label（§2.6）。已删字段：Iteration（原 daily-planner 每日调度，技能已退役）、
> Size（XS-XL）、Estimate（原承载 Cx1-Cx4，已改 `cx-X` label）。

---

## 5. PR 流程（ship → review → fix → check）

**外部 app handoff contract**：外部 app 是 `needs-review-again` / `needs-check-fix` 的实时消费者；`/pr-monitor` 是 ship/fix 收尾约 15min 后必跑的一次性兜底检查器。消费者只能在同仓、非 draft、可信作者、same-head、无已记录失败、未重复领取的前提下 dispatch，并且必须同时满足 live label 与最新 fresh canonical 机器块：

| live label | latest block | allowed dispatch |
|------|------|------|
| `pr-status/needs-review-again` | `kind=ship` + `verdict=needs-review-again` + `next.triggerLabel=pr-status/needs-review-again` | `codex review` |
| `pr-status/needs-check-fix` | `kind=fix` + `verdict=needs-check-fix` + `next.triggerLabel=pr-status/needs-check-fix` | `/pr-review --check` |
| `pr-status/needs-fix` | `kind=pr-review` + `verdict=changes-requested` + `next.triggerLabel=pr-status/needs-fix` | `/fix`（`/pr-monitor` 过 handoff 门——fresh canonical block + verdict + same-head + next 一致——才接力；Cx / scope 判定下放 `/fix`，读 finding 文件 + `byCx`） |

离线契约测试直接运行 `bash hack/automation/pr-meta.sh selftest`（离线，无网络）；该协议 selftest 独立于 Rust 代码验证门。

```
/ship <issue>
  实施 → PR 创建 → 贴 pr-status/in-progress
  → ship：内置 6 维 reviewer → IN_SCOPE Cx3/Cx4 处置门（每条 AskUserQuestion 判「当前 PR 修」or「defer」，判 defer 后自动建 issue、不二次确认）→ /fix Cx1/Cx2 → push/冲突预检 → deferred 留痕 + pm:ship
  → 切 pr-status/needs-review-again（首审唯一使用点）→ 10 分钟有界 `make ci CI_BASE=<remote>/develop`（重型门交 nightly/develop）；外部 app 可先行 review
  → 延迟 ~15min 必须启动 pr-monitor --mode=auto 监听交接（needs-fix 自动 /fix；单次跑完即止）

[review 轮] codex review 或 /pr-review <PR#>
  → 贴 findings 评论（codex / pm:pr-review）
  → 有需改 → 切 pr-review/changes-requested + pr-status/needs-fix
  → 无需改（无 findings）→ 切 pr-review/approved + pr-status/ready（无需 fix/check 的终态）

/fix <PR#>（pr-status/needs-fix 时；可多次跑，≤3 轮自动循环）
  → bash hack/automation/pr-comments.sh latest <N> pr-review（最新 pm:pr-review findings）→ 过滤最新一轮
  → triage + IN_SCOPE Cx3/Cx4 处置门（AskUserQuestion 判修/defer，defer 后自动建 issue、不二次确认）+ Cx1/Cx2 修复 → push/冲突预检 → deferred 留痕 + pm:fix
  → 切 pr-status/needs-check-fix + 移除 pr-status/needs-fix → 10 分钟有界 `make ci CI_BASE=<remote>/develop`（不追加 `make ci-full`）
  → 外部 app 可在 label 后先行执行 /pr-review --check
  → 延迟 ~15min 必须启动 pr-monitor --mode=auto 监听 check 交接

/pr-review <PR#> --check（验证上一轮 findings 是否修复 + 抓回归）
  → 逐条核对当前代码：✅已修复 / ❌未修复 / ⚠️回归 / 🔧部分 → 贴 pm:pr-review（--check）
  → 全 ✅ → 切 pr-status/ready + pr-review/approved
  → 有 ❌/⚠️/🔧 → 切 pr-review/changes-requested + pr-status/needs-fix
              + 移除 pr-review/approved + 移除 pr-status/needs-check-fix → 回 /fix
```

> 不变式：PR 始终恰好一个 `pr-status/*`、pr-review 轴 `approved` XOR `changes-requested`（切换时同步移除同轴对侧）；每阶段结束都贴评论留痕（约定，无 CI 机器门），标记按来源不编 round 号。`needs-review-again` 只在 ship 首次交接后出现一次；所有后续 review→changes-requested 均切 `needs-fix`（5-state 不变式）。
> `/fix` 不能直接到 `ready`——必过 `/pr-review --check` 独立验证（fix 不能自证完成）。
> 本地 canonical `make ci` 只承担 10 分钟有界 affected preflight；unknown 本地忽略并留痕，workspace/feature/integration/coverage/public-api/dylint/audit/container 等重型全量门由 nightly/develop 承接。`make ci-full` 仅人工诊断，任何 skill/template 不得把它追加为 PR 默认完成条件。
> **IN_SCOPE Cx3 处置门**：ship/fix 切触发 label 前，每条 IN_SCOPE Cx3（及 Cx4）经处置门 AskUserQuestion 判「当前 PR 修（带措施）」or「defer（带原因）」；**判 defer 后自动建 issue 跟踪（机器可判定 artifact，不再二次确认）**，与 OOS artifact-before-trigger 同序；全部 deferred issue 已建方可切 label。
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
