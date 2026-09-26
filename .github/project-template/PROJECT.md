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
| `area-kernel` | 公共基础与资源生命周期 | `crates/runtime` `crates/request-context` `crates/contract` |
| `area-auth` | 身份与授权边界 | `crates/request-context` 的身份边界；产品认证与协议归仓外 |
| `area-http` | 公共契约与产品 HTTP 边界 | `crates/contract` 的公共契约；HTTP host 归产品 |
| `area-eventing` | 事务消息与持久化执行 | `crates/transactional-messaging*` `crates/saga*` `crates/projection*` `crates/reconcile*` `crates/device-command*` |
| `area-data` | 组件持久化与存储保护 | `crates/data-protection` `crates/*-postgres` |
| `area-observability` | Metrics / Tracing / Logging | `crates/diagctx` `crates/tracewire`；telemetry exporter 归产品 |
| `area-tooling` | Cargo package 选择 + deny.toml + 标准工具链 | `hack/ci-impact.py` `deny.toml` `clippy.toml` |
| `area-cross` | 跨 ≥4 领域 / 无明确归属 | 跨 ≥4 个能力领域的变更 |

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

### 2.5 PR 状态 label（单轴）

PR 同时只保留一个 `pr-status/*` 流程标签；审查结论保留在 pm 评论与机器块，不再贴 `pr-review/*`。

| Label | 含义 |
|-------|------|
| `pr-status/in-progress` | ship 实施、内置 review/fix 与本地验证中 |
| `pr-status/needs-review` | ship 已交接，待完整审查 |
| `pr-status/needs-fix` | 有阻断 findings；等待或正在 fix，含本地验证期间 |
| `pr-status/needs-check` | fix 已交接，待 `/pr-review --check` 独立复核 |
| `pr-status/ready` | 当前 head 审查通过；合并仍须满足 CI 等门禁 |

统一使用 `bash hack/automation/forge.sh pr-set-status <PR#> <status> <head-sha>` 切换，status 不带前缀。
传入本阶段实际验证/审查并写入机器块的 SHA，禁止临时读取新 head 来替代证据中的 SHA。
入口检查开放 PR 与 head，清理其它 `pr-status/*` 和旧 `pr-review/*`，保留无关标签，完成后回读标签与 head。
各 forge 标签 API 不提供原子切换：中间可能短暂无标签，失败时报告并重新核对后重试，不能当作交接成功。
消费者只在恰好一个状态标签且与 fresh canonical 机器块一致时派发。
`/fix` 执行期间保持 `needs-fix`，不回 `in-progress`；重复派发由消费者对机器块 idempotencyKey 的持久化互斥领取防止，标签不充当运行锁。
`/fix` 不能自证 `ready`，必须经过独立 check；`ready` 后新增提交使旧审查失效，应对新 head 重新审查并产出证据。

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
*统一/合并/拆分/抽象/converge/unify/dedup/single source/funnel/sealed/Hard 升级* ；或触及 `crates/runtime` / `crates/transactional-messaging` 等多个核心 crate /
crate 依赖图·deny.toml·clippy typed funnel / ≥3 crate；或 AI-robust Soft→Hard 未闭合；或影响 ≥3 领域。

**触发型例外**：`flag-cond` 风格触发型条目，若其守护的 invariant 已被 Medium clippy lint/cargo-deny/governance 守住（CI 绿），
架构信号升级**封顶 P2**。**反向降级**：纯 feat/bug 触发型无业务推动、或"推测性/无 benchmark/待审视"无明确 outcome
的 P2 → 降 P3。

### 3.2 Cx 复杂度（= 改动量/实现风险，以 PR diff 为单位）

| 级 | 文件域 | 类型加载 | 典型 |
|----|--------|---------|------|
| **Cx1** | 单文件 / 同文件 ≤3 处 | 不需类型推导 | 改字面量、补 rustdoc、加单测 |
| **Cx2** | 同 crate ≤5 文件 | 可能需 clippy / deny.toml 单条 | 加方法、抽 helper、补 governance 守卫单条 |
| **Cx3** | 跨 crate 5–15 文件 | 需 sealed trait / 类型系统强制 | trait 扩字段 + 多实现同步、funnel 双向锁、ADR amendment |
| **Cx4** | ≥15 文件 / ≥3 领域 | 跨 crate 类型变更 + build.rs/proc-macro codegen | trait ctx 透传、域 crate 接口重构、codegen 链路改造 |

> Cx 由 `cx-1`..`cx-4` label 承载（§2.6）。Cx5+ 必须拆为多 item / 多 wave。

### 3.3 Finding 范围归属（IN_SCOPE / RELATED / OUT_OF_SCOPE）

Finding 的范围归属与 P/Cx 正交；先按需求证据和文件关系判归属，再按 §3.1/§3.2 评级。需求证据优先于文件位置：明确属于当前任务、issue、PR 描述或验收标准的 finding，即使落在尚未修改的文件中，也不能判为范围外。

| 归属 | 判定条件 | 执行结果 |
|------|----------|----------|
| **IN_SCOPE** | finding 文件在当前分支 diff 中；或 finding 由当前改动直接引入/暴露；或当前任务、issue、PR 描述、验收标准明确包含该 finding（含可对应的 finding ID） | 在当前 PR 处理；Cx1/Cx2 按流程直接修，Cx3/Cx4 进入 §5 的单次批量处置门 |
| **RELATED** | 不满足 IN_SCOPE，但位于同一 package/crate、子系统或调用链，属于可搭车处理的既有问题 | 明确标注“搭车”；改动可控时建议当前 PR 修，改动较大、存在前置依赖或会扩大交付风险时 defer，并按 §5 落 issue artifact |
| **OUT_OF_SCOPE** | 既不属于当前需求/验收，也不在当前 diff 或其直接影响链上，且位于不同 package/crate、模块或子系统 | 不在当前 PR 修；按 §5 自动创建 backlog issue，并在 pm:oos 中无损留痕（`pri-p0` / 标签判不定例外按该节处理） |

判定必须给出需求证据和文件/调用链证据；不能仅因 finding 文件未出现在 diff 中就判 OUT_OF_SCOPE。输出至少包含归属、理由和对应执行结果。

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

**交接等待（ship/fix 共用）**：本地验证及必要修复收尾完成后开始计时，等待满 15 分钟。期间主 agent 禁止查询该 PR 及其 CI、review、监控状态，包括 label、评论、API、日志、进程和结果文件；不得委派子 agent 代查或提前启动 `/pr-monitor`。到期后再启动一次 `/pr-monitor <PR#> --mode=auto` 完成交接兜底。

**等待期间的执行与沟通**：进入等待时只说明一次原因、UTC 到期时间和到期后的动作；没有新信息时保持静默，禁止每分钟报时、倒计数或重复“仍在等待 / 未查询状态”。纯等待不属于实施进展，不应为了凑进度更新而制造消息。优先使用环境支持且已获授权的定时唤醒；否则按工具与上级指令允许的最长等待时长续等，分段返回本身不触发用户消息，也不触发外部状态查询。只有用户主动询问、出现异常或到期检查取得结果时才更新。未实际建立唤醒机制时，不得结束任务并声称会自动回来；到期检查仍须完成。

**外部 app handoff contract**：外部 app 是 `needs-review` / `needs-check` 的实时消费者，不受主 agent 交接等待限制；`/pr-monitor` 是上述等待期满后必跑的一次性兜底检查器。消费者只能在同仓、非 draft、可信作者、same-head、无已记录失败、对 idempotencyKey 完成持久化互斥领取的前提下 dispatch，并且必须同时满足 live label 与最新 fresh canonical 机器块：

| live label | latest block | allowed dispatch |
|------|------|------|
| `pr-status/needs-review` | `kind=ship` + `verdict=needs-review` + `next.triggerLabel=pr-status/needs-review` | `codex review` |
| `pr-status/needs-check` | `kind=fix` + `verdict=needs-check` + `next.triggerLabel=pr-status/needs-check` | `/pr-review --check` |
| `pr-status/needs-fix` | `kind=pr-review` + `verdict=changes-requested` + `next.triggerLabel=pr-status/needs-fix` | `/fix`（`/pr-monitor` 过 handoff 门——fresh canonical block + verdict + same-head + next 一致——才接力；Cx / scope 判定下放 `/fix`，读 finding 文件 + `byCx`） |

单轴迁移须先暂停消费者派发，更新外部 app 的标签映射，再为开放 PR 核对当前 head 与原 findings/round，并重新发布对应机器块后切标签，最后恢复派发。新 ship/fix 块写入 `needs-review` / `needs-check` verdict；历史 v1 的 `needs-review-again` / `needs-check-fix` 仍可 canonical 解码和计入 round，但旧路由不触发新消费者。迁移不能只重贴标签或重置 round：保留原 cycle.round、findings、refs，用 `emit-block --round-base`（ship 固定 0，fix 为原 round−1）重发；旧 head 先重新审查。仅改仓库不能证明外部 app 已同步，生产消费者必须先满足同 head、机器块校验与互斥领取契约再启用。

离线状态切换测试：`python3 hack/automation/forge/status.selftest.py`。
离线契约测试直接运行 `bash hack/automation/pr-meta.sh selftest`（离线，无网络）；该协议 selftest 独立于 Rust 代码验证门。

```
/ship <issue>
  实施 → PR 创建 → pr-set-status in-progress
  → 内置 review + findings 处置 → 本地 make ci 与必要精确复验
  → push 最终 head / 冲突预检 → deferred 留痕 + pm:ship（绑定最终 head）
  → pr-set-status needs-review → 等待满 15min → pr-monitor --mode=auto

/pr-review <PR#>
  → 对当前 head 完整审查 → 贴 pm:pr-review
  → 有阻断项：pr-set-status needs-fix
  → 无阻断项：pr-set-status ready

/fix <PR#>
  保持 needs-fix → triage + 修复 → 本地 make ci 与必要精确复验
  → push 最终 head / 冲突预检 → deferred 留痕 + pm:fix（绑定最终 head）
  → pr-set-status needs-check → 等待满 15min → pr-monitor --mode=auto

/pr-review <PR#> --check
  → 独立验证上一轮 findings + 回归检查 → 贴 pm:pr-review
  → 有未修复/回归/部分修复或误判 OOS：pr-set-status needs-fix
  → 无阻断项：pr-set-status ready
```

> 各阶段通过 §2.5 的统一入口切状态，不手工拼 add/remove 列表。先完成验证与必要修复，再发布绑定最终 head 的评论，最后切触发标签；发生合并或额外修改后须验证受影响范围并更新证据。完整审查和修复复核保持不同入口，自动 review↔fix 最多 3 轮。
> `/fix` 不能直接到 `ready`——必过 `/pr-review --check` 独立验证（fix 不能自证完成）。
> 本地验证政策遵循[验证规则](../../docs/rules/verification-scope.md)；本节只拥有 PR 状态流转与交接顺序。
> **IN_SCOPE Cx3/Cx4 批量处置门**：ship/fix 切触发 label 前，先为全部 IN_SCOPE Cx3/Cx4 生成「当前 PR 修」or「defer」的建议及理由：属于原验收范围且是正确性、安全性或构建必需的 Cx3 建议当前 PR 修，其他 Cx3/Cx4 建议 defer。如果存在这类 finding，**只发起一次批量处置请求**，用户可全盘采纳建议，或按 finding ID 覆盖个别项；没有 IN_SCOPE Cx3/Cx4 时不发起沟通。**判 defer 后自动建 issue 跟踪（机器可判定 artifact，不再二次确认）**，与 OOS artifact-before-trigger 同序；全部 deferred issue 已建方可切 label。
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
