# RSS 项目管理定义与状态契约

issue 内容、状态和父子关系以激活 forge 的 issue/work-item tracker 与看板为真值源。本文件拥有标签取值、工作项层级、P/Cx 评级、范围归属与 PR 状态契约；模板拥有正文结构，技能拥有执行编排。

## 1. 真源与入口

| 数据 | 载体 |
|------|------|
| issue 内容与进度 | forge issue/work-item tracker 与看板 |
| 领域、类型、优先级、复杂度 | area / type / pri / cx 标签 |
| 父子关系 | forge 原生父子关系 |
| Epic 实施顺序 | 最新的可见 `pm:epic-wave` 评论 |

issue/PR 读写经 `hack/automation/forge.sh`，正文使用本目录的对应模板。新建 backlog 使用同一份标签先校验再创建：

```bash
LABELS="backlog,pri-pX,area-XX,type-XX,cx-X"
bash hack/automation/issue-labels.sh validate --labels "$LABELS"
bash hack/automation/forge.sh issue-create "[<ID>] ..." <填好的 backlog.md> "$LABELS"
```

### 1.1 Work Item Type 工作项层级

默认使用 Epic → Product Backlog Item（PBI）；明确需要中间容器时才使用 Feature。

| 类型 | 用途 | parent | 标签轴 |
|------|------|--------|--------|
| Epic | 能力聚合 | — | epic / backlog / area / pri |
| PBI | 可交付增量，通常对应一个 PR | 默认 Epic；使用 Feature 时挂 Feature | backlog / area / type / pri / cx |
| Feature（按需） | 跨多个 PBI 的能力块 | Epic | backlog / area / pri |

PBI 使用 area/type/pri/cx 四轴；Epic 与 Feature 使用 area/pri。父子关系经 `forge.sh subissue-link` 写入，同层工作项不互作父子。

创建类型由 `issue-create` 第 4 参指定，正文使用 `epic.md`、`backlog.md` 或按需使用的 `feature.md`。标签校验通过 `--tier epic|pbi|feature` 区分类型。

## 2. Label 体系（area / type / pri / cx 四轴）

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

### 2.3 pri-XX（优先级，1 个，CLI 显式贴）

`pri-p0` / `pri-p1` / `pri-p2` / `pri-p3`（语义见 §3 rubric）。建 issue 时必须显式 `--label pri-pX`。复杂度 label（cx）见 §2.6。

### 2.4 工具 / 标记 label

- `backlog`：backlog 条目标记与自动化入口。
- `epic`：Epic 容器标记。
- `pr-fu`：PR review 派生项。
- `flag-cond`：条件延后，正文的 `Trigger` 记录触发条件。

### 2.5 PR 状态 label（单轴）

| Label | 含义 |
|-------|------|
| `pr-status/in-progress` | ship 实施及内置审查中 |
| `pr-status/needs-review-again` | ship 已交接，等待外部完整再审 |
| `pr-status/needs-fix` | 等待或正在修复阻断 findings |
| `pr-status/needs-check-fix` | fix 已交接，等待独立复核 |
| `pr-status/ready` | 当前 head 审查通过；合并须满足仓库门禁 |

每个 PR 只接受一个流程标签。状态切换使用实际处理并写入评论的完整 head SHA：

```bash
bash hack/automation/forge.sh pr-set-status <PR#> <status> <head-sha>
```

`status` 不带 `pr-status/` 前缀。状态或 head 不一致、切换失败时报告实际结果。一次 PR 修复由一个执行者接管，调度去重由调用方持有。

### 2.6 cx-XX（复杂度）

PBI 必须使用 `cx-1` / `cx-2` / `cx-3` / `cx-4` 之一，含义见 §3.2；review/fix 派生项保留 finding 的 Cx。Epic 与 Feature 不携带 type/cx。

标签完整性由 `hack/automation/issue-labels.sh validate` 校验；验证器自检命令：

```bash
bash hack/automation/issue-labels.sh selftest
```

## 3. 评级与范围归属

### 3.1 P 严重程度

| 级 | 含义 | 用法 |
|----|------|------|
| **P0** | 发布阻塞 / 数据丢失 / 安全 CVE / 编译失败 | **红线**，仅 incident-driven；body 须写 incident ID 或 CVE 编号 |
| **P1** | 架构/安全/正确性关键 + 抽象/去重/funnel 闭环关键 | 架构 refactor 的上限（即使跨 ≥3 领域也顶 P1，不进 P0） |
| **P2** | 常规债务、影响维护性但不阻塞功能 | 默认档 |
| **P3** | 触发型 / 可延后 / 性能微调 / 文档完善 | |

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

## 4. 看板与 Wave 载体

| 数据 | 载体 | 含义 |
|------|------|------|
| Status | forge 看板 | Backlog / Ready / In progress / In review / Done |
| Parent issue | forge 原生关系 | 工作项的父级 |
| Sub-issues progress | forge 原生关系 | 已完成子任务进度 |
| 实施 Wave | 最新 `pm:epic-wave` 评论 | 未完成任务的依赖层级，Wave 层数与成员数无上限 |

实施 Wave 的生成由 issues 技能负责；已完成任务单列。看板中历史的四档 Wave 字段不作为编排依据，Epic 正文也不维护第二份顺序表。

## 5. PR 状态与交接契约

| 阶段 | 输入 | 交接结果 |
|------|------|----------|
| ship | 实施任务 | `pm:ship` → `needs-review-again` |
| pr-review | 当前 head | `pm:pr-review` → `needs-fix` 或 `ready` |
| fix | 当前 head 对应的待修 findings | `pm:fix` → `needs-check-fix` |
| pr-review --check | 当前 head 对应的修复记录 | `pm:pr-review` → `needs-fix` 或 `ready` |

- 先完成验证、提交及冲突处理，再登记 deferred 项、发布绑定最终 head 的评论，最后切换触发标签。fix 经独立 check 才能进入 ready。
- fix/check 输入记录的 SHA 须与 live head 一致；head 改变后，旧审查与修复记录失效。
- IN_SCOPE Cx3/Cx4 合并为一次批量处置请求。属于原验收且为正确性、安全性或构建必需的 Cx3 建议当前 PR 修，其他建议 defer；用户可按 finding 覆盖建议。
- deferred/OOS 项先落 issue，再发布评论与切标签；pri-p0 或标签无法确定时记录原因和草稿。
- 修复与本地验证收尾后等待 15 分钟，再执行一次 `/pr-monitor <PR#> --mode=auto`。
- 自动 fix 最多三轮，按受信 `pm:fix` 评论计数；每轮仅发布一次，读取失败不当作零轮，用户明确要求继续时例外。
- 对话报告与 PR 评论保留完整 finding、`file:line`、证据、处置与验证结果。评论标记和正文结构由 `pr-comment.md` 定义。
