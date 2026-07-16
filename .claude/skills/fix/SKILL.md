---
name: fix
description: "问题诊断与修复: 验证+根因+复杂度分级+修复方案+backlog登记。当用户说'这个问题存在吗''帮我分析这个bug''诊断一下这个模块''修复这个问题'时触发。输入优先 PR 号（自动读 PR 评论），也支持 文件:行号 / 自然语言；多 findings 自动批量。issue 号不再受理——issue triage 走 `issues` 技能（建议 /ship 或 close）。"
argument-hint: "<#PR | 文件:行号 | 问题描述>"
allowed-tools: [Read, Write, Edit, Glob, Grep, Bash, Agent, AskUserQuestion]
---

# 问题诊断与修复

> 真源 = 激活 forge 的 issue/work-item tracker + 看板（经 `forge.sh` 适配）；label / 评级 rubric 与 PR 流转见 `.github/project-template/PROJECT.md`，issue / PR 评论 body 见 `backlog.md` / `pr-comment.md`，协议块由 `pr-meta.sh` 生成。

---

## 输入解析
优先级：**PR 号**（裸数字先按 PR 试 → `bash hack/automation/pr-comments.sh latest <N> pr-review` 取最新一条 pm:pr-review body 作为 findings 源；**只取最新一轮**——该 body 的 `<details>` 无损详表即本轮 findings；为空 → 无待修 review，报告退出。回退：pr-review body 为空时取最新一条 codex review/comment。**跳过**自己上一轮的 `pm:ship`/`pm:fix`/`pm:ci`/`pm:oos` 留痕（已处理）与早于该最新 review 的旧 `pm:pr-review`，**不回头处理上一轮已 triage 的 findings**）> **文件:行号** > **自然语言**（Grep/Glob）。**issue 号不再受理**——裸数字一律先按 PR 解析；issue 状态核查 + triage 收敛到 `issues` 技能（判定后建议 `/ship #<N>` 或 file:line）。

**熔断闸门（PR 输入）**：先 `bash hack/automation/pr-meta.sh extract <PR#>`（EC=0 读 `cycle.exhausted` / `next.agent`；EC≠0 无块/stale → 降级 `pr-meta.sh round`）——`cycle.exhausted == true` 或 `next.agent == "human"` 或 `round ≥ 3` → 打印「review↔fix 已达 3 轮上限，转人工」退出，不修。（`next.agent=human` / `exhausted` = 自动闭环停派、交回人接管，非禁止 /fix 技能本身；后续由人处理。）

---

## 阶段 1: 问题定位

### 1.1 找到问题代码

按精度递进：明确路径 → Read；模糊描述 → Grep 类型/方法签名 → Grep 错误码/注释 → Agent(Explore) 调用图。三层均无果 → 请求用户补充上下文。

### 1.2 追踪调用链 + 数据流

从问题代码向上（调用方）和向下（被调用方）追踪。跨 3+ 包用 Agent(Explore)。
同时追踪数据流：数据源 → 变换 → 消费者。

### 1.3 确认问题是否存在

| 状态 | 含义 | 下一步 |
|------|------|--------|
| **CONFIRMED** | 问题真实存在，可以复现 | → 进入阶段 2 |
| **RESOLVED** | 问题已被修复（给出证据：哪行代码、哪个 PR） | → 向用户报告，结束 |
| **CHANGED** | 代码重构过，问题形态变化 | → 向用户描述新形态，确认是否继续 |
| **CANNOT_VERIFY** | 无法确认（缺少上下文、需要运行时验证） | → 请求更多信息 |

输出含：状态 / 位置 / 调用链 / 数据流 / 问题描述（自己总结，不照搬 backlog）。

### 1.4 复现测试（Reproduction Test First）

CONFIRMED 后、修复前，先构造一个能**复现问题**的测试用例：

1. 基于调用链和数据流分析，编写最小测试用例触发问题
2. 运行测试确认 FAIL（证明问题可复现）
3. 将此测试作为修复验收标准

| 场景 | 操作 |
|------|------|
| 已有测试可稍加修改复现 | 修改已有测试 + 确认 FAIL |
| 需新写测试 | 在 `xxx.rs` 的 `#[cfg(test)]` 模块新增 `fn xxx_bug描述()` |
| 并发问题 | 写可触发的竞态测试（`tokio::test` / `loom`，必要时 `cargo test` 下复现） |
| 无法在单测中复现（需运行时状态） | 标注 `RUNTIME_ONLY`，跳过此步 |

---

## 阶段 2: 根因分析 + 复杂度分级（CONFIRMED 后执行）

### 2.1 根因三维度

- **代码层面**: 哪行代码、哪个设计决策导致的
- **架构层面**: 是否系统性（Grep 同模式，1 处=局部，3+=架构缺陷）。架构缺陷 → 请求用户裁定局部修还是系统性重构
- **历史层面**: git log 搜索同类已有修复，发现团队惯例，避免退化

### 2.2 影响范围

直接影响 / 间接影响（列出受影响文件）/ 同类问题（Grep 相同模式数量）

### 2.3 复杂度分级

**必须对问题做复杂度判定**，决定后续方案形态（方案数见 3.1）。**Cx1-4 定义单源在 `.github/project-template/PROJECT.md` §3.2**（= 改动量/实现风险，本技能不复制）。

> Cx1 表示"容易修"，不代表"不重要"。IN_SCOPE/RELATED/OUT_OF_SCOPE 按 `.github/project-template/PROJECT.md` §3.3 判定，与 Cx 等级无关——Cx1 也可以是 IN_SCOPE 且必须修。

判定依据（按顺序检查）：
1. 修复涉及多少个文件？（`Grep` 搜索所有受影响的调用点）
2. 是否需要修改底座 crate（`consistency` / `primitives` / `vocab` 等）的 trait 或类型？
3. 是否需要修改数据库 schema（migration）？
4. 是否影响组合根（assembly / bin crate）的组装逻辑？
5. 同类问题在其他模块是否重复出现？（1 处=局部，3+=系统性）

### 2.4 当前分支归属判定

按 `.github/project-template/PROJECT.md` §3.3 确定 finding 是否属于当前分支/PR：

1. 用 `/usr/bin/git diff --name-only "$(bash hack/automation/forge.sh remote)/develop...HEAD"` 取得当前分支改动文件。
2. 对照 finding 的文件、调用链与当前改动的直接影响关系。
3. 有关联 PR 时，检查任务/issue/PR 描述、验收标准以及已读取的最新 review 上下文，确认 finding ID 或需求是否明确在范围内。
4. 按 §3.3 输出 IN_SCOPE / RELATED / OUT_OF_SCOPE、判定证据和对应执行结果；不得仅因文件不在 diff 中就判 OUT_OF_SCOPE。

输出含：代码/架构/历史三维度根因、复杂度、当前分支归属（含理由）、影响范围（直接/间接/同类）、历史修复。

---

## 阶段 3: 修复方案设计

### 方案设计原则（贯穿 3.0-3.4；进入阶段 4 / 输出 Cx3+ 方案 / 提交批量汇总前强制自检）

- **彻底**：根因级修复，不留 TODO/FIXME/follow-up；阶段 2.2 列出的"同类"问题一并纳入。自检"是否还藏 TODO、兼容代码、未列入的同类？"
- **不向后兼容**：直接改签名/删字段/换实现，不留 deprecation 别名、shim、双路径。自检"是否留了别名、旧字段、双路径？"
- **优雅简洁**：最少代码、最少抽象、最少新文件，不预设未来需求。自检"能否用更少代码、抽象、新文件达成？"

不通过 → 修订；必须保留的违反项 → 显式列入"遗留 / 取舍说明"，不得默默放行。默认走彻底方案；Cx2 最小修复仅在 3.2 明确"不能现在做"时启用，必须给升级窗口 + 按 §沟通规则闸门输出 issue 建议命令。批量时"搭车修"同样适用。

### 3.0 对标参考查询（Cx2+ 必须执行）

Cx2 及以上问题，**先查参考实现再动手**。三层按权威性递减：

1. **Rust 标准库 / 核心生态** → 有做法必须遵循，不自创。查 `docs/references/framework-comparison.md` "Rust 标准库参考" 表
2. **组件官方库** → 遵循推荐模式 + 检查 Issues 已知陷阱。查同文件 "组件官方库参考" 表
3. **对标框架** → 参考，可偏离但须注明理由。查同文件 "按 RSS 模块的参考映射"

**决策优先级**: 层 1 > 层 2 > 层 3 > `WebSearch "rust best practice"`

**何时跳过**: Cx1 全跳过；纯业务 bug 全跳过
**不可跳过**（即使 Cx2）: 并发/锁、连接池/生命周期、重连/重试/超时、密码学/认证、事件发布/消费

---

### 3.1 方案分级

| 等级 | 方案数 | 形态 |
|------|--------|------|
| Cx1 | 1 | 直接修，跳过比较 |
| Cx2 | 2 | A 最小修复 + B 彻底方案 |
| Cx3 | 3 | A 最小 + B 彻底 + C 重构 |
| Cx4 | 设计文档 | 生成方案；是否执行由 3.4 的批量处置结果决定 |

每个方案须含：改动范围、原理、优缺点、遗留（仅最小修复）、预估改动量、参考来源（Cx2+ 必填）。

### 3.2 时机判断：现在做还是后面做

**必须给出明确的时机建议**，回答三个问题：

**Q0: 是否属于当前分支？** 取 2.4 归属结果：**OUT_OF_SCOPE** → 自动建 backlog issue（4.6 step 3；pri-p0/标签判不定除外），跳过 Q1-Q3；**IN_SCOPE / RELATED** → 进 Q1（RELATED 改动量大可 defer）。

**Q1: 推荐现在做还是后面做？**（仅 IN_SCOPE / RELATED 继续）

| 推荐 | 判定条件 |
|------|---------|
| **现在做** | 安全漏洞 / 运行时崩溃 / 阻塞其他工作 / 改动量 ≤ 50 行 |
| **本迭代做** | 有明确影响但不紧急 / 改动量 50-200 行 / 不阻塞他人 |
| **下迭代做** | 设计级问题 / 改动量 200+ 行 / 需要先完成其他前置工作 |
| **记录不做** | 理论风险但实际不触发 / 修复代价远大于收益 |

**Q2: 能不能现在做？** 检查：已有 issue 依赖、活跃分支冲突、底座 crate（`consistency` / `primitives` / `vocab`）trait 消费方。

**Q3: 最小修复的有效期？** 给出彻底方案的建议时间窗口。

### 3.3 详细修复计划

文件级改动清单。收尾统一运行 10 分钟有界 `make ci CI_BASE=<remote>/develop`；workspace/feature/integration 全量重门交 nightly/develop，skill 不重复或追加低层门。

### 3.4 执行决策

| 复杂度                                                      | 条件 | 决策 |
|----------------------------------------------------------|------|-----|
| Cx1/Cx2 + IN_SCOPE + 不改底座 crate trait/migration/组合根/并发语义 | 全满足 | 直接修 |
| Cx2 + IN_SCOPE + 触禁域 + 能做                          | — | 执行推荐方案（A/B 比较） |
| Cx2 + 不能做（有前置依赖）                                         | — | 记录报告，标注阻塞 |
| **Cx3/Cx4 IN_SCOPE** | 任何 | 如存在，执行下方单次批量处置门；无这类 finding 时不沟通 |
| 任何 + OUT_OF_SCOPE                                        | — | 不修，自动建 backlog issue（4.6 step 3；pri-p0/判不定除外） |

**Cx3/Cx4 单次批量处置门**：先为全部 IN_SCOPE Cx3/Cx4 生成「当前 PR 修」or「defer」的建议及理由。属于原验收范围且是正确性、安全性或构建必需的 Cx3 建议当前 PR 修，其他 Cx3/Cx4 建议 defer。然后只发起一次批量处置请求：用户可全盘采纳建议，或按 finding ID 覆盖个别项。判当前 PR 修的记 `✅ 已修`并纳入本轮；判 defer 的自动建 issue、记 `⏸ defer`，不再二次确认。

**不可直接修（须经批量处置门或推荐方案）**: 并发语义变更、trait 签名修改、新依赖、数据流方向变更、Cx3+。

> 判 Cx 优先读 `pr-meta.sh extract` 的 `findings.byCx`（`cx3==0 ∧ cx4==0 ∧ (cx1+cx2)>0` = 无 Cx3+）。

**何时沟通**: 见文末 §沟通规则；Cx3/Cx4 仅在存在 IN_SCOPE finding 时发起一次批量处置请求，其余默认按 3.4 表处置。

### 3.5 执行前任务清单（阶段 3 → 4 门禁）

**用 TaskCreate 注册每项任务**，执行时 TaskUpdate 更新状态（✔/◼/◻）。

规则：
- 所有 finding 都创建 task，OUT_OF_SCOPE 标注 `[→ 自动建 issue（4.6 step 3）；pri-p0/判不定除外]`
- 单条 Cx1 IN_SCOPE → 跳过清单直接修；批量或 Cx2+ → 必须创建
- 最后两项固定：`commit + push` + `闭合/创建 GitHub issues`
- 创建后立即执行，不等确认

### 3.6 决策自检信号（3.4 → 4.x hook 锚点）

进阶段 4 改代码前，发一次决策自检信号：

```
bash "$CLAUDE_PROJECT_DIR/.claude/hooks/fix-self-audit.sh" emit
```

`PreToolUse(Bash)` hook 锚定该命令：本次 fix 首次发信号会 deny 并回喂「措施符合彻底、不向后兼容 措施优雅简洁、AI HARD的原则吗」。收到后**真正**按四原则复审本次 fix 方案（彻底 / 不向后兼容 / 优雅简洁 / AI-HARD），按需回调 3.1–3.4 决策，再重发同一命令即放行、进入阶段 4。机制同 ExitPlanMode 的 `.claude/hooks/exitplan-self-audit.sh`，但**每个 /fix 都自检**（消费式 toggle，非每会话一次）。这是自检提醒，**不是**新的用户决策门（不重复 §沟通规则）。

---

## 阶段 4: 执行修复

### 4.1 Commit 格式

在当前分支直接修改。Commit: `fix(<scope>): <问题简述>` + 根因 + 复杂度 + Refs + Co-Authored-By。
scope 按 crate 名（扁平 workspace，如 `consistency` / `httpserve` / `identity` / `eventexec` / `postgres`）。安全约束：只 add 修复文件（不 add -A）；不 amend。

### 4.2 执行代码修改（逐编辑测试循环）

> **批量并行**：4+ 条 finding 时按 crate（扁平 workspace 的 `crates/*` 域/底座 crate、`adapters/*`、`bins/*`）聚类派发 `developer` sub-agent（**同 crate 同 agent** 防写冲突，组内串行执行下面循环）；并发 4-9→2 / ≥10→3；≤3 条由主 agent 直接处理。triage 同理可按聚类并行（`Explore`）。

对每个任务，执行 Edit-Test Loop + 状态更新：

1. **TaskUpdate → in_progress**（开始处理当前任务）
2. Read 目标文件
3. Edit / Write 修改代码
4. **Rust crate 改动**：对受影响 crate 运行快速 build 与阶段 1.4 的复现测试；**非 crate 改动**：直接运行对应的最小复现测试，不强制 Cargo build/test
5. 立即检查测试结果
6. 如果测试失败：
   - 分析失败原因
   - 如果是当前编辑引入 → 立即修正，重回步骤 3
   - 如果是暴露了后续步骤的依赖 → 记录，继续下一步骤
7. 测试通过 → **TaskUpdate → completed** → 进入下一个任务

### 4.3 编辑循环收敛

确认每条 finding 的复现测试与适用的 Edit-Test Loop 已通过；不在此重复跑最终本地漏斗。canonical `make ci CI_BASE=<remote>/develop` 统一在 4.6 **切 label 后**执行。

### 4.4 测试失败处理（分层回退）

| Round | 策略 |
|-------|------|
| 1-2 | 在当前方案上迭代修正 |
| 3 | `git stash` + 切换到备选方案重新执行 |
| 4 | 回滚（`git checkout -- <文件>`），Cx1 标 ESCALATE，Cx2 降级到最小修复标遗留 |

### 4.5 验证修复

重新执行阶段 1 的定位逻辑，确认：
- 原问题代码已被替换
- 数据流已正确保护
- 测试覆盖了问题场景

### 4.6 Git 收尾

> **pm:* 评论统一**：填 `.github/project-template/pr-comment.md`（无损 `file:line` + 详表入 `<details>`），用 `pr-meta.sh emit-block --kind=<k> --pr=<PR#>` 追加机器块，再用 `forge.sh pr-comment` 发布并回显 stdout 返回的 URL。

1. **提交 + push**：仅 `git add` 修复文件，按 4.1 commit/push；无 PR 才用填好的 `pull_request_template.md` 调 `forge.sh pr-create`。
2. **冲突预检（阻塞）**：先 fetch 激活 remote，再用 `forge.sh pr-mergeable <PR#>` 最多轮询 5 次（间隔约 10s）；仍为 `UNKNOWN` 则停下报告。冲突则 merge 最新 remote/develop、commit/push 后按同一上限重检。
3. **deferred 登记（先于 pm:fix 与切 label）**：所有 deferred——OOS finding + 批量处置判定 defer 的 IN_SCOPE Cx3+/RELATED——逐条按 `.github/project-template/backlog.md` 无损成文，从 `PROJECT.md` 取四轴标签，严格执行 `PROJECT.md` §1 的同标签 `validate --labels` → `forge.sh issue-create` 顺序，注明 `Discovered via /fix #<original>`；`pri-p0`→请求用户决策、`validate` 失败→`deferred=labels-underivable` 回退草稿。OOS 另贴 pm:oos（`--kind=oos`，每 item 必带 `issue` 或 `deferred`，否则 emit-block 拒绝）。
4. **pm:fix**（`--kind=fix`，OOS artifact 已存在、指针有效）：findings triage + 修复结果 + 遗留 IN_SCOPE；OOS 仅一行指针 `🚦 OUT_OF_SCOPE（见 pm:oos）`；用 `forge.sh pr-comment` 发布并回显 URL。
5. **切 label**：按 `PROJECT.md` §5 执行 `forge.sh pr-set-labels <PR#> --add pr-status/needs-check-fix --remove pr-status/needs-fix`。**前置不变式（artifact-before-trigger）**：全部 deferred 的 issue 已建、pm 评论已贴，方可切 label（与 ship 阶段 8 同序）。
6. **本地验证（label 后执行）**：运行 `make ci CI_BASE=<remote>/develop`。该 canonical 入口是 10 分钟有界 affected preflight，只分析 `<remote>/develop...HEAD` 的已提交项目差异；unknown 本地忽略并留痕，重型门显示 `DEFERRED` 后交 nightly/develop。不得追加 `make ci-full`、workspace/feature/integration 全量门；失败则回阶段 1-4，修复并 push 后重新执行冲突预检、pm 评论与 label 流转，再重跑本步骤。
7. **延迟启监控（必做）**：本地验证结束后延迟约 15min 启 `/pr-monitor <PR#> --mode=auto`（check-side）；外部 app 可在 `needs-check-fix` 后先行 `/pr-review --check`，pr-monitor 只做一次性交接兜底。完成后 **TaskUpdate → completed**。

Priority：review finding 用原 `[P0-P3]`；`/fix` 派生默认 `pri-p2`；`pri-p0` 仅 incident（线上故障/数据完整性/CVE）请求用户决策。

---

## 阶段 5: 输出 + 验证

窗口打印诊断 / 修复报告是主输出、pm:fix 评论（4.6 已贴）是无损留痕，两者都做（输出纪律单源见 `PROJECT.md` §5）。

- 诊断报告（未修）
- 修复报告（已修）
- 批量验证（审查报告）

**验证**（4.6 已执行，此处复核，不再查找）：核对 fix 评论 + `pr-status` 已切；全部 deferred（OOS + 批量处置判 defer 的 Cx3+/RELATED）issue 已自动建 + 回填 #N（pri-p0/判不定除外）。

---

## 沟通规则

**默认按分析结果自动决策。** 仅以下情况请求决策：
- 无法定位问题代码
- 测试失败且 4 轮回退后仍无法修正
- 存在 IN_SCOPE Cx3/Cx4 时，按 3.4 将全部 finding 合并为一次批量处置请求；无这类 finding 时不沟通
- **OUT_OF_SCOPE / 批量处置判定 defer 的 Cx3+/RELATED / /fix 派生新问题 → 默认自动 `bash hack/automation/forge.sh issue-create` + 回填 #N**（流程见 4.6 step 3：无损填 backlog.md body + 派生四轴标签 → `issue-labels.sh validate` → 建单）。**判定 defer 后建 issue 不再二次确认**。仅 `pri-p0`（incident）请求用户决策，或 area/type 判不定（`validate` 失败）时标 `deferred=labels-underivable` 回退草稿。
- pri-p0 红线升级（incident-driven 或安全 CVE）
