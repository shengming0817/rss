---
name: fix
description: "问题诊断与修复: 验证+根因+复杂度分级+修复方案+backlog登记。当用户说'这个问题存在吗''帮我分析这个bug''诊断一下这个模块''修复这个问题'时触发。输入优先 PR 号（自动读 PR 评论），也支持 文件:行号 / 自然语言；多 findings 自动批量。issue 号不再受理——issue triage 走 `issues` 技能（建议 /ship 或 close）。"
argument-hint: "<#PR | 文件:行号 | 问题描述>"
allowed-tools: [Read, Write, Edit, Glob, Grep, Bash, Agent, AskUserQuestion]
---

# 问题诊断与修复

> 真源 = 激活 forge 的 issue/work-item tracker + 看板（经 `forge.sh` 适配）；label / 评级 rubric 与 PR 流转见 `.github/project-template/PROJECT.md`，issue / PR 评论 body 见 `backlog.md` / `pr-comment.md`。

---

## 阶段 1: 输入解析
优先级：**PR 号**（裸数字先按 PR 试 → `bash hack/automation/pr-comments.sh latest <N> pr-review` 取最新一条 pm:pr-review body 作为 findings 源；**只取最新一轮**——该 body 的 `<details>` 无损详表即本轮 findings；为空 → 无待修 review，报告退出。回退：pr-review body 为空时取最新一条 codex review/comment。**跳过**自己上一轮的 `pm:ship`/`pm:fix`/`pm:ci`/`pm:oos` 留痕（已处理）与早于该最新 review 的旧 `pm:pr-review`，**不回头处理上一轮已 triage 的 findings**）> **文件:行号** > **自然语言**（Grep/Glob）。**issue 号不再受理**——裸数字一律先按 PR 解析；issue 状态核查 + triage 收敛到 `issues` 技能（判定后建议 `/ship #<N>` 或 file:line）。

**PR 状态入口**：先用 `forge.sh pr-state <PR#>` 确认 PR 开放，再读取 refs 与最新 review 正文。自动接力只接受唯一 `pr-status/needs-fix` 且无旧 `pr-review/*`；其它状态、缺失或冲突标签只报告，不修改代码。用户直接指定 PR 修复时，确认当前 head 上的待修 findings 后，先用 `forge.sh pr-set-status <PR#> needs-fix <已核对的 headSha>` 统一状态；切换成功后才能开始修改和验证。用户对修复预算的例外不会使 ready/check 标签适用于正在修复的 PR。

**自动修复预算（PR 输入）**：按 `PROJECT.md` §5 从受信 pm:fix 评论计数；已有 3 条则停止自动 fix，用户明确要求继续时例外。读取失败不当作 0。读取最新 review 正文的 head SHA，与 live PR head 核对；自动接力遇到缺失或不一致时报告需重新 review，不凭旧结论直接修改。

---

## 阶段 2: 问题确认

| 状态 | 含义 | 下一步 |
|------|------|--------|
| **CONFIRMED** | 问题真实存在，可以复现 | 诊断请求 → 阶段 6；修复请求 → 阶段 3 |
| **RESOLVED** | 问题已被修复（给出证据：哪行代码、哪个 PR） | → 向用户报告，结束 |
| **CHANGED** | 代码重构过，问题形态变化 | → 向用户描述新形态，确认是否继续 |
| **CANNOT_VERIFY** | 无法确认（缺少上下文、需要运行时验证） | → 请求更多信息 |

本阶段输出：状态 / 位置 / 问题描述 / 根因 / 影响范围 / Cx 分级 / 范围归属 / 判定依据，作为阶段 3 的输入。

---

## 阶段 3: 修复方案与决策

### 3.1 方案设计原则（贯穿阶段 3；进入阶段 4 / 输出 Cx3+ 方案 / 提交批量汇总前强制自检）

- **彻底**：根因级修复，不留 TODO/FIXME/follow-up；已发现的"同类"问题一并纳入。自检"是否还藏 TODO、兼容代码、未列入的同类？"
- **不向后兼容**：直接改签名/删字段/换实现，不留 deprecation 别名、shim、双路径。自检"是否留了别名、旧字段、双路径？"
- **优雅简洁**：最少代码、最少抽象、最少新文件，不预设未来需求。自检"能否用更少代码、抽象、新文件达成？"

不通过 → 修订；必须保留的违反项 → 显式列入"遗留 / 取舍说明"，不得默默放行。默认走彻底方案；Cx2 最小修复仅在 3.3 确认彻底方案无法当前实施时启用，必须给升级窗口 + 按 §沟通规则闸门输出 issue 建议命令。批量时"搭车修"同样适用。

### 3.2 对标参考查询（Cx2+ 必须执行）

Cx2 及以上问题，**先查参考实现再动手**。三层按权威性递减：

1. **Rust 标准库 / 核心生态** → 有做法必须遵循，不自创，直接读取对应 primary 源码
2. **组件官方库** → 遵循官方推荐模式并检查 Issues 已知陷阱
3. **对标框架** → 选择可验证的工业实现参考，可偏离但须注明理由

**决策优先级**: 层 1 > 层 2 > 层 3 > `WebSearch "rust best practice"`

**何时跳过**: Cx1 全跳过；纯业务 bug 全跳过
**不可跳过**（即使 Cx2）: 并发/锁、连接池/生命周期、重连/重试/超时、密码学/认证、事件发布/消费

---

### 3.3 执行决策

| 复杂度                                                      | 条件 | 决策 |
|----------------------------------------------------------|------|-----|
| Cx1/Cx2 + IN_SCOPE + 不改底座 crate trait/migration/组合根/并发语义 | 全满足 | 直接修 |
| Cx2 + IN_SCOPE + 触禁域 + 能做                          | — | 执行推荐方案 |
| Cx2 + 不能做（有前置依赖）                                         | — | 记录报告，标注阻塞 |
| **Cx3/Cx4 IN_SCOPE** | 任何 | 如存在，执行下方单次批量处置门；无这类 finding 时不沟通 |
| 任何 + OUT_OF_SCOPE                                        | — | 不修，自动建 backlog issue（阶段 5 step 4；pri-p0/判不定除外） |

**Cx3/Cx4 单次批量处置门**：先为全部 IN_SCOPE Cx3/Cx4 生成「当前 PR 修」or「defer」的建议及理由。属于原验收范围且是正确性、安全性或构建必需的 Cx3 建议当前 PR 修，其他 Cx3/Cx4 建议 defer。然后只发起一次批量处置请求：用户可全盘采纳建议，或按 finding ID 覆盖个别项。判当前 PR 修的纳入阶段 4，完成后记 `✅ 已修`；判 defer 的自动建 issue、记 `⏸ defer`，不再二次确认。

**不可直接修（须经批量处置门或推荐方案）**: 并发语义变更、trait 签名修改、新依赖、数据流方向变更、Cx3+。

> 判 Cx 读取最新 review 评论的逐条 `[P·Cx·维度]`，不能仅凭汇总计数代替逐条处置。

**何时沟通**: 见文末 §沟通规则；Cx3/Cx4 仅在存在 IN_SCOPE finding 时发起一次批量处置请求，其余默认按 3.3 表处置。

### 3.4 决策自检信号（3.3 → 阶段 4 hook 锚点）

进阶段 4 改代码前，发一次决策自检信号：

```
bash "$CLAUDE_PROJECT_DIR/.claude/hooks/fix-self-audit.sh" emit
```

`PreToolUse(Bash)` hook 锚定该命令：本次 fix 首次发信号会 deny 并回喂「措施符合彻底、不向后兼容 措施优雅简洁、AI HARD的原则吗」。收到后**真正**按四原则复审本次 fix 方案（彻底 / 不向后兼容 / 优雅简洁 / AI-HARD），按需回调 3.3 决策，再重发同一命令即放行、进入阶段 4。机制同 ExitPlanMode 的 `.claude/hooks/exitplan-self-audit.sh`，但**每个 /fix 都自检**（消费式 toggle，非每会话一次）。这是自检提醒，**不是**新的用户决策门（不重复 §沟通规则）。

---

## 阶段 4: 实施修复与验证

新增或变更可测试行为、修复可复现 bug 时，先写或复用测试并确认失败。

按阶段 3 的执行决策实施修复。每批次修改完成后、提交前运行受影响测试，通过后按已有授权提交。代码任务全部修改完成且各批测试通过后，运行一次项目规定的 CI。每阶段一次收集全部失败，集中修复后复验失败项及受影响范围。

---

## 阶段 5: 提交与交接

非 PR 输入：登记 deferred 项并输出修复结果；按用户授权执行提交、推送或创建 PR。PR 输入、新建或已授权关联的 PR，执行以下交接流程。

> **pm:* 评论统一**：填 `.github/project-template/pr-comment.md`（无损 `file:line` + 详表入 `<details>`），正文写明实际处理的完整 head SHA，再用 `forge.sh pr-comment` 发布并回显 stdout 返回的 URL。

1. **PR 状态**：fix 执行及验证期间保持 `pr-status/needs-fix`，不切回 `in-progress`。
2. **提交 + push**：仅 `git add` 修复文件，提交已通过批次测试的修改并 push；已提交的批次直接 push。
3. **冲突预检（阻塞）**：先 fetch 激活 remote，再用 `forge.sh pr-mergeable <PR#>` 最多轮询 5 次（间隔约 10s）；仍为 `UNKNOWN` 则停下报告。冲突则 merge 最新 remote/develop、commit/push 后按同一上限重检。 冲突处理引入改动后复验受影响范围，再基于最终 head 生成评论。
4. **deferred 登记（先于 pm:fix 与切 label）**：所有 deferred——OOS finding + 批量处置判定 defer 的 IN_SCOPE Cx3+/RELATED——逐条按 `.github/project-template/backlog.md` 无损成文，从 `PROJECT.md` 取四轴标签，严格执行 `PROJECT.md` §1 的同标签 `validate --labels` → `forge.sh issue-create` 顺序，注明本次输入来源，有来源 PR 时注明 `Discovered via /fix #<original>`；`pri-p0`→请求用户决策、`validate` 失败→`deferred=labels-underivable` 回退草稿。PR 流程的 OOS 另贴 pm:oos（每条 finding 必须写明已建 issue 或 deferred 原因）。
5. **pm:fix**（绑定最终已验证 head；OOS artifact 已存在、指针有效）：findings triage + 修复结果 + 遗留 IN_SCOPE；OOS 仅一行指针 `🚦 OUT_OF_SCOPE（见 pm:oos）`；用 `forge.sh pr-comment` 发布并回显 URL。
6. **切 label**：按 `PROJECT.md` §2.5/§5 使用 `forge.sh pr-set-status <PR#> needs-check-fix <已验证且写入评论正文的 head-sha>`。全部 deferred issue、pm 评论先落地，方可切状态；失败不得宣称交接完成。
7. **交接等待（必做）**：本地验证及必要修复收尾完成后，按 `.github/project-template/PROJECT.md` §5 的交接等待及执行与沟通规则静默等待满 15 分钟；开始时一次性说明 UTC 到期时间，期间禁止查询交接状态或倒计时报时，到期后再启动一次 `/pr-monitor <PR#> --mode=auto`（check-side）。外部 app 可在 `needs-check-fix` 后执行 `/pr-review --check`，pr-monitor 只做一次性交接兜底。完成后汇总交接结果。

Priority：review finding 用原 `[P0-P3]`；`/fix` 派生默认 `pri-p2`；`pri-p0` 仅 incident（线上故障/数据完整性/CVE）请求用户决策。

---

## 阶段 6: 输出

窗口打印诊断 / 修复报告；PR 流程同时发布阶段 5 的 pm:fix 评论，保留完整 findings 和实际提交 SHA。

- 诊断报告（未修）
- 修复报告（已修）
- 批量验证（审查报告）

输出含：状态 / 位置 / 根因 / 影响范围 / Cx 分级 / 范围归属 / 判定依据 / 处置结果或建议 / 验证结果 / 遗留项。

**交接结果**：记录提交 SHA、deferred issue 链接或未建单原因；PR 流程同时记录 PR、pm:fix 评论链接和最终 `pr-status`。

---

## 沟通规则

**默认按分析结果自动决策。** 仅以下情况请求决策：
- 无法定位问题代码
- 修复遇到无法自行解决的阻塞
- 存在 IN_SCOPE Cx3/Cx4 时，按 3.3 将全部 finding 合并为一次批量处置请求；无这类 finding 时不沟通
- **OUT_OF_SCOPE / 批量处置判定 defer 的 Cx3+/RELATED / /fix 派生新问题 → 默认自动 `bash hack/automation/forge.sh issue-create` + 回填 #N**（流程见 阶段 5 step 4：无损填 backlog.md body + 派生四轴标签 → `issue-labels.sh validate` → 建单）。**判定 defer 后建 issue 不再二次确认**。仅 `pri-p0`（incident）请求用户决策，或 area/type 判不定（`validate` 失败）时标 `deferred=labels-underivable` 回退草稿。
- pri-p0 红线升级（incident-driven 或安全 CVE）
