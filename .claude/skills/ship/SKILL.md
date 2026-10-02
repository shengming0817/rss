---
name: ship
description: "全流程实施编排：探索→计划→worktree→分批实施→PR→内置 review→findings 处置→集中验证→交接。L1 跳过探索，L2 定向探索，L3（默认）并行探索。"
argument-hint: "[--level=L1|L2|L3] <#issue-number 或任务描述>"
allowed-tools: [Read, Write, Edit, Glob, Grep, Bash, Agent, AskUserQuestion]
---

# RSS Ship — 全流程实施编排

调用 `/ship` 即授权完成探索、计划、worktree、实施、PR、内置 review、修复和交接的标准流程。探索结论与实施计划是进度产物，不是默认审批门；无实质歧义时展示后直接继续。

只有仓库证据无法消除、且不同选择会实质改变需求范围、用户可见行为、数据模型、安全边界或交付物时，才请求用户决策。先合并同阶段全部待决事项，一次给出推荐项、影响和默认处置。

命令或工具失败时先重试、诊断并尝试安全替代，不把可由项目规则、代码或测试确定的工程问题交给用户。若仍无法继续，报告 blocker；不要把“是否忽略失败继续”当成默认问题。

剥离 `--level=` 后，剩余参数匹配 `^#?[0-9]+$` 时视为 issue 号。用 `hack/automation/forge.sh issue-view <N>` 拉取上下文，后续以 issue title/body 作为需求，并在 PR 中建立关闭关联。只有确认 issue 已关闭时才请求用户裁定是否继续；查询失败按上述工具失败规则处理，不等同于 issue 已关闭。

## 等级

| 等级 | 探索深度 | 后续流程 |
|------|----------|----------|
| L1 | 跳过专项探索，直接读取本仓上下文 | 标准全流程 |
| L2 | 单方向定向探索 | 标准全流程 |
| L3（默认） | 并行探索实现、测试与边界 | 标准全流程 |

等级只调整探索深度，不改变实施授权，也不增加审批门。

---

## 阶段 1：探索（L1 跳过专项探索）

- **L2**：派 `explorer` 聚焦最关键的不确定点。
- **L3**：并行探索现有实现与依赖、测试策略、边界与安全风险；任务互相独立，避免重复读取和结论重叠。

所有等级都先读取目标文件、测试、相关规则和 `CLAUDE.md`。需要开源对标时直接读取 primary upstream 源码并记录可追溯参考。

汇总根因、建议方案、影响范围和风险并自检。存在实质歧义时集中请求一次决策；否则直接进入阶段 2。

---

## 阶段 2：计划

先用 Read/Grep 核实具体修改点（仓库、文件、函数）、真实消费者和前置依赖，标明已就绪与缺失部分。

按依赖和可验证产出确定 **1–8 个实施批次**，计划包含：

- 本次范围与完成边界；
- 每批的具体修改点、前置依赖、产出与完成判定；
- 并行关系与文件归属，同一文件只归一个任务；
- 文档、迁移、兼容性或安全影响（适用时）。

按 `CLAUDE.md` 与相关 `docs/rules/` 生成计划。展示计划作为进度信息；无新的实质歧义时直接进入阶段 3。

---

## 阶段 3：Worktree

按 `git-worktree` skill 从激活 forge remote 的 `develop` 创建隔离 worktree。创建后解析并记录其绝对路径，后续统一记为 `<worktree>`。

---

## 阶段 4：实施

按计划逐批执行；独立任务可并行，前置依赖任务串行。读取、编辑和 Git 操作绑定绝对 `<worktree>` 路径，只提交所属文件。

以“批次 i/n”说明本批目标，完成后报告产出、状态和剩余缺口，再按授权提交。依赖变化时调整剩余批次，整项计划保持 1–8 批；相关修复归回所属批次。全部批次完成后核对计划覆盖和文件归属。

正式 CI、T2 及直接调用同一 runner 的验证仅在阶段 7 集中执行。

---

## 阶段 5：PR

使用 `.github/project-template/pull_request_template.md` 填写 PR，通过激活 forge helper 推送并创建 PR，然后按 `.github/project-template/PROJECT.md` §5 进入 `in-progress` 流程。

---

## 阶段 6：Review（内置首审）

按 `.claude/agents/reviewer.md` 的派发分档启动内置 reviewer。主 agent 对结果去重并按根因聚类；P/Cx 评级引用 `.github/project-template/PROJECT.md` §3，Finding 范围归属引用 `PROJECT.md` §3.3，后续流程引用 §5。

外部再审不属于本阶段；本技能只完成 ship 流程内的首审与交接。

---

## 阶段 7：Findings 处置与交接

1. 完整展示聚类后的 findings，并保留可定位证据。
2. IN_SCOPE Cx1/Cx2 直接修复，不逐条询问。只要存在任一 IN_SCOPE Cx3/Cx4，就必须严格按 `.github/project-template/PROJECT.md` §5 发起一次批量处置，由用户对整批建议作出决策；只有不存在此类 finding 时才不沟通。这是顶部自主推进规则的显式决策门，不以“方案无歧义”为由跳过。
3. 提交并推送本轮修复，完成冲突预检及冲突处理。
4. **集中验证**：全部计划批次、review 修复和冲突处理完成后，代码任务按目标仓入口执行必要 T2，再运行一次项目 CI；CI 已承载的同项 T2 复用该入口的结果。每次收集全部失败，集中修复后精确复验失败项及受影响范围；通过后提交并推送验证修复。
5. 验证通过后，按 `.github/project-template/PROJECT.md` §5 完成 OOS/defer issue、绑定最终 head 的可读评论 artifact，最后用 §2.5 的 `forge.sh pr-set-status` 切 `needs-review-again`；内容格式引用 `backlog.md` 和 `pr-comment.md`。
6. **交接等待（必做）**：本地验证及必要修复收尾完成后，按 `.github/project-template/PROJECT.md` §5 的交接等待及执行与沟通规则静默等待满 15 分钟；开始时一次性说明 UTC 到期时间，期间禁止查询交接状态或倒计时报时，到期后再启动一次 `/pr-monitor <PR#> --mode=auto`。

artifact 必须先于总结与触发 label 落地；具体顺序见 `.github/project-template/PROJECT.md` §5。

---

## 阶段 8：交付报告

向用户报告：

- PR 编号、URL 与交接状态；
- pm:ship 评论 URL；
- 实施范围与关键测试结果；
- findings 的修复/defer 摘要及对应 issue 指针；
- 本地验证结果和后续 reviewer/monitor 交接。

交付报告只汇总已落地 artifact，不重复 findings 详表，也不新增审批门。
