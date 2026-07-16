---
name: ship
description: "全流程实施编排：探索→计划→worktree→TDD→实施→PR→内置 review→findings 处置→交付。L1 跳过探索，L2 定向探索，L3（默认）并行探索。"
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

所有等级都先读取 `README.md`、目标文件、测试、相关文档和仓库规则。是否需要开源对标按 `CLAUDE.md` 判断；需要时从 `docs/references/framework-comparison.md` 选择 primary 来源并记录可追溯参考。

汇总根因、建议方案、影响范围和风险并自检。存在实质歧义时集中请求一次决策；否则直接进入阶段 2。

---

## 阶段 2：计划

生成可执行计划，至少包含：

- 按依赖顺序排列的文件级改动；
- 串行/并行任务 DAG 与文件 owner，同一文件只归一个任务；
- 与改动载体匹配的 TDD 失败用例和最小回归命令；
- 文档、迁移、兼容性或安全影响（适用时）。

按 `CLAUDE.md` 与相关 `docs/rules/` 生成计划。展示计划作为进度信息；无新的实质歧义时直接进入阶段 3，阶段 5 复用此 DAG，不重新分组。

---

## 阶段 3：Worktree

按 `git-worktree` skill 从激活 forge remote 的 `develop` 创建隔离 worktree。创建后解析并记录其绝对路径，后续统一记为 `<worktree>`。

---

## 阶段 4：TDD

在 `<worktree>` 中先添加与改动载体匹配的测试或结构守卫，覆盖正常、边界和错误路径；运行阶段 2 选定的最小命令，确认目标测试先失败，再进入实施。测试范围、覆盖率和最终验证遵循 `CLAUDE.md`。

---

## 阶段 5：实施

按阶段 2 的 DAG 逐批执行；无文件交叉且无逻辑依赖的任务可并行，有前置依赖的任务串行。需要派发时使用 `developer` agent（执行约束见 `.claude/agents/developer.md`）；每个 developer prompt（包括阶段 8 的修复派发）必须包含绝对 `<worktree>` 路径，明确授权按 ship 流程提交且只提交所属文件，并要求读取、编辑、测试和 Git 操作全部绑定该路径，禁止落到主仓或其他 worktree。

每批完成后汇总改动、commit 和最小测试结果；失败先定位根因并在本批修复。全部批次完成后检查计划覆盖和文件归属，不在此重复最终本地验证。

---

## 阶段 6：PR

使用 `.github/project-template/pull_request_template.md` 填写 PR，执行仓库 benchmark gate，通过激活 forge helper 推送并创建 PR，然后按 `.github/project-template/PROJECT.md` §5 进入 `in-progress` 流程。

---

## 阶段 7：Review（内置首审）

按 `.claude/agents/reviewer.md` 的派发分档启动内置 reviewer。主 agent 对结果去重并按根因聚类；P/Cx 评级引用 `.github/project-template/PROJECT.md` §3，Finding 范围归属引用 `PROJECT.md` §3.3，后续流程引用 §5。

外部再审不属于本阶段；本技能只完成 ship 流程内的首审与交接。

---

## 阶段 8：Findings 处置与收尾

1. 完整展示聚类后的 findings，并保留可定位证据。
2. IN_SCOPE Cx1/Cx2 直接派 `developer` 修复，不逐条询问。只要存在任一 IN_SCOPE Cx3/Cx4，就必须严格按 `.github/project-template/PROJECT.md` §5 发起一次批量处置，由用户对整批建议作出决策；只有不存在此类 finding 时才不沟通。这是顶部自主推进规则的显式决策门，不以“方案无歧义”为由跳过。
3. 推送修复并完成冲突预检；按 `.github/project-template/PROJECT.md` §5 完成 OOS/defer issue、评论 artifact、机器块、label 流转与延迟监控，内容格式分别引用 `backlog.md` 和 `pr-comment.md`。
4. **本地验证（label 后执行）**：运行 `make -C <worktree> ci CI_BASE=<remote>/develop`，其中 `<worktree>` 是阶段 3 记录的绝对路径，展开后的命令形如 `make -C /absolute/worktrees/<type>/<name> ci CI_BASE=<remote>/develop`。这是 10 分钟有界 affected preflight；失败则回到相应实施批次，修复、推送并重新完成收尾流转。重型门交 nightly/develop。

artifact 必须先于总结与触发 label 落地；具体顺序见 `.github/project-template/PROJECT.md` §5。

---

## 阶段 9：交付报告

向用户报告：

- PR 编号、URL 与交接状态；
- pm:ship 评论 URL；
- 实施范围与关键测试结果；
- findings 的修复/defer 摘要及对应 issue 指针；
- 本地验证结果和后续 reviewer/monitor 交接。

交付报告只汇总已落地 artifact，不重复 findings 详表，也不新增审批门。
