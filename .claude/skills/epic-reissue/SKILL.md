---
name: epic-reissue
description: "Azure epic 子 issue 丢失后，从 epic 描述 + 仓库 spec/计划/tasks + 代码现状反推应有子任务，去重后重建并挂回 epic。当用户说『epic 的子 issue 丢了/没了，按 spec 和计划重新建出来挂上去』『issue 系统迁移后把这个 epic 的子任务补回来』时使用。流程：读 epic → 匹配规格源 → dry-run 提案确认 → issue-create + subissue-link。只重建+挂载，不改 epic body、不排 wave（那是 issues 技能）。"
argument-hint: "<epic 工作项号>"
allowed-tools: [Read, Glob, Grep, Bash, Agent, AskUserQuestion]
---

# epic-reissue — 从 spec/计划重建 epic 子 issue

> 场景：issue 系统迁移 / 丢失，Azure epic 还在但子 work item 没了。真源 = epic 描述 + 仓库里的 spec/计划/tasks 文件 + 代码现状。本技能只编排：读 epic → 找规格源 → 反推子任务 → 去重 → 提案确认 → 经 forge 重建 + 挂回 epic。
> **不复制命令形态 / 标签四轴 / body 骨架**：issue 创建与 label 见 `issues` 技能 Part B，body 见 `.github/project-template/backlog.md`，label 取值见 `.github/project-template/PROJECT.md` §2/§3。
> repo 与看板经激活 forge 适配器（`bash hack/automation/forge.sh`，默认 azure）操作，不写死平台。

## 1. 读 epic

```bash
bash hack/automation/forge.sh issue-view <epic#>
```

确认是 epic（带 `epic` label）；从 title + 目标/范围提取关键字（能力名、cell 名、编号如 `#1895` / `070`）。不是 epic / 不存在 → 停下 AskUserQuestion，不臆测。

## 2. 找规格源 + 跟代码核实

按关键字/编号 Glob + Grep 匹配该 epic 的规格文件：

- `specs/<NNN>-*/`（`spec.md` / `plan.md` / `tasks.md`）
- `docs/plans/specs/<id>-*/` 与 `docs/plans/*<编号>*.md`

读其中的任务 / 阶段清单 → 得到「应有子任务」候选；跨 3+ 文件时并行派 `Agent(Explore)` 核实每条的落地状态（**已实现 / 部分 / 未动**），证据精确到 `file:line`。匹配不到规格源 → 停下 AskUserQuestion。

## 3. 去重 + dry-run 提案（确认后才建）

- 查现存（避免重建幸存的）：`bash hack/automation/forge.sh issue-list "<关键字>" all` —— 命中同名子任务即视为已存在，跳过。
- 输出提案表，AskUserQuestion 确认（不擅自全建）：

| # | 候选子任务标题 | area·type·pri·cx | 规格源 file | 落地状态 | 动作 |
|---|---------------|------------------|-----------|---------|------|
| 1 | [<ID>] ... | area-x·type-x·pri-p2·cx-2 | specs/070.../tasks.md | 未动 | 建 |
| 2 | ... | ... | ... | 已实现 | 跳过（标已完成） |
| 3 | ... | ... | ... | — | 已存在 #N |

落地状态判定：**已实现 → 不建**（仅在表里记「已完成」）；**部分 / 未动 → 建**。

## 4. 重建 + 挂回 epic（每条确认要建的）

命令单源 = `issues` 技能 Part B，body 骨架 = `.github/project-template/backlog.md`：

1. 填 `backlog.md` body：`## 现状` ← 落地状态 + 证据；`## 修复方向` ← 规格里的任务描述 / 范围；`## Files` ← 核实到的 `file:line`；`## Source` ← `Recreated from <spec/plan file> via /epic-reissue（issue 系统迁移丢失）`。
2. 四轴门：`bash hack/automation/issue-labels.sh validate --labels "backlog,pri-pX,area-XX,type-XX,cx-X"`（pri 缺省 `pri-p2`，`pri-p0` 须 AskUserQuestion；cx 必填）。
3. 建单：`bash hack/automation/forge.sh issue-create "[<ID>] <标题>" <body-file> "backlog,pri-pX,area-XX,type-XX,cx-X"` → 回显 `#N`。
4. 挂回：`bash hack/automation/forge.sh subissue-link <epic#> <N>`。

## 边界

- 只重建 + 挂载子任务；**不改 epic body、不写 Project 字段、不排 wave**（wave 调度走 `issues` 技能 Part A）。
- 建单幂等：第 3 步 `issue-list` 命中同名即跳过；重复跑安全。
- 完工输出：已建 `#N` 列表 + 已跳过（已存在/已完成）清单 + 建议下一步（`/issues <epic#>` 排 wave）。
