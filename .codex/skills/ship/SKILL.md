---
name: ship
description: "全流程实施编排：探索→计划→worktree→分批实施→PR→内置 review→findings 处置→集中验证→交接。L1 跳过探索，L2 定向探索，L3（默认）并行探索。"
argument-hint: "[--level=L1|L2|L3] <#issue-number 或任务描述>"
allowed-tools: [Read, Write, Edit, Glob, Grep, Bash, Agent, AskUserQuestion]
---

> **子 agent 约束（覆盖下文）**：探索与内置 review 子 agent 使用 `gpt-6.1-sol`（effort medium）；实施、测试与 findings 修复一律由主 agent 执行，不启动子 agent。

See .claude/skills/ship/SKILL.md

当前产品基线与字段分类遵循 `docs/rules/api-versioning.md`、`docs/rules/ai-robust.md`；
模型、读写、生成、验证和规则按所属实施项闭环，不另设版本/兼容门禁。
