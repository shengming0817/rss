---
name: pr-review
description: "对指定 PR 跑自动分级六维度 review（默认）；或 --check 模式验证上一轮 findings 是否修复 + 抓回归。按 diff 净增删行数自动分配 2/3/6 reviewer agent 并行（< 200 行不派发，主 agent 自审）；主 agent 做根因聚类 + Cx 分级 + 修复分流建议，不自动 fix。"
argument-hint: "<PR 编号> [--check]"
allowed-tools: [Read, Glob, Grep, Bash, Agent]
---

> **子 agent 约束（覆盖下文）**：派发的 reviewer 子 agent 统一使用 `gpt-5.6-sol`（effort medium）。

See .claude/skills/pr-review/SKILL.md

**完成后对根因进行开源对标，给出修复方向**
