---
name: fix
description: "问题诊断与修复: 验证+根因+复杂度分级+修复方案+backlog登记。当用户说'这个问题存在吗''帮我分析这个bug''诊断一下这个模块''修复这个问题'时触发。支持单条问题和多方审查报告批量输入。"
argument-hint: "<问题描述|文件:行号|review报告路径>"
allowed-tools: [Read, Write, Edit, Glob, Grep, Bash, Agent, AskUserQuestion]
---

> **子 agent 约束（覆盖下文）**：全程不启动任何子 agent，由主 agent 自行完成定位、分析与修复。

See .claude/skills/fix/SKILL.md

当前产品基线与字段分类以 `docs/rules/api-versioning.md`、`docs/rules/ai-robust.md` 为准；
本包装不增加兼容、全字段闭合或全局升版要求，不改变 RSS/Identity 的受保护承诺。
