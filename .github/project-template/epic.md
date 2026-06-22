<!--
Epic body 模版 — 顶层容器（Work Item Type = Epic，PROJECT.md §1.1 三层映射的顶层）。
按当前流程在 Azure Boards UI 手工建；脚本化时先过门 `bash hack/automation/issue-labels.sh validate --labels "epic,backlog,area-XX,pri-pX" --tier epic`，再 `bash hack/automation/forge.sh issue-create "[EPIC] <能力级标题>" <填好的本文件> "epic,backlog,area-XX,pri-pX" "$AZURE_WI_TYPE_EPIC"`（第 4 参指定 Epic 类型）。
labels = `epic` + `backlog` + `area-XX` + `pri-pX`（容器不贴 `cx` / `type` —— §1.1 / §2.6）。
子项是 **Feature**（再下挂 PBI），用原生父子关系经 `forge.sh subissue-link` 关联（不在 body 手写 task list）。
-->

## 目标 / 范围

<这个 epic 要达成什么能力级结果，边界在哪>

## 验收标准

- [ ] <所有子任务 close + 何种端到端能力可用>

## 实施顺序

<!-- 实施顺序承载在「以可见 token pm:epic-wave 起头」的评论（Azure 剥离 HTML 注释，故 marker 用可见 token）；技能只追加评论，不写看板 Wave 字段、不改 epic body。滚动：仅列 OPEN 的 Wave 1-4，已完成与超窗(Wave 4 之后)单列 -->

Wave 1: #aaa, #bbb
Wave 2: #ccc（blocked-by #aaa）
超窗(Wave 4 之后): #fff
