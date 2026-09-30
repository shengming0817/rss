<!--
Epic body 模版 — 顶层容器（Work Item Type = Epic，PROJECT.md §1.1 工作项层级）。
按当前流程在 Azure Boards UI 手工建；脚本化时先过门 `bash hack/automation/issue-labels.sh validate --labels "epic,backlog,area-XX,pri-pX" --tier epic`，再 `bash hack/automation/forge.sh issue-create "[EPIC] <能力级标题>" <填好的本文件> "epic,backlog,area-XX,pri-pX" "$AZURE_WI_TYPE_EPIC"`（第 4 参指定 Epic 类型）。
labels = `epic` + `backlog` + `area-XX` + `pri-pX`（容器不贴 `cx` / `type` —— §1.1 / §2.6）。
子项默认是 **PBI**；明确需要中间容器时才使用 **Feature**。用原生父子关系经 `forge.sh subissue-link` 关联。
-->

## 目标 / 范围

<这个 epic 要达成什么能力级结果，边界在哪>

## 验收标准

- [ ] <所有子任务 close + 何种端到端能力可用>

## 实施顺序

见最新的可见 `pm:epic-wave` 评论；本正文只承载目标与验收，实施顺序由评论记录。
