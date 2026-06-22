<!--
Feature body 模版 — 中层容器（Work Item Type = Feature，PROJECT.md §1.1 三层映射的中层；跨多 PR）。
按当前流程在 Azure Boards UI 手工建；脚本化时先过门 `bash hack/automation/issue-labels.sh validate --labels "backlog,area-XX,pri-pX" --tier feature`，再 `bash hack/automation/forge.sh issue-create "[<阶段ID>] <能力块标题>" <填好的本文件> "backlog,area-XX,pri-pX" "$AZURE_WI_TYPE_FEATURE"`（第 4 参指定 Feature 类型）。
labels = `backlog` + `area-XX` + `pri-pX`（容器不贴 `cx` / `type` —— §1.1 / §2.6）。
parent = 所属 **Epic**；子项是 **Product Backlog Item**（≈ 一个 PR）。父子关系经 `forge.sh subissue-link <epic#> <feature#>` 与 `forge.sh subissue-link <feature#> <pbi#>` 写原生关系（不在 body 手写 task list）。
-->

## 目标 / 范围

<这个 feature 要交付什么能力块，边界在哪；它在所属 Epic 下解决哪一段>

## 验收标准

- [ ] <所有子 PBI close + 该能力块何种端到端行为可用 / 治理绿>
