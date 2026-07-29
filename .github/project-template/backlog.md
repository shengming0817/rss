<!--
Backlog issue body 模版 — 经 `bash hack/automation/forge.sh issue-create "<title>" <填好的本文件> "<labels>"` 创建。
labels（`backlog` + `area-XX` + `type-XX` + `pri-pX` + `cx-X`）与 title `[<ID>] <简短标题>` 由建 issue 的一方用显式标签参数给（非 epic backlog 四轴齐全，cx 必填、无 unknown sentinel）；取值见 PROJECT.md §2/§3。

由 review/fix finding（OUT_OF_SCOPE / 派生）成文时，**无损映射**自 finding 详表（`pr-comment.md` 的 `<details>`），不得一句话带过：
  现状     ← 证据代码片段 + 三维根因（代码/架构/历史）+ 影响范围（直接/间接/同类 Grep N 处）
  修复方向 ← 三级方案种子（最小 / 彻底 / 重构）
  Files    ← finding 的 file:line 全集（不止主命中行）
  Source   ← `PR #<N> finding <Fk>`（OOS 自动建单再加 `Discovered via /ship|/fix #<N>`）
-->

## 现状

<当前代码状态 / 已落地 / 已尝试方案；finding 成文时填：证据代码片段 + 三维根因 + 影响范围>

## 修复方向

<设计思路 / 替代方案 / 范围；finding 成文时填：三级方案种子（最小 / 彻底 / 重构）>

## Production acceptance evidence plan

<!--
仅当 issue 新增、扩展、替换或重新声明 T3 production acceptance carrier，或切换 production assembly artifact
journey 时保留本节；其余 issue 删除整节，不填 N/A。字段语义以
`docs/rules/project-scope.md` §Production acceptance evidence plan 与 carrier replacement 为单一事实源。
每个独立 invariant / join hazard 复制一份下方 item，不得把多个独立 hazard 藏在一个不可选择的 target 后。
-->

### <Evidence ID> — <production assembly / invariant 或 join hazard>

- Canonical owner: `<T1|T2|T3> / <exact executable target and assertion>`
- T1/T2 prerequisites: `<target → 所证事实 → candidate revision receipt；未满足时填 blocking issue 与绿色标准>`
- T3 incremental proof: `<仅 production 组合后新增的 assertion>`
- Lower-layer gap: `<为何 T1/T2 无法观测该失效模式>`
- Reproduction: `<exact test/filter/subcommand>`
- Cost: `<timeout / 预计耗时 / 外部资源 / 执行频率或 profile>`
- Change kind: `<activation | extension-or-redeclaration | replacement>`
- Carrier transition: `<activation：candidate + activation/registration 条件；extension-or-redeclaration：canonical owner/assertion 前 → 后 + 接纳条件；replacement：old → candidate + canonical selector 切换条件 + 同交付删除项；artifact journey replacement 另列 assemblies/artifacts.toml 指针>`

## Files

- path/to/file1.rs:line
- path/to/file2.rs:line

## Trigger

<仅条件延后型（贴 `flag-cond` label）填：触发条件文本——什么事件 / PR 发生后才动手>

## Source

<来源：`PR #<N> finding <Fk>` / review path / issue#；OOS 自动建单加 `Discovered via /ship|/fix #<N>`>
