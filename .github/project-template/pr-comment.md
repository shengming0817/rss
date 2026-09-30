# PR 评论格式（`pm:ship` / `pm:fix` / `pm:pr-review` 模板单源）

> 何时贴 / 留痕约定 / 标记规则见 `PROJECT.md` §5；P + Cx 评级见 §3。
> **footer 必填**（每个模板末尾那行）：AI 自填 `<Claude Code|Codex>`、PR 号、head 分支、**worktree 路径**（当前工作目录；develop 直改填 `—`）、**session 会话id**（AI 想办法拿到，如 `$CLAUDE_CODE_SESSION_ID` / codex 等价；拿不到填 `—`）。
> **贴完回显评论 URL**：`bash hack/automation/forge.sh pr-comment <N> <body-file>` 的 stdout 返回评论 URL（含定位锚点），贴完必须捕获并回显给用户。

> **评论即 review 结果，无损（关键约定）**：评论是 `/fix <PR#>` 提取 findings 的**唯一来源**。
> 每条 Finding **必带 `file:line`**（fix 据此定位，不重新 review），根因 + 证据 + 建议 + 三级方案种子写进 `<details>`（人看摘要、fix 读详表，两不丢）。
> **OUT_OF_SCOPE finding 同享无损区，不准降级成计数 `OUT_OF_SCOPE <k>`**：每条 OOS 带 file:line + 证据 + 三维根因（代码/架构/历史）+ 三级方案种子 + Files 列表 + **处置（自动建的 issue #N 或 `deferred` 原因）**，由 ship/fix **自动 `bash hack/automation/forge.sh issue-create`**（body 按 `backlog.md` 字段映射：现状←证据+根因+影响 / 修复方向←方案种子 / Files←file:line 全集 / Source←`PR #<N> finding <Fk>`）无损成文，详记入独立 pm:oos 评论。
> **IN_SCOPE Cx3/Cx4 必带批量处置结果，不准停留在 `遗留`**：ship/fix 先为全部 IN_SCOPE Cx3/Cx4 生成建议及理由，再发起一次批量处置请求；用户可全盘采纳建议，或按 finding ID 覆盖个别项。没有 IN_SCOPE Cx3/Cx4 时不发起沟通。评论里每项必标 `✅ 已修（批量处置确认）` 或 `⏸ defer：已建 #N（<原因>）`（判 defer 后自动建 issue、不二次确认）——`⏸ 遗留（需人工决策）` 这类**未决态不得带过切 label**。
> **禁止有损浓缩**——只写计数 / 模糊一句话会让 fix 与后续建 issue 丢失定位与根因，违背本约定。

## 可读记录

评论正文写明本阶段实际处理的完整 head SHA、审查/修复结论和验证结果；切状态使用同一 SHA。
`pm:*` 标记仅供按评论类型检索，不携带隐藏执行状态。findings、OOS 处置和修复轮次依据可读评论核对。

## ship 评论（`<!-- pm:ship -->`）

```markdown
<!-- pm:ship -->
## 🛠 ship review + fix

**提交**：<本阶段实际处理的完整 head SHA>

**reviewer** <数> · **Findings** <总数>（已修 Cx1/Cx2 <n> · Cx3/Cx4 处置 <m>（修/defer）· OUT_OF_SCOPE <k>）

- **F1** [P1·Cx2·安全] `path/to/file.rs:120` — <一句话> → ✅ 已修
- **F2** [P2·Cx3·DX] `path/to/x.rs:88` — <一句话> → ⏸ defer：已建 #N（<原因>）（或 ✅ 已修（批量处置确认））
- **F3** [P2·Cx2·运维] `other/pkg/z.rs:64` — <一句话> → 🚦 OUT_OF_SCOPE（详见本 PR 的 pm:oos 评论）

<details><summary>完整详表（根因 + 证据 + 建议 + 方案种子，/fix 读此）</summary>

**F1** [P1·Cx2·安全] `path/to/file.rs:120`
- 证据：`<code 片段>`
- 建议：<彻底修复方向>
- 处置：✅ 已修（commit <sha>）

**F2** [P2·Cx3·DX] `path/to/x.rs:88`（IN_SCOPE）
- 证据：`<code 片段>`
- 三级方案种子：最小 <…> / 彻底 <…> / 重构 <…>
- 处置（批量处置门判修/defer，非未决）：⏸ defer（已建 #N，原因：<…>）｜或 ✅ 已修（批量处置确认：<措施>，commit <sha>）
</details>

**下一步**：切 `pr-status/needs-review-again`（待再审：codex / `/pr-review`）。

---
🤖 PR <N> · Generated with <Claude Code|Codex> · branch <head 分支> · worktree <路径|—> · session <会话id|—>
```

## fix 评论（`<!-- pm:fix -->`，每次 fix 都贴）

```markdown
<!-- pm:fix -->
## 🔁 fix（findings triage + fix）

**提交**：<本阶段实际处理的完整 head SHA>

**Findings** <总数>（已修 Cx1/Cx2 <n> · Cx3/Cx4 处置 <m>（修/defer）· OUT_OF_SCOPE <k>）

- **F1** [P1·Cx2·安全] `path/to/file.rs:120` — <一句话> → ✅ 已修
- **F2** [P2·Cx3·DX] `path/to/x.rs:88` — <一句话> → ⏸ defer：已建 #N（<原因>）（或 ✅ 已修（批量处置确认））
- **F3** [P2·Cx2·运维] `other/pkg/z.rs:64` — <一句话> → 🚦 OUT_OF_SCOPE（详见本 PR 的 pm:oos 评论）

<details><summary>完整详表（triage 依据 + 证据 + 建议，下次 fix 读此）</summary>

**F1** [P1·Cx2·安全] `path/to/file.rs:120`（IN_SCOPE）
- 证据：`<code 片段>`
- 修复：<做了什么> → ✅ commit <sha>

**F2** [P2·Cx3·DX] `path/to/x.rs:88`（IN_SCOPE，批量处置门）
- 三级方案种子：最小 <…> / 彻底 <…> / 重构 <…>
- 处置（批量处置门判修/defer，非未决）：⏸ defer（已建 #N，原因 + 升级窗口：<…>）｜或 ✅ 已修（批量处置确认：<措施>，commit <sha>）
</details>

**下一步**：切 `pr-status/needs-check-fix`（待 `/pr-review --check` 验证；fix 不直接到 ready）。

---
🤖 PR <N> · Generated with <Claude Code|Codex> · branch <head 分支> · worktree <路径|—> · session <会话id|—>
```

## pr-review 评论（`<!-- pm:pr-review -->`，独立 review 留痕）

> 评论 = 阶段 5 的五块**完整**写入（不浓缩）：summary + 根因簇 + Finding 列表（带 file:line）+ 详表 details + 修复分流 + 结论。
> **`--check` 变体**（验证上一轮 findings，见 pr-review 模式 B）：Finding 列表每条用 `✅已修复 / ❌未修复 / ⚠️回归 / 🔧部分 / 🔲范围外(合理)` 替代「→ 簇 C{m}」；summary 用 `已修复 N / 未修复 M / 回归 K / 部分 J / 范围外合理 R（🔲）/ 误判OSS S`；详表 `<details>` 记每条验证证据；结论给流转建议（无触发 → ready / 有遗留含误判OSS → 回 /fix）。

```markdown
<!-- pm:pr-review -->
## 🔍 pr-review（六维度分级审查）

**提交**：<本阶段实际处理的完整 head SHA>

**根因簇** <N> · **Findings** <M>（P0 <a>·P1 <b>·P2 <c>·P3 <d> ｜ Cx1 <w>·Cx2 <x>·Cx3 <y>·Cx4 <z>）· **结论** <通过/需修复/需讨论>

**根因簇**
- **C1** <根因一句>（维度 <…>；系统性 Grep <N> 处）→ F1,F3

**Findings**（每条带 file:line，/fix 无损提取）
- **F1** [P1·Cx2·安全] `path/to/file.rs:120` — <一句话> → 簇 C1
- **F2** [P2·Cx3·DX] `path/to/x.rs:88` — <一句话> → 簇 C1

<details><summary>完整详表（证据 + 建议 + 根因 + 方案种子，/fix 读此）</summary>

**F1** [P1·Cx2·安全] `path/to/file.rs:120`（→ C1）
- 证据：`<code 片段>`
- 建议：<彻底修复方向>

**F2** [P2·Cx3·DX] `path/to/x.rs:88`（→ C1）
- 证据：`<code 片段>`
- 三级方案种子：最小 <…> / 彻底 <…> / 重构 <…>
</details>

**修复分流**：Cx1/Cx2 → `/fix`；Cx3/Cx4 → 需人工决策（方案种子见详表）。<若 PR body 含 closing keyword 附 `← issue #<N>`>
**结论**：<一句话理由>

---
🤖 PR <N> · Generated with <Claude Code|Codex> · branch <head 分支> · worktree <路径|—> · session <会话id|—>
```

## pm:ci 评论（`<!-- pm:ci -->`）

> 外部 CI-capable producer 的检查结果记录；ship/fix 的验证由各自技能编排，交接遵循 [PROJECT](PROJECT.md) §5 的状态契约。本评论只记录外部检查结果，不触发自动修复。

```markdown
<!-- pm:ci -->
## CI 检查结果

**提交**：<本阶段实际处理的完整 head SHA>

**状态**：<通过 / 失败>（已通过 <n> / 共 <total> 个检查）

<若有失败>
**失败检查**：
- `<check-name>` — <url>

---
🤖 PR <N> · Generated with <Claude Code|Codex> · branch <head 分支> · worktree <路径|—> · session <会话id|—>
```

## pm:oos 评论（`<!-- pm:oos -->`）

> Out-of-scope findings 的**无损**独立记录。ship/fix 在贴本评论前按 `backlog.md` 成文、经 `issue-labels.sh validate` 后用 `forge.sh issue-create` 把每条 finding 落为 backlog issue，正文回填 issue 号；无法自动建（`pri-p0` incident / area·type 判不定）的标 `deferred` 并回退草稿。每条 finding 为一个 lossless item（file:line + 三维根因 + 三级方案种子 + 处置 `issue`｜`deferred`），逐条保留在下面的可读记录中。与 pm:ship / pm:fix 解耦：OOS finding 移出主评论详表，改为一行指针（`→ 🚦 OUT_OF_SCOPE（详见本 PR 的 pm:oos 评论）`）。

```markdown
<!-- pm:oos -->
## Out-of-Scope Findings（已自动建 issue）

**提交**：<本阶段实际处理的完整 head SHA>

**OOS Findings** <k> 条（已从 pm:ship/pm:fix 的主评论分离，本评论为无损存档；每条已建 issue 或显式 deferred）

**F3** [P2·Cx2·运维] `other/pkg/z.rs:64`（🚦 OUT_OF_SCOPE，属 `other/` 子系统）
- 证据：`<code 片段>`
- 三维根因：代码 <…> / 架构 <1 处局部｜Grep N 处系统性> / 历史 <git log 同类>
- 三级方案种子：最小 <…> / 彻底 <…> / 重构 <…>
- 影响范围：直接 <…> / 间接 <…> / 同类 <Grep N 处>
- Files：`other/pkg/z.rs:64` `other/pkg/w.rs:30`
- → ✅ 已建 issue **#<N>** <url>（body 按 backlog.md：现状←证据+根因+影响 / 修复方向←方案种子 / Files←上行 / Source←`PR #<N> F3`；四轴 `backlog,pri-p2,area-XX,type-XX,cx-2`，cx 从 finding `[…Cx…]` tag 取，此例 F3=Cx2）
  - 无法自动建时改记 `🟡 deferred:<pri-p0-incident｜labels-underivable>` + 草稿命令 `bash hack/automation/forge.sh issue-create "[<ID>] <标题>" <backlog.md> "backlog,pri-pX,area-XX,type-XX,cx-X"`

---
🤖 PR <N> · Generated with <Claude Code|Codex> · branch <head 分支> · worktree <路径|—> · session <会话id|—>
```
