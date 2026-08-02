---
name: issues
description: "激活 forge 的 issue/work-item tracker + 看板，处理 epic 子任务关联、wave 实施顺序评论（blocked-by DAG、依赖层级自然展开、wave 内并行组/串行链），或核查普通 issue 是否仍成立。不修改代码、issue body、label 或看板字段。"
allowed-tools: [Read, Grep, Bash, Agent, AskUserQuestion]
---

# issues — Epic/Wave 编排 + Issue 状态核查

> 真源 = 激活 forge 的 issue 系统（GitHub Issues / Azure Boards / GitLab Issues）+ 激活 forge 的看板（Azure Boards / GitHub Project / GitLab）。issue/epic 内容结构见 `.github/project-template/`，label/字段/评级见 `PROJECT.md`；本技能只做状态核查与 Epic/Wave 编排。
> 输入分派：**`epic #N` / 带 `epic` label 的 issue** → 拆解 + wave 调度；**普通 issue 号（无 `epic` label）** → 下方「非 epic issue 状态核查」。
> repo 标识经 `bash hack/automation/forge.sh repo-slug` 取得；看板经激活 forge 的看板机制管理，不写死平台路径。

---

## 非 epic issue 状态核查（查代码判状态，只判不修）

输入普通 issue 号（无 `epic` label）时，不排 wave，而是查代码判断该 issue 是否仍成立：

1. `bash hack/automation/forge.sh issue-view <N>` 读问题描述 + body 的 Files。
2. 按 Files / 关键字 Read/Grep 定位代码；跨 3+ 文件时并行派 `Agent(Explore)` 核查。
3. 判状态（**只判不修**）：**存在** / **已修复**（给证据：哪行 / 哪 PR）/ **已变更**（形态变化）/ **无法确认**。
4. 输出状态 + 证据 + 建议：需修 → 建议 `/ship #<N>`（或定位到 file:line 后 `/fix`）；已修复 / 过期 → 建议用 `forge.sh issue-close` 关闭。

---

# Epic 拆解 + Wave 实施顺序评论

> 负责 epic 级「找子任务 → 排 wave → 追加 epic 评论」。不写 Project 字段，不改 epic body。

## A1. 读 epic → 关键字查找相关 issues → 关联 → 汇总子 issues

1. **读 epic**：`bash hack/automation/forge.sh issue-view <epic#>`（确认 epic label；从 title + 目标/范围提取关键字）。
2. **关键字查找相关 issues**：`bash hack/automation/forge.sh issue-list "<关键字>" open`，挑出属于本 epic 的候选；用 AskUserQuestion 确认候选集（不擅自全关联）。
3. **关联到 epic**（建父子关系，已关联的跳过）：
   ```bash
   bash hack/automation/forge.sh subissue-link <epic#> <child#>
   ```
4. **汇总子 issues**：经 forge 列出 epic 子任务（`bash hack/automation/forge.sh issue-list "" open` 结合父子关系过滤，或激活 forge 的父子关系 API）；对每个 OPEN 子任务读 label（area/type/pri）+ body 的 `Blocked-by: #NNN`（多行/逗号分隔，无声明=无前置）。

> 子任务跨 3+ 包或描述模糊时，用 `Agent(Explore)` 核实归属 / 状态 / `Blocked-by` 再汇总（**wave 内冲突分区 + 实施顺序的分析在 A2 第 5 步，见下**）。

## A2. 建 blocked-by DAG + wave 依赖层级排序（Wave 1-N，无容量上限）

**滚动依赖层级算法**（每次更新 epic 都重跑；作用域 = epic 的 **OPEN** 子任务）。wave 只表达依赖先后，不承担并发容量限制；不限制每个 wave 的 issue 数量，也不限制 wave 总数：

1. **节点 = OPEN 子任务**；CLOSED（已完成）子任务**排除**——不参与排序，仅在评论中单列为已完成。
2. 有向边 `blocker → dependent`（来自 `Blocked-by`），**仅当 blocker 也 OPEN**；blocker 已 close = 依赖已满足 → 删该边。**这是「滚动」的来源**：前置完成后 dependent 自动前移到更早 wave。
3. 检测环：若有环，AskUserQuestion 让用户裁定断哪条边（不静默）。
4. **按依赖深度分 wave**：
   - 无 OPEN blocker 的节点进入 Wave 1。
   - 其余节点按 `wave(node) = 1 + max(wave(open blocker))` 分配，依赖链有多深就自然展开到 Wave N。
   - `pri`(p0>p1>p2>p3) → **基础性产出先** → `Cx`(小先，由 `cx-X` label 提供) → issue# 仅用于同一 wave 内的展示与串行定序，不改变依赖层级。
5. **wave 内冲突分区**（确认「真并行」vs「须串行」）：对每个 wave（成员 ≥2）**并行**派 `Agent(Explore)` 分析其中每个任务的 scope / 触碰文件 / 产出↔消费 / 风险，主 agent 汇总后切：
   - **并行组**：两两**无文件重叠 + 无隐式产出↔消费 + 无资源冲突** → 可同时跑。「可并行」= 经冲突分析确认无冲突，**非**仅「无 `Blocked-by`」。
   - **串行链**：有上述任一冲突 → 须串行，链内按 `pri` → 基础性产出先 → `Cx` → issue# 定序，并注明冲突原因（如「同改 foo.rs」）。
   - 单任务 wave 跳过分析。
6. 输出每个 OPEN 子任务的 `(wave, 并行组/串行链, 链内序)`。

呈现给用户的 dry-run 表（只列 OPEN；已完成单列）：

```
Wave 1（无 OPEN blocker）:
  并行组 A（零冲突，可同时）: #a(p0·Cx1)  #b(p0·Cx2)
  串行链 B（#c→#d 同改 foo.rs，按 pri）: [1] #c(p1·Cx2)  [2] #d(p2·Cx1)
Wave 2（依赖 Wave 1）:
  并行组 A: #g(p1·Cx2 ←blocked-by #a)
Wave 5（按依赖深度自然展开，无 Wave 4 上限）:
  并行组 A: #z(p3·Cx1 ←blocked-by #q)
已完成(不动): #y
```

## A3. 追加 epic 实施顺序评论

```bash
# 只追加评论；不编辑 epic body，不写 Project 字段。
# 把评论正文写入临时文件，再经 forge 贴出。
# ⚠ Azure work-item 评论服务端强制 HTML 消毒（?format=markdown 也拦不住）：HTML 注释 <!-- --> 被整段剥离、
#   裸 < / > 被编码成 &lt; / &gt;（代码围栏里显示字面量）。故 marker 用可见 token `pm:epic-wave`（不再用
#   HTML 注释），正文全程不写裸尖括号 / 行首 blockquote（用「之后 / 越 W4」等措辞替代）。
#   marker 现仅作可见锚点：就地更新去重是后续 forge upsert 能力（暂未接，评论仍 append）。
cat > /tmp/epic-wave-comment.md <<'C'
`pm:epic-wave`
🌊 Epic 实施顺序更新：OPEN 按 blocked-by 依赖深度自然展开到 Wave 1-N，不限制每 wave 数量或 wave 总数；wave 内标明并行组 / 串行链；已完成单列。排序结果只写在本评论中，不写 Project 字段，不改 epic body。

粘贴 A2 dry-run 表（不带尖括号占位符）
C
bash hack/automation/forge.sh issue-comment <epic#> /tmp/epic-wave-comment.md
```

## A4. 沟通规则

- 环检测命中：停下 AskUserQuestion。
- DAG 排序结果先 dry-run 呈现，确认后只追加 epic 评论。
- 不改子任务代码 / 不关 issue / 不改 area-type-pri label。

---
