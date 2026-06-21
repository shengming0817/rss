---
name: pr-monitor
description: "PR 状态自动接力检查器：ship/fix 收尾约 10min 后必须启动；读取外部 app/review 已产生的 label + 最新机器块，检测到 needs-fix 即接力 /fix——Cx/scope/熔断判定全由 /fix 自理。pr-monitor 自身不贴评论、不切 label。"
argument-hint: "<PR#> --mode=auto [--role fix|review]"
allowed-tools: [Bash, Read, Skill, Agent]
---

# pr-monitor — PR 状态自动接力检查器（fix 侧）

> **适用场景**：ship/fix 推完 PR 后，延迟约 10 分钟必须启动一次 `/pr-monitor <PR#> --mode=auto`。外部 app 负责实时监听 `pr-status/needs-review-again` / `pr-status/needs-check-fix` 并执行 review/check；本技能只检查这些流程产出的 label + 机器块，并在满足自动门时接力 `/fix`。
>
> **单 tick 模型**：每次调用只做一次检查就返回；不携带 tick payload、不写文件，状态全部从 PR 实时读取（label + 最新机器块）。

---

## §0 角色与边界

**主要角色**：fix 侧监控（默认）；`--role=review` 时可主动触发 review 侧（见 §4）。

**路由依据**：所有自动分支判定基于 **PR label + 最新 fresh canonical 机器块**（`bash hack/automation/forge.sh pr-state <N>` + `bash hack/automation/pr-meta.sh extract <N>`）。label 表示当前状态，机器块证明状态来源与下一跳契约；二者必须一致。

`--mode=auto` 是唯一支持的运行模式；保留该 flag 是为了让 ship/fix 的收尾命令形态稳定。

---

## §1 输入解析

```bash
PR="${1#\#}"; [[ "$PR" =~ ^[0-9]+$ ]] || { echo "error: invalid PR number: $1"; exit 1; }
MODE=auto; ROLE=fix
shift; while [[ $# -gt 0 ]]; do case "$1" in
  --mode=auto)    MODE=auto ;;
  --role=*)       ROLE="${1#--role=}" ;;
  *) echo "unknown flag: $1" >&2; exit 1 ;;
esac; shift; done
```

---

## §2 每 tick 逻辑（顶层控制流）

每次 `/pr-monitor` 调用按序执行，做完即返回：

1. **读 PR 状态（一次 forge 调用，兼存在性校验）**：
   ```bash
   STATE=$(bash hack/automation/forge.sh pr-state "$PR") \
     || { echo "error: PR #$PR not found / forge auth failed"; exit 1; }
   ```
2. **§3.1 终止检查**（优先；命中即打印结束语并返回）。
3. 按 `$ROLE` 分支：`--role=review` → §4；否则执行自动接力（§3.2-3.4）。
4. 返回；单次调用到此结束。

> **无 cursor / 无时间戳追增量**：「有无待修 findings」由 **label + 最新机器块**判定——`pr-status/needs-fix` 在即「review 给了结论待修」，幂等可重报。

---

## §3 fix 侧逻辑

### §3.1 终止条件（命中即结束）

| 条件 | 判定 | 窗口输出 |
|------|------|---------|
| `pr-status/ready` ∈ labels | label 含 | "PR #N 已 ready，监控结束" |
| PR state != open | `state != "open"` | "PR #N 已关闭（state=$STATE），监控结束" |

> ready/closed 是终止出口；review↔fix 3 轮熔断已下放 `/fix` 自判（fix 输入解析的熔断闸门读 `pr-meta.sh round`）。ship/fix 经延迟单次调用本技能、跑完即止。

### §3.2 调 fix（有 needs-fix 即接力）

`pr-status/needs-fix` ∈ labels → host LLM in-session 调用 `Skill("fix", args="<N>")`。Cx / scope / 能否修 / 熔断（3 轮上限）全由 fix 自读评论 + 机器块（`pr-meta.sh extract` / `round`）判定——pr-monitor 不做机器门判定。

fix 会贴 pm:fix + 切 `pr-status/needs-check-fix`；pr-monitor 本次单次调用到此结束。后续 `/pr-review --check` 由外部 app 监听触发，再由 fix 收尾延迟约 10 分钟启动下一次 pr-monitor 接力。

### §3.3 不自动修的情况（只报告，不 AskUserQuestion）

- **`pr-status/needs-review-again`**：窗口打印 "PR #N 待外部 app 执行首轮 review；如需手动兜底，运行 `/pr-monitor <N> --mode=auto --role=review`"。
- **`pr-status/needs-check-fix`**：窗口打印 "PR #N 待外部 app 执行 `/pr-review --check`；如需手动兜底，运行 `/pr-monitor <N> --mode=auto --role=review`"。
- **无 `pr-status/needs-fix`**：窗口打印 "PR #N 暂无待修 label，本次接力结束"。

### §3.4 冲突解（复用 issues B5）

```bash
MERGEABLE=$(bash hack/automation/forge.sh pr-mergeable "$PR")
```

`UNKNOWN` → 轮询（≤5 次，间隔 10s）落定。`CONFLICTING` → 在 PR 的**已有** dev worktree 内解（不新建）：

```bash
HEAD_REF=$(bash hack/automation/forge.sh pr-refs "$PR" | jq -r .headRef)
WT_PATH=$(git worktree list --porcelain | awk -v b="$HEAD_REF" \
  '/^worktree / {wt=$2} /^branch / && $2 == "refs/heads/"b {print wt; exit}')
if [[ -n "$WT_PATH" ]]; then
  REMOTE=$(bash hack/automation/forge.sh remote)
  git -C "$WT_PATH" fetch "$REMOTE" && git -C "$WT_PATH" merge "$REMOTE/develop" --no-edit && git -C "$WT_PATH" push
else
  echo "pr-monitor: 无 PR 分支对应的已有 worktree，请人工解冲突" >&2
fi
```

解完后返回；下一次接力调用回 §3.1 重检。

---

## §4 alternate review 能力（`--role=review`）

review 角色 in-session 按当前 `pr-status` 跑 review/check（Claude review 引擎）：

```bash
if [[ " ${LABELS[*]} " == *" pr-status/needs-check-fix "* ]]; then
  claude -p "/pr-review $PR --check"
else
  claude -p "/pr-review $PR"
fi
```

review 结果由 /pr-review 贴评论 + 切 label；fix 侧接力仍由后续 `/pr-monitor <PR#> --mode=auto` 完成。

---

## §5 沟通规则

**窗口打印是主输出**；pr-monitor 自身不贴 PR 评论（贴评论是 /fix 或 /pr-review 的职责）。

| 路径 | 允许的副作用 |
|------|------------|
| fix 侧自动接力 | 有 `needs-fix` 时 `Skill("fix")`；§3.4 冲突时 git merge + push |
| `--role=review` | §4 调 `claude -p "/pr-review"`；review 贴 pm:pr-review 评论 + 切 label 由 /pr-review 完成（非 pr-monitor 自身） |

**label 切换**：pr-monitor 不直接切 `pr-status/*`（由 /fix 或 /pr-review 完成）。

**不自动处理**的情况统一报告，不 AskUserQuestion。
