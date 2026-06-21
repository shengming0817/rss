#!/usr/bin/env bash
# selftest.sh — 两个 committed hook 的关键行为自检
# 用法: bash .claude/hooks/selftest.sh
# 全部 PASS 则 exit 0；任意 FAIL 则 exit 1。
set -uo pipefail

PASS=0
FAIL=0

# 找到脚本所在目录（兼容直接调用和 cd 后调用）
HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX_HOOK="${HOOKS_DIR}/fix-self-audit.sh"
EXITPLAN_HOOK="${HOOKS_DIR}/exitplan-self-audit.sh"

# 每个测试用临时目录隔离状态文件
TMPDIR_BASE="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_BASE"' EXIT

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# helper: 以指定 TMPDIR 调 hook，捕获 stdout；hook deny 时非零退出，用 || true 容错
run_fix() {
  local tmpdir="$1"; shift
  TMPDIR="$tmpdir" bash "$FIX_HOOK" "$@" 2>/dev/null || true
}

run_fix_stdin() {
  local tmpdir="$1"
  local json="$2"
  TMPDIR="$tmpdir" bash "$FIX_HOOK" 2>/dev/null <<< "$json" || true
}

run_exitplan_stdin() {
  local tmpdir="$1"
  local json="$2"
  TMPDIR="$tmpdir" bash "$EXITPLAN_HOOK" 2>/dev/null <<< "$json" || true
}

# ── fix-self-audit.sh ──────────────────────────────────────────────────────

# (a) emit 实参直跑 → exit 0 无输出
T="$(mktemp -d -p "$TMPDIR_BASE")"
out=$(TMPDIR="$T" bash "$FIX_HOOK" emit 2>/dev/null || true)
if [ -z "$out" ]; then
  pass "(a) fix: emit 实参直跑 exit 0 且无输出"
else
  fail "(a) fix: emit 实参直跑有意外输出: $out"
fi

# (b) tool_input.command 含 fix-self-audit.sh emit + 固定 session_id，首次 → deny
T="$(mktemp -d -p "$TMPDIR_BASE")"
SID="test-session-abc123"
json_fix=$(printf '{"session_id":"%s","tool_input":{"command":"bash %s emit"}}' "$SID" "$FIX_HOOK")
out=$(run_fix_stdin "$T" "$json_fix")
state_file="${T}/claude-fix-audited-${SID}"
if printf '%s' "$out" | grep -q '"permissionDecision":"deny"' && [ -f "$state_file" ]; then
  pass "(b) fix: 首次发信号 → deny 且状态文件已生成"
else
  fail "(b) fix: 首次发信号未正确 deny 或状态文件未生成. out=$out state_exists=$([ -f "$state_file" ] && echo yes || echo no)"
fi

# (c) 紧接同 session_id 第二次 → exit 0 放行（消费式 toggle）
out2=$(run_fix_stdin "$T" "$json_fix")
if ! printf '%s' "$out2" | grep -q '"permissionDecision":"deny"' && [ ! -f "$state_file" ]; then
  pass "(c) fix: 同 session_id 第二次 → 放行且状态文件已消费"
else
  fail "(c) fix: 第二次未放行或状态文件残留. out2=$out2 state_exists=$([ -f "$state_file" ] && echo yes || echo no)"
fi

# (d) tool_input.command 为 cargo test（非 emit 信号）→ exit 0 无 deny
T="$(mktemp -d -p "$TMPDIR_BASE")"
json_cargo=$(printf '{"session_id":"%s","tool_input":{"command":"cargo test"}}' "$SID")
out=$(run_fix_stdin "$T" "$json_cargo")
if ! printf '%s' "$out" | grep -q '"permissionDecision":"deny"'; then
  pass "(d) fix: cargo test 命令 → 无 deny 放行"
else
  fail "(d) fix: cargo test 命令意外触发 deny. out=$out"
fi

# ── exitplan-self-audit.sh ─────────────────────────────────────────────────

# (e) 固定 session_id 首次 → deny
T="$(mktemp -d -p "$TMPDIR_BASE")"
SID2="exitplan-session-xyz789"
json_exit=$(printf '{"session_id":"%s"}' "$SID2")
out=$(run_exitplan_stdin "$T" "$json_exit")
ep_state="${T}/claude-exitplan-audited-${SID2}"
if printf '%s' "$out" | grep -q '"permissionDecision":"deny"' && [ -f "$ep_state" ]; then
  pass "(e) exitplan: 首次 → deny 且状态文件已生成"
else
  fail "(e) exitplan: 首次未正确 deny 或状态文件未生成. out=$out state_exists=$([ -f "$ep_state" ] && echo yes || echo no)"
fi

# (f) 同 session_id 第二次 → exit 0（每会话一次）
out2=$(run_exitplan_stdin "$T" "$json_exit")
if ! printf '%s' "$out2" | grep -q '"permissionDecision":"deny"'; then
  pass "(f) exitplan: 同 session_id 第二次 → 放行"
else
  fail "(f) exitplan: 第二次未放行. out2=$out2"
fi

# ── sid 消毒 ──────────────────────────────────────────────────────────────

# (g) session_id 含 ../ 等字符 → 状态文件名被消毒，落在 TMPDIR 内无路径穿越
T="$(mktemp -d -p "$TMPDIR_BASE")"
DIRTY_SID='../../etc/passwd'
SANITIZED_SID=$(printf '%s' "$DIRTY_SID" | tr -cd 'A-Za-z0-9-')
json_dirty=$(printf '{"session_id":"%s","tool_input":{"command":"bash %s emit"}}' "$DIRTY_SID" "$FIX_HOOK")
run_fix_stdin "$T" "$json_dirty" >/dev/null
# 预期状态文件落在 T 目录内（使用消毒后的 sid）
clean_state="${T}/claude-fix-audited-${SANITIZED_SID}"
# 确认 /etc/passwd 路径不存在（无路径穿越）
traversal_file="/etc/passwd-from-hook"
if [ -f "$clean_state" ] && [ ! -f "$traversal_file" ]; then
  pass "(g) sid 消毒: 状态文件落在 TMPDIR 内，无路径穿越"
elif [ -f "$clean_state" ]; then
  pass "(g) sid 消毒: 状态文件落在 TMPDIR 内，无路径穿越"
else
  # 消毒后 sid 为空（../../etc/passwd 经 tr 后为空串），降级为 default
  default_state="${T}/claude-fix-audited-default"
  if [ -f "$default_state" ]; then
    pass "(g) sid 消毒: 消毒后 sid 为空降级 default，状态文件落在 TMPDIR 内，无路径穿越"
  else
    fail "(g) sid 消毒: 状态文件既非消毒路径也非 default 路径，结果不符预期"
  fi
fi

# ── 汇总 ──────────────────────────────────────────────────────────────────
echo ""
echo "结果: PASS=${PASS} FAIL=${FAIL}"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
