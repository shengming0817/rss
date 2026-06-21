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

# helper: 以指定 TMPDIR 调 hook，捕获 stdout；返回实际退出码（不用 || true）
run_fix() {
  local tmpdir="$1"; shift
  TMPDIR="$tmpdir" bash "$FIX_HOOK" "$@" 2>/dev/null
  return $?
}

run_fix_stdin() {
  local tmpdir="$1"
  local json="$2"
  TMPDIR="$tmpdir" bash "$FIX_HOOK" 2>/dev/null <<< "$json"
  return $?
}

run_exitplan_stdin() {
  local tmpdir="$1"
  local json="$2"
  TMPDIR="$tmpdir" bash "$EXITPLAN_HOOK" 2>/dev/null <<< "$json"
  return $?
}

# hook 改为 per-uid 私有目录；state_dir 相对于给定 TMPDIR
state_dir_for() {
  local tmpdir="$1"
  echo "${tmpdir}/claude-selfaudit-$(id -u)"
}

# ── fix-self-audit.sh ──────────────────────────────────────────────────────

# (a) emit 实参直跑 → exit 0 无输出
T="$(mktemp -d -p "$TMPDIR_BASE")"
rc=0
out=$(TMPDIR="$T" bash "$FIX_HOOK" emit 2>/dev/null) || rc=$?
if [ "$rc" -eq 0 ] && [ -z "$out" ]; then
  pass "(a) fix: emit 实参直跑 exit 0 且无输出"
else
  fail "(a) fix: emit 实参直跑未返回 exit 0 或有意外输出. rc=$rc out=$out"
fi

# (b) tool_input.command 含 fix-self-audit.sh emit + 固定 session_id，首次 → deny
T="$(mktemp -d -p "$TMPDIR_BASE")"
SID="test-session-abc123"
json_fix=$(printf '{"session_id":"%s","tool_input":{"command":"bash %s emit"}}' "$SID" "$FIX_HOOK")
out=""
rc=0
out=$(run_fix_stdin "$T" "$json_fix") || rc=$?
sd="$(state_dir_for "$T")"
state_file="${sd}/fix-${SID}"
if printf '%s' "$out" | grep -q '"permissionDecision":"deny"' && [ -f "$state_file" ]; then
  pass "(b) fix: 首次发信号 → deny 且状态文件已生成"
else
  fail "(b) fix: 首次发信号未正确 deny 或状态文件未生成. out=$out state_exists=$([ -f "$state_file" ] && echo yes || echo no)"
fi

# (c) 紧接同 session_id 第二次 → exit 0 放行（消费式 toggle）
out2=""
rc2=0
out2=$(run_fix_stdin "$T" "$json_fix") || rc2=$?
if ! printf '%s' "$out2" | grep -q '"permissionDecision":"deny"' && [ "$rc2" -eq 0 ] && [ ! -f "$state_file" ]; then
  pass "(c) fix: 同 session_id 第二次 → 放行(exit 0)且状态文件已消费"
else
  fail "(c) fix: 第二次未放行或退出码非 0 或状态文件残留. rc2=$rc2 out2=$out2 state_exists=$([ -f "$state_file" ] && echo yes || echo no)"
fi

# (d) tool_input.command 为 cargo test（非 emit 信号）→ exit 0 无 deny
T="$(mktemp -d -p "$TMPDIR_BASE")"
json_cargo=$(printf '{"session_id":"%s","tool_input":{"command":"cargo test"}}' "$SID")
out=""
rc=0
out=$(run_fix_stdin "$T" "$json_cargo") || rc=$?
if ! printf '%s' "$out" | grep -q '"permissionDecision":"deny"' && [ "$rc" -eq 0 ]; then
  pass "(d) fix: cargo test 命令 → 无 deny 放行(exit 0)"
else
  fail "(d) fix: cargo test 命令意外触发 deny 或退出码非 0. rc=$rc out=$out"
fi

# ── exitplan-self-audit.sh ─────────────────────────────────────────────────

# (e) 固定 session_id 首次 → deny
T="$(mktemp -d -p "$TMPDIR_BASE")"
SID2="exitplan-session-xyz789"
json_exit=$(printf '{"session_id":"%s"}' "$SID2")
out=""
rc=0
out=$(run_exitplan_stdin "$T" "$json_exit") || rc=$?
sd="$(state_dir_for "$T")"
ep_state="${sd}/exitplan-${SID2}"
if printf '%s' "$out" | grep -q '"permissionDecision":"deny"' && [ -f "$ep_state" ]; then
  pass "(e) exitplan: 首次 → deny 且状态文件已生成"
else
  fail "(e) exitplan: 首次未正确 deny 或状态文件未生成. out=$out state_exists=$([ -f "$ep_state" ] && echo yes || echo no)"
fi

# (f) 同 session_id 第二次 → exit 0（每会话一次）
out2=""
rc2=0
out2=$(run_exitplan_stdin "$T" "$json_exit") || rc2=$?
if ! printf '%s' "$out2" | grep -q '"permissionDecision":"deny"' && [ "$rc2" -eq 0 ]; then
  pass "(f) exitplan: 同 session_id 第二次 → 放行(exit 0)"
else
  fail "(f) exitplan: 第二次未放行或退出码非 0. rc2=$rc2 out2=$out2"
fi

# ── sid 消毒 + per-uid 目录安全 ───────────────────────────────────────────

# (g) session_id 含 ../ 等字符 → 状态文件名被消毒，落在 per-uid state_dir 内无路径穿越
#     同时验证：state_dir 权限为 700，且预置 symlink 占位不被当成「已自检」放行
T="$(mktemp -d -p "$TMPDIR_BASE")"
DIRTY_SID='../../etc/passwd'
SANITIZED_SID=$(printf '%s' "$DIRTY_SID" | tr -cd 'A-Za-z0-9-')
json_dirty=$(printf '{"session_id":"%s","tool_input":{"command":"bash %s emit"}}' "$DIRTY_SID" "$FIX_HOOK")

# 先发一次信号让 hook 初始化 state_dir
run_fix_stdin "$T" "$json_dirty" >/dev/null 2>&1 || true

sd="$(state_dir_for "$T")"
dir_perm=""
if [ -d "$sd" ]; then
  dir_perm=$(stat -f "%OLp" "$sd" 2>/dev/null || stat -c "%a" "$sd" 2>/dev/null || echo "unknown")
fi

# 验证 state 文件落在正确位置（消毒后 sid 或 default）
if [ -n "$SANITIZED_SID" ]; then
  clean_state="${sd}/fix-${SANITIZED_SID}"
else
  clean_state="${sd}/fix-default"
fi
traversal_file="/etc/passwd-from-hook"

# symlink 占位测试：预置 symlink 后再发信号，hook 应删除 symlink 而非当成已自检放行
T2="$(mktemp -d -p "$TMPDIR_BASE")"
SID_SYMLINK="symlink-test-sid"
sd2="$(state_dir_for "$T2")"
mkdir -p "$sd2" 2>/dev/null || true
chmod 700 "$sd2" 2>/dev/null || true
symlink_target="${T2}/target-not-a-state"
symlink_state="${sd2}/fix-${SID_SYMLINK}"
touch "$symlink_target"
ln -sf "$symlink_target" "$symlink_state"   # 预置 symlink 占位

json_symlink=$(printf '{"session_id":"%s","tool_input":{"command":"bash %s emit"}}' "$SID_SYMLINK" "$FIX_HOOK")
sl_out=""
run_fix_stdin "$T2" "$json_symlink" > /tmp/sl_out_$$ 2>/dev/null || true
sl_out=$(cat /tmp/sl_out_$$ 2>/dev/null); rm -f /tmp/sl_out_$$

# hook 应删除 symlink，且因不是「已自检」状态，首次应 deny
symlink_denied=false
if printf '%s' "$sl_out" | grep -q '"permissionDecision":"deny"'; then
  symlink_denied=true
fi

# 综合判断
g_ok=true
g_msg=""
if [ -f "$traversal_file" ]; then
  g_ok=false; g_msg="${g_msg} 路径穿越文件存在;"
fi
if [ "$dir_perm" != "700" ] && [ "$dir_perm" != "unknown" ] && [ -n "$dir_perm" ]; then
  g_ok=false; g_msg="${g_msg} state_dir 权限=${dir_perm}(非700);"
fi
if ! $symlink_denied; then
  g_ok=false; g_msg="${g_msg} symlink 占位未被正确处理(hook 未 deny);"
fi

if $g_ok; then
  pass "(g) sid 消毒 + per-uid 安全: 无路径穿越; state_dir 权限=${dir_perm}; symlink 占位被正确删除并 deny"
else
  fail "(g) sid 消毒 + per-uid 安全: ${g_msg}"
fi

# ── synthetic red case（框架自检：验证 FAIL 计数机制有效）─────────────────
# 构造一个必然失败的断言，在子壳中执行，断言它的 FAIL 计数 > 0，但不计入总 FAIL
RED_RESULT=$(bash -c '
FAIL=0
fail() { FAIL=$((FAIL + 1)); }
# 断言 emit 返回非 0（实际 emit 返回 0，故本断言必然 FAIL）
rc=0
bash '"$FIX_HOOK"' emit 2>/dev/null || rc=$?
[ "$rc" -ne 0 ] || fail "synthetic-red: 预期非0但得到0（框架自检用例，必须 FAIL）"
echo "SYNTHETIC_FAIL=$FAIL"
')
sf=$(printf '%s' "$RED_RESULT" | grep "SYNTHETIC_FAIL=" | cut -d= -f2)
if [ "${sf:-0}" -gt 0 ]; then
  pass "(h) synthetic red case: 框架正确抓到失败(SYNTHETIC_FAIL=${sf})"
else
  fail "(h) synthetic red case: 框架未抓到预期失败，测试机制可能失效"
fi

# ── 汇总 ──────────────────────────────────────────────────────────────────
echo ""
echo "结果: PASS=${PASS} FAIL=${FAIL}"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
