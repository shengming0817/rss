#!/bin/sh
# Allow L1 (spawned by root/main). Deny L2+ (spawned by an existing subagent).
# Strategy: remember every allowed subagent_id; if parent_conversation_id
# matches a known subagent, this is nested → deny.
# Also log full payload for debugging.

STATE_DIR="${CURSOR_PROJECT_DIR:-.}/.cursor/hooks/state"
# Prefer workspace-relative path from script location
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STATE_DIR="$SCRIPT_DIR/state"
LOG="$STATE_DIR/subagent-start.log"
KNOWN="$STATE_DIR/known-subagents.txt"

mkdir -p "$STATE_DIR"
input=$(cat)
printf '%s\n' "----- $(date -u +%Y-%m-%dT%H:%M:%SZ) -----" >>"$LOG"
printf '%s\n' "$input" >>"$LOG"

# Extract fields without jq
get_field() {
  printf '%s' "$input" | sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -n1
}

subagent_id=$(get_field subagent_id)
parent_id=$(get_field parent_conversation_id)
conv_id=$(get_field conversation_id)
model=$(get_field subagent_model)
stype=$(get_field subagent_type)

touch "$KNOWN"

# Nested if parent is already a known subagent
if [ -n "$parent_id" ] && grep -Fxq "$parent_id" "$KNOWN" 2>/dev/null; then
  printf '%s\n' "DENY nested parent=$parent_id subagent=$subagent_id type=$stype model=$model" >>"$LOG"
  printf '%s\n' '{"permission":"deny","user_message":"二级及以下子 Agent 已被 hooks 拦截（仅允许主 Agent 启动一级子 Agent）。"}'
  exit 0
fi

# Also: if conversation_id (caller) is a known subagent, deny
if [ -n "$conv_id" ] && grep -Fxq "$conv_id" "$KNOWN" 2>/dev/null; then
  printf '%s\n' "DENY caller_is_subagent conv=$conv_id subagent=$subagent_id" >>"$LOG"
  printf '%s\n' '{"permission":"deny","user_message":"二级及以下子 Agent 已被 hooks 拦截（调用方已是子 Agent）。"}'
  exit 0
fi

# Allow L1: record this subagent_id (and conversation_id if different) as known
if [ -n "$subagent_id" ]; then
  grep -Fxq "$subagent_id" "$KNOWN" 2>/dev/null || printf '%s\n' "$subagent_id" >>"$KNOWN"
fi
printf '%s\n' "ALLOW L1 parent=$parent_id conv=$conv_id subagent=$subagent_id type=$stype model=$model" >>"$LOG"
printf '%s\n' '{"permission":"allow"}'
exit 0
