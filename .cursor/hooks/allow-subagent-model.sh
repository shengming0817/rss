#!/bin/sh
# Optional model allowlist for subagentStart.
# Swap into hooks.json instead of deny-subagent.sh when you want subagents
# but only with approved models.
#
#   ALLOWED_SUBAGENT_MODELS='grok|inherit'  # pipe-separated substrings (case-insensitive)

ALLOWED_SUBAGENT_MODELS="${ALLOWED_SUBAGENT_MODELS:-grok|inherit}"

input=$(cat)
model=$(printf '%s' "$input" | sed -n 's/.*"subagent_model"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
model_lc=$(printf '%s' "$model" | tr '[:upper:]' '[:lower:]')

if [ -z "$model_lc" ]; then
  printf '%s\n' '{"permission":"deny","user_message":"子 Agent 未声明模型，已拒绝。请在自定义 Agent frontmatter 写 model: inherit 或显式模型 ID。"}'
  exit 0
fi

matched=0
rest="$ALLOWED_SUBAGENT_MODELS"
while [ -n "$rest" ]; do
  case "$rest" in
    *\|*)
      pat=${rest%%\|*}
      rest=${rest#*\|}
      ;;
    *)
      pat=$rest
      rest=
      ;;
  esac
  pat_lc=$(printf '%s' "$pat" | tr '[:upper:]' '[:lower:]')
  [ -z "$pat_lc" ] && continue
  case "$model_lc" in
    *"$pat_lc"*)
      matched=1
      break
      ;;
  esac
done

if [ "$matched" -eq 1 ]; then
  printf '%s\n' '{"permission":"allow"}'
  exit 0
fi

# Escape model for JSON string (minimal)
model_json=$(printf '%s' "$model" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf '%s\n' "{\"permission\":\"deny\",\"user_message\":\"子 Agent 模型 '${model_json}' 不在允许列表，已拒绝。允许子串: ${ALLOWED_SUBAGENT_MODELS}\"}"
exit 0
