#!/bin/sh
# Belt-and-suspenders: block Task tool via preToolUse (matcher: Task).
cat >/dev/null
printf '%s\n' '{"permission":"deny","user_message":"Task 工具已被 .cursor/hooks 禁止，无法启动子 Agent。","agent_message":"Do not retry Task/subagent. Complete the work yourself with local tools (Read/Grep/Shell/etc.)."}'
exit 0
