#!/bin/sh
# Hard-deny all subagent launches (subagentStart).
# Consumes stdin JSON; always blocks.
cat >/dev/null
printf '%s\n' '{"permission":"deny","user_message":"子 Agent 启动已被 .cursor/hooks 禁止。请由主 Agent 直接完成任务；如需放开，删除或注释 hooks.json 中的 subagentStart。"}'
exit 0
