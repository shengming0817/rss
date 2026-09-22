#!/usr/bin/env python3
"""Codex PreToolUse token guard: rewrite expensive defaults, never deny-loop.

Primary lever (openai/codex spawn.rs): omitted fork_turns defaults to \"all\".
This hook rewrites omit / all / >MAX_FORK_TURNS to fork_turns=\"none\".

Secondary: Bash/exec payloads whose command string polls via empty write_stdin
cannot use native write_stdin PreToolUse (handler returns None). When the poll
is embedded in a Bash/exec command string, bump yield_time_ms in-place.

Tertiary: short wait_agent timeout_ms polls burn a full parent model turn each
time. Raise omit / short timeouts toward TARGET_WAIT_AGENT_TIMEOUT_MS (clamped
to Codex HARD_MAX 1h). Code-mode `wait` intentionally skips PreToolUse upstream
and cannot be rewritten here.

Fail-open on malformed input. Prefer updatedInput rewrite over deny so the
model does not burn another full-context turn retrying.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any, Optional


MAX_FORK_TURNS = 2
TARGET_FORK_TURNS = "none"
MIN_EMPTY_WRITE_STDIN_YIELD_MS = 60_000
# Codex multi_agents_common: HARD_MAX = 3600_000; default model poll ≈ 30_000.
MIN_WAIT_AGENT_TIMEOUT_MS = 120_000
TARGET_WAIT_AGENT_TIMEOUT_MS = 300_000
HARD_MAX_WAIT_AGENT_TIMEOUT_MS = 3_600_000
SPAWN_TOOL_NAMES = {"spawn_agent", "Agent"}
WAIT_AGENT_TOOL_NAMES = {"wait_agent"}
BASH_TOOL_NAMES = {"Bash", "bash", "exec_command", "exec"}
WRITE_STDIN_CALL_RE = re.compile(
    r"write_stdin\s*\(\s*(\{.*?\})\s*\)",
    re.DOTALL | re.IGNORECASE,
)
YIELD_RE = re.compile(
    r"""(['"]?)yield_time_ms\1\s*:\s*(\d+)""",
    re.IGNORECASE,
)
EMPTY_CHARS_RE = re.compile(
    r"""(['"]?)chars\1\s*:\s*(['"])\s*\2""",
    re.IGNORECASE,
)

COORDINATION_NOTE = (
    "子 agent 调用间隔：wait_agent timeout_ms 至少 120000，通常 300000；"
    "对同一子 agent 的 list_agents/send_message/followup_task 非紧急调用至少间隔 5 分钟，"
    "禁止连续短周期 list_agents 或逐步骤催问。仅在需求改变、安全风险、文件冲突、"
    "明确请求信息或新证据将导致大面积返工时立即协调；"
    "interrupt_agent 仅用于方向错误、失控、冲突、需求变更或继续执行可能造成损失。"
)
CI_NOTE = (
    "make ci 返回 session 后仅空输入 write_stdin 续等，yield_time_ms 取工具及上级约束允许的最大值"
    "（exec_command 上限 30000 ms）；禁止频繁查询日志、进程或 artifact；"
    "完整结束后集中修复，仅复验失败项及受影响测试，同阶段不重跑完整 CI。"
)


def is_make_ci(command: str) -> bool:
    """Recognize literal shell invocations; never interpret scripts or heredoc data."""
    if "<<" in command:
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        words = list(lexer)
    except ValueError:
        return False
    segment = []
    for word in words + [";"]:
        if word and all(c in ";&|()\n" for c in word):
            while segment and (re.match(r"^[A-Za-z_][A-Za-z_0-9]*=", segment[0])
                               or segment[0] in {"env", "command", "time"}):
                segment.pop(0)
            if segment and Path(segment[0]).name in {"make", "gmake"}:
                # Skip values of options that consume a following argument.
                args = iter(segment[1:])
                for arg in args:
                    if arg in {"-C", "-f", "--directory", "--file", "--makefile", "-I"}:
                        next(args, None)
                    elif arg == "ci":
                        return True
            segment = []
        else:
            segment.append(word)
    return False


def emit_context(event_name: str, note: str) -> None:
    emit({"hookSpecificOutput": {"hookEventName": event_name, "additionalContext": note}})


def emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.write("\n")


def allow_rewrite(updated_input: dict, note: Optional[str] = None) -> None:
    specific: dict[str, Any] = {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "updatedInput": updated_input,
    }
    if note:
        specific["additionalContext"] = note
    emit({"hookSpecificOutput": specific})


def maybe_log(event: dict, action: str, detail: str) -> None:
    raw = os.environ.get("CODEX_TOKEN_GUARD_LOG")
    if not raw:
        return
    try:
        path = Path(raw).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "session_id": event.get("session_id"),
                        "tool_name": event.get("tool_name"),
                        "action": action,
                        "detail": detail,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    except OSError:
        pass


def normalize_fork_turns(value: Any) -> Optional[str]:
    if value is None:
        return TARGET_FORK_TURNS
    text = str(value).strip()
    if not text:
        return TARGET_FORK_TURNS
    if text.lower() == "all":
        return TARGET_FORK_TURNS
    if text.lower() == "none":
        return None
    try:
        n = int(text)
    except ValueError:
        return TARGET_FORK_TURNS
    if n <= 0 or n > MAX_FORK_TURNS:
        return TARGET_FORK_TURNS
    return None


def rewrite_spawn(tool_input: Any) -> Optional[tuple[dict, str]]:
    if not isinstance(tool_input, dict):
        return None
    updated = dict(tool_input)
    decision = normalize_fork_turns(updated.get("fork_turns"))
    if decision is None:
        return None
    updated["fork_turns"] = decision
    return updated, "fork_turns->%s" % decision


def rewrite_write_stdin_object_text(obj_text: str) -> Optional[str]:
    if not EMPTY_CHARS_RE.search(obj_text):
        # Also treat missing chars as empty poll (schema default).
        if re.search(r"""(['"]?)chars\1\s*:""", obj_text, re.IGNORECASE):
            return None
    match = YIELD_RE.search(obj_text)
    if match:
        current = int(match.group(2))
        if current >= MIN_EMPTY_WRITE_STDIN_YIELD_MS:
            return None
        quote = match.group(1) or ""
        replacement = "%syield_time_ms%s: %d" % (
            quote,
            quote,
            MIN_EMPTY_WRITE_STDIN_YIELD_MS,
        )
        return YIELD_RE.sub(replacement, obj_text, count=1)
    # No yield_time_ms: insert after opening brace.
    insert = " yield_time_ms: %d," % MIN_EMPTY_WRITE_STDIN_YIELD_MS
    if obj_text.startswith("{"):
        return "{" + insert + obj_text[1:]
    return None


def rewrite_bash_command(command: str) -> Optional[str]:
    if "write_stdin" not in command:
        return None
    rewritten = command
    changed = False
    for match in list(WRITE_STDIN_CALL_RE.finditer(command)):
        obj_text = match.group(1)
        new_obj = rewrite_write_stdin_object_text(obj_text)
        if new_obj is None:
            continue
        rewritten = rewritten.replace(match.group(0), "write_stdin(%s)" % new_obj, 1)
        changed = True
    return rewritten if changed else None


def rewrite_bash(tool_input: Any) -> Optional[tuple[dict, str]]:
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if not isinstance(command, str) or not command:
        return None
    new_command = rewrite_bash_command(command)
    if new_command is None:
        return None
    updated = dict(tool_input)
    updated["command"] = new_command
    return updated, "empty write_stdin yield_time_ms->%d" % MIN_EMPTY_WRITE_STDIN_YIELD_MS


def normalize_wait_agent_timeout_ms(value: Any) -> Optional[int]:
    """Return rewritten timeout_ms, or None when the current value is acceptable."""
    if value is None or value == "":
        return TARGET_WAIT_AGENT_TIMEOUT_MS
    try:
        current = int(value)
    except (TypeError, ValueError):
        return TARGET_WAIT_AGENT_TIMEOUT_MS
    if current <= 0:
        return TARGET_WAIT_AGENT_TIMEOUT_MS
    if current < MIN_WAIT_AGENT_TIMEOUT_MS:
        return TARGET_WAIT_AGENT_TIMEOUT_MS
    if current > HARD_MAX_WAIT_AGENT_TIMEOUT_MS:
        return HARD_MAX_WAIT_AGENT_TIMEOUT_MS
    return None


def rewrite_wait_agent(tool_input: Any) -> Optional[tuple[dict, str]]:
    if not isinstance(tool_input, dict):
        return None
    decision = normalize_wait_agent_timeout_ms(tool_input.get("timeout_ms"))
    if decision is None:
        return None
    updated = dict(tool_input)
    updated["timeout_ms"] = decision
    return updated, "timeout_ms->%d" % decision


def handle_pre_tool_use(event: dict) -> None:
    tool_name = str(event.get("tool_name") or "").split(".")[-1]
    tool_input = event.get("tool_input")

    if tool_name in {"list_agents", "send_message", "followup_task", "interrupt_agent"}:
        emit_context("PreToolUse", COORDINATION_NOTE)
        return

    if tool_name in SPAWN_TOOL_NAMES:
        result = rewrite_spawn(tool_input)
        if result is None:
            return
        updated, detail = result
        maybe_log(event, "rewrite_spawn", detail)
        allow_rewrite(
            updated,
            note="token_guard: fork_turns rewritten to none (Codex default all is forbidden).",
        )
        return

    if tool_name in WAIT_AGENT_TOOL_NAMES:
        result = rewrite_wait_agent(tool_input)
        if result is None:
            return
        updated, detail = result
        maybe_log(event, "rewrite_wait_agent", detail)
        allow_rewrite(
            updated,
            note=(
                "token_guard: wait_agent timeout_ms raised to reduce parent "
                "full-context poll turns."
            ),
        )
        return

    if tool_name in BASH_TOOL_NAMES:
        command = tool_input.get("command", tool_input.get("cmd", "")) if isinstance(tool_input, dict) else ""
        if isinstance(command, str) and is_make_ci(command):
            emit_context("PreToolUse", CI_NOTE)
            return
        result = rewrite_bash(tool_input)
        if result is None:
            return
        updated, detail = result
        maybe_log(event, "rewrite_bash_poll", detail)
        allow_rewrite(
            updated,
            note="token_guard: empty write_stdin poll yield_time_ms raised to reduce model turns.",
        )


def main() -> int:
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
    except (ValueError, TypeError):
        return 0
    if not isinstance(event, dict):
        return 0
    try:
        event_name = event.get("hook_event_name")
        if event_name == "PreToolUse":
            handle_pre_tool_use(event)
        elif event_name == "PostToolUse":
            tool_input = event.get("tool_input")
            if isinstance(tool_input, dict) and str(event.get("tool_name", "")).split(".")[-1] in BASH_TOOL_NAMES:
                command = tool_input.get("command", tool_input.get("cmd", ""))
                if isinstance(command, str) and is_make_ci(command):
                    emit_context("PostToolUse", CI_NOTE)
    except Exception:
        # Fail-open: never block Codex on guard bugs.
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
