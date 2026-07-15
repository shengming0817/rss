#!/usr/bin/env python3
"""Allow only first-level subagents (spawned by a root/main conversation).

Live payload evidence:
- L1: conversation_id = main chat, transcript_path set
- L2: conversation_id = L1 agent UUID, transcript_path null

Handles: sessionStart | subagentStart | preToolUse(Task)
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(__file__).resolve().parent / "state"
LOG = STATE_DIR / "subagent-start.log"
ROOTS = STATE_DIR / "root-conversations.txt"

DENY_MSG = "二级及以下子 Agent 已被 hooks 拦截（仅允许主 Agent 启动一级子 Agent）。"


def _log(msg: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(msg if msg.endswith("\n") else msg + "\n")


def _load_roots() -> set[str]:
    if not ROOTS.exists():
        return set()
    return {line.strip() for line in ROOTS.read_text(encoding="utf-8").splitlines() if line.strip()}


def _save_roots(roots: set[str]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    ROOTS.write_text("\n".join(sorted(roots)) + ("\n" if roots else ""), encoding="utf-8")


def _read_payload() -> tuple[str, dict]:
    raw = sys.stdin.read()
    _log(f"----- {datetime.now(timezone.utc).isoformat()} -----\n{raw}")
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        _log("WARN invalid JSON")
        data = {}
    return raw, data


def _promote_root(data: dict, roots: set[str]) -> set[str]:
    conv_id = str(data.get("conversation_id") or data.get("session_id") or "")
    transcript = data.get("transcript_path")
    if conv_id and transcript:
        roots.add(conv_id)
        _save_roots(roots)
        _log(f"ROOT via transcript {conv_id}")
    return roots


def _is_root_caller(data: dict) -> bool:
    roots = _load_roots()
    roots = _promote_root(data, roots)
    conv_id = str(data.get("conversation_id") or data.get("session_id") or "")
    return bool(conv_id and conv_id in roots)


def handle_session_start(data: dict) -> None:
    roots = _load_roots()
    cid = str(data.get("conversation_id") or data.get("session_id") or "")
    if cid:
        roots.add(cid)
        _save_roots(roots)
        _log(f"ROOT sessionStart {cid}")
    print("{}")


def handle_subagent_start(data: dict) -> None:
    conv_id = str(data.get("conversation_id") or data.get("session_id") or "")
    parent_id = str(data.get("parent_conversation_id") or "")
    model = str(data.get("subagent_model") or "")
    stype = str(data.get("subagent_type") or "")
    if _is_root_caller(data):
        _log(f"ALLOW L1 conv={conv_id} parent={parent_id} type={stype} model={model}")
        print(json.dumps({"permission": "allow"}))
        return
    _log(f"DENY L2+ [subagentStart] conv={conv_id} parent={parent_id} type={stype} model={model}")
    print(json.dumps({"permission": "deny", "user_message": DENY_MSG}, ensure_ascii=False))


def handle_pre_tool_use(data: dict) -> None:
    tool = str(data.get("tool_name") or "")
    conv_id = str(data.get("conversation_id") or data.get("session_id") or "")
    if tool != "Task":
        print(json.dumps({"permission": "allow"}))
        return
    if _is_root_caller(data):
        _log(f"ALLOW L1 [preToolUse Task] conv={conv_id}")
        print(json.dumps({"permission": "allow"}))
        return
    _log(f"DENY L2+ [preToolUse Task] conv={conv_id}")
    print(
        json.dumps(
            {
                "permission": "deny",
                "user_message": DENY_MSG,
                "agent_message": DENY_MSG + " Do not retry Task. Report the deny verbatim.",
            },
            ensure_ascii=False,
        )
    )


def main() -> None:
    _, data = _read_payload()
    event = str(data.get("hook_event_name") or "")
    if event == "sessionStart":
        handle_session_start(data)
    elif event == "preToolUse":
        handle_pre_tool_use(data)
    else:
        handle_subagent_start(data)


if __name__ == "__main__":
    main()
