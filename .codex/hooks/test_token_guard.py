#!/usr/bin/env python3
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
HOOK_PATH = HERE / "token_guard.py"
CONFIG_PATH = HERE.parent / "hooks.json"


def load_hook_module():
    spec = importlib.util.spec_from_file_location("token_guard", str(HOOK_PATH))
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载 token_guard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TokenGuardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hook = load_hook_module()

    def run_hook(self, event, env=None):
        payload = json.dumps(event, ensure_ascii=False)
        merged = os.environ.copy()
        if env:
            merged.update(env)
        completed = subprocess.run(
            [sys.executable, str(HOOK_PATH)],
            input=payload,
            text=True,
            capture_output=True,
            env=merged,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout.strip()

    def parse_rewrite(self, stdout):
        self.assertTrue(stdout, "expected rewrite JSON on stdout")
        body = json.loads(stdout)
        specific = body["hookSpecificOutput"]
        self.assertEqual(specific["hookEventName"], "PreToolUse")
        self.assertEqual(specific["permissionDecision"], "allow")
        self.assertIn("updatedInput", specific)
        return specific["updatedInput"], specific.get("additionalContext")

    def test_hooks_json_registers_pre_tool_use_token_guard(self):
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertIn("PreToolUse", config["hooks"])
        groups = config["hooks"]["PreToolUse"]
        matchers = {group.get("matcher") for group in groups}
        self.assertIn("spawn_agent|Agent", matchers)
        self.assertIn("wait_agent", matchers)
        self.assertIn("Bash", matchers)
        for group in groups:
            command = group["hooks"][0]["command"]
            self.assertIn("token_guard.py", command)
            self.assertIn(".venv/bin/python", command)
            self.assertIn("/usr/bin/python3", command)

    def test_spawn_omitted_fork_turns_rewritten_to_none(self):
        stdout = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "spawn_agent",
                "tool_input": {
                    "task_name": "review_security",
                    "message": "review diff only",
                },
            }
        )
        updated, note = self.parse_rewrite(stdout)
        self.assertEqual(updated["fork_turns"], "none")
        self.assertEqual(updated["task_name"], "review_security")
        self.assertIn("fork_turns", note or "")

    def test_spawn_all_rewritten_to_none(self):
        stdout = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Agent",
                "tool_input": {
                    "task_name": "x",
                    "message": "y",
                    "fork_turns": "all",
                },
            }
        )
        updated, _ = self.parse_rewrite(stdout)
        self.assertEqual(updated["fork_turns"], "none")

    def test_spawn_over_limit_rewritten(self):
        stdout = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "spawn_agent",
                "tool_input": {"message": "m", "fork_turns": "9"},
            }
        )
        updated, _ = self.parse_rewrite(stdout)
        self.assertEqual(updated["fork_turns"], "none")

    def test_spawn_none_and_small_int_passthrough(self):
        for fork in ("none", "1", "3"):
            stdout = self.run_hook(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "spawn_agent",
                    "tool_input": {"message": "m", "fork_turns": fork},
                }
            )
            self.assertEqual(stdout, "", fork)

    def test_wait_agent_short_timeout_raised(self):
        stdout = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "wait_agent",
                "tool_input": {"timeout_ms": 30000, "targets": ["agent-1"]},
            }
        )
        updated, note = self.parse_rewrite(stdout)
        self.assertEqual(updated["timeout_ms"], 600000)
        self.assertEqual(updated["targets"], ["agent-1"])
        self.assertIn("timeout_ms", note or "")

    def test_wait_agent_omitted_timeout_raised(self):
        stdout = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "wait_agent",
                "tool_input": {},
            }
        )
        updated, _ = self.parse_rewrite(stdout)
        self.assertEqual(updated["timeout_ms"], 600000)

    def test_wait_agent_long_timeout_passthrough(self):
        stdout = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "wait_agent",
                "tool_input": {"timeout_ms": 600000},
            }
        )
        self.assertEqual(stdout, "")

    def test_wait_agent_over_hard_max_clamped(self):
        stdout = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "wait_agent",
                "tool_input": {"timeout_ms": 9_999_999},
            }
        )
        updated, _ = self.parse_rewrite(stdout)
        self.assertEqual(updated["timeout_ms"], 3_600_000)

    def test_bash_empty_write_stdin_poll_yield_raised(self):
        command = (
            'const r = await tools.write_stdin('
            '{session_id:6838, chars:"", yield_time_ms:1000});'
        )
        stdout = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }
        )
        updated, note = self.parse_rewrite(stdout)
        self.assertIn("yield_time_ms: 60000", updated["command"])
        self.assertNotIn("yield_time_ms:1000", updated["command"].replace(" ", ""))
        self.assertIn("write_stdin", note or "")

    def test_bash_non_empty_write_stdin_passthrough(self):
        command = 'await tools.write_stdin({session_id:1, chars:"exit\\n", yield_time_ms:1000})'
        stdout = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }
        )
        self.assertEqual(stdout, "")

    def test_bash_unrelated_command_passthrough(self):
        stdout = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "cargo test -p vocab"},
            }
        )
        self.assertEqual(stdout, "")

    def test_malformed_stdin_fail_open(self):
        completed = subprocess.run(
            [sys.executable, str(HOOK_PATH)],
            input="not-json",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.strip(), "")

    def test_unit_normalize_fork_turns(self):
        self.assertEqual(self.hook.normalize_fork_turns(None), "none")
        self.assertEqual(self.hook.normalize_fork_turns("all"), "none")
        self.assertEqual(self.hook.normalize_fork_turns("0"), "none")
        self.assertEqual(self.hook.normalize_fork_turns("4"), "none")
        self.assertIsNone(self.hook.normalize_fork_turns("none"))
        self.assertIsNone(self.hook.normalize_fork_turns("2"))

    def test_optional_log_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "guard.jsonl"
            stdout = self.run_hook(
                {
                    "hook_event_name": "PreToolUse",
                    "session_id": "s1",
                    "tool_name": "spawn_agent",
                    "tool_input": {"message": "m"},
                },
                env={"CODEX_TOKEN_GUARD_LOG": str(log)},
            )
            self.assertTrue(stdout)
            lines = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["action"], "rewrite_spawn")
            self.assertEqual(entry["session_id"], "s1")


if __name__ == "__main__":
    unittest.main()
