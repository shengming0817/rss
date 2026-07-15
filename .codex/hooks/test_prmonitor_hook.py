#!/usr/bin/env python3
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

try:
    import tomllib
except ImportError:  # Python 3.9 system fallback has no stdlib TOML parser.
    tomllib = None


HERE = Path(__file__).resolve().parent
HOOK_PATH = HERE / "prmonitor_hook.py"
CONFIG_PATH = HERE.parent / "hooks.json"


def load_hook_module():
    spec = importlib.util.spec_from_file_location("prmonitor_hook", str(HOOK_PATH))
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载 prmonitor_hook.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrmonitorHookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hook = load_hook_module()

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.calls = self.root / "calls.jsonl"
        self.fake_prmonitor = self.root / "prmonitor"
        self.fake_prmonitor.write_text(
            "#!/usr/bin/python3\n"
            "import json, os, sys\n"
            "with open(os.environ['PRMONITOR_TEST_CALLS'], 'a', encoding='utf-8') as f:\n"
            "    f.write(json.dumps(sys.argv[1:], ensure_ascii=False) + '\\n')\n",
            encoding="utf-8",
        )
        self.fake_prmonitor.chmod(0o755)
        self.env = {
            "PRMONITOR_BIN": str(self.fake_prmonitor),
            "PRMONITOR_HOOK_CONFIG": str(self.root / "missing-hook-config.json"),
            "PRMONITOR_INTEGRATION_ID": "feishu-b8a9ec7f",
            "PRMONITOR_CONVERSATION_ID": "oc_42f0b43f40dc692c5d29b4b6df9f632e",
            "PRMONITOR_INCLUDE_CONTENT": "1",
            "PRMONITOR_TEST_CALLS": str(self.calls),
            "CODEX_PRMONITOR_STATE_DIR": str(self.root / "state"),
            "PRMONITOR_DISABLE_WATCHER": "1",
            "PRMONITOR_QUESTION_RETRY_SECONDS": "0.01",
        }

    def tearDown(self):
        self.tempdir.cleanup()

    def read_calls(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]

    def last_message(self):
        calls = self.read_calls()
        self.assertTrue(calls)
        args = calls[-1]
        self.assertEqual(args[:5], [
            "message", "send-card", "--integration-id", "feishu-b8a9ec7f", "--conversation-id",
        ])
        self.assertEqual(args[5], "oc_42f0b43f40dc692c5d29b4b6df9f632e")
        return args[args.index("--text") + 1]

    def last_card(self):
        args = self.read_calls()[-1]
        return {
            "title": args[args.index("--title") + 1],
            "template": args[args.index("--template") + 1],
            "text": args[args.index("--text") + 1],
        }

    def base_event(self, event_name):
        return {
            "hook_event_name": event_name,
            "session_id": "session-1",
            "turn_id": "turn-1",
            "cwd": str(HERE.parent.parent),
            "model": "gpt-test",
            "permission_mode": "default",
            "transcript_path": str(self.root / "rollout.jsonl"),
        }

    def cache_prompt(self, mode="default"):
        event = self.base_event("UserPromptSubmit")
        event.update({"prompt": "实现通知 hooks", "permission_mode": mode})
        Path(event["transcript_path"]).write_text("", encoding="utf-8")
        self.hook.handle_hook(event, self.env)

    def test_config_uses_supported_events_and_prefers_venv(self):
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(set(config["hooks"]), {"UserPromptSubmit", "PermissionRequest", "Stop"})
        for groups in config["hooks"].values():
            command = groups[0]["hooks"][0]["command"]
            self.assertIn(".venv/bin/python", command)
            self.assertIn("/usr/bin/python3", command)
            self.assertIn("/usr/bin/git rev-parse --show-toplevel", command)

    def test_hook_command_prefers_venv_and_falls_back_to_system_python(self):
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        command = config["hooks"]["Stop"][0]["hooks"][0]["command"]
        repo = self.root / "repo"
        hook_dir = repo / ".codex" / "hooks"
        venv_bin = repo / ".venv" / "bin"
        hook_dir.mkdir(parents=True)
        venv_bin.mkdir(parents=True)
        (hook_dir / "prmonitor_hook.py").write_text(
            "import os,sys\nopen(os.environ['PY_USED'],'w').write(sys.executable)\n",
            encoding="utf-8",
        )
        subprocess.run(["/usr/bin/git", "init", "-q", str(repo)], check=True)
        marker = self.root / "python-used"
        shim = venv_bin / "python"
        shim.write_text(
            "#!/bin/sh\nprintf venv > \"$PY_USED\"\nexit 0\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
        env = os.environ.copy()
        env["PY_USED"] = str(marker)
        subprocess.run(["/bin/sh", "-c", command], cwd=str(repo), env=env,
                       input="{}", text=True, check=True)
        self.assertEqual(marker.read_text(encoding="utf-8"), "venv")
        shim.unlink()
        subprocess.run(["/bin/sh", "-c", command], cwd=str(repo), env=env,
                       input="{}", text=True, check=True)
        expected = subprocess.run(
            ["/usr/bin/python3", "-c", "import sys; print(sys.executable)"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(marker.read_text(encoding="utf-8"), expected)

    def test_permission_request_is_operation_approval(self):
        event = self.base_event("PermissionRequest")
        event.update({"permission_mode": "plan", "tool_name": "Bash", "tool_input": {"description": "需要访问受保护资源"}})
        self.hook.handle_hook(event, self.env)
        message = self.last_message()
        self.assertIn("等待操作批准", message)
        self.assertNotIn("等待计划批准", message)
        self.assertEqual(self.last_card()["template"], "orange")

    def test_same_turn_permission_requests_without_call_id_are_distinct(self):
        first = self.base_event("PermissionRequest")
        first.update({
            "tool_name": "Bash",
            "tool_input": {"command": "git fetch", "description": "同步远端"},
        })
        second = self.base_event("PermissionRequest")
        second.update({
            "tool_name": "Bash",
            "tool_input": {"command": "git push", "description": "推送分支"},
        })

        self.hook.handle_hook(first, self.env)
        self.hook.handle_hook(second, self.env)

        self.assertEqual(len(self.read_calls()), 2)

    def test_stop_detects_plan_three_ways(self):
        for current, cached, reply in [
            ("plan", "default", "普通回复"),
            ("default", "plan", "普通回复"),
            ("default", "default", "<proposed_plan>计划</proposed_plan>"),
        ]:
            with self.subTest(current=current, cached=cached):
                self.cache_prompt(cached)
                event = self.base_event("Stop")
                event.update({"permission_mode": current, "last_assistant_message": reply})
                self.hook.handle_hook(event, self.env)
                self.assertIn("等待计划批准", self.last_message())

    def test_default_stop_has_full_context(self):
        self.cache_prompt()
        event = self.base_event("Stop")
        event.update({"stop_reason": "等待用户继续", "last_assistant_message": "已完成诊断"})
        self.hook.handle_hook(event, self.env)
        message = self.last_message()
        for expected in ("任务已停止", "等待用户继续", "session-1", "turn-1", "实现通知 hooks", "已完成诊断"):
            self.assertIn(expected, message)
        card = self.last_card()
        self.assertEqual(
            card["title"],
            "%s · Codex 任务已停止" % HERE.parent.parent.name,
        )
        self.assertEqual(card["template"], "grey")

    def test_content_requires_opt_in(self):
        metadata_only = dict(self.env)
        metadata_only.pop("PRMONITOR_INCLUDE_CONTENT")
        self.hook.handle_hook(dict(self.base_event("UserPromptSubmit"), prompt="敏感任务"), metadata_only)
        self.hook.handle_hook(
            dict(self.base_event("Stop"), stop_reason="敏感原因", last_assistant_message="敏感回复"),
            metadata_only,
        )
        message = self.last_message()
        self.assertNotIn("敏感任务", message)
        self.assertNotIn("敏感原因", message)
        self.assertNotIn("敏感回复", message)

    def test_missing_or_partial_route_does_not_send(self):
        cases = [
            {},
            {"PRMONITOR_INTEGRATION_ID": "environment-integration"},
            {"PRMONITOR_CONVERSATION_ID": "environment-conversation"},
        ]
        for index, route in enumerate(cases):
            with self.subTest(route=route):
                env = dict(self.env)
                env.pop("PRMONITOR_INTEGRATION_ID")
                env.pop("PRMONITOR_CONVERSATION_ID")
                env.update(route)
                event = dict(
                    self.base_event("PermissionRequest"),
                    tool_name="Bash",
                    call_id="missing-route-%d" % index,
                )
                self.hook.handle_hook(event, env)
        self.assertEqual(self.read_calls(), [])

    def test_partial_environment_route_does_not_mix_with_config(self):
        config = self.root / "hook-config.json"
        config.write_text(json.dumps({
            "integration_id": "configured-integration",
            "conversation_id": "configured-conversation",
        }), encoding="utf-8")
        config.chmod(0o600)
        env = dict(self.env)
        env["PRMONITOR_HOOK_CONFIG"] = str(config)
        env["PRMONITOR_INTEGRATION_ID"] = "environment-integration"
        env.pop("PRMONITOR_CONVERSATION_ID")

        self.hook.handle_hook(
            dict(self.base_event("PermissionRequest"), tool_name="Bash"), env,
        )

        self.assertEqual(self.read_calls(), [])

    def test_insecure_or_partial_user_config_route_does_not_send(self):
        for index, config_value in enumerate([
            {"integration_id": "configured-integration"},
            {
                "integration_id": "configured-integration",
                "conversation_id": "configured-conversation",
            },
        ]):
            with self.subTest(config=config_value):
                config = self.root / ("hook-config-%d.json" % index)
                config.write_text(json.dumps(config_value), encoding="utf-8")
                if index == 0:
                    config.chmod(0o600)
                else:
                    config.chmod(0o644)
                env = dict(self.env)
                env["PRMONITOR_HOOK_CONFIG"] = str(config)
                env.pop("PRMONITOR_INTEGRATION_ID")
                env.pop("PRMONITOR_CONVERSATION_ID")
                event = dict(
                    self.base_event("PermissionRequest"),
                    tool_name="Bash",
                    call_id="invalid-config-%d" % index,
                )
                self.hook.handle_hook(event, env)
        self.assertEqual(self.read_calls(), [])

    def test_malformed_user_config_route_does_not_send(self):
        config = self.root / "hook-config.json"
        config.write_text("{broken-json", encoding="utf-8")
        config.chmod(0o600)
        env = dict(self.env)
        env["PRMONITOR_HOOK_CONFIG"] = str(config)
        env.pop("PRMONITOR_INTEGRATION_ID")
        env.pop("PRMONITOR_CONVERSATION_ID")

        self.hook.handle_hook(
            dict(self.base_event("PermissionRequest"), tool_name="Bash"), env,
        )

        self.assertEqual(self.read_calls(), [])

    def test_user_config_overrides_local_route_and_environment_overrides_config(self):
        config = self.root / "hook-config.json"
        config.write_text(json.dumps({
            "integration_id": "configured-integration",
            "conversation_id": "configured-conversation",
            "include_content": True,
        }), encoding="utf-8")
        config.chmod(0o600)
        env = dict(self.env)
        env["PRMONITOR_HOOK_CONFIG"] = str(config)
        env.pop("PRMONITOR_INTEGRATION_ID")
        env.pop("PRMONITOR_CONVERSATION_ID")
        self.hook.handle_hook(dict(self.base_event("PermissionRequest"), tool_name="Bash"), env)
        args = self.read_calls()[-1]
        self.assertEqual(args[args.index("--integration-id") + 1], "configured-integration")
        self.assertEqual(args[args.index("--conversation-id") + 1], "configured-conversation")

        env["PRMONITOR_INTEGRATION_ID"] = "environment-integration"
        env["PRMONITOR_CONVERSATION_ID"] = "environment-conversation"
        event = dict(self.base_event("PermissionRequest"), tool_name="Read")
        event["call_id"] = "second-call"
        self.hook.handle_hook(event, env)
        args = self.read_calls()[-1]
        self.assertEqual(args[args.index("--integration-id") + 1], "environment-integration")
        self.assertEqual(args[args.index("--conversation-id") + 1], "environment-conversation")

    def test_all_hook_notifications_are_cards_without_action_payloads(self):
        self.cache_prompt()
        cases = [
            (dict(self.base_event("PermissionRequest"), tool_name="Bash", call_id="permission"), "orange"),
            (dict(self.base_event("Stop"), permission_mode="plan", call_id="plan"), "orange"),
            (dict(self.base_event("Stop"), stop_reason="done", call_id="stop"), "grey"),
        ]
        for event, template in cases:
            with self.subTest(event=event["hook_event_name"], template=template):
                self.hook.handle_hook(event, self.env)
                args = self.read_calls()[-1]
                self.assertEqual(args[:2], ["message", "send-card"])
                self.assertEqual(args[args.index("--template") + 1], template)
                self.assertNotIn("--actions", args)

    def test_build_card_collects_repository_context_once(self):
        calls = []
        original = self.hook.repository_context

        def fake_repository_context(cwd):
            calls.append(cwd)
            return {
                "name": "rss",
                "root": str(HERE.parent.parent),
                "branch": "feature/test",
                "commit": "0123456789ab",
            }

        self.hook.repository_context = fake_repository_context
        try:
            self.hook.build_card(
                "stopped", self.base_event("Stop"), {}, "done", self.env,
            )
        finally:
            self.hook.repository_context = original

        self.assertEqual(calls, [str(HERE.parent.parent)])

    def test_extracts_all_questions_and_options(self):
        detail = self.hook.extract_question_detail({"questions": [
            {"header": "发布", "question": "选择发布窗口？", "options": [
                {"label": "现在", "description": "立即发布"},
                {"label": "稍后", "description": "等待低峰期"},
            ]},
            {"header": "确认", "question": "是否继续？"},
        ]})
        for expected in ("发布：选择发布窗口？", "现在 — 立即发布", "确认：是否继续？"):
            self.assertIn(expected, detail)

    def test_message_utf8_budget_and_fail_open(self):
        self.cache_prompt()
        event = self.base_event("Stop")
        event["last_assistant_message"] = "中文" * 5000
        self.hook.handle_hook(event, self.env)
        self.assertLessEqual(len(self.last_message().encode("utf-8")), 3800)
        env = dict(self.env)
        env["PRMONITOR_BIN"] = str(self.root / "missing")
        before = len(self.read_calls())
        self.hook.handle_hook(self.base_event("Stop"), env)
        self.assertEqual(len(self.read_calls()), before)

    def test_watcher_incremental_corrupt_json_and_dedupe(self):
        transcript = self.root / "watch.jsonl"
        transcript.write_text('{"type":"old"}\n', encoding="utf-8")
        state_dir = self.root / "watch-state"
        state_dir.mkdir(mode=0o700)
        (state_dir / "state.json").write_text(json.dumps({
            "session_id": "session-watch", "turn_id": "turn-watch",
            "cwd": str(HERE.parent.parent), "initial_prompt": "监听提问",
            "current_prompt": "监听提问", "model": "gpt-test", "permission_mode": "plan",
        }), encoding="utf-8")
        env = os.environ.copy()
        env.update(self.env)
        env.pop("PRMONITOR_DISABLE_WATCHER", None)
        env["PRMONITOR_WATCH_POLL_SECONDS"] = "0.02"
        env["PRMONITOR_WATCH_TTL_SECONDS"] = "5"
        process = subprocess.Popen([
            sys.executable, str(HOOK_PATH), "watch", "--transcript", str(transcript),
            "--offset", str(transcript.stat().st_size), "--state-dir", str(state_dir),
            "--turn-id", "turn-watch",
        ], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            record = {"type": "response_item", "payload": {
                "type": "function_call", "name": "request_user_input", "call_id": "call-1",
                "arguments": json.dumps({"questions": [{"header": "审批", "question": "是否实施？"}]}, ensure_ascii=False),
            }}
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write("not-json\n")
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
                stream.flush()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not self.read_calls():
                time.sleep(0.02)
            calls = self.read_calls()
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][:2], ["message", "send-card"])
            self.assertEqual(calls[0][calls[0].index("--template") + 1], "orange")
            self.assertIn("是否实施？", calls[0][calls[0].index("--text") + 1])
        finally:
            process.terminate()
            process.wait(timeout=3)

    def test_real_watcher_retries_failed_record_without_duplicate_transcript_line(self):
        transcript = self.root / "retry-watch.jsonl"
        transcript.write_text("", encoding="utf-8")
        state_dir = self.root / "retry-watch-state"
        self.hook.atomic_write_json(state_dir / "state.json", {
            "session_id": "session-retry-watch", "turn_id": "turn-retry-watch",
            "cwd": str(HERE.parent.parent), "initial_prompt": "监听重试",
            "current_prompt": "监听重试", "model": "gpt-test", "permission_mode": "default",
        })
        flaky = self.root / "flaky-prmonitor"
        flaky.write_text(
            "#!/usr/bin/python3\n"
            "import json, os, pathlib, sys\n"
            "counter = pathlib.Path(os.environ['PRMONITOR_ATTEMPTS'])\n"
            "attempt = int(counter.read_text() if counter.exists() else '0') + 1\n"
            "counter.write_text(str(attempt))\n"
            "if attempt == 1: raise SystemExit(1)\n"
            "with open(os.environ['PRMONITOR_TEST_CALLS'], 'a', encoding='utf-8') as f:\n"
            "    f.write(json.dumps(sys.argv[1:], ensure_ascii=False) + '\\n')\n",
            encoding="utf-8",
        )
        flaky.chmod(0o755)
        attempts = self.root / "retry-attempts"
        env = os.environ.copy()
        env.update(self.env)
        env.update({
            "PRMONITOR_BIN": str(flaky),
            "PRMONITOR_ATTEMPTS": str(attempts),
            "PRMONITOR_WATCH_POLL_SECONDS": "0.01",
            "PRMONITOR_WATCH_TTL_SECONDS": "5",
        })
        env.pop("PRMONITOR_DISABLE_WATCHER", None)
        process = subprocess.Popen([
            sys.executable, str(HOOK_PATH), "watch", "--transcript", str(transcript),
            "--offset", "0", "--state-dir", str(state_dir), "--turn-id", "turn-retry-watch",
        ], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            record = {"type": "response_item", "payload": {
                "type": "function_call", "name": "request_user_input", "call_id": "call-flaky",
                "arguments": json.dumps({"questions": [{"question": "自动重试？"}]}, ensure_ascii=False),
            }}
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
                stream.flush()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not self.read_calls():
                time.sleep(0.02)
            self.assertEqual(attempts.read_text(encoding="utf-8"), "2")
            self.assertEqual(len(self.read_calls()), 1)
        finally:
            process.terminate()
            process.wait(timeout=3)

    def test_watcher_ttl_cleans_sensitive_state(self):
        transcript = self.root / "ttl-watch.jsonl"
        transcript.write_text("", encoding="utf-8")
        directory = self.root / "ttl-watch-state"
        self.hook.atomic_write_json(directory / "state.json", {
            "session_id": "session-ttl", "turn_id": "turn-ttl", "current_prompt": "敏感任务",
        })
        self.hook.atomic_write_json(directory / "turn-turn-ttl.mcp.json", {"purpose": "human_input"})
        env = dict(self.env)
        env.update({"PRMONITOR_WATCH_TTL_SECONDS": "1", "PRMONITOR_WATCH_POLL_SECONDS": "0.01"})
        self.hook.watch_transcript(transcript, 0, directory, "turn-ttl", env)
        self.assertFalse((directory / "state.json").exists())
        self.assertFalse((directory / "turn-turn-ttl.mcp.json").exists())

    def test_transcript_question_exhaustion_is_terminal(self):
        directory = self.root / "retry-state"
        self.hook.atomic_write_json(directory / "state.json", {
            "session_id": "session-retry",
            "turn_id": "turn-retry",
            "cwd": str(HERE.parent.parent),
        })
        record = {"type": "function_call", "name": "request_user_input", "call_id": "call-retry",
                  "arguments": json.dumps({"questions": [{"question": "是否重试？"}]}, ensure_ascii=False)}
        failed_env = dict(self.env)
        failed_env["PRMONITOR_BIN"] = str(self.root / "missing-prmonitor")

        self.assertFalse(self.hook.process_transcript_record(
            record, directory, "turn-retry", failed_env,
        ))
        retry_state = json.loads((directory / "turn-turn-retry.retry.json").read_text(encoding="utf-8"))
        self.assertEqual(retry_state["call-retry"], self.hook.MAX_QUESTION_SEND_ATTEMPTS)
        self.assertFalse(self.hook.process_transcript_record(
            record, directory, "turn-retry", self.env,
        ))
        self.assertEqual(len(self.read_calls()), 0)

    def test_transcript_question_send_retries_are_bounded(self):
        directory = self.root / "bounded-retry-state"
        self.hook.atomic_write_json(directory / "state.json", {
            "session_id": "session-bounded",
            "turn_id": "turn-bounded",
            "cwd": str(HERE.parent.parent),
        })
        failing_prmonitor = self.root / "failing-prmonitor"
        failing_prmonitor.write_text(
            "#!/usr/bin/python3\n"
            "import os\n"
            "with open(os.environ['PRMONITOR_FAILURE_CALLS'], 'a', encoding='utf-8') as f:\n"
            "    f.write('attempt\\n')\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        failing_prmonitor.chmod(0o755)
        failure_calls = self.root / "failure-calls"
        env = dict(self.env)
        env.update({
            "PRMONITOR_BIN": str(failing_prmonitor),
            "PRMONITOR_FAILURE_CALLS": str(failure_calls),
        })
        record = {"type": "function_call", "name": "request_user_input", "call_id": "call-bounded",
                  "arguments": json.dumps({"questions": [{"question": "是否继续？"}]}, ensure_ascii=False)}

        for _ in range(self.hook.MAX_QUESTION_SEND_ATTEMPTS + 1):
            self.assertFalse(self.hook.process_transcript_record(
                record, directory, "turn-bounded", env,
            ))

        self.assertEqual(
            failure_calls.read_text(encoding="utf-8").splitlines(),
            ["attempt"] * self.hook.MAX_QUESTION_SEND_ATTEMPTS,
        )
        self.assertFalse((directory / "turn-turn-bounded.seen.json").exists())

    def test_mcp_plan_question_suppresses_duplicate_plan_notification(self):
        self.cache_prompt("plan")
        event = self.base_event("Stop")
        directory = self.hook.state_directory(event, self.hook.merged_environment(self.env))
        payload = {
            "type": "custom_tool_call",
            "name": "mcp__prmonitor_human__ask_via_feishu",
            "call_id": "mcp-call-1",
            "input": json.dumps({"purpose": "plan_approval"}),
        }
        self.assertFalse(self.hook.process_transcript_record(payload, directory, "turn-1", self.env))
        event["last_assistant_message"] = "<proposed_plan>计划</proposed_plan>"
        self.hook.handle_hook(event, self.env)
        message = self.last_message()
        self.assertIn("任务已停止", message)
        self.assertNotIn("等待计划批准", message)
        self.assertFalse((directory / "state.json").exists())
        self.assertFalse((directory / "turn-turn-1.mcp.json").exists())
        self.assertTrue((directory / "sent.json").exists())

    def test_fail_open_records_only_static_bounded_diagnostics(self):
        env = dict(self.env)
        env["PRMONITOR_BIN"] = str(self.root / "missing")
        event = dict(self.base_event("PermissionRequest"), tool_name="SecretTool")
        self.hook.handle_hook(event, env)
        directory = self.hook.state_directory(event, self.hook.merged_environment(env))
        diagnostics = json.loads((directory / "diagnostics.json").read_text(encoding="utf-8"))
        self.assertLessEqual(len(diagnostics), self.hook.MAX_DIAGNOSTIC_ENTRIES)
        encoded = json.dumps(diagnostics, ensure_ascii=False)
        self.assertIn("executable_unavailable", encoded)
        self.assertNotIn("SecretTool", encoded)

    def test_unknown_question_schema_is_best_effort_and_diagnosable(self):
        directory = self.root / "schema-state"
        record = {"type": "response_item", "item": {
            "type": "future_tool_call", "name": "request_user_input", "call_id": "future-call",
        }}
        self.assertFalse(self.hook.process_transcript_record(record, directory, "turn-schema", self.env))
        diagnostics = json.loads((directory / "diagnostics.json").read_text(encoding="utf-8"))
        self.assertEqual(diagnostics[-1]["failure_class"], "unsupported_schema")

    @unittest.skipIf(tomllib is None, "Python 3.9 has no tomllib; parsed by the venv run")
    def test_project_config_is_valid_toml_and_enables_mcp(self):
        config = tomllib.loads((HERE.parent / "config.toml").read_text(encoding="utf-8"))
        for category in (
            "sandbox_approval", "rules", "mcp_elicitations", "request_permissions", "skill_approval",
        ):
            self.assertTrue(config["approval_policy"]["granular"][category])
        self.assertTrue(config["mcp_servers"]["prmonitor_human"]["enabled"])

    def test_verify_fast_runs_hook_tests(self):
        makefile = (HERE.parent.parent / "Makefile").read_text(encoding="utf-8")
        self.assertIn("verify-hooks", makefile)
        self.assertIn("/usr/bin/python3 -m unittest discover -s .codex/hooks", makefile)


if __name__ == "__main__":
    unittest.main()
