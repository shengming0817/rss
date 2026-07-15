#!/usr/bin/env python3
"""Codex lifecycle hooks -> prmonitor message channel.

The hook is intentionally fail-open.  It uses only Python's standard library
and supports both the project virtual environment and macOS system Python 3.9.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import NamedTuple


DEFAULT_PRMONITOR_BIN = "/Applications/prmonitor.app/Contents/MacOS/prmonitor"
DEFAULT_HOOK_CONFIG = Path.home() / "Library/Application Support/com.ghbvf.prmonitor/codex-hooks.json"
GIT_BIN = "/usr/bin/git"
PS_BIN = "/bin/ps"
MESSAGE_LIMIT_BYTES = 3800
MAX_QUESTION_SEND_ATTEMPTS = 3
MAX_DIAGNOSTIC_ENTRIES = 64
TRANSCRIPT_ADAPTER_VERSION = 1
QUESTION_TOOL_NAMES = {"request_user_input", "RequestUserInput", "AskUserQuestion"}
MCP_TOOL_NAMES = {"ask_via_feishu", "mcp__prmonitor_human__ask_via_feishu"}
SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9_.-]+")
HOOK_PATH = Path(__file__).resolve()


class Route(NamedTuple):
    integration_id: str
    conversation_id: str


def merged_environment(overrides=None):
    env = os.environ.copy()
    if overrides:
        env.update({str(key): str(value) for key, value in overrides.items()})
    return env


def safe_component(value, fallback):
    cleaned = SAFE_COMPONENT.sub("_", str(value or "")).strip("._")
    if cleaned:
        return cleaned[:160]
    digest = hashlib.sha256(str(value or fallback).encode("utf-8")).hexdigest()[:24]
    return "%s-%s" % (fallback, digest)


def ensure_private_directory(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def atomic_write_json(path, value):
    ensure_private_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def read_json_file(path, default):
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, ValueError, TypeError):
        return default


def hook_configuration_path(env):
    return Path(env.get("PRMONITOR_HOOK_CONFIG") or DEFAULT_HOOK_CONFIG).expanduser()


def hook_configuration(env):
    path = hook_configuration_path(env)
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            return {}
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            return {}
    except OSError:
        return {}
    value = read_json_file(path, {})
    return value if isinstance(value, dict) else {}


def configuration_value(env, config, environment_key, config_key, default=""):
    value = env.get(environment_key)
    if value in (None, ""):
        value = config.get(config_key)
    return str(value if value not in (None, "") else default)


def resolve_route(env, config):
    environment_integration = str(env.get("PRMONITOR_INTEGRATION_ID") or "").strip()
    environment_conversation = str(env.get("PRMONITOR_CONVERSATION_ID") or "").strip()
    if environment_integration or environment_conversation:
        if environment_integration and environment_conversation:
            return Route(environment_integration, environment_conversation), ""
        return None, "recipient_incomplete"

    configured_integration = str(config.get("integration_id") or "").strip()
    configured_conversation = str(config.get("conversation_id") or "").strip()
    if configured_integration and configured_conversation:
        return Route(configured_integration, configured_conversation), ""
    if configured_integration or configured_conversation:
        return None, "recipient_incomplete"
    return None, "recipient_missing"


def content_enabled(env):
    config = hook_configuration(env)
    value = env.get("PRMONITOR_INCLUDE_CONTENT", config.get("include_content", False))
    return value is True or str(value).strip().lower() in ("1", "true", "yes", "on")


def state_directory(event, env):
    base = Path(env.get("CODEX_PRMONITOR_STATE_DIR") or tempfile.gettempdir())
    if "CODEX_PRMONITOR_STATE_DIR" not in env:
        base = base / "codex-prmonitor"
    session = event.get("session_id") or event.get("transcript_path") or event.get("cwd") or "unknown"
    return base / safe_component(session, "session")


def state_path(directory):
    return directory / "state.json"


def turn_file(directory, turn_id, suffix):
    return directory / ("turn-%s.%s" % (safe_component(turn_id, "unknown"), suffix))


def record_diagnostic(directory, component, operation, failure_class):
    try:
        path = directory / "diagnostics.json"
        entries = read_json_file(path, [])
        if not isinstance(entries, list):
            entries = []
        entry = {
            "time": utc_now(),
            "component": str(component),
            "operation": str(operation),
            "failure_class": str(failure_class),
        }
        if component == "transcript":
            entry["adapter_version"] = TRANSCRIPT_ADAPTER_VERSION
        entries.append(entry)
        atomic_write_json(path, entries[-MAX_DIAGNOSTIC_ENTRIES:])
    except (OSError, ValueError, TypeError):
        pass


def read_state(directory):
    value = read_json_file(state_path(directory), {})
    return value if isinstance(value, dict) else {}


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def cache_prompt(event, directory, env):
    state = read_state(directory)
    prompt = str(event.get("prompt") or "")
    if content_enabled(env):
        if prompt and not state.get("initial_prompt"):
            state["initial_prompt"] = prompt
        if prompt:
            state["current_prompt"] = prompt
    else:
        state.pop("initial_prompt", None)
        state.pop("current_prompt", None)
    for key in ("session_id", "turn_id", "cwd", "model", "permission_mode", "transcript_path"):
        value = event.get(key)
        if value not in (None, ""):
            state[key] = value
    state["updated_at"] = utc_now()
    atomic_write_json(state_path(directory), state)
    return state


def run_git(cwd, arguments):
    if not cwd or not os.path.isdir(cwd) or not os.access(GIT_BIN, os.X_OK):
        return ""
    try:
        result = subprocess.run(
            [GIT_BIN, "-C", cwd] + list(arguments),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            timeout=3, check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def repository_context(cwd):
    root = run_git(cwd, ["rev-parse", "--show-toplevel"]) or str(cwd or "")
    branch = run_git(cwd, ["symbolic-ref", "--quiet", "--short", "HEAD"])
    if not branch:
        branch = run_git(cwd, ["rev-parse", "--short", "HEAD"])
    return {
        "name": Path(root).name if root else "rss",
        "root": root,
        "branch": branch,
        "commit": run_git(cwd, ["rev-parse", "--short=12", "HEAD"]),
    }


def value_from(event, state, key, default=""):
    value = event.get(key)
    if value in (None, ""):
        value = state.get(key)
    return str(value if value not in (None, "") else default)


def truncate_utf8(text, limit=MESSAGE_LIMIT_BYTES):
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    marker = "\n…（消息已截断）"
    marker_bytes = marker.encode("utf-8")
    body = encoded[: max(0, limit - len(marker_bytes))].decode("utf-8", errors="ignore")
    return body + marker


def build_message(kind, event, state, detail, env, repository=None):
    if repository is None:
        repository = repository_context(value_from(event, state, "cwd"))
    titles = {
        "human_input": "等待人工输入",
        "plan_approval": "等待计划批准",
        "operation_approval": "等待操作批准",
        "stopped": "任务已停止",
    }
    title = titles[kind]
    lines = ["%s · Codex %s" % (repository["name"], title), "事件: %s" % title,
             "项目: %s" % repository["name"]]
    for label, key in (("路径", "root"), ("分支", "branch"), ("提交", "commit")):
        if repository[key]:
            lines.append("%s: %s" % (label, repository[key]))
    lines.extend([
        "会话: %s" % value_from(event, state, "session_id", "未知"),
        "本轮: %s" % value_from(event, state, "turn_id", "未知"),
        "模型: %s" % value_from(event, state, "model", "未知"),
        "模式: %s" % value_from(event, state, "permission_mode", "未知"),
        "时间: %s" % utc_now(),
        "详情: %s" % ((detail or "无") if content_enabled(env) else "已触发 %s 事件" % title),
    ])
    if content_enabled(env):
        if state.get("initial_prompt"):
            lines.append("初始任务: %s" % state["initial_prompt"])
        if state.get("current_prompt"):
            lines.append("当前任务: %s" % state["current_prompt"])
        if event.get("last_assistant_message"):
            lines.append("最后回复: %s" % event["last_assistant_message"])
    return truncate_utf8("\n".join(lines))


def build_card(kind, event, state, detail, env):
    repository = repository_context(value_from(event, state, "cwd"))
    titles = {
        "human_input": "等待人工输入",
        "plan_approval": "等待计划批准",
        "operation_approval": "等待操作批准",
        "stopped": "任务已停止",
    }
    templates = {
        "human_input": "orange",
        "plan_approval": "orange",
        "operation_approval": "orange",
        "stopped": "grey",
    }
    return {
        "title": "%s · Codex %s" % (repository["name"], titles[kind]),
        "template": templates[kind],
        "text": build_message(kind, event, state, detail, env, repository),
    }


def send_card(card, directory, env):
    config = hook_configuration(env)
    executable = configuration_value(env, config, "PRMONITOR_BIN", "prmonitor_bin", DEFAULT_PRMONITOR_BIN)
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        record_diagnostic(directory, "transport", "send", "executable_unavailable")
        return False
    route, failure_class = resolve_route(env, config)
    if route is None:
        record_diagnostic(directory, "routing", "resolve_recipient", failure_class)
        return False
    command = [
        executable, "message", "send-card", "--integration-id",
        route.integration_id, "--conversation-id", route.conversation_id,
        "--title", card["title"], "--template", card["template"],
        "--text", card["text"],
    ]
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=env,
            timeout=float(env.get("PRMONITOR_SEND_TIMEOUT_SECONDS", "20")), check=False,
        )
        if result.returncode == 0:
            return True
        record_diagnostic(directory, "transport", "send", "command_failed")
        return False
    except ValueError:
        record_diagnostic(directory, "transport", "send", "invalid_timeout")
        return False
    except (OSError, subprocess.SubprocessError):
        record_diagnostic(directory, "transport", "send", "process_error")
        return False


def extract_question_detail(arguments):
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except ValueError:
            arguments = {"prompt": arguments}
    if not isinstance(arguments, dict):
        arguments = {}
    questions = arguments.get("questions")
    if not isinstance(questions, list):
        questions = [arguments]
    rendered = []
    for index, question in enumerate(questions, 1):
        if not isinstance(question, dict):
            rendered.append("%d. %s" % (index, question))
            continue
        prompt = question.get("question") or question.get("prompt") or "Codex 需要你的输入"
        header = question.get("header")
        rendered.append("%d. %s" % (index, "%s：%s" % (header, prompt) if header else prompt))
        options = question.get("options")
        if isinstance(options, list):
            for option in options:
                if isinstance(option, dict):
                    label = option.get("label") or option.get("value") or "选项"
                    description = option.get("description")
                    rendered.append("   - %s" % ("%s — %s" % (label, description) if description else label))
                else:
                    rendered.append("   - %s" % option)
    return "\n".join(rendered) or "Codex 需要你的输入后才能继续任务。"


def permission_detail(event):
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    reason = tool_input.get("description") or event.get("reason") or tool_input.get("reason")
    tool_name = event.get("tool_name") or "未知工具"
    return "%s\n工具: %s" % (reason, tool_name) if reason else "请求批准工具: %s" % tool_name


def event_key(kind, event, state, detail=""):
    call_id = event.get("call_id")
    if call_id:
        identity = str(call_id)
    elif kind == "operation_approval":
        identity = json.dumps({
            "tool_name": event.get("tool_name"),
            "tool_input": event.get("tool_input"),
            "reason": event.get("reason"),
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    else:
        identity = str(event.get("tool_name") or detail)
    values = [
        value_from(event, state, "session_id", "unknown"),
        value_from(event, state, "turn_id", "unknown"), kind,
        identity,
    ]
    return hashlib.sha256("\x1f".join(values).encode("utf-8")).hexdigest()


def send_once(kind, event, state, detail, directory, env):
    seen_path = directory / "sent.json"
    seen = read_json_file(seen_path, [])
    if not isinstance(seen, list):
        seen = []
    key = event_key(kind, event, state, detail)
    if key in seen:
        return False
    if send_card(build_card(kind, event, state, detail, env), directory, env):
        atomic_write_json(seen_path, (seen + [key])[-512:])
        return True
    return False


def is_plan_stop(event, state):
    if str(event.get("permission_mode") or "") == "plan":
        return True
    if str(state.get("permission_mode") or "") == "plan":
        return True
    return "<proposed_plan>" in str(event.get("last_assistant_message") or "")


def mark_mcp_question(payload, directory, turn_id):
    arguments = payload.get("arguments") or payload.get("input") or payload.get("tool_input") or {}
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except ValueError:
            arguments = {}
    purpose = arguments.get("purpose") if isinstance(arguments, dict) else None
    marker = {"purpose": purpose or "human_input", "call_id": payload.get("call_id") or payload.get("id")}
    atomic_write_json(turn_file(directory, turn_id, "mcp.json"), marker)


def transcript_tool_call(record):
    """Parse transcript adapter v1; unknown shapes remain best-effort."""
    if not isinstance(record, dict):
        return None
    candidates = [record]
    for key in ("payload", "item"):
        candidate = record.get(key)
        if isinstance(candidate, dict):
            candidates.append(candidate)
    for candidate in candidates:
        if candidate.get("type") in ("function_call", "custom_tool_call"):
            return candidate
    return None


def contains_question_tool_name(value):
    if isinstance(value, dict):
        if value.get("name") in QUESTION_TOOL_NAMES:
            return True
        return any(contains_question_tool_name(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_question_tool_name(item) for item in value)
    return False


def process_transcript_record(record, directory, turn_id, env):
    payload = transcript_tool_call(record)
    if payload is None:
        if contains_question_tool_name(record):
            record_diagnostic(directory, "transcript", "parse_question", "unsupported_schema")
        return False
    name = payload.get("name")
    if name in MCP_TOOL_NAMES or (isinstance(name, str) and name.endswith("__ask_via_feishu")):
        mark_mcp_question(payload, directory, turn_id)
        return False
    if name not in QUESTION_TOOL_NAMES:
        return False
    call_id = payload.get("call_id") or payload.get("id")
    if not call_id:
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        call_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    seen_path = turn_file(directory, turn_id, "seen.json")
    seen = read_json_file(seen_path, [])
    if not isinstance(seen, list):
        seen = []
    if call_id in seen:
        return False
    retry_path = turn_file(directory, turn_id, "retry.json")
    retry_attempts = read_json_file(retry_path, {})
    if not isinstance(retry_attempts, dict):
        retry_attempts = {}
    attempts = retry_attempts.get(call_id, 0)
    if not isinstance(attempts, int) or attempts < 0:
        attempts = 0
    if attempts >= MAX_QUESTION_SEND_ATTEMPTS:
        return False
    arguments = payload.get("arguments") or payload.get("input") or payload.get("tool_input")
    state = read_state(directory)
    event = dict(state)
    event.update({"turn_id": turn_id or state.get("turn_id"), "call_id": call_id})
    retry_seconds = max(0.0, float(env.get("PRMONITOR_QUESTION_RETRY_SECONDS", "0.5")))
    while attempts < MAX_QUESTION_SEND_ATTEMPTS:
        delivered = send_once(
            "human_input", event, state, extract_question_detail(arguments), directory, env,
        )
        if delivered:
            atomic_write_json(seen_path, (seen + [call_id])[-512:])
            if call_id in retry_attempts:
                retry_attempts.pop(call_id, None)
                atomic_write_json(retry_path, retry_attempts)
            return True
        attempts += 1
        retry_attempts[call_id] = attempts
        atomic_write_json(retry_path, retry_attempts)
        if attempts < MAX_QUESTION_SEND_ATTEMPTS:
            time.sleep(retry_seconds * (2 ** (attempts - 1)))
    record_diagnostic(directory, "transcript", "deliver_question", "retry_exhausted")
    return False


def pid_is_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def start_watcher(event, directory, env):
    if env.get("PRMONITOR_DISABLE_WATCHER") == "1":
        return
    transcript = str(event.get("transcript_path") or "")
    turn_id = str(event.get("turn_id") or "")
    if not transcript or not turn_id or not os.path.isfile(transcript):
        return
    pid_path = turn_file(directory, turn_id, "pid")
    try:
        existing = int(pid_path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        existing = 0
    if existing and pid_is_running(existing):
        return
    try:
        pid_path.unlink()
    except FileNotFoundError:
        pass
    try:
        fd = os.open(str(pid_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    try:
        process = subprocess.Popen([
            sys.executable, str(HOOK_PATH), "watch", "--transcript", transcript,
            "--offset", str(os.path.getsize(transcript)), "--state-dir", str(directory),
            "--turn-id", turn_id, "--pid-file", str(pid_path),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env, start_new_session=True, close_fds=True)
        os.write(fd, (str(process.pid) + "\n").encode("ascii"))
    except (OSError, ValueError, subprocess.SubprocessError):
        record_diagnostic(directory, "watcher", "start", "process_error")
        try:
            pid_path.unlink()
        except FileNotFoundError:
            pass
    finally:
        os.close(fd)


def expected_watcher_process(pid, turn_id):
    if not os.access(PS_BIN, os.X_OK):
        return False
    try:
        result = subprocess.run([PS_BIN, "-p", str(pid), "-o", "command="],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, timeout=2, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    command = result.stdout
    return str(HOOK_PATH) in command and " watch " in (" " + command + " ") and turn_id in command


def stop_watcher(directory, turn_id):
    if not turn_id:
        return
    pid_path = turn_file(directory, turn_id, "pid")
    try:
        pid = int(pid_path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        pid = 0
    if pid and pid != os.getpid() and expected_watcher_process(pid, turn_id):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    for path in (
        pid_path,
        turn_file(directory, turn_id, "seen.json"),
        turn_file(directory, turn_id, "retry.json"),
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def cleanup_sensitive_state(directory, turn_id):
    for path in (state_path(directory), turn_file(directory, turn_id, "mcp.json")):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def cleanup_own_pid(pid_path):
    if not pid_path:
        return
    path = Path(pid_path)
    try:
        if int(path.read_text(encoding="ascii").strip()) == os.getpid():
            path.unlink()
    except (OSError, ValueError):
        pass


def watch_transcript(transcript, offset, directory, turn_id, env, pid_path=None):
    poll_seconds = max(0.01, float(env.get("PRMONITOR_WATCH_POLL_SECONDS", "0.25")))
    deadline = time.monotonic() + max(1.0, float(env.get("PRMONITOR_WATCH_TTL_SECONDS", "86400")))
    stopped = [False]
    def request_stop(_signum, _frame):
        stopped[0] = True
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        with Path(transcript).open("rb") as stream:
            stream.seek(max(0, offset))
            while not stopped[0] and time.monotonic() < deadline:
                position = stream.tell()
                line = stream.readline()
                if not line:
                    try:
                        if os.path.getsize(transcript) < position:
                            stream.seek(0)
                    except OSError:
                        pass
                    time.sleep(poll_seconds)
                    continue
                if not line.endswith(b"\n"):
                    stream.seek(position)
                    time.sleep(poll_seconds)
                    continue
                try:
                    record = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    record_diagnostic(directory, "transcript", "decode_record", "invalid_json")
                    continue
                process_transcript_record(record, directory, turn_id, env)
    except OSError:
        record_diagnostic(directory, "watcher", "read_transcript", "io_error")
    finally:
        cleanup_own_pid(pid_path)
        if not stopped[0] and time.monotonic() >= deadline:
            cleanup_sensitive_state(directory, turn_id)


def handle_hook(event, environment=None):
    env = merged_environment(environment)
    event_name = event.get("hook_event_name")
    directory = state_directory(event, env)
    ensure_private_directory(directory)
    if event_name == "UserPromptSubmit":
        cache_prompt(event, directory, env)
        start_watcher(event, directory, env)
        return
    state = read_state(directory)
    if event_name == "PermissionRequest":
        detail = permission_detail(event)
        send_once("operation_approval", event, state, detail, directory, env)
        return
    if event_name == "Stop":
        turn_id = value_from(event, state, "turn_id")
        try:
            mcp_marker = read_json_file(turn_file(directory, turn_id, "mcp.json"), {})
            if is_plan_stop(event, state) and mcp_marker.get("purpose") not in ("plan", "plan_approval"):
                kind = "plan_approval"
                detail = "Codex 已完成计划，请返回审核并决定是否开始实施。"
            else:
                kind = "stopped"
                detail = str(event.get("stop_reason") or event.get("stopReason") or "Codex 已停止本轮任务。")
            send_once(kind, event, state, detail, directory, env)
        finally:
            stop_watcher(directory, turn_id)
            cleanup_sensitive_state(directory, turn_id)


def parse_watch_arguments(arguments):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--transcript", required=True)
    parser.add_argument("--offset", type=int, required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--turn-id", required=True)
    parser.add_argument("--pid-file")
    return parser.parse_args(arguments)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    env = merged_environment()
    try:
        if arguments and arguments[0] == "watch":
            options = parse_watch_arguments(arguments[1:])
            watch_transcript(options.transcript, options.offset, Path(options.state_dir),
                             options.turn_id, env, options.pid_file)
            return 0
        event = json.load(sys.stdin)
        if isinstance(event, dict):
            handle_hook(event)
    except (Exception, KeyboardInterrupt):
        record_diagnostic(state_directory({}, env), "hook", "dispatch", "unhandled_exception")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
