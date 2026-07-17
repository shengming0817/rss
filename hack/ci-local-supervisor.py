#!/usr/bin/env python3
"""Bound the complete local-CI bootstrap and its POSIX process group."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


CONFIG_ERROR = 78
TIMEOUT = 124
POLL_SECONDS = 0.02
RESERVED_ENV = ("RSS_CI_LOCAL_WORKER", "RSS_CI_LOCAL_SUPERVISED")
RUNNER_PATHS = (
    ".cargo/config.toml",
    "Cargo.lock",
    "Cargo.toml",
    "Makefile",
    "hack/cargo.sh",
    "hack/target-pool.py",
    "hack/ci-local-supervisor.py",
    "rust-toolchain.toml",
    "xtask",
)


class ConfigurationError(RuntimeError):
    pass


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--budget-seconds", type=float, default=600.0)
    parser.add_argument("--term-grace-seconds", type=float, default=2.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    if args.budget_seconds <= 0 or args.term_grace_seconds < 0:
        parser.error("budgets must be positive and grace must be non-negative")
    return args


def reject_reserved_environment() -> None:
    present = [name for name in RESERVED_ENV if name in os.environ]
    if present:
        raise ConfigurationError(
            "reserved local-CI environment is set: " + ", ".join(present)
        )


def reject_dirty_runner(repo_root: Path) -> None:
    result = subprocess.run(
        [
            "/usr/bin/git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            *RUNNER_PATHS,
        ],
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise ConfigurationError("cannot inspect committed local-CI runner")
    if result.stdout:
        paths = ", ".join(line[3:] for line in result.stdout.splitlines())
        raise ConfigurationError(f"local-CI runner is dirty: {paths}")


def group_alive(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stop_group(
    process_group: int,
    leader: subprocess.Popen[bytes],
    first_signal: int,
    grace_seconds: float,
) -> None:
    if group_alive(process_group):
        try:
            os.killpg(process_group, first_signal)
        except (ProcessLookupError, PermissionError):
            pass
    grace_deadline = time.monotonic() + grace_seconds
    while group_alive(process_group) and time.monotonic() < grace_deadline:
        leader.poll()
        time.sleep(POLL_SECONDS)
    if group_alive(process_group):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        leader.wait(timeout=max(grace_seconds, 0.1))
    except subprocess.TimeoutExpired:
        leader.kill()
        leader.wait()


def supervise(command: list[str], repo_root: Path, budget: float, grace: float) -> int:
    if os.name != "posix":
        raise ConfigurationError("local-CI process-group supervision requires POSIX")

    cancelled: list[int] = []

    def request_cancel(signum: int, _frame: object) -> None:
        if not cancelled:
            cancelled.append(signum)

    previous = {
        signum: signal.signal(signum, request_cancel)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    started = time.monotonic()
    leader = subprocess.Popen(command, cwd=repo_root, start_new_session=True)
    process_group = leader.pid
    try:
        while True:
            if cancelled:
                stop_group(process_group, leader, cancelled[0], grace)
                return 128 + cancelled[0]
            returncode = leader.poll()
            if returncode is not None:
                if group_alive(process_group):
                    stop_group(process_group, leader, signal.SIGTERM, grace)
                return returncode
            if time.monotonic() - started >= budget:
                stop_group(process_group, leader, signal.SIGTERM, grace)
                return TIMEOUT
            time.sleep(POLL_SECONDS)
    finally:
        if group_alive(process_group):
            stop_group(process_group, leader, signal.SIGTERM, grace)
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        reject_reserved_environment()
        repo_root = args.repo_root.resolve(strict=True)
        reject_dirty_runner(repo_root)
        return supervise(
            args.command,
            repo_root,
            args.budget_seconds,
            args.term_grace_seconds,
        )
    except ConfigurationError as error:
        print(f"ci-local-supervisor: {error}", file=sys.stderr)
        return CONFIG_ERROR


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
