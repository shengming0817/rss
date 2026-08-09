#!/usr/bin/env python3
"""Bound the complete local-CI bootstrap and its POSIX process group."""

from __future__ import annotations

import argparse
import errno
import fcntl
import math
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path


CONFIG_ERROR = 78
TIMEOUT = 124
POLL_SECONDS = 0.02
SNAPSHOT_CACHE_LIMIT = 8
HANDSHAKE_BYTES = 32
WORKER_BUDGET_SECONDS = 600.0
RESERVED_ENV = (
    "RSS_CI_LOCAL_WORKER",
    "RSS_CI_LOCAL_SUPERVISED",
    "RSS_CI_LOCAL_HANDSHAKE_FD",
    "RSS_CI_LOCAL_HANDSHAKE_TOKEN",
    "RSS_CI_LOCAL_DEADLINE",
    "RSS_CI_CALLER_WORKTREE",
    "RSS_CI_CALLER_BRANCH",
    "RSS_CI_EXPECTED_SNAPSHOT_ROOT",
    "RSS_CI_EXPECTED_HEAD",
    "RSS_CI_EXPECTED_BASE",
    "RSS_CI_EXPECTED_MERGE_BASE",
    "RSS_RUNTIME_ROOT_BASE",
    "RSS_LOCAL_CI_LEDGER_PATH",
    "RSS_LOCAL_CI_LEDGER_BRANCH",
)
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


class BudgetExpired(RuntimeError):
    pass


class SnapshotOwnership:
    def __init__(self, lock: Path, opened: object) -> None:
        self.lock = lock
        self.opened = opened

    def release(self) -> None:
        if self.opened is None:
            return
        fcntl.flock(self.opened.fileno(), fcntl.LOCK_UN)
        self.opened.close()
        self.opened = None

    def __enter__(self) -> SnapshotOwnership:
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.release()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--budget-seconds", type=float, default=600.0)
    parser.add_argument("--term-grace-seconds", type=float, default=2.0)
    parser.add_argument("--local-ci", action="store_true")
    parser.add_argument("--local-ci-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--cargo-wrapper", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command and not args.local_ci_worker:
        parser.error("a command is required after --")
    if (
        not math.isfinite(args.budget_seconds)
        or not math.isfinite(args.term_grace_seconds)
        or args.budget_seconds <= 0
        or args.term_grace_seconds < 0
    ):
        parser.error("budgets must be positive and grace must be non-negative")
    if args.local_ci and args.local_ci_worker:
        parser.error("--local-ci and --local-ci-worker are mutually exclusive")
    if (args.local_ci or args.local_ci_worker) != (args.cargo_wrapper is not None):
        parser.error("local CI mode requires --cargo-wrapper")
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


def git_output(repo_root: Path, *arguments: str, allow_failure: bool = False) -> str:
    completed = subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        if allow_failure:
            return ""
        detail = completed.stderr.strip() or "unknown git failure"
        raise ConfigurationError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def resolve_commit(repo_root: Path, revision: str) -> str:
    output = git_output(
        repo_root,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{revision}^{{commit}}",
    )
    values = output.splitlines()
    if len(values) != 1 or re.fullmatch(r"[0-9a-f]{40}", values[0]) is None:
        raise ConfigurationError(f"git revision is not one exact commit: {revision}")
    return values[0]


def normalize_local_arguments(repo_root: Path, arguments: list[str]) -> tuple[list[str], str, str, str]:
    base_values: list[tuple[int, str]] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--base":
            if index + 1 >= len(arguments):
                raise ConfigurationError("ci local --base requires a git ref")
            base_values.append((index, arguments[index + 1]))
            index += 2
            continue
        if argument.startswith("--base="):
            base_values.append((index, argument.removeprefix("--base=")))
        index += 1
    if len(base_values) != 1 or not base_values[0][1]:
        raise ConfigurationError("ci local requires exactly one --base git ref")

    base_index, base_ref = base_values[0]
    base = resolve_commit(repo_root, base_ref)
    head = resolve_commit(repo_root, "HEAD")
    merge_base = git_output(repo_root, "merge-base", base, head).strip()
    if re.fullmatch(r"[0-9a-f]{40}", merge_base) is None:
        raise ConfigurationError("git merge-base did not return one exact commit")

    normalized = list(arguments)
    if normalized[base_index] == "--base":
        normalized[base_index + 1] = base
    else:
        normalized[base_index] = f"--base={base}"
    return normalized, base, head, merge_base


def repository_cache_root(repo_root: Path) -> Path:
    raw = git_output(repo_root, "rev-parse", "--git-dir").strip()
    git_dir = Path(raw)
    if not git_dir.is_absolute():
        git_dir = repo_root / git_dir
    return git_dir.resolve() / "rss-ci-local" / "sources"


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ConfigurationError(f"committed snapshot cache must be a real directory: {path}")
    path.chmod(0o700)


def acquire_snapshot_ownership(
    cache_root: Path, revision: str, deadline: float, *, wait: bool = True
) -> SnapshotOwnership | None:
    locks = cache_root / ".locks"
    ensure_private_directory(locks)
    lock = locks / f"{revision}.lock"
    opened = lock.open("a+", encoding="utf-8")
    os.chmod(lock, 0o600)
    while True:
        try:
            fcntl.flock(opened.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            opened.seek(0)
            opened.truncate()
            opened.write(f"{os.getpid()}\n")
            opened.flush()
            return SnapshotOwnership(lock, opened)
        except BlockingIOError:
            if not wait:
                opened.close()
                return None
            if time.monotonic() >= deadline:
                opened.close()
                raise BudgetExpired("timed out waiting for committed snapshot ownership")
            time.sleep(POLL_SECONDS)


def snapshot_revisions(cache_root: Path) -> list[Path]:
    revisions: list[tuple[int, Path]] = []
    for candidate in cache_root.iterdir():
        try:
            if (
                re.fullmatch(r"[0-9a-f]{40}", candidate.name)
                and candidate.is_dir()
                and not candidate.is_symlink()
            ):
                revisions.append((candidate.stat().st_mtime_ns, candidate))
        except FileNotFoundError:
            continue
    return [path for _, path in sorted(revisions, key=lambda item: item[0], reverse=True)]


def collect_snapshot_cache(cache_root: Path, retained_revision: str, deadline: float) -> None:
    revisions = snapshot_revisions(cache_root)
    keep = {path.name for path in revisions[:SNAPSHOT_CACHE_LIMIT]}
    keep.add(retained_revision)
    for candidate in revisions:
        if candidate.name in keep:
            continue
        ownership = acquire_snapshot_ownership(
            cache_root, candidate.name, deadline, wait=False
        )
        if ownership is None:
            continue
        with ownership:
            if candidate.exists() and not candidate.is_symlink():
                shutil.rmtree(candidate)


def open_cached_snapshot(snapshot: Path, revision: str) -> Path:
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise ConfigurationError("committed snapshot revision cache must be a real directory")
    root = snapshot / "tree"
    if root.is_symlink() or not root.is_dir():
        raise ConfigurationError("committed snapshot checkout must be a real directory")
    observed = git_output(root, "rev-parse", "--verify", "HEAD").strip()
    if observed != revision:
        raise ConfigurationError("committed snapshot cache revision mismatch")
    git_output(root, "reset", "--hard", revision)
    git_output(root, "clean", "-ffdx", "--")
    dirty = git_output(root, "status", "--porcelain", "--untracked-files=all")
    if dirty:
        raise ConfigurationError("committed snapshot cache is dirty")
    return root.resolve()


def checkout_snapshot(
    repo_root: Path, revision: str, deadline: float
) -> tuple[Path, SnapshotOwnership]:
    cache_root = repository_cache_root(repo_root)
    ensure_private_directory(cache_root)
    ownership = acquire_snapshot_ownership(cache_root, revision, deadline)
    assert ownership is not None
    try:
        snapshot = cache_root / revision
        if not snapshot.exists():
            staging = cache_root / f".{revision}.tmp-{os.getpid()}"
            if staging.exists():
                shutil.rmtree(staging)
            staging.mkdir(mode=0o700)
            root = staging / "tree"
            try:
                completed = subprocess.run(
                    [
                        "/usr/bin/git",
                        "clone",
                        "--quiet",
                        "--shared",
                        "--no-checkout",
                        "--",
                        str(repo_root),
                        str(root),
                    ],
                    check=False,
                )
                if completed.returncode != 0:
                    raise ConfigurationError("clone committed CI snapshot failed")
                git_output(root, "checkout", "--quiet", "--detach", revision, "--")
                try:
                    staging.rename(snapshot)
                except OSError as error:
                    if error.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                        raise
                    shutil.rmtree(staging)
            except Exception:
                shutil.rmtree(staging, ignore_errors=True)
                raise
        root = open_cached_snapshot(snapshot, revision)
        os.utime(snapshot, None)
        collect_snapshot_cache(cache_root, revision, deadline)
        return root, ownership
    except Exception:
        ownership.release()
        raise


def caller_branch(repo_root: Path) -> str:
    return git_output(
        repo_root, "symbolic-ref", "--quiet", "--short", "HEAD", allow_failure=True
    ).strip()


def caller_ledger_path(repo_root: Path) -> Path:
    raw = git_output(
        repo_root, "rev-parse", "--git-path", "rss-local-ci/checkpoint-v1.json"
    ).strip()
    path = Path(raw)
    return path if path.is_absolute() else repo_root / path


def snapshot_wrapper(repo_root: Path, snapshot_root: Path, wrapper: Path) -> Path:
    source = wrapper if wrapper.is_absolute() else repo_root / wrapper
    try:
        relative = source.resolve(strict=True).relative_to(repo_root)
    except (FileNotFoundError, ValueError) as error:
        raise ConfigurationError("local CI cargo wrapper must be inside the caller worktree") from error
    candidate = snapshot_root / relative
    if not candidate.is_file():
        raise ConfigurationError("committed snapshot cargo wrapper is missing")
    return candidate


def profile(phase: str, started: float) -> None:
    print(f"ci-local-profile: phase={phase} seconds={time.monotonic() - started:.3f}", file=sys.stderr)


def local_ci_handshake() -> tuple[int, bytes]:
    try:
        descriptor = int(os.environ["RSS_CI_LOCAL_HANDSHAKE_FD"])
        token = bytes.fromhex(os.environ["RSS_CI_LOCAL_HANDSHAKE_TOKEN"])
    except (KeyError, ValueError) as error:
        raise ConfigurationError("local CI worker handshake is missing or malformed") from error
    if len(token) != HANDSHAKE_BYTES:
        raise ConfigurationError("local CI worker handshake token has the wrong size")
    if os.getpid() != os.getsid(0) or os.getpid() != os.getpgrp():
        raise ConfigurationError("local CI worker must be the supervised session and process-group leader")
    try:
        observed = os.read(descriptor, len(token))
    except OSError as error:
        raise ConfigurationError("local CI worker handshake descriptor is invalid") from error
    if not secrets.compare_digest(observed, token):
        raise ConfigurationError("local CI worker handshake token does not match")
    return descriptor, token


def bounded_worker_deadline(claimed_deadline: float, worker_started: float) -> float:
    if not math.isfinite(claimed_deadline):
        raise ConfigurationError("local CI deadline is not finite")
    return min(claimed_deadline, worker_started + WORKER_BUDGET_SECONDS)


def run_local_ci_worker(repo_root: Path, wrapper: Path, arguments: list[str]) -> int:
    if os.environ.get("RSS_CI_LOCAL_SUPERVISED") != "1":
        raise ConfigurationError("local CI worker requires the supervised launcher")
    worker_started = time.monotonic()
    handshake_fd, _ = local_ci_handshake()
    try:
        claimed_deadline = float(os.environ["RSS_CI_LOCAL_DEADLINE"])
    except (KeyError, ValueError) as error:
        raise ConfigurationError("local CI deadline is missing or malformed") from error
    deadline = bounded_worker_deadline(claimed_deadline, worker_started)
    if deadline <= time.monotonic():
        raise BudgetExpired("local CI deadline elapsed before snapshot checkout")
    total_started = worker_started
    revision_started = time.monotonic()
    normalized, base, head, merge_base = normalize_local_arguments(repo_root, arguments)
    branch = caller_branch(repo_root)
    profile("revision.resolve", revision_started)

    snapshot_started = time.monotonic()
    snapshot_root, ownership = checkout_snapshot(repo_root, head, deadline)
    profile("snapshot.checkout", snapshot_started)
    executable = snapshot_wrapper(repo_root, snapshot_root, wrapper)

    environment = os.environ.copy()
    environment.update(
        {
            "RSS_CI_LOCAL_WORKER": "1",
            "RSS_CI_LOCAL_SUPERVISED": "1",
            "RSS_CI_CALLER_WORKTREE": str(repo_root),
            "RSS_CI_CALLER_BRANCH": branch,
            "RSS_CI_EXPECTED_SNAPSHOT_ROOT": str(snapshot_root),
            "RSS_CI_EXPECTED_HEAD": head,
            "RSS_CI_EXPECTED_BASE": base,
            "RSS_CI_EXPECTED_MERGE_BASE": merge_base,
            "RSS_RUNTIME_ROOT_BASE": merge_base,
        }
    )
    if branch:
        environment["RSS_LOCAL_CI_LEDGER_PATH"] = str(caller_ledger_path(repo_root))
        environment["RSS_LOCAL_CI_LEDGER_BRANCH"] = branch
    else:
        environment.pop("RSS_LOCAL_CI_LEDGER_PATH", None)
        environment.pop("RSS_LOCAL_CI_LEDGER_BRANCH", None)

    command_started = time.monotonic()
    try:
        completed = subprocess.run(
            [str(executable), "__ci-local-worker", *normalized],
            cwd=snapshot_root,
            env=environment,
            check=False,
            pass_fds=(handshake_fd,),
        )
        profile("xtask.worker", command_started)
        profile("total", total_started)
        return completed.returncode
    finally:
        ownership.release()


def cleanup_snapshot_staging(repo_root: Path, worker_pid: int) -> None:
    try:
        cache_root = repository_cache_root(repo_root)
    except ConfigurationError:
        return
    if not cache_root.is_dir():
        return
    for candidate in cache_root.glob(f".*.tmp-{worker_pid}"):
        if candidate.is_dir() and not candidate.is_symlink():
            shutil.rmtree(candidate, ignore_errors=True)


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


def supervise(
    command: list[str],
    repo_root: Path,
    budget: float,
    grace: float,
    *,
    environment: dict[str, str] | None = None,
    started: float | None = None,
    cleanup_staging: bool = False,
    pass_fds: tuple[int, ...] = (),
    timeout_phase: str = "command",
) -> int:
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
    started = time.monotonic() if started is None else started
    leader = subprocess.Popen(
        command,
        cwd=repo_root,
        env=environment,
        start_new_session=True,
        pass_fds=pass_fds,
    )
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
                elapsed = time.monotonic() - started
                print(
                    "ci-local-supervisor: reason=timeout "
                    f"phase={timeout_phase} budget_seconds={budget:.3f} "
                    f"elapsed_seconds={elapsed:.3f}",
                    file=sys.stderr,
                )
                return TIMEOUT
            time.sleep(POLL_SECONDS)
    finally:
        if group_alive(process_group):
            stop_group(process_group, leader, signal.SIGTERM, grace)
        if cleanup_staging:
            cleanup_snapshot_staging(repo_root, leader.pid)
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        started = time.monotonic()
        if args.local_ci_worker:
            return run_local_ci_worker(
                args.repo_root.resolve(strict=True), args.cargo_wrapper, args.command
            )
        reject_reserved_environment()
        repo_root = args.repo_root.resolve(strict=True)
        reject_dirty_runner(repo_root)
        if args.local_ci:
            environment = os.environ.copy()
            environment["RSS_CI_LOCAL_SUPERVISED"] = "1"
            handshake_fd, handshake_writer = os.pipe()
            handshake_token = secrets.token_bytes(HANDSHAKE_BYTES)
            os.write(handshake_writer, handshake_token * 3)
            os.close(handshake_writer)
            environment["RSS_CI_LOCAL_HANDSHAKE_FD"] = str(handshake_fd)
            environment["RSS_CI_LOCAL_HANDSHAKE_TOKEN"] = handshake_token.hex()
            environment["RSS_CI_LOCAL_DEADLINE"] = str(started + args.budget_seconds)
            worker = [
                "/usr/bin/python3",
                str(Path(__file__).resolve()),
                "--repo-root",
                str(repo_root),
                "--local-ci-worker",
                "--cargo-wrapper",
                str(args.cargo_wrapper),
                "--",
                *args.command,
            ]
            try:
                return supervise(
                    worker,
                    repo_root,
                    args.budget_seconds,
                    args.term_grace_seconds,
                    environment=environment,
                    started=started,
                    cleanup_staging=True,
                    pass_fds=(handshake_fd,),
                    timeout_phase="local-ci",
                )
            finally:
                os.close(handshake_fd)
        return supervise(
            args.command,
            repo_root,
            args.budget_seconds,
            args.term_grace_seconds,
            started=started,
        )
    except BudgetExpired as error:
        elapsed = time.monotonic() - started
        print(
            "ci-local-supervisor: reason=timeout phase=snapshot-lock "
            f"budget_seconds={args.budget_seconds:.3f} elapsed_seconds={elapsed:.3f} "
            f"detail={error}",
            file=sys.stderr,
        )
        return TIMEOUT
    except ConfigurationError as error:
        print(f"ci-local-supervisor: {error}", file=sys.stderr)
        return CONFIG_ERROR


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
