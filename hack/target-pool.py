#!/usr/bin/env python3
"""N-slot Cargo target lease pool for RSS worktrees.

Slots are serial exclusive leases (one worktree per slot at a time), not a
shared mutable target. Acquire stays offline; ``gc`` optionally asks forge
whether the leased branch's PR has been squash-merged.

Usage:
  target-pool.py acquire --pool-root DIR --n N --worktree PATH --pid PID
      [--branch BRANCH]
  target-pool.py gc --pool-root DIR [--merged-check CMD]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


LEASE_NAME = "lease.json"
LOCK_NAME = ".lock"


class PoolError(RuntimeError):
    """Fail-closed pool error surfaced to the cargo wrapper."""


def die(message: str, code: int = 1) -> None:
    print(f"rss-target-pool: {message}", file=sys.stderr)
    raise SystemExit(code)


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def physical(path: Path) -> Path:
    return Path(os.path.realpath(path))


def slot_dir(pool_root: Path, index: int) -> Path:
    return pool_root / f"slot-{index}"


def slot_index(slot: Path) -> int | None:
    name = slot.name
    if not name.startswith("slot-"):
        return None
    suffix = name[len("slot-") :]
    if not suffix.isdigit():
        return None
    return int(suffix)


def lease_path(slot: Path) -> Path:
    return slot / LEASE_NAME


def read_lease(slot: Path) -> dict[str, Any] | None:
    path = lease_path(slot)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def write_lease(slot: Path, lease: dict[str, Any]) -> None:
    slot.mkdir(parents=True, exist_ok=True)
    path = lease_path(slot)
    temporary = path.with_name(f".lease.{os.getpid()}.tmp")
    payload = json.dumps(lease, sort_keys=True, separators=(",", ":")) + "\n"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def wipe_slot_contents(slot: Path) -> None:
    if not slot.exists():
        return
    for child in slot.iterdir():
        if child.name == LEASE_NAME:
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)


def release_slot(slot: Path) -> None:
    wipe_slot_contents(slot)
    path = lease_path(slot)
    path.unlink(missing_ok=True)


def git_worktree_paths(worktree: Path) -> set[str]:
    """Return physical paths of worktrees sharing the same git common dir."""
    try:
        completed = subprocess.run(
            ["/usr/bin/git", "-C", str(worktree), "worktree", "list", "--porcelain"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return set()
    if completed.returncode != 0:
        return set()
    paths: set[str] = set()
    for line in completed.stdout.splitlines():
        if line.startswith("worktree "):
            paths.add(str(physical(Path(line[len("worktree ") :]))))
    return paths


def worktree_branch(worktree: Path) -> str:
    try:
        completed = subprocess.run(
            ["/usr/bin/git", "-C", str(worktree), "rev-parse", "--abbrev-ref", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def worktree_gone(lease: dict[str, Any], live_worktrees: set[str]) -> bool:
    raw = lease.get("worktree")
    if not isinstance(raw, str) or not raw:
        return True
    path = Path(raw)
    if not path.exists():
        return True
    physical_path = str(physical(path))
    if live_worktrees and physical_path not in live_worktrees:
        return True
    return False


class PoolLock:
    def __init__(self, pool_root: Path, timeout_seconds: float = 30.0) -> None:
        self.lock_dir = pool_root / LOCK_NAME
        self.timeout_seconds = timeout_seconds
        self._held = False

    def _stale_lock_reclaim(self) -> None:
        """Break a lock left behind by a crashed holder (no PID file; age-based)."""
        try:
            age = time.time() - self.lock_dir.stat().st_mtime
        except FileNotFoundError:
            return
        except OSError:
            return
        if age < self.timeout_seconds:
            return
        try:
            os.rmdir(self.lock_dir)
        except OSError:
            pass

    def __enter__(self) -> PoolLock:
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                os.mkdir(self.lock_dir)
                self._held = True
                return self
            except FileExistsError:
                self._stale_lock_reclaim()
                if time.monotonic() >= deadline:
                    raise PoolError(
                        f"timed out waiting for pool lock at {self.lock_dir}"
                    ) from None
                time.sleep(0.05)

    def __exit__(self, *_exc: object) -> None:
        if self._held:
            try:
                os.rmdir(self.lock_dir)
            except OSError:
                pass
            self._held = False


def claim_slot(
    slot: Path,
    worktree: Path,
    pid: int,
    branch: str,
    *,
    wipe: bool,
) -> Path:
    if wipe:
        wipe_slot_contents(slot)
    write_lease(
        slot,
        {
            "worktree": str(worktree),
            "branch": branch,
            "pid": pid,
            "acquired_at": time.time(),
        },
    )
    return physical(slot)


def acquire(
    pool_root: Path,
    n: int,
    worktree: Path,
    pid: int,
    branch: str | None = None,
) -> Path:
    if n < 1:
        raise PoolError(f"N must be a positive integer, got: {n}")
    pool_root = physical(pool_root)
    worktree = physical(worktree)
    pool_root.mkdir(parents=True, exist_ok=True)
    resolved_branch = branch if branch is not None else worktree_branch(worktree)
    live = git_worktree_paths(worktree)

    with PoolLock(pool_root):
        # 1. sticky — discover every slot-*, not just range(n). Out-of-range
        # leases (after N was lowered) are released so acquire cannot dual-own.
        sticky_hit: Path | None = None
        for slot in sorted(pool_root.glob("slot-*")):
            if not slot.is_dir():
                continue
            lease = read_lease(slot)
            if lease is None:
                continue
            leased = lease.get("worktree")
            if not (isinstance(leased, str) and physical(Path(leased)) == worktree):
                continue
            index = slot_index(slot)
            if index is None or index >= n:
                release_slot(slot)
                continue
            if sticky_hit is None:
                sticky_hit = slot
            else:
                # Duplicate in-range leases for one worktree: keep lowest name.
                release_slot(slot)
        if sticky_hit is not None:
            lease = read_lease(sticky_hit) or {}
            write_lease(
                sticky_hit,
                {
                    "worktree": str(worktree),
                    "branch": resolved_branch or lease.get("branch", ""),
                    "pid": pid,
                    "acquired_at": lease.get("acquired_at", time.time()),
                },
            )
            return physical(sticky_hit)

        # 2. empty slot
        for index in range(n):
            slot = slot_dir(pool_root, index)
            if read_lease(slot) is None:
                return claim_slot(slot, worktree, pid, resolved_branch, wipe=False)

        # 3. worktree gone
        for index in range(n):
            slot = slot_dir(pool_root, index)
            lease = read_lease(slot)
            if lease is None:
                continue
            if worktree_gone(lease, live):
                return claim_slot(slot, worktree, pid, resolved_branch, wipe=True)

        # 4. LRU among dead-PID leases
        candidates: list[tuple[float, int, Path]] = []
        for index in range(n):
            slot = slot_dir(pool_root, index)
            lease = read_lease(slot)
            if lease is None:
                continue
            leased_pid = lease.get("pid")
            if not isinstance(leased_pid, int) or process_alive(leased_pid):
                continue
            acquired = lease.get("acquired_at")
            stamp = float(acquired) if isinstance(acquired, (int, float)) else 0.0
            candidates.append((stamp, index, slot))
        if candidates:
            candidates.sort(key=lambda item: (item[0], item[1]))
            return claim_slot(
                candidates[0][2], worktree, pid, resolved_branch, wipe=True
            )

        raise PoolError(
            f"pool full ({n} slots); run `hack/target-pool.py gc`, raise "
            f"RSS_TARGET_POOL_N, or remove a worktree"
        )


def default_merged_checker(branch: str) -> bool | None:
    """Return True/False when forge answers, None when unreachable."""
    if not branch or branch in {"HEAD", "develop", "main"}:
        return False
    script = Path(__file__).resolve().parent / "automation" / "forge.sh"
    if not script.is_file():
        return None
    try:
        completed = subprocess.run(
            ["bash", str(script), "branch-pr-merged", branch],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    answer = completed.stdout.strip().lower()
    if answer == "true":
        return True
    if answer == "false":
        return False
    return None


def run_merged_check(command: str, branch: str) -> bool | None:
    if not branch:
        return False
    try:
        completed = subprocess.run(
            [*command.split(), branch],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    answer = completed.stdout.strip().lower()
    if answer == "true":
        return True
    if answer == "false":
        return False
    return None


def gc(
    pool_root: Path,
    *,
    merged_check: Callable[[str], bool | None] | None = None,
    merged_check_command: str | None = None,
) -> list[str]:
    """Release reclaimable slots. Returns human-readable action lines."""
    pool_root = physical(pool_root)
    if not pool_root.is_dir():
        return []
    actions: list[str] = []
    checker = merged_check
    if checker is None and merged_check_command is not None:
        checker = lambda branch: run_merged_check(merged_check_command, branch)
    if checker is None:
        checker = default_merged_checker

    with PoolLock(pool_root):
        for slot in sorted(pool_root.glob("slot-*")):
            if not slot.is_dir():
                continue
            lease = read_lease(slot)
            if lease is None:
                continue
            worktree_raw = lease.get("worktree")
            branch = lease.get("branch") if isinstance(lease.get("branch"), str) else ""
            live: set[str] = set()
            if isinstance(worktree_raw, str) and worktree_raw:
                live = git_worktree_paths(Path(worktree_raw))
            if worktree_gone(lease, live):
                release_slot(slot)
                actions.append(f"released {slot.name}: worktree gone")
                continue
            merged = checker(branch)
            if merged is True:
                leased_pid = lease.get("pid")
                if isinstance(leased_pid, int) and process_alive(leased_pid):
                    actions.append(
                        f"kept {slot.name}: PR for branch {branch!r} is merged "
                        f"but pid {leased_pid} still alive"
                    )
                    continue
                release_slot(slot)
                actions.append(
                    f"released {slot.name}: PR for branch {branch!r} is merged "
                    f"but worktree remains at {worktree_raw}"
                )
            elif merged is None:
                actions.append(
                    f"kept {slot.name}: forge unreachable for branch {branch!r}"
                )
    return actions


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="target-pool.py")
    sub = parser.add_subparsers(dest="command", required=True)

    acquire_parser = sub.add_parser("acquire")
    acquire_parser.add_argument("--pool-root", type=Path, required=True)
    acquire_parser.add_argument("--n", type=int, required=True)
    acquire_parser.add_argument("--worktree", type=Path, required=True)
    acquire_parser.add_argument("--pid", type=int, required=True)
    acquire_parser.add_argument("--branch", default=None)

    gc_parser = sub.add_parser("gc")
    gc_parser.add_argument("--pool-root", type=Path, required=True)
    gc_parser.add_argument(
        "--merged-check",
        default=None,
        help="command prefix that accepts a branch and prints true|false",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "acquire":
            path = acquire(
                args.pool_root,
                args.n,
                args.worktree,
                args.pid,
                branch=args.branch,
            )
            print(path)
            return 0
        if args.command == "gc":
            actions = gc(
                args.pool_root,
                merged_check_command=args.merged_check,
            )
            for line in actions:
                print(line)
            return 0
    except PoolError as error:
        die(str(error))
    die(f"unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
