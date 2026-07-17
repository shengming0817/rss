#!/usr/bin/env python3
"""Unit tests for hack/target-pool.py."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "hack" / "target-pool.py"


def load_pool():
    spec = importlib.util.spec_from_file_location("rss_target_pool", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pool = load_pool()


def init_git_repo(root: Path) -> None:
    subprocess.run(["/usr/bin/git", "init", "-q"], cwd=root, check=True)
    subprocess.run(
        ["/usr/bin/git", "config", "user.email", "pool@example.invalid"],
        cwd=root,
        check=True,
    )
    subprocess.run(
        ["/usr/bin/git", "config", "user.name", "pool"],
        cwd=root,
        check=True,
    )
    (root / "README").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["/usr/bin/git", "add", "."], cwd=root, check=True)
    subprocess.run(
        ["/usr/bin/git", "commit", "-qm", "fixture"],
        cwd=root,
        check=True,
    )


@unittest.skipUnless(os.name == "posix", "target pool uses POSIX mkdir locks")
class TargetPoolTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.pool_root = self.root / "pool"
        self.main = self.root / "main"
        self.main.mkdir()
        init_git_repo(self.main)
        self.main = self.main.resolve()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def add_worktree(self, name: str) -> Path:
        path = self.root / name
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.main),
                "worktree",
                "add",
                "-q",
                "-b",
                name,
                str(path),
            ],
            check=True,
        )
        return path.resolve()

    def test_acquire_defaults_to_sticky_same_slot(self) -> None:
        first = pool.acquire(self.pool_root, 5, self.main, os.getpid(), branch="main")
        second = pool.acquire(self.pool_root, 5, self.main, os.getpid(), branch="main")
        self.assertEqual(first, second)
        self.assertEqual(first.name, "slot-0")

    def test_hard_cap_refuses_n_plus_one(self) -> None:
        a = self.add_worktree("a")
        b = self.add_worktree("b")
        pool.acquire(self.pool_root, 2, a, os.getpid(), branch="a")
        pool.acquire(self.pool_root, 2, b, os.getpid(), branch="b")
        # Hold both leases alive with this process PID so LRU cannot reclaim.
        with self.assertRaises(pool.PoolError) as raised:
            pool.acquire(
                self.pool_root, 2, self.main, os.getpid(), branch="main"
            )
        self.assertIn("pool full", str(raised.exception))
        self.assertFalse((self.pool_root / "slot-2").exists())

    def test_reclaims_gone_worktree_and_wipes(self) -> None:
        linked = self.add_worktree("linked")
        slot = pool.acquire(self.pool_root, 1, linked, 1, branch="linked")
        marker = slot / "stale-artifact"
        marker.write_text("keep-me-not\n", encoding="utf-8")
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.main), "worktree", "remove", "--force", str(linked)],
            check=True,
        )
        claimed = pool.acquire(
            self.pool_root, 1, self.main, os.getpid(), branch="main"
        )
        self.assertEqual(claimed, slot)
        self.assertFalse(marker.exists())
        lease = json.loads((slot / "lease.json").read_text(encoding="utf-8"))
        self.assertEqual(lease["worktree"], str(self.main))

    def test_lru_dead_pid_reclaim(self) -> None:
        a = self.add_worktree("a")
        b = self.add_worktree("b")
        older = pool.acquire(self.pool_root, 2, a, 1, branch="a")
        time.sleep(0.02)
        newer = pool.acquire(self.pool_root, 2, b, 1, branch="b")
        # Both PIDs are dead (1 is init on some systems — use clearly dead PIDs).
        # Re-write leases with dead PIDs and ordered timestamps.
        for slot, worktree, branch, stamp, dead_pid in (
            (older, a, "a", 100.0, 999_999_001),
            (newer, b, "b", 200.0, 999_999_002),
        ):
            pool.write_lease(
                slot,
                {
                    "worktree": str(worktree),
                    "branch": branch,
                    "pid": dead_pid,
                    "acquired_at": stamp,
                },
            )
        claimed = pool.acquire(
            self.pool_root, 2, self.main, os.getpid(), branch="main"
        )
        self.assertEqual(claimed, older)

    def test_rejects_non_positive_n(self) -> None:
        with self.assertRaises(pool.PoolError):
            pool.acquire(self.pool_root, 0, self.main, os.getpid())

    def test_gc_releases_merged_branch(self) -> None:
        linked = self.add_worktree("merged-branch")
        slot = pool.acquire(
            self.pool_root, 1, linked, 999_999_101, branch="merged-branch"
        )
        marker = slot / "artifact"
        marker.write_text("x\n", encoding="utf-8")

        def merged_check(branch: str) -> bool | None:
            return True if branch == "merged-branch" else False

        actions = pool.gc(self.pool_root, merged_check=merged_check)
        self.assertTrue(any("merged" in line for line in actions))
        self.assertIsNone(pool.read_lease(slot))
        self.assertFalse(marker.exists())

    def test_gc_keeps_merged_when_pid_alive(self) -> None:
        linked = self.add_worktree("alive-merged")
        slot = pool.acquire(
            self.pool_root, 1, linked, os.getpid(), branch="alive-merged"
        )
        marker = slot / "artifact"
        marker.write_text("keep\n", encoding="utf-8")

        def merged_check(branch: str) -> bool | None:
            return True if branch == "alive-merged" else False

        actions = pool.gc(self.pool_root, merged_check=merged_check)
        self.assertTrue(any("still alive" in line for line in actions))
        self.assertIsNotNone(pool.read_lease(slot))
        self.assertTrue(marker.exists())

    def test_sticky_reclaims_out_of_range_lease_without_double_occupy(self) -> None:
        # Simulate a historical N=3 sticky lease that survives after N drops to 2.
        orphan = self.pool_root / "slot-2"
        orphan.mkdir(parents=True)
        pool.write_lease(
            orphan,
            {
                "worktree": str(self.main),
                "branch": "main",
                "pid": os.getpid(),
                "acquired_at": 1.0,
            },
        )
        (orphan / "warm").write_text("cache\n", encoding="utf-8")

        claimed = pool.acquire(
            self.pool_root, 2, self.main, os.getpid(), branch="main"
        )
        self.assertIn(claimed.name, {"slot-0", "slot-1"})
        self.assertIsNone(pool.read_lease(orphan))
        owned = [
            slot
            for slot in self.pool_root.glob("slot-*")
            if (lease := pool.read_lease(slot))
            and lease.get("worktree") == str(self.main)
        ]
        self.assertEqual(len(owned), 1)
        self.assertEqual(owned[0].resolve(), claimed.resolve())

    def test_gc_fail_safe_when_forge_unreachable(self) -> None:
        linked = self.add_worktree("kept-branch")
        slot = pool.acquire(
            self.pool_root, 1, linked, os.getpid(), branch="kept-branch"
        )

        def unreachable(_branch: str) -> bool | None:
            return None

        actions = pool.gc(self.pool_root, merged_check=unreachable)
        self.assertTrue(any("unreachable" in line for line in actions))
        self.assertIsNotNone(pool.read_lease(slot))

    def test_cli_acquire_prints_slot_path(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "acquire",
                "--pool-root",
                str(self.pool_root),
                "--n",
                "5",
                "--worktree",
                str(self.main),
                "--pid",
                str(os.getpid()),
                "--branch",
                "main",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        printed = Path(completed.stdout.strip())
        self.assertTrue(printed.is_dir())
        self.assertEqual(printed.name, "slot-0")

    def test_stale_lock_is_reclaimed(self) -> None:
        lock = self.pool_root / ".lock"
        self.pool_root.mkdir(parents=True, exist_ok=True)
        lock.mkdir()
        old = time.time() - 120.0
        os.utime(lock, (old, old))
        claimed = pool.acquire(
            self.pool_root, 1, self.main, os.getpid(), branch="main"
        )
        self.assertEqual(claimed.name, "slot-0")
        self.assertFalse(lock.exists())


if __name__ == "__main__":
    unittest.main()
