"""Process-level contracts for the whole-run Cargo target lease."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "hack/ci-run.py"
spec = importlib.util.spec_from_file_location("ci_run", SCRIPT)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rss-pool-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pool = self.root / "pool"
        self.work = self.root / "work tree"
        self.work.mkdir()
        self.env = dict(os.environ, RSS_TARGET_POOL_ROOT=str(self.pool),
                        RSS_TARGET_POOL_N="2", RSS_COMPILER_CACHE="off")
        self.env.pop("CARGO_TARGET_DIR", None)

    def run_cmd(self, code, work=None, **env):
        return subprocess.run([sys.executable, str(SCRIPT), "--", sys.executable, "-c", code],
                              cwd=work or self.work, env=self.env | env,
                              capture_output=True, text=True, timeout=10)

    def hold(self, work=None, **env):
        ready = self.root / str(time.monotonic_ns())
        code = f"from pathlib import Path; import time; Path({str(ready)!r}).touch(); time.sleep(30)"
        p = subprocess.Popen([sys.executable, str(SCRIPT), "--", sys.executable, "-c", code],
                             cwd=work or self.work, env=self.env | env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop, p)
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline and p.poll() is None:
            time.sleep(.02)
        self.assertTrue(ready.exists(), f"holder failed: {p.poll()}")
        return p

    @staticmethod
    def stop(p):
        if p.poll() is None:
            p.terminate()
            p.wait(timeout=5)

    def test_sticky_then_reassignment_wipes(self):
        first = self.run_cmd("import os; from pathlib import Path; p=Path(os.environ['CARGO_TARGET_DIR']); (p/'artifact').touch(); print(p)", RSS_TARGET_POOL_N="1")
        self.assertEqual(first.returncode, 0, first.stderr)
        target = Path(first.stdout.strip())
        again = self.run_cmd("import os; print(os.environ['CARGO_TARGET_DIR'])", RSS_TARGET_POOL_N="1")
        self.assertEqual(again.stdout.strip(), str(target))
        self.assertTrue((target / "artifact").exists())
        other = self.root / "other"
        other.mkdir()
        self.assertEqual(self.run_cmd("pass", work=other, RSS_TARGET_POOL_N="1").returncode, 0)
        self.assertFalse((target / "artifact").exists())

    def test_busy_owner_and_full_pool(self):
        self.hold()
        self.assertNotEqual(self.run_cmd("pass").returncode, 0)
        other = self.root / "other"
        other.mkdir()
        self.hold(other)
        third = self.root / "third"
        third.mkdir()
        result = self.run_cmd("pass", work=third)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pool full", result.stderr)

    def test_signal_releases_only_after_child_exit(self):
        p = self.hold(RSS_TARGET_POOL_N="1")
        self.stop(p)
        self.assertEqual(p.returncode, 128 + signal.SIGTERM)
        self.assertEqual(self.run_cmd("pass", RSS_TARGET_POOL_N="1").returncode, 0)

    def test_orphan_keeps_lock(self):
        p = self.hold(RSS_TARGET_POOL_N="1")
        # The command PID is diagnostic; the kernel lock owns liveness.
        lease = json.loads((self.pool / "slot-0.json").read_text())
        child = lease["pid"]
        p.kill()
        p.wait(timeout=5)
        try:
            self.assertNotEqual(self.run_cmd("pass", RSS_TARGET_POOL_N="1").returncode, 0)
        finally:
            os.killpg(child, signal.SIGTERM)

    def test_missing_and_corrupt_metadata_wipe(self):
        self.assertEqual(self.run_cmd("pass").returncode, 0)
        target = self.pool / "slot-0"
        for contents in (None, "invalid json"):
            (target / "stale").touch()
            meta = self.pool / "slot-0.json"
            if contents is None:
                meta.unlink()
            else:
                meta.write_text(contents)
            self.assertEqual(self.run_cmd("pass").returncode, 0)
            self.assertFalse((target / "stale").exists())

    def test_override_off_invalid_and_exit_code(self):
        target = str(self.root / "explicit")
        result = self.run_cmd("pass", CARGO_TARGET_DIR=target)
        self.assertNotEqual(result.returncode, 0)  # explicit pool + target
        result = self.run_cmd("import os; print(os.environ['CARGO_TARGET_DIR']); raise SystemExit(7)",
                              RSS_TARGET_POOL_N="off", CARGO_TARGET_DIR=target)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout.strip(), target)
        self.assertNotEqual(self.run_cmd("pass", RSS_TARGET_POOL_N="bad").returncode, 0)

    def test_symlink_slot_rejected_without_touching_destination(self):
        self.pool.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "safe").touch()
        (self.pool / "slot-0").symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.run_cmd("pass").returncode, 0)
        self.assertTrue((outside / "safe").exists())

class CacheTests(unittest.TestCase):
    def test_modes_and_existing_wrapper(self):
        base = {"PATH": "", "RSS_COMPILER_CACHE": "auto"}
        self.assertIsNone(ci.compiler_cache(base))
        with self.assertRaises(ValueError):
            ci.compiler_cache(base | {"RSS_COMPILER_CACHE": "on"})
        custom = base | {"RUSTC_WRAPPER": "/custom/wrapper"}
        self.assertIsNone(ci.compiler_cache(custom))
        self.assertEqual(custom["RUSTC_WRAPPER"], "/custom/wrapper")
        with self.assertRaises(ValueError):
            ci.compiler_cache(custom | {"RSS_COMPILER_CACHE": "on"})
        with self.assertRaises(ValueError):
            ci.compiler_cache(base | {"RSS_COMPILER_CACHE": "typo"})
        self.assertIsNone(ci.compiler_cache(base | {"RSS_COMPILER_CACHE": "off"}))

    def test_defaults_are_six_slots_and_upstream_cache_size(self):
        pool, target = ci.target_config({}, Path('/tmp/example'))
        self.assertEqual(pool[1], 6)
        self.assertIsNone(target)


class ExtraPoolTests(unittest.TestCase):
    setUp = PoolTests.setUp
    run_cmd = PoolTests.run_cmd
    hold = PoolTests.hold
    stop = staticmethod(PoolTests.stop)

    def test_unowned_directory_is_not_deleted(self):
        slot = self.pool / 'slot-0'
        slot.mkdir(parents=True)
        (slot / 'important').touch()
        result = self.run_cmd('pass')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unmarked nonempty', result.stderr)
        self.assertTrue((slot / 'important').exists())

    def test_legacy_pool_rejected_without_migration_or_deletion(self):
        slot = self.pool / 'slot-0'
        slot.mkdir(parents=True)
        (slot / 'lease.json').write_text('{"pid": 0}')
        (slot / 'artifact').touch()
        result = self.run_cmd('pass')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('legacy pool detected', result.stderr)
        self.assertTrue((slot / 'artifact').exists())

    def test_cancel_during_spawn_is_forwarded(self):
        ready = self.root / 'spawned'
        launch = f"""import importlib.util, time
spec=importlib.util.spec_from_file_location('run', {str(SCRIPT)!r})
ci=importlib.util.module_from_spec(spec); spec.loader.exec_module(ci)
original=ci.subprocess.Popen
def delayed(*a, **kw):
 p=original(*a, **kw)
 from pathlib import Path
 Path({str(ready)!r}).touch()
 time.sleep(.3)
 return p
ci.subprocess.Popen=delayed
raise SystemExit(ci.main(['--', {sys.executable!r}, '-c', 'import time; time.sleep(30)']))
"""
        p = subprocess.Popen([sys.executable, '-c', launch], cwd=self.work, env=self.env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop, p)
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(ready.exists())
        self.stop(p)
        self.assertEqual(p.returncode, 128 + signal.SIGTERM)
        self.assertEqual(self.run_cmd('pass').returncode, 0)

    def test_shrink_retains_active_out_of_range_slot(self):
        first = self.hold()
        other = self.root / 'other'
        other.mkdir()
        second = self.hold(other)
        self.stop(first)
        self.assertEqual(self.run_cmd('pass', RSS_TARGET_POOL_N='1').returncode, 0)
        self.assertTrue((self.pool / 'slot-1').exists())
        self.stop(second)
        self.assertEqual(self.run_cmd('pass', RSS_TARGET_POOL_N='1').returncode, 0)
        self.assertFalse((self.pool / 'slot-1').exists())

    def test_global_lock_not_broken_by_age(self):
        self.pool.mkdir()
        fd = ci.lock_file(self.pool / '.pool.lock')
        os.utime(self.pool / '.pool.lock', (1, 1))
        process = subprocess.Popen([sys.executable, str(SCRIPT), '--', sys.executable, '-c', 'pass'],
                                   cwd=self.work, env=self.env, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        try:
            time.sleep(.15)
            self.assertIsNone(process.poll())
        finally:
            os.close(fd)
            process.wait(timeout=5)
        self.assertEqual(process.returncode, 0)

    def test_real_make_cargo_child_keeps_lease_after_wrapper_dies(self):
        # A build.rs child provides a deterministic point while real Cargo owns target.
        (self.work / 'src').mkdir()
        (self.work / 'src/lib.rs').write_text('pub fn value() -> u8 { 1 }')
        (self.work / 'Cargo.toml').write_text('[package]\nname="lease-proof"\nversion="0.0.0"\nedition="2021"\n')
        (self.work / 'build.rs').write_text('fn main() { std::fs::write("ready", "ready").unwrap(); while !std::path::Path::new("release").exists() { std::thread::sleep(std::time::Duration::from_millis(20)); } }')
        (self.work / 'Makefile').write_text('all:\n\tcargo build --offline\n')
        env = self.env.copy()
        for key in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTFLAGS'):
            env.pop(key, None)
        p = subprocess.Popen([sys.executable, str(SCRIPT), '--', 'make'], cwd=self.work, env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop, p)
        deadline = time.monotonic() + 30
        while not (self.work / 'ready').exists() and time.monotonic() < deadline and p.poll() is None:
            time.sleep(.05)
        try:
            self.assertTrue((self.work / 'ready').exists(), f'Cargo build failed: {p.poll()}')
            p.kill()
            p.wait(timeout=5)
            self.assertNotEqual(self.run_cmd('pass').returncode, 0)
        finally:
            (self.work / 'release').touch()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = self.run_cmd('pass')
            if result.returncode == 0:
                break
            time.sleep(.05)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
