"""Exercise real Make recipes with observable stand-ins for expensive Cargo commands."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class MakeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rss-ci-make-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "hack/tests").mkdir(parents=True)
        (self.root / "hack/tests/test_ci_fixture.py").write_text("import unittest\nclass Fixture(unittest.TestCase):\n def test_fixture(self): pass\n")
        shutil.copy(ROOT / "Makefile", self.root)
        shutil.copy(ROOT / "hack/ci-run.py", self.root / "hack")
        (self.root / "hack/ci-impact.py").write_text("import os; print(os.environ['DECISION'])\n")
        (self.root / "hack/semver-checks.sh").write_text('echo semver >> "$COMMAND_LOG"\n')
        self.bin = self.root / "bin"
        self.bin.mkdir()
        cargo = self.bin / "cargo"
        cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMAND_LOG"\ncase "$*" in *"${FAIL_COMMAND:-NEVER}"*) exit 9;; esac\n')
        cargo.chmod(0o755)
        for command in (["init", "-q"], ["-c", "user.name=Test", "-c", "user.email=test@example.com",
                                        "commit", "--allow-empty", "-qm", "fixture"],
                        ["-c", "user.name=Test", "-c", "user.email=test@example.com",
                         "commit", "--allow-empty", "-qm", "fixture two"]):
            subprocess.run(["/usr/bin/git", *command], cwd=self.root, check=True, capture_output=True)
        self.log = self.root / "commands"
        self.env = os.environ | {"PATH": f"{self.bin}:{os.environ['PATH']}",
                                 "RSS_COMPILER_CACHE": "off", "RSS_TARGET_POOL_N": "off",
                                 "COMMAND_LOG": str(self.log),
                                 "DECISION": json.dumps({"full": False, "packages": ["rss-contract"], "reasons": []})}
        # Each fixture is an independent Make invocation, not a recursive parent build.
        for key in ('CARGO_TARGET_DIR', 'MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'CI_FULL',
                    'CI_PART', 'CI_PACKAGES', 'CI_BASE', 'CI_HEAD'):
            self.env.pop(key, None)

    def run_make(self, part, target="ci", **env):
        self.log.unlink(missing_ok=True)
        result = subprocess.run(["make", target, f"CI_PART={part}", "CI_BASE=HEAD"],
                                cwd=self.root, env=self.env | env, capture_output=True, text=True, timeout=15)
        commands = self.log.read_text().splitlines() if self.log.exists() else []
        return result, commands

    def test_dry_run_does_not_execute_or_allocate(self):
        pool = self.root / 'dry-pool'
        result = subprocess.run(['make', '-n', 'ci', 'CI_PART=checks'], cwd=self.root,
                                env=self.env | {'RSS_TARGET_POOL_N': '6', 'RSS_TARGET_POOL_ROOT': str(pool)},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ci-run.py', result.stdout)
        self.assertFalse(self.log.exists())
        self.assertFalse(pool.exists())
        self.assertNotIn('rss-ci:', result.stderr)

    def test_partition_and_full_fallback(self):
        for full in (False, True):
            env = {"DECISION": json.dumps({"full": True, "packages": [], "reasons": ["global"]})} if full else {}
            checks, a = self.run_make("checks", **env)
            tests, b = self.run_make("tests", **env)
            all_result, both = self.run_make("all", **env)
            for result in (checks, tests, all_result):
                self.assertEqual(result.returncode, 0, result.stderr)
            packages = '--workspace' if full else '-p rss-contract'
            expected_checks = [f'check --locked {packages}',
                               f'check --locked --no-default-features {packages}',
                               f'check --locked --all-features {packages}',
                               f'clippy --locked --all-targets --all-features {packages} -- -D warnings']
            if full:
                expected_checks += ['deny check -D unused-wrapper', 'semver']
            expected_tests = ([f'llvm-cov nextest --locked {packages} --all-features --no-report'] if full else
                              [f'nextest run --locked --all-features {packages}'])
            expected_tests += [f'test --doc --locked --all-features {packages}']
            if full:
                expected_tests += ['llvm-cov report --fail-under-lines 80 --lcov --output-path lcov.info']
            self.assertEqual(a, expected_checks)
            self.assertEqual(b, expected_tests)
            self.assertEqual(both, expected_checks + expected_tests)
            self.assertEqual(all_result.stderr.count("pool=off"), 1)

    def test_failure_propagates_but_other_group_runs(self):
        result, commands = self.run_make("all", FAIL_COMMAND="check --locked")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any("nextest run" in c for c in commands))

    def test_invalid_part_and_empty_selection(self):
        result, commands = self.run_make("typo")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(commands)
        result, commands = self.run_make("all", DECISION='{"full": false, "packages": [], "reasons": []}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(commands)


if __name__ == "__main__":
    unittest.main()
