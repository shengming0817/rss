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
        shutil.copy(ROOT / "hack/ci-pipeline.py", self.root / "hack")
        (self.root / "hack/ci-impact.py").write_text("import os; print(os.environ['DECISION'])\n")
        (self.root / "hack/semver-checks.sh").write_text('echo semver >> "$COMMAND_LOG"\nexit "${FAIL_SEMVER:-0}"\n')
        self.bin = self.root / "bin"
        self.bin.mkdir()
        cargo = self.bin / "cargo"
        cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMAND_LOG"\ncase "$*" in *"${FAIL_COMMAND-NEVER}"*) exit 9;; esac\n')
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
                    'CI_PART', 'CI_PACKAGES', 'CI_BASE', 'CI_HEAD', 'CI_PLAN', 'CI_ARTIFACTS', 'CI_FILTER'):
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

    def test_scope_and_depth_are_independent(self):
        for target, decision, deep, packages in [
            ("ci", self.env['DECISION'], False, '-p rss-contract'),
            ("ci", '{"full":true,"packages":[],"reasons":["global"]}', False, '--workspace'),
            ("ci-full", self.env['DECISION'], True, '--workspace'),
            ("ci", 'invalid json', False, '--workspace'),
        ]:
            result, commands = self.run_make("checks", target=target, DECISION=decision)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = [f'check --locked {packages}',
                        f'check --locked --no-default-features {packages}',
                        f'check --locked --all-features {packages}',
                        f'clippy --locked --all-targets --all-features {packages} -- -D warnings']
            if deep: expected += ['deny check -D unused-wrapper', 'semver']
            self.assertEqual(commands, expected)

    def test_every_check_runs_after_multiple_failures(self):
        green, expected = self.run_make("checks", target="ci-full")
        self.assertEqual(green.returncode, 0, green.stderr)
        for failure in ("check --locked", "clippy", ""):
            result, commands = self.run_make("checks", target="ci-full",
                                             FAIL_COMMAND=failure, FAIL_SEMVER="7")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(commands, expected)

    def test_semver_collects_package_and_feature_failures(self):
        shutil.copy(ROOT / "hack/semver-checks.sh", self.root / "hack")
        manifest = '\n'.join([
            '[workspace]', 'members = []',
            '[[workspace.metadata.release-surface.packages]]', 'package = "first"',
            '[[workspace.metadata.release-surface.packages]]', 'package = "second"',
        ])
        (self.root / 'Cargo.toml').write_text(manifest)
        for args in (["add", "Cargo.toml"], ["-c", "user.name=Test", "-c", "user.email=test@example.com",
                                            "commit", "-qm", "surface"]):
            subprocess.run(["/usr/bin/git", *args], cwd=self.root, check=True, capture_output=True)
        metadata = {"packages": [{"name": name, "targets": [{"kind": ["lib"]}]}
                                  for name in ('first', 'second')],
                    "metadata": {"release-surface": {"packages": [{"package": name}
                                                                  for name in ('first', 'second')]}}}
        (self.bin / 'cargo').write_text(
            '#!/usr/bin/env python3\nimport json, os, sys\n'
            'if sys.argv[1] == "metadata": print(os.environ["METADATA"])\n'
            'else:\n'
            ' with open(os.environ["COMMAND_LOG"], "a") as log: log.write(" ".join(sys.argv[1:])+"\\n")\n'
            ' sys.exit(9 if "--all-features" not in sys.argv else 0)\n')
        result = subprocess.run(['bash', 'hack/semver-checks.sh', 'HEAD', 'HEAD~1'],
                                cwd=self.root, env=self.env | {'METADATA': json.dumps(metadata)},
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        commands = self.log.read_text().splitlines()
        self.assertEqual(len(commands), 4, result.stderr)
        self.assertEqual(sum('--all-features' in command for command in commands), 2)
        self.assertEqual(sum('--package second' in command for command in commands), 2)

    def test_invalid_part_and_empty_selection(self):
        result, commands = self.run_make("typo")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(commands)
        result, commands = self.run_make("all", DECISION='{"full": false, "packages": [], "reasons": []}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(commands)


if __name__ == "__main__":
    unittest.main()
