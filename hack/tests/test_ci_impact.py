#!/usr/bin/env python3
"""Black-box contract for the package-only CI impact selector."""

from __future__ import annotations

import fcntl
import importlib.util
import json
import re
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


RSS_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SELECTOR = [sys.executable, str(RSS_ROOT / "hack" / "ci-impact.py")]


def selector_command() -> list[str]:
    override = os.environ.get("CI_IMPACT_COMMAND")
    return shlex.split(override) if override else DEFAULT_SELECTOR


class FixtureRepo:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="rss-ci-impact-")
        self.root = Path(self._tmp.name)
        self._write(
            "Cargo.toml",
            """[workspace]
resolver = "2"
members = [
  "crates/core",
  "crates/leaf",
  "crates/other",
  "crates/dev-consumer",
  "crates/build-consumer",
  "crates/optional-consumer",
  "tests/leaf-integration",
  "tests/other-integration",
]
""",
        )
        self._package("crates/core", "core")
        self._package("crates/leaf", "leaf", dependencies={"core": "../core"})
        self._package("crates/other", "other")
        self._package(
            "crates/dev-consumer",
            "dev-consumer",
            dev_dependencies={"core": "../core"},
        )
        self._package(
            "crates/build-consumer",
            "build-consumer",
            build_dependencies={"core": "../core"},
        )
        self._package(
            "crates/optional-consumer",
            "optional-consumer",
            optional_dependencies={"core": "../core"},
        )
        self._package(
            "tests/leaf-integration",
            "leaf-integration",
            dependencies={"leaf": "../../crates/leaf"},
            publish=False,
        )
        self._package(
            "tests/other-integration",
            "other-integration",
            dependencies={"other": "../../crates/other"},
            publish=False,
        )
        self._write("crates/leaf/src/obsolete.rs", "pub const OBSOLETE: bool = true;\n")
        self._write("README.md", "fixture\n")
        self._write("docs/guide.md", "guide\n")
        self.git("init", "-q")
        self.git("config", "user.email", "ci-impact@example.invalid")
        self.git("config", "user.name", "CI Impact Test")
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1"],
            cwd=self.root,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.commit("base")
        self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def close(self) -> None:
        self._tmp.cleanup()

    def _write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _package(
        self,
        relative: str,
        name: str,
        *,
        dependencies: dict[str, str] | None = None,
        dev_dependencies: dict[str, str] | None = None,
        build_dependencies: dict[str, str] | None = None,
        optional_dependencies: dict[str, str] | None = None,
        publish: bool = True,
    ) -> None:
        manifest = [
            "[package]",
            f'name = "{name}"',
            'version = "0.1.0"',
            'edition = "2024"',
        ]
        if not publish:
            manifest.append("publish = false")
        for heading, values in (
            ("dependencies", dependencies),
            ("dev-dependencies", dev_dependencies),
            ("build-dependencies", build_dependencies),
        ):
            if values:
                manifest.extend(["", f"[{heading}]"])
                manifest.extend(
                    f'{dependency} = {{ path = "{path}" }}'
                    for dependency, path in values.items()
                )
        if optional_dependencies:
            manifest.extend(["", "[features]", 'default = []', 'integration = ["dep:core"]'])
            manifest.extend(["", "[dependencies]"])
            manifest.extend(
                f'{dependency} = {{ path = "{path}", optional = true }}'
                for dependency, path in optional_dependencies.items()
            )
        self._write(f"{relative}/Cargo.toml", "\n".join(manifest) + "\n")
        self._write(f"{relative}/src/lib.rs", f"pub const NAME: &str = \"{name}\";\n")

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/usr/bin/git", *args],
            cwd=self.root,
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def change(self, relative: str, content: str = "changed\n") -> str:
        self._write(relative, content)
        return self.commit(f"change {relative}")

    def delete(self, relative: str) -> str:
        (self.root / relative).unlink()
        return self.commit(f"delete {relative}")

    def rename(self, source: str, destination: str) -> str:
        destination_path = self.root / destination
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(self.root / source, destination_path)
        return self.commit(f"rename {source}")

    def copy(self, source: str, destination: str) -> str:
        destination_path = self.root / destination
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.root / source, destination_path)
        return self.commit(f"copy {source}")

    def select(
        self,
        *,
        base: str | None = None,
        head: str = "HEAD",
        environment: dict[str, str] | None = None,
    ) -> tuple[bytes, dict]:
        process_environment = os.environ.copy()
        process_environment.update(environment or {})
        result = subprocess.run(
            [
                *selector_command(),
                "--base",
                base or self.base,
                "--head",
                head,
            ],
            cwd=self.root,
            check=False,
            env=process_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._last_result = result
        self.assert_selector_process(result)
        raw = result.stdout
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise AssertionError(f"selector stdout is not one JSON line: {raw!r}")
        decision = json.loads(raw)
        if list(decision) != ["full", "packages", "reasons"]:
            raise AssertionError(f"unexpected schema/order: {decision!r}")
        if type(decision["full"]) is not bool:
            raise AssertionError(f"full is not bool: {decision!r}")
        for key in ("packages", "reasons"):
            values = decision[key]
            if not isinstance(values, list):
                raise AssertionError(f"{key} is not a list: {decision!r}")
            if not all(isinstance(value, str) and value for value in values):
                raise AssertionError(f"{key} contains invalid values: {decision!r}")
            if values != sorted(set(values)):
                raise AssertionError(f"{key} is not sorted and unique: {decision!r}")
        if decision["full"]:
            if decision["packages"] or not decision["reasons"]:
                raise AssertionError(f"invalid full decision: {decision!r}")
        return raw, decision

    def assert_selector_process(self, result: subprocess.CompletedProcess[bytes]) -> None:
        if result.returncode != 0:
            raise AssertionError(
                f"selector exited {result.returncode}: {result.stderr.decode(errors='replace')}"
            )


class CiImpactContract(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = FixtureRepo()

    def tearDown(self) -> None:
        self.repo.close()

    def assert_decision(
        self,
        decision: dict,
        *,
        full: bool,
        packages: list[str],
        reason: str,
    ) -> None:
        self.assertEqual(decision["full"], full)
        self.assertEqual(decision["packages"], packages)
        self.assertIn(reason, decision["reasons"])

    def test_no_changes_is_empty_and_stable(self) -> None:
        first, decision = self.repo.select(head=self.repo.base)
        second, _ = self.repo.select(head=self.repo.base)
        self.assertEqual(first, second)
        self.assert_decision(decision, full=False, packages=[], reason="no-changes")

    def test_docs_only_skips_packages(self) -> None:
        head = self.repo.change("docs/guide.md", "updated\n")
        _, decision = self.repo.select(head=head)
        self.assert_decision(decision, full=False, packages=[], reason="docs-only")

    def test_skill_markdown_skips_packages_but_executable_inputs_do_not(self) -> None:
        for prefix in (".claude/skills/", ".codex/skills/"):
            with self.subTest(prefix=prefix):
                head = self.repo.change(prefix + "ship/SKILL.md", "workflow instructions\n")
                _, decision = self.repo.select(head=head)
                self.assert_decision(decision, full=False, packages=[], reason="docs-only")
        for prefix in (".claude/skills/", ".codex/skills/"):
            with self.subTest(executable_prefix=prefix):
                head = self.repo.change(prefix + "ship/check.sh", "#!/bin/sh\nexit 1\n")
                _, decision = self.repo.select(head=head)
                self.assert_decision(decision, full=True, packages=[], reason="unknown-path")
                self.repo.git("reset", "--hard", self.repo.base)

    def test_skill_moves_and_copies_are_docs_but_unknown_inputs_remain_full(self) -> None:
        for operation in ("rename", "copy", "unknown"):
            with self.subTest(operation=operation):
                self.repo.git("reset", "--hard", self.repo.base)
                source = ".codex/skills/ship/SKILL.md"
                base = self.repo.change(source, "specific workflow instructions\n")
                self.repo.change("README.md", "updated guide\n")
                if operation == "unknown":
                    head = self.repo.change("unowned/check.py", "raise RuntimeError()\n")
                else:
                    head = getattr(self.repo, operation)(source, ".codex/skills/fix/SKILL.md")
                _, decision = self.repo.select(base=base, head=head)
                self.assert_decision(decision, full=operation == "unknown", packages=[],
                    reason="unknown-path" if operation == "unknown" else "docs-only")

    def test_documentation_is_neutral_in_package_changes(self) -> None:
        self.repo.change("README.md", "new public API\n")
        self.repo.change(".claude/skills/ship/SKILL.md", "instructions\n")
        self.repo.delete("docs/guide.md")
        head = self.repo.change("crates/core/src/lib.rs")
        _, decision = self.repo.select(head=head)
        self.assert_decision(decision, full=False, packages=[
            "build-consumer", "core", "dev-consumer", "leaf",
            "leaf-integration", "optional-consumer",
        ], reason="package-change")
        head = self.repo.change("Makefile", "ci:\n\tfalse\n")
        _, decision = self.repo.select(head=head)
        self.assert_decision(decision, full=True, packages=[], reason="global-input")

    def test_every_controlled_root_document_is_docs_only(self) -> None:
        for relative in sorted(
            {
                "AGENTS.md",
                "CHANGELOG.md",
                "CLAUDE.md",
                "CODE_OF_CONDUCT.md",
                "CONTRIBUTING.md",
                "GOVERNANCE.md",
                "LICENSE",
                "LICENSE.md",
                "MAINTAINERS.md",
                "README.md",
                "RELEASES.md",
                "SECURITY.md",
            }
        ):
            with self.subTest(relative=relative):
                repo = FixtureRepo()
                try:
                    head = repo.change(relative)
                    _, decision = repo.select(head=head)
                    self.assert_decision(
                        decision, full=False, packages=[], reason="docs-only"
                    )
                finally:
                    repo.close()

    def test_leaf_selects_its_integration_reverse_dependency(self) -> None:
        head = self.repo.change("crates/leaf/src/lib.rs")
        _, decision = self.repo.select(head=head)
        self.assert_decision(
            decision,
            full=False,
            packages=["leaf", "leaf-integration"],
            reason="package-change",
        )

    def test_reverse_closure_includes_normal_dev_and_build_edges(self) -> None:
        head = self.repo.change("crates/core/src/lib.rs")
        _, decision = self.repo.select(head=head)
        self.assert_decision(
            decision,
            full=False,
            packages=[
                "build-consumer",
                "core",
                "dev-consumer",
                "leaf",
                "leaf-integration",
                "optional-consumer",
            ],
            reason="package-change",
        )

    def test_nested_package_uses_the_deepest_package_root(self) -> None:
        self.repo._package("crates/leaf/nested", "nested")
        workspace = (self.repo.root / "Cargo.toml").read_text(encoding="utf-8")
        self.repo._write(
            "Cargo.toml",
            workspace.replace(
                '  "crates/leaf",\n',
                '  "crates/leaf",\n  "crates/leaf/nested",\n',
            ),
        )
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1"],
            cwd=self.repo.root,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.repo.base = self.repo.commit("add nested package")
        head = self.repo.change("crates/leaf/nested/src/lib.rs")
        _, decision = self.repo.select(head=head)
        self.assert_decision(
            decision,
            full=False,
            packages=["nested"],
            reason="package-change",
        )

    def test_known_package_deletion_remains_selective(self) -> None:
        head = self.repo.delete("crates/leaf/src/obsolete.rs")
        _, decision = self.repo.select(head=head)
        self.assert_decision(
            decision,
            full=False,
            packages=["leaf", "leaf-integration"],
            reason="package-change",
        )

    def test_selector_and_its_tests_use_script_checks_and_preserve_mixed_impact(self):
        self.repo.change("hack/ci-impact.py", "# selector change\n")
        self.repo.change("hack/tests/test_ci_impact.py", "# contract change\n")
        head = self.repo.change("docs/guide.md", "verification scope\n")
        _, decision = self.repo.select(head=head)
        self.assert_decision(decision, full=False, packages=[], reason="selector-only")
        head = self.repo.change("crates/leaf/src/lib.rs")
        _, decision = self.repo.select(head=head)
        self.assert_decision(decision, full=False, packages=["leaf", "leaf-integration"], reason="package-change")
        head = self.repo.change("Makefile")
        _, decision = self.repo.select(head=head)
        self.assert_decision(decision, full=True, packages=[], reason="global-input")

    def test_ci_inputs_are_full(self) -> None:
        for relative in ("Makefile", ".config/nextest.toml", ".github/workflows/ci.yml"):
            with self.subTest(relative=relative):
                head = self.repo.change(relative)
                _, decision = self.repo.select(head=head)
                self.assert_decision(decision, full=True, packages=[], reason="global-input")

    def test_global_workspace_setting_is_full(self):
        manifest = self.repo.root / "Cargo.toml"
        head = self.repo.change("Cargo.toml", manifest.read_text() + "\n[profile.dev]\ndebug = 1\n")
        _, decision = self.repo.select(head=head)
        self.assert_decision(decision, full=True, packages=[], reason="global-input")

    def test_member_manifest_and_lock_formatting(self):
        path = self.repo.root / "crates/leaf/Cargo.toml"
        head = self.repo.change("crates/leaf/Cargo.toml", path.read_text() + '# comment\n')
        _, decision = self.repo.select(head=head)
        self.assert_decision(decision, full=False, packages=["leaf", "leaf-integration"], reason="package-change")
        lock = self.repo.root / "Cargo.lock"
        end = self.repo.change("Cargo.lock", lock.read_text() + "# comment\n")
        _, decision = self.repo.select(base=head, head=end)
        self.assert_decision(decision, full=False, packages=[], reason="package-change")

    def test_add_six_members_selects_only_import_and_removal_drops_dead_names(self):
        libraries = ["audit-core", "audit-postgres", "ledger", "ledger-postgres"]
        suites = ["audit-postgres-integration", "ledger-postgres-integration"]
        workspace = self.repo.root / "Cargo.toml"
        old_manifest = workspace.read_text()
        paths = [f"crates/{name}" for name in libraries] + [f"tests/{name}" for name in suites]
        for name, path in zip(libraries + suites, paths):
            self.repo._package(path, name, dependencies={"core": "../../crates/core"})
        workspace.write_text(old_manifest.replace("members = [", "members = [" +
                             "".join(f'\n  "{path}",' for path in paths)) +
                             '\n[workspace.dependencies]\naudit-core = { path = "crates/audit-core" }\n')
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.repo.root, check=True)
        added = self.repo.commit("import four libraries and two integration packages")
        _, decision = self.repo.select(head=added)
        self.assert_decision(decision, full=False, packages=sorted(libraries + suites), reason="package-change")
        self.repo.git("revert", "--no-edit", added)
        _, decision = self.repo.select(base=added)
        self.assert_decision(decision, full=False, packages=[], reason="package-change")

    def test_inherited_target_dependency_selects_its_consumers(self):
        manifest = self.repo.root / "Cargo.toml"
        manifest.write_text(manifest.read_text() + '\n[workspace.dependencies]\ncore = { path = "crates/core" }\n')
        leaf = self.repo.root / "crates/leaf/Cargo.toml"
        leaf.write_text(leaf.read_text().replace('[dependencies]', """[target.'cfg(unix)'.dependencies]""")
                        .replace('core = { path = "../core" }', "core.workspace = true"))
        base = self.repo.commit("inherit core for one target")
        head = self.repo.change("Cargo.toml", manifest.read_text().replace(
            'path = "crates/core" }', 'path = "crates/core", default-features = false }'))
        _, decision = self.repo.select(base=base, head=head)
        self.assert_decision(decision, full=False, packages=["leaf", "leaf-integration"], reason="package-change")

    def test_lock_only_repin_selects_transitive_consumers(self):
        with tempfile.TemporaryDirectory() as temp:
            remote = Path(temp).resolve()
            def commit_version(value):
                (remote / "src/lib.rs").write_text(f"pub const VALUE: u8 = {value};\n")
                subprocess.run(["/usr/bin/git", "add", "."], cwd=remote, check=True)
                subprocess.run(["/usr/bin/git", "-c", "user.name=CI", "-c", "user.email=ci@test.invalid",
                                "commit", "-qm", "update"], cwd=remote, check=True)
            subprocess.run(["/usr/bin/git", "init", "-q"], cwd=remote, check=True)
            (remote / "Cargo.toml").write_text('[package]\nname="external"\nversion="0.1.0"\nedition="2024"\n')
            (remote / "src").mkdir()
            commit_version(1)
            member = self.repo.root / "crates/leaf/Cargo.toml"
            member.write_text(member.read_text() + f'external = {{ git = "{remote.as_uri()}" }}\n')
            def update():
                subprocess.run(["cargo", "update", "-q"], cwd=self.repo.root, check=True)
            update()
            base = self.repo.commit("pin external dependency")
            commit_version(2)
            update()
            head = self.repo.commit("repin external at same version")
            _, decision = self.repo.select(base=base, head=head)
            self.assert_decision(decision, full=False, packages=["leaf", "leaf-integration"], reason="package-change")

    def test_shared_fixture_selects_literal_readers_on_either_side(self):
        fixture = "tests/fixtures/shared.rs"
        reader = "tests/leaf-integration/src/lib.rs"
        self.repo._write(reader, '#[path = "../../fixtures/shared.rs"] mod shared;\n')
        added = self.repo.change(fixture, "pub const VALUE: u8 = 1;\n")
        changed = self.repo.change(fixture, "pub const VALUE: u8 = 2;\n")
        self.repo._write(reader, 'pub struct Finished;\n')
        removed = self.repo.delete(fixture)
        for base, head in ((self.repo.base, added), (added, changed), (changed, removed)):
            _, decision = self.repo.select(base=base, head=head)
            self.assert_decision(decision, full=False, packages=["leaf-integration"], reason="package-change")

    def test_shared_fixture_change_ignores_homonymous_package_private_fixture(self):
        shared = "tests/fixtures/shared.rs"
        self.repo._write("tests/leaf-integration/src/lib.rs", 'include!("../../fixtures/shared.rs");\n')
        self.repo._write("tests/other-integration/src/lib.rs", 'include!("../fixtures/shared.rs");\n')
        self.repo._write("tests/other-integration/fixtures/shared.rs", "pub struct Private;\n")
        base = self.repo.change(shared, "pub struct Shared;\n")
        head = self.repo.change(shared, "pub struct Updated;\n")
        _, decision = self.repo.select(base=base, head=head)
        self.assert_decision(decision, full=False, packages=["leaf-integration"], reason="package-change")

    def test_fixture_with_literal_and_computed_readers_selects_both(self):
        fixture = "tests/fixtures/shared.rs"
        self.repo._write("tests/leaf-integration/src/lib.rs", 'include!("../../fixtures/shared.rs");\n')
        self.repo._write("tests/other-integration/src/lib.rs",
                         'include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../", "fixtures/", "shared.rs"));\n')
        self.repo._write("crates/other/src/lib.rs",
                         'pub fn load(name: &str) { let _ = std::fs::read(format!("../tests/fixtures/{name}")); }\n')
        base = self.repo.change(fixture, "pub struct Shared;\n")
        head = self.repo.change(fixture, "pub struct Updated;\n")
        _, decision = self.repo.select(base=base, head=head)
        self.assert_decision(decision, full=False, packages=["leaf-integration", "other", "other-integration"],
                             reason="package-change")

    def test_inline_module_path_selects_reader_with_different_base_directory(self):
        fixture = "tests/fixtures/shared.rs"
        self.repo._write("tests/leaf-integration/src/lib.rs", 'include!("../../fixtures/shared.rs");\n')
        self.repo._write("tests/other-integration/src/inline/.keep", "")
        self.repo._write("tests/other-integration/src/lib.rs", """
mod inline {
    #[path = "../../../fixtures/shared.rs"] mod shared;
    pub use shared::Shared;
}
pub use inline::Shared;
""")
        base = self.repo.change(fixture, "pub struct Shared;\n")
        command = ["cargo", "check", "-q", "--locked", "-p", "other-integration"]
        subprocess.run(command, cwd=self.repo.root, check=True)
        head = self.repo.change(fixture, "pub struct Replaced;\n")
        _, decision = self.repo.select(base=base, head=head)
        self.assert_decision(decision, full=False, packages=["leaf-integration", "other-integration"],
                             reason="package-change")
        failure = subprocess.run(command, cwd=self.repo.root, capture_output=True, text=True)
        self.assertNotEqual(failure.returncode, 0)
        self.assertIn("unresolved import", failure.stderr)

    def test_blocked_cargo_tree_returns_full_plan_and_releases_child_lock(self):
        member = self.repo.root / "crates/leaf/Cargo.toml"
        member.write_text(member.read_text().replace('version = "0.1.0"', 'version = "0.1.1"'))
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.repo.root, check=True)
        head = self.repo.commit("change a locked member")
        with tempfile.TemporaryDirectory() as temp:
            tools = Path(temp)
            lock = tools / "child.lock"
            cargo = tools / "cargo"
            waiter = tools / "wait.py"
            waiter.write_text("import fcntl, sys, time\n"
                              "with open(sys.argv[1], 'w') as f:\n"
                              "    fcntl.flock(f, fcntl.LOCK_EX)\n    time.sleep(60)\n")
            # The direct process and its child share the selector query's process group.
            cargo.write_text(f"#!{sys.executable}\nimport os, subprocess, sys\n"
                             "if sys.argv[1] == 'tree':\n"
                             f"    subprocess.run([sys.executable, {str(waiter)!r}, {str(lock)!r}])\n"
                             "else:\n"
                             f"    os.execv({shutil.which('cargo')!r}, sys.argv)\n")
            cargo.chmod(0o755)
            wrapper = tools / "select.py"
            wrapper.write_text("import importlib.util\n"
                               f"spec = importlib.util.spec_from_file_location('impact', {DEFAULT_SELECTOR[1]!r})\n"
                               "impact = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(impact)\n"
                               "impact.QUERY_TIMEOUT_SECONDS = 2\nimpact.main()\n")
            with patch.dict(os.environ, CI_IMPACT_COMMAND=shlex.join([sys.executable, str(wrapper)])):
                _, decision = self.repo.select(head=head, environment={"PATH": str(tools) + os.pathsep + os.environ["PATH"]})
            self.assertTrue(decision["full"])
            self.assertEqual(decision["packages"], [])
            self.assertRegex(decision["reasons"][0], r"^cargo-tree-[\w-]+-timeout$")
            with lock.open() as f:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_snapshot_preserves_caller_head_index_and_files_under_git_hook_environment(self):
        member = self.repo.root / "crates/leaf/Cargo.toml"
        head = self.repo.change("crates/leaf/Cargo.toml", member.read_text() + "# committed\n")
        self.repo._write("README.md", "staged\n")
        self.repo.git("add", "README.md")
        self.repo._write("README.md", "working copy\n")
        def state():
            return (self.repo.git("symbolic-ref", "HEAD").stdout, self.repo.git("rev-parse", "HEAD").stdout,
                    self.repo.git("ls-files", "--stage").stdout, self.repo.git("diff").stdout,
                    self.repo.git("status", "--porcelain").stdout)
        before = state()
        for key, file in (("GIT_DIR", ".git"), ("GIT_INDEX_FILE", ".git/index")):
            with self.subTest(key=key):
                _, decision = self.repo.select(head=head, environment={key: str(self.repo.root / file)})
                self.assertEqual(state(), before)
                self.assert_decision(decision, full=False, packages=["leaf", "leaf-integration"],
                                     reason="package-change")

    def test_unattributed_fixture_fails_full(self):
        head = self.repo.change("tests/fixtures/unknown.rs", "pub struct Unknown;\n")
        _, decision = self.repo.select(head=head)
        self.assert_decision(decision, full=True, packages=[], reason="unknown-fixture-owner")

    def test_actual_archive_shared_input_selects_only_its_consumers(self):
        archive = RSS_ROOT / "tests/archive-integration/tests/archive.rs"
        include = re.search(r'#\[path = "([^"]+)"\]\s*mod support;', archive.read_text())
        path = (archive.parent / include.group(1)).resolve().relative_to(RSS_ROOT).as_posix()
        spec = importlib.util.spec_from_file_location("impact", RSS_ROOT / "hack/ci-impact.py")
        impact = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(impact)
        roots, _ = impact.workspace_graph(RSS_ROOT, impact.metadata(RSS_ROOT))
        self.assertEqual(impact.fixture_owners(RSS_ROOT, "HEAD", path, roots),
                         {"archive-integration", "postgres-integration"})

    def test_unknown_add_and_delete_are_full(self) -> None:
        head = self.repo.change("unknown/source.rs")
        _, added = self.repo.select(head=head)
        self.assert_decision(added, full=True, packages=[], reason="unknown-path")

        repo = FixtureRepo()
        try:
            repo.change("orphan.txt")
            base = repo.git("rev-parse", "HEAD").stdout.strip()
            head = repo.delete("orphan.txt")
            _, deleted = repo.select(base=base, head=head)
            self.assert_decision(
                deleted, full=True, packages=[], reason="unowned-deletion"
            )
        finally:
            repo.close()

    def test_move_selects_both_owners_and_copy_only_the_destination(self):
        source = "crates/leaf/src/obsolete.rs"
        copied = self.repo.copy(source, "crates/other/src/copied.rs")
        _, decision = self.repo.select(head=copied)
        self.assert_decision(decision, full=False, packages=["other", "other-integration"], reason="package-change")
        moved = self.repo.rename(source, "crates/other/src/moved.rs")
        _, decision = self.repo.select(base=copied, head=moved)
        self.assert_decision(decision, full=False, packages=["leaf", "leaf-integration", "other", "other-integration"],
                             reason="package-change")

    def test_abnormal_type_change_is_full(self) -> None:
        target = self.repo.root / "crates/leaf/src/lib.rs"
        target.unlink()
        target.symlink_to("../../../README.md")
        head = self.repo.commit("type change leaf source")
        _, decision = self.repo.select(head=head)
        self.assert_decision(decision, full=True, packages=[], reason="diff-invalid")

    def test_invalid_base_fails_full_without_process_failure(self) -> None:
        _, decision = self.repo.select(base="missing-revision")
        self.assert_decision(decision, full=True, packages=[], reason="diff-unavailable")

    def test_metadata_process_failure_fails_full(self) -> None:
        head = self.repo.change("crates/leaf/src/lib.rs")
        empty_path = tempfile.mkdtemp(prefix="rss-ci-impact-empty-path-")
        try:
            _, decision = self.repo.select(head=head, environment={"PATH": empty_path})
        finally:
            shutil.rmtree(empty_path)
        self.assert_decision(
            decision,
            full=True,
            packages=[],
            reason="metadata-unavailable",
        )

    def test_missing_workspace_resolve_node_fails_full(self) -> None:
        head = self.repo.change("crates/leaf/src/lib.rs")
        document = json.loads(
            subprocess.run(
                ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
                cwd=self.repo.root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout
        )
        missing = document["workspace_members"][0]
        document["resolve"]["nodes"] = [
            node for node in document["resolve"]["nodes"] if node["id"] != missing
        ]
        fake_path = Path(tempfile.mkdtemp(prefix="rss-ci-impact-fake-cargo-"))
        try:
            metadata_path = fake_path / "metadata.json"
            metadata_path.write_text(json.dumps(document), encoding="utf-8")
            cargo = fake_path / "cargo"
            cargo.write_text(
                f"#!/bin/sh\nexec /bin/cat {shlex.quote(str(metadata_path))}\n",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            _, decision = self.repo.select(head=head, environment={"PATH": str(fake_path)})
        finally:
            shutil.rmtree(fake_path)
        self.assert_decision(
            decision, full=True, packages=[], reason="metadata-invalid"
        )


if __name__ == "__main__":
    unittest.main()
