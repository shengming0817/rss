#!/usr/bin/env python3
"""Black-box contract for the package-only CI impact selector."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


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

    def test_manifest_lock_and_ci_inputs_are_full(self) -> None:
        cases = [
            ("Cargo.toml", None),
            ("Cargo.lock", "# changed\n"),
            ("Makefile", "ci:\n\ttrue\n"),
            (".config/nextest.toml", "[profile.default]\n"),
            (".github/workflows/ci.yml", "name: ci\n"),
        ]
        for relative, content in cases:
            with self.subTest(relative=relative):
                repo = FixtureRepo()
                try:
                    if content is None:
                        current = (repo.root / relative).read_text(encoding="utf-8")
                        content = current + "\n# changed\n"
                    head = repo.change(relative, content)
                    _, decision = repo.select(head=head)
                    self.assert_decision(decision, full=True, packages=[], reason="global-input")
                finally:
                    repo.close()

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

    def test_rename_and_copy_are_full(self) -> None:
        head = self.repo.rename("crates/leaf/src/lib.rs", "crates/leaf/src/renamed.rs")
        _, renamed = self.repo.select(head=head)
        self.assert_decision(renamed, full=True, packages=[], reason="rename-or-copy")

        repo = FixtureRepo()
        try:
            head = repo.copy("crates/leaf/src/lib.rs", "crates/leaf/src/copied.rs")
            _, copied = repo.select(head=head)
            self.assert_decision(copied, full=True, packages=[], reason="rename-or-copy")
        finally:
            repo.close()

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
