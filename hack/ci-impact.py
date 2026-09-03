#!/usr/bin/env python3
"""Select affected Cargo workspace packages from a Git revision range."""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys


GLOBAL_FILES = {
    "Cargo.lock",
    "Makefile",
    "clippy.toml",
    "deny.toml",
    "rust-toolchain.toml",
}
GLOBAL_PREFIXES = (
    ".cargo/",
    ".config/",
    ".github/actions/",
    ".github/scripts/",
    ".github/workflows/",
)
ROOT_DOCS = {
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


class SelectionError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


def emit(full: bool, packages: set[str] | None, reasons: set[str]) -> None:
    decision = {
        "full": full,
        "packages": [] if full else sorted(packages or set()),
        "reasons": sorted(reasons),
    }
    print(json.dumps(decision, separators=(",", ":"), ensure_ascii=False))


def run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise SelectionError("diff-unavailable") from error


def parse_args(arguments: list[str]) -> tuple[str, str]:
    if len(arguments) != 4 or arguments[0] != "--base" or arguments[2] != "--head":
        raise SelectionError("invalid-arguments")
    if not arguments[1] or not arguments[3]:
        raise SelectionError("invalid-arguments")
    return arguments[1], arguments[3]


def valid_path(raw: str) -> bool:
    path = PurePosixPath(raw)
    return bool(raw) and not path.is_absolute() and ".." not in path.parts


def changed_paths(root: Path, base: str, head: str) -> list[tuple[str, str]]:
    result = run(
        [
            "/usr/bin/git",
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            "--find-copies",
            "--find-copies-harder",
            base,
            head,
            "--",
        ],
        cwd=root,
    )
    if result.returncode != 0:
        raise SelectionError("diff-unavailable")
    try:
        fields = result.stdout.decode("utf-8").split("\0")
    except UnicodeDecodeError as error:
        raise SelectionError("diff-invalid") from error
    if fields and fields[-1] == "":
        fields.pop()

    changes: list[tuple[str, str]] = []
    cursor = 0
    while cursor < len(fields):
        status = fields[cursor]
        cursor += 1
        if not status or status[0] not in "ADMRC":
            raise SelectionError("diff-invalid")
        path_count = 2 if status[0] in "RC" else 1
        if cursor + path_count > len(fields):
            raise SelectionError("diff-invalid")
        paths = fields[cursor : cursor + path_count]
        cursor += path_count
        if not all(valid_path(path) for path in paths):
            raise SelectionError("invalid-path")
        if status[0] in "RC":
            raise SelectionError("rename-or-copy")
        changes.append((status[0], paths[0]))
    return changes


def is_global(path: str) -> bool:
    return (
        path in GLOBAL_FILES
        or path.endswith("/Cargo.toml")
        or path == "Cargo.toml"
        or path == "hack/ci-impact.py"
        or any(path.startswith(prefix) for prefix in GLOBAL_PREFIXES)
    )


def is_docs(path: str) -> bool:
    return path.startswith("docs/") or path.startswith(".github/project-template/") or path in ROOT_DOCS


def metadata(root: Path) -> dict:
    try:
        result = subprocess.run(
            ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise SelectionError("metadata-unavailable") from error
    if result.returncode != 0:
        raise SelectionError("metadata-unavailable")
    try:
        document = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SelectionError("metadata-invalid") from error
    if not isinstance(document, dict):
        raise SelectionError("metadata-invalid")
    return document


def workspace_graph(root: Path, document: dict) -> tuple[list[tuple[PurePosixPath, str]], dict[str, set[str]]]:
    try:
        metadata_root = Path(document["workspace_root"]).resolve()
        members = set(document["workspace_members"])
        packages = document["packages"]
        nodes = document["resolve"]["nodes"]
    except (KeyError, TypeError) as error:
        raise SelectionError("metadata-invalid") from error
    if metadata_root != root:
        raise SelectionError("workspace-root-mismatch")

    id_to_name: dict[str, str] = {}
    roots: list[tuple[PurePosixPath, str]] = []
    try:
        for package in packages:
            package_id = package["id"]
            if package_id not in members:
                continue
            name = package["name"]
            manifest = Path(package["manifest_path"]).resolve()
            package_root = manifest.parent.relative_to(root)
            relative = PurePosixPath(package_root.as_posix())
            if ".." in relative.parts:
                raise ValueError("path escape")
            id_to_name[package_id] = name
            roots.append((relative, name))
    except (KeyError, TypeError, ValueError) as error:
        raise SelectionError("metadata-invalid") from error
    if set(id_to_name) != members:
        raise SelectionError("metadata-invalid")
    roots.sort(key=lambda item: (-len(item[0].parts), item[0].as_posix()))

    reverse = {name: set() for name in id_to_name.values()}
    seen_nodes: set[str] = set()
    try:
        for node in nodes:
            node_id = node["id"]
            if node_id in seen_nodes:
                raise ValueError("duplicate resolve node")
            seen_nodes.add(node_id)
            dependent = id_to_name.get(node_id)
            if dependent is None:
                continue
            for dependency in node["deps"]:
                dependency_name = id_to_name.get(dependency["pkg"])
                if dependency_name is not None:
                    reverse[dependency_name].add(dependent)
    except (KeyError, TypeError, ValueError) as error:
        raise SelectionError("metadata-invalid") from error
    if seen_nodes.intersection(members) != members:
        raise SelectionError("metadata-invalid")
    return roots, reverse


def owner(path: str, roots: list[tuple[PurePosixPath, str]]) -> str | None:
    candidate = PurePosixPath(path)
    for package_root, name in roots:
        if candidate == package_root or package_root in candidate.parents:
            return name
    return None


def reverse_closure(seeds: set[str], reverse: dict[str, set[str]]) -> set[str]:
    selected = set(seeds)
    pending = list(seeds)
    while pending:
        dependency = pending.pop()
        for dependent in reverse.get(dependency, set()):
            if dependent not in selected:
                selected.add(dependent)
                pending.append(dependent)
    return selected


def select(root: Path, base: str, head: str) -> tuple[bool, set[str], set[str]]:
    changes = changed_paths(root, base, head)
    if not changes:
        return False, set(), {"no-changes"}
    if any(is_global(path) for _, path in changes):
        return True, set(), {"global-input"}
    if all(is_docs(path) for _, path in changes):
        return False, set(), {"docs-only"}

    roots, reverse = workspace_graph(root, metadata(root))
    seeds: set[str] = set()
    for status, path in changes:
        package = owner(path, roots)
        if package is None:
            reason = "unowned-deletion" if status == "D" else "unknown-path"
            return True, set(), {reason}
        seeds.add(package)
    return False, reverse_closure(seeds, reverse), {"package-change"}


def main() -> None:
    try:
        base, head = parse_args(sys.argv[1:])
        root_result = run(["/usr/bin/git", "rev-parse", "--show-toplevel"], cwd=Path.cwd())
        if root_result.returncode != 0:
            raise SelectionError("diff-unavailable")
        try:
            root = Path(os.fsdecode(root_result.stdout.rstrip(b"\n"))).resolve()
        except (OSError, ValueError) as error:
            raise SelectionError("invalid-path") from error
        full, packages, reasons = select(root, base, head)
        emit(full, packages, reasons)
    except SelectionError as error:
        emit(True, set(), {error.reason})
    except Exception:
        emit(True, set(), {"metadata-invalid"})


if __name__ == "__main__":
    main()
