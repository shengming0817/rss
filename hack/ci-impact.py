#!/usr/bin/env python3
"""Select affected Cargo workspace packages from a Git revision range."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import tomllib


SELECTOR_FILES = {"hack/ci-impact.py", "hack/tests/test_ci_impact.py"}
GLOBAL_FILES = {
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
            "--no-renames",
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
        if not status or status not in ("A", "D", "M"):
            raise SelectionError("diff-invalid")
        if cursor == len(fields) or not valid_path(fields[cursor]):
            raise SelectionError("diff-invalid")
        changes.append((status, fields[cursor]))
        cursor += 1
    return changes


def is_global(path: str) -> bool:
    return (
        path in GLOBAL_FILES
        or any(path.startswith(prefix) for prefix in GLOBAL_PREFIXES)
    )


def is_docs(path: str) -> bool:
    return (
        path.startswith("docs/")
        or path.startswith(".github/project-template/")
        or path in ROOT_DOCS
        or (path.endswith(".md") and path.startswith((".claude/skills/", ".codex/skills/")))
    )


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


def git(root: Path, *arguments: str) -> bytes:
    result = run(["/usr/bin/git", *arguments], cwd=root)
    if result.returncode:
        raise SelectionError("diff-unavailable")
    return result.stdout


@contextmanager
def checkout(root: Path, revision: str):
    """Read Cargo inputs from this revision without changing the caller's checkout."""
    sha = git(root, "rev-parse", "--verify", revision + "^{commit}").decode().strip()
    if git(root, "rev-parse", "HEAD").decode().strip() == sha and not git(
        root, "status", "--porcelain", "--untracked-files=normal"
    ):
        yield root
        return
    with tempfile.TemporaryDirectory(prefix="rss-impact-") as directory:
        snapshot = Path(directory).resolve() / "repo"
        git(root, "clone", "--quiet", "--shared", "--no-checkout", "--", str(root), str(snapshot))
        git(snapshot, "checkout", "--quiet", "--detach", sha)
        yield snapshot


def read_toml(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def workspace_inputs(root: Path) -> tuple[dict, dict]:
    manifest = read_toml(root / "Cargo.toml")
    workspace = manifest["workspace"]
    workspace.pop("members", None)
    dependencies = workspace.pop("dependencies", {})
    return manifest, dependencies


def inherited_dependencies(manifest: dict) -> set[str]:
    names = set()
    for table in (manifest, *manifest.get("target", {}).values()):
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, spec in table.get(kind, {}).items():
                if isinstance(spec, dict) and spec.get("workspace"):
                    names.add(name)
    return names


def lock_packages(root: Path) -> dict:
    return {(p["name"], p["version"], p.get("source")): p
            for p in read_toml(root / "Cargo.lock")["package"]}


def package_tree(root: Path, package: str) -> str:
    # Cargo resolves features for the selected consumer. A workspace-wide union
    # would make a new, unrelated member's provider features look like changes.
    result = run(["cargo", "tree", "--locked", "--all-features", "--target", "all",
                  "--package", package, "--prefix", "depth", "--format", "{p} {f}"], cwd=root)
    if result.returncode:
        raise SelectionError("metadata-unavailable")
    return result.stdout.decode().replace("(" + str(root) + "/", "(./")


def graph_changes(before: Path, after: Path, old_roots, new_roots) -> set[str]:
    old_config, old_deps = workspace_inputs(before)
    new_config, new_deps = workspace_inputs(after)
    if old_config != new_config:
        raise SelectionError("global-input")
    changed_deps = {key for key in old_deps.keys() | new_deps.keys()
                    if old_deps.get(key) != new_deps.get(key)}
    old = {name: path for path, name in old_roots}
    new = {name: path for path, name in new_roots}
    affected = old.keys() ^ new.keys()
    old_lock, new_lock = lock_packages(before), lock_packages(after)
    # Adding only new lock records cannot alter an existing resolution.
    check_trees = any(new_lock.get(key) != data for key, data in old_lock.items())
    # Cargo tree abbreviates Git revisions and omits registry checksums. Match
    # complete lock identities for packages whose printed name/version collides.
    identities = {}
    for key in old_lock.keys() | new_lock.keys():
        identities.setdefault(key[:2], set()).add(key[2])
    sensitive = {key[:2] for key in old_lock.keys() | new_lock.keys()
                 if old_lock.get(key) != new_lock.get(key) and (
                     len(identities[key[:2]]) > 1 or
                     (key in old_lock and key in new_lock and
                      old_lock[key].get("checksum") != new_lock[key].get("checksum")))}
    for name in old.keys() & new.keys():
        if changed_deps and changed_deps & inherited_dependencies(
            read_toml(after / new[name] / "Cargo.toml")
        ):
            affected.add(name)
        elif check_trees:
            previous = package_tree(before, name)
            current = package_tree(after, name)
            if previous != current or sensitive.intersection(
                re.findall(r"^\d+([\w-]+) v(\S+)", previous + current, re.MULTILINE)
            ):
                affected.add(name)
    return affected


def fixture_owners(root: Path, revision: str, path: str, roots) -> set[str]:
    # Shared fixture imports use literal paths. Include unresolved directory
    # references conservatively (e.g. a build script constructing a filename).
    basename = PurePosixPath(path).name
    result = run(["/usr/bin/git", "grep", "-I", "-z", "-F", "-e", basename,
                  "-e", "fixtures/", "-e", '/fixtures"', revision, "--"], cwd=root)
    if result.returncode not in (0, 1):
        raise SelectionError("diff-unavailable")
    packages = set()
    for row in result.stdout.decode().splitlines():
        filename, line = row.split("\0", 1)
        filename = filename.split(":", 1)[1]
        if is_docs(filename):
            continue
        package = owner(filename, roots)
        if package is None:
            # Tooling may discuss the fixture directory; a reference to this
            # particular file outside a package has no attributable consumer.
            if basename in line:
                raise SelectionError("unknown-fixture-owner")
            continue
        literals = re.findall(r"""["']([^"'\\]*)["']""", line)
        references = [value for value in literals if "fixtures" in value or basename in value]
        package_root = next(directory for directory, name in roots if name == package)
        if re.search(r'(?:#\[path\s*=|include(?:_bytes|_str)?!\s*\()\s*"', line):
            origins = (posixpath.dirname(filename),)
        else:
            origins = ("", posixpath.dirname(filename), str(package_root))
        targets = {posixpath.normpath(posixpath.join(origin, value.lstrip("/")))
                   for origin in origins for value in references}
        if any(target == path or path.startswith(target + "/") for target in targets):
            packages.add(package)
        elif basename in line and not references:
            packages.add(package)  # A nonliteral reference still names the fixture.
    if not packages:
        raise SelectionError("unknown-fixture-owner")
    return packages


def select(root: Path, base: str, head: str) -> tuple[bool, set[str], set[str]]:
    changes = changed_paths(root, base, head)
    if not changes:
        return False, set(), {"no-changes"}
    # CI's Python contract tests always run, including when no Cargo package is selected.
    selector_changed = any(path in SELECTOR_FILES for _, path in changes)
    changes = [(status, path) for status, path in changes if path not in SELECTOR_FILES]
    if any(is_global(path) for _, path in changes):
        return True, set(), {"global-input"}
    if all(is_docs(path) for _, path in changes):
        return False, set(), {"selector-only" if selector_changed else "docs-only"}

    with checkout(root, head) as current:
        roots, reverse = workspace_graph(current, metadata(current))
        cargo_changed = any(path in ("Cargo.toml", "Cargo.lock") or path.endswith("/Cargo.toml")
                            for _, path in changes)
        affected = set()
        old_roots, old_reverse = roots, reverse
        if cargo_changed:
            with checkout(root, base) as previous:
                old_roots, old_reverse = workspace_graph(previous, metadata(previous))
                affected = graph_changes(previous, current, old_roots, roots)

        before, after = set(affected), set(affected)
        for status, path in changes:
            if is_docs(path) or path in ("Cargo.toml", "Cargo.lock"):
                continue
            if path.startswith("tests/fixtures/"):
                if status != "A":
                    before.update(fixture_owners(root, base, path, old_roots))
                if status != "D":
                    after.update(fixture_owners(root, head, path, roots))
            else:
                package = owner(path, old_roots if status == "D" else roots)
                if package is None:
                    reason = "unowned-deletion" if status == "D" else "unknown-path"
                    return True, set(), {reason}
                (before if status == "D" else after).add(package)
        # Removed members can affect surviving callers. Only HEAD packages run.
        surviving = reverse_closure(before, old_reverse).intersection(reverse)
        return False, reverse_closure(after | surviving, reverse).intersection(reverse), {"package-change"}


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
