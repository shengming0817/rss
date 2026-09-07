#!/usr/bin/env python3
"""Run the extraction examples against independently resolved sources or exact archives."""

import hashlib
import gzip
from contextlib import contextmanager
import json
import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
MAX_COMPRESSED_BYTES = 16 * 1024 * 1024
MAX_TAR_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_CONTENT_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 4096
SCENARIOS = {
    "diagnostic": ["diagnostic"], "task-local": ["task-local"], "trace": ["trace"],
    "redact": ["redact"], "derive": ["derive"], "protection": ["protection"],
    "lifecycle": ["lifecycle"], "core": ["core"], "none": ["memory"],
    "producer": ["producer"], "consumer": ["consumer"], "both": ["producer", "consumer"],
    "self-host": ["providers"], "managed": ["managed"],
    "managed-worker": ["managed-worker"],
}


def archive_digest(path):
    if path.stat().st_size > MAX_COMPRESSED_BYTES:
        raise ValueError("compressed archive budget exceeded")
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


@contextmanager
def bounded_archive(path):
    """Bound decompression, including PAX headers/padding, before tarfile parses it."""
    if path.stat().st_size > MAX_COMPRESSED_BYTES:
        raise ValueError("compressed archive budget exceeded")
    with tempfile.TemporaryFile() as raw, gzip.open(path, "rb") as source:
        size = 0
        while block := source.read(min(1024 * 1024, MAX_TAR_BYTES + 1 - size)):
            size += len(block)
            if size > MAX_TAR_BYTES:
                raise ValueError("decompressed archive budget exceeded")
            raw.write(block)
        raw.seek(0)
        with tarfile.open(fileobj=raw, mode="r:") as archive:
            yield archive


def checked_members(archive, prefix):
    seen, total = set(), 0
    for member in archive:
        total += member.size
        if (len(seen) >= MAX_MEMBERS or member.size < 0 or member.size > MAX_MEMBER_BYTES
                or total > MAX_CONTENT_BYTES):
            raise ValueError("archive member budget exceeded")
        parts = PurePosixPath(member.name).parts
        canonical = "/".join(parts)
        spelling = member.name.removesuffix("/") if member.isdir() else member.name
        if (not parts or parts[0] != prefix or ".." in parts
                or "\\" in member.name or spelling != canonical or member.issparse()
                or not (member.isfile() or member.isdir()) or canonical in seen):
            raise ValueError(f"unsafe archive member: {member.name}")
        seen.add(canonical)
        yield member


def candidate_archives(directory, revision, versions):
    """Validate inventory, bytes, Cargo identity and safe extraction before using any archive."""
    rows = {}
    for line in (directory / "packages.tsv").read_text().splitlines():
        name, version, sha = line.split("\t")
        if name in rows:
            raise ValueError(f"duplicate package: {name}")
        if sha != revision:
            raise ValueError(f"revision mismatch: {name}")
        rows[name] = version
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, filename = line.split()
        if filename in sums:
            raise ValueError(f"duplicate checksum: {filename}")
        sums[filename] = digest
    result = {}
    for name, version in versions.items():
        if rows.get(name) != version:
            raise ValueError(f"missing package or version mismatch: {name}")
        path = directory / f"{name}-{version}.crate"
        if archive_digest(path) != sums.get(path.name):
            raise ValueError(f"checksum mismatch: {path.name}")
        prefix = f"{name}-{version}"
        with bounded_archive(path) as archive:
            list(checked_members(archive, prefix))
            vcs = json.load(archive.extractfile(f"{prefix}/.cargo_vcs_info.json"))["git"]
            if vcs.get("sha1") != revision or vcs.get("dirty", False):
                raise ValueError(f"revision mismatch or dirty archive: {name}")
            manifest = tomllib.loads(archive.extractfile(f"{prefix}/Cargo.toml").read().decode())
            if (manifest["package"]["name"], manifest["package"]["version"]) != (name, version):
                raise ValueError(f"archive package version mismatch: {name}")
            reject_source_dependencies(manifest)
        result[name] = path
    if not result:
        raise ValueError("empty artifact selection")
    return result


def reject_source_dependencies(table):
    """Normalized packaged dependencies must resolve without original source paths."""
    for key, value in table.items():
        if key in ("dependencies", "build-dependencies", "dev-dependencies"):
            for dependency in value.values():
                if isinstance(dependency, dict) and ("path" in dependency or "workspace" in dependency):
                    raise ValueError("normalized archive contains a source dependency")
        elif isinstance(value, dict):
            reject_source_dependencies(value)


def validate_graph(facts, consumer_root, allowed_paths, expected_message_features, forbidden_names):
    """Reject workspace leakage, provider leakage and unintended feature unification."""
    if Path(facts["workspace_root"]).resolve() != consumer_root.resolve():
        raise ValueError("consumer joined another workspace")
    if "target_directory" in facts and Path(facts["target_directory"]).resolve() != (consumer_root / "target").resolve():
        raise ValueError("consumer uses another workspace target directory")
    root_id = facts["resolve"]["root"]
    nodes = {node["id"]: node for node in facts["resolve"]["nodes"]}
    for package in facts["packages"]:
        if package["id"] not in nodes:
            continue
        name = package["name"]
        if name in forbidden_names:
            raise ValueError(f"forbidden dependency: {name}")
        source = Path(package["manifest_path"]).parent.resolve()
        if package["id"] == root_id:
            if source != consumer_root.resolve():
                raise ValueError("wrong consumer source")
        elif name.startswith("rss-") or package["source"] is None:
            if name not in allowed_paths or source != allowed_paths[name].resolve():
                raise ValueError(f"unexpected dependency source: {name}: {source}")
        if name == "rss-transactional-messaging":
            actual = set(nodes[package["id"]]["features"])
            if actual != expected_message_features:
                raise ValueError(f"message feature mismatch: {actual} != {expected_message_features}")


def selected_dependencies(manifest, selected, workspace):
    """Expand this example's additive feature declarations into explicit consumer dependencies."""
    features, dependencies, additions = set(), set(), {}
    pending = list(selected)
    while pending:
        feature = pending.pop()
        if feature in features:
            continue
        features.add(feature)
        for item in manifest["features"][feature]:
            if item.startswith("dep:"):
                dependencies.add(item[4:])
            elif "/" in item:
                dependency, enabled = item.split("/", 1)
                dependencies.add(dependency)
                additions.setdefault(dependency, set()).add(enabled)
            else:
                pending.append(item)
    resolved = {}
    for name, value in manifest["dependencies"].items():
        if value.get("optional") and name not in dependencies:
            continue
        if value.get("workspace"):
            inherited = workspace["dependencies"][name]
            inherited = {"version": inherited} if isinstance(inherited, str) else inherited
            value = {**inherited, **value, "features": list(set(inherited.get("features", [])) | set(value.get("features", [])))}
        else:
            value = dict(value)
        value.pop("workspace", None)
        value.pop("optional", None)
        value["features"] = sorted(set(value.get("features", [])) | additions.get(name, set()))
        resolved[name] = value
    return features, resolved


def cargo(command, directory, *, success=True):
    env = {key: value for key, value in os.environ.items() if key not in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR")}
    env["CARGO_TARGET_DIR"] = str(directory / "target")
    with (directory / "commands.log").open("a") as log:
        log.write(f"$ cargo {' '.join(command)}\n")
        log.flush()
        try:
            result = subprocess.run(["cargo", *command], cwd=directory, env=env, text=True, capture_output=True, timeout=600)
        except subprocess.TimeoutExpired as error:
            for partial in (error.stdout, error.stderr):
                log.write(partial.decode(errors="replace") if isinstance(partial, bytes) else partial or "")
            log.write(f"\nexit=timeout timeout={error.timeout}\n")
            raise
        log.write(f"{result.stdout}{result.stderr}\nexit={result.returncode}\n")
    if (result.returncode == 0) != success:
        raise ValueError(f"unexpected Cargo result: {directory}/commands.log\n{result.stderr[-4000:]}")
    return result.stdout if success else result.stderr


def inline_table(value):
    return "{ " + ", ".join(f"{json.dumps(key)} = {json.dumps(item)}" for key, item in value.items()) + " }"


def consumer(directory, features, dependencies, allowed):
    directory.mkdir()
    shutil.copytree(ROOT / "crates/examples/src", directory / "src")
    lines = ['[package]', 'name = "rss-examples"', 'version = "0.0.0"', 'edition = "2024"', 'autobins = false', 'default-run = "rss-examples"', '[workspace]', 'resolver = "2"', '[features]', 'default = ' + json.dumps(sorted(features))]
    declared = tomllib.loads((ROOT / "crates/examples/Cargo.toml").read_text())["features"]
    lines += [f'{json.dumps(feature)} = []' for feature in sorted(set(declared) - {"default"})]
    lines += ['[dependencies]']
    for name, dependency in dependencies.items():
        dependency = dict(dependency)
        if name in allowed:
            dependency.pop("path", None)
            dependency["version"] = "=" + dependency["version"].lstrip("=")
        lines.append(f'{json.dumps(name)} = {inline_table(dependency)}')
    lines.append('[patch.crates-io]')
    lines += [f'{json.dumps(name)} = {{ path = {json.dumps(str(path))} }}' for name, path in sorted(allowed.items())]
    lines += ['[[bin]]', 'name = "rss-examples"', 'path = "src/main.rs"']
    if "providers" in features:
        lines += ['[[bin]]', 'name = "providers"', 'path = "src/bin/providers.rs"']
    (directory / "Cargo.toml").write_text("\n".join(lines) + "\n")
    # A copied lock is a seed, never a shared lock. Cargo independently resolves this manifest.
    shutil.copyfile(ROOT / "Cargo.lock", directory / "Cargo.lock")


def package_closure(metadata, seeds):
    packages = {p["name"]: p for p in metadata["packages"]}
    selected, pending = {}, list(seeds)
    release = {p["package"] for p in metadata["metadata"]["release-surface"]["packages"]}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        if name not in release:
            raise ValueError(f"internal dependency is not a candidate: {name}")
        package = packages[name]
        selected[name] = package
        pending.extend(dep["name"] for dep in package["dependencies"] if dep["kind"] != "dev" and dep.get("path"))
    return selected


def absent_apis(directory, name, features):
    """Check real compiler rejection, after the same dependency graph has successfully run."""
    probes = []
    if "core" in features:
        if "producer" not in features:
            probes.append(("use rss_transactional_messaging::outbox::OutboxStore;", "outbox"))
        if "consumer" not in features:
            probes.append(("use rss_transactional_messaging::inbox::InboxStore;", "inbox"))
    if name == "diagnostic":
        probes.append(("use rss_diag_context::scope;", "scope"))
    if name == "redact":
        probes.append(("#[derive(rss_redact::Redact)] struct Secret;", "Redact"))
    source = directory / "src/main.rs"
    original = source.read_text()
    try:
        for probe, symbol in probes:
            source.write_text(probe + "\nfn main() {}\n")
            diagnostic = cargo(["check", "--locked", "--bin", "rss-examples"], directory, success=False)
            if symbol not in diagnostic or not any(code in diagnostic for code in ("E0432", "E0433")):
                raise ValueError(f"negative API probe failed for the wrong reason: {directory}")
    finally:
        source.write_text(original)


def validate_provider_results(log, binaries):
    if "test postgres_transactional_messaging_suite ... ok" not in log:
        raise ValueError("provider suite did not actually run")
    for binary in binaries:
        if log.count(f"external-provider-consumer PASS {binary}\n") != 1:
            raise ValueError(f"provider consumer did not actually run once: {binary}")


def validate_optional_features(facts, selected, expected_message):
    ports = expected_message - {"default"}
    managed = bool({"managed", "managed-worker"} & selected)
    expected = {
        "rss-transactional-messaging-testkit": ports,
        "rss-transactional-messaging-runtime": ports | ({"managed-runtime"} if managed else set()),
        "rss-transactional-messaging-postgres": {"default"} | ({"rss-runtime"} if managed else set()),
        "rss-transactional-messaging-amqp": {"default"} | ({"managed-runtime"} if managed else set()),
    }
    nodes = {node["id"]: set(node["features"]) for node in facts["resolve"]["nodes"]}
    for package in facts["packages"]:
        name = package["name"]
        if name in expected and package["id"] in nodes and nodes[package["id"]] != expected[name]:
            raise ValueError(f"optional feature mismatch: {name}: {nodes[package['id']]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source", action="store_true", help="development evidence, not fixed artifact acceptance")
    mode.add_argument("--artifacts", type=Path)
    parser.add_argument("--revision", help="exact clean commit embedded by Cargo in each artifact")
    parser.add_argument("--scenario", choices=SCENARIOS, action="append")
    args = parser.parse_args()
    if args.artifacts and not args.revision:
        parser.error("--artifacts requires --revision")
    if args.artifacts:
        head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        dirty = subprocess.check_output(["/usr/bin/git", "status", "--porcelain"], cwd=ROOT, text=True)
        if head != args.revision or dirty:
            raise ValueError("artifact scenarios must come from the same clean candidate revision")
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
    manifest = tomllib.loads((ROOT / "crates/examples/Cargo.toml").read_text())
    selected = {name: selected_dependencies(manifest, SCENARIOS[name], workspace) for name in (args.scenario or SCENARIOS)}
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=ROOT, text=True))
    closure = package_closure(metadata, {name for _, dependencies in selected.values() for name in dependencies if name.startswith("rss-")})
    output = ROOT / "rss-external-check"
    output.mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="source-" if args.source else "artifact-", dir=output))
    if args.source:
        allowed = {name: Path(p["manifest_path"]).parent for name, p in closure.items()}
    else:
        archives = candidate_archives(args.artifacts.resolve(), args.revision, {name: p["version"] for name, p in closure.items()})
        for name, path in sorted(archives.items()):
            print(f"artifact\t{name}\t{closure[name]['version']}\t{args.revision}\t{archive_digest(path)}", flush=True)
        extracted = run / "extracted"
        extracted.mkdir()
        for path in archives.values():
            with bounded_archive(path) as archive:
                members = list(checked_members(archive, path.stem))
                archive.extractall(extracted, members=members, filter="data")
        allowed = {name: extracted / f'{name}-{p["version"]}' for name, p in closure.items()}
    print(f"proof output: {run}", flush=True)
    providers = []
    for name, (features, dependencies) in selected.items():
        directory = run / name
        consumer(directory, features, dependencies, allowed)
        facts = json.loads(cargo(["metadata", "--format-version", "1"], directory))
        actual = {p["name"] for p in facts["packages"]}
        if not set(dependencies) <= actual:
            raise ValueError(f"missing consumer dependency: {set(dependencies) - actual}")
        expected = features & {"producer", "consumer"}
        forbidden = {"rss-transactional-messaging-postgres", "rss-transactional-messaging-amqp", "testkit"}
        if "providers" in features:
            expected = {"producer", "consumer", "default"}
            forbidden = {"testkit", "rss-transactional-messaging-testkit"}
        if "lifecycle" not in features and "managed" not in features:
            forbidden.add("rss-runtime")
        if name in ("core", "diagnostic", "redact", "derive", "protection"):
            forbidden.add("tokio")
        validate_graph(facts, directory, allowed, expected, forbidden)
        validate_optional_features(facts, features, expected)
        (directory / "resolved.json").write_text(json.dumps(facts, indent=2) + "\n")
        if "providers" in features:
            cargo(["build", "--locked", "--bin", "providers"], directory)
            providers.append(str(directory / "target/debug/providers"))
            print(f"READY {name}: graph + provider binary; runtime result pending", flush=True)
        else:
            cargo(["run", "--locked", "--quiet"], directory)
            absent_apis(directory, name, features)
            print(f"PASS {name}: graph + cargo run + absent APIs", flush=True)
    if providers:
        env = dict(os.environ, RSS_EXAMPLE_CONSUMERS=json.dumps(providers), RSS_TEST_RUN_ID=f"extract-{run.name}")
        command = ["cargo", "test", "--locked", "-p", "postgres-integration", "--test", "suite", "postgres_transactional_messaging_suite", "--", "--exact", "--nocapture"]
        command = ["cargo", "run", "--locked", "-p", "testkit", "--features", "containers", "--bin", "rss-test-launcher", "--", "--", *command]
        with (run / "provider-integration.log").open("w") as log:
            subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        validate_provider_results((run / "provider-integration.log").read_text(), providers)
        print(f"PASS {len(providers)} provider consumers: real PG/AMQP flow, cancellation and shutdown", flush=True)
    for name in selected:
        shutil.rmtree(run / name / "target")
    print(f"PASS {'source' if args.source else args.revision}: {len(selected)} independent scenarios", flush=True)


if __name__ == "__main__":
    main()
