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

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from package_proof import (archive_digest, bounded_archive, checked_members, candidate_archives,
    validate_graph, selected_dependencies, cargo, consumer, package_closure, require_candidate_revision, run_command, cargo_environment, validate_execution)

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = {
    "diagnostic": ["diagnostic"], "task-local": ["task-local"], "trace": ["trace"],
    "redact": ["redact"], "derive": ["derive"], "protection": ["protection"],
    "lifecycle": ["lifecycle"], "core": ["core"], "none": ["memory"],
    "producer": ["producer"], "consumer": ["consumer"], "both": ["producer", "consumer"],
    "self-host": ["providers"], "managed": ["managed"],
    "managed-worker": ["managed-worker"],
    "outbox-writer": ["outbox-writer"], "relay-only": ["relay-only"],
}
























def absent_apis(directory, name, features):
    """Check real compiler rejection, after the same dependency graph has successfully run."""
    probes = []
    if "core" in features:
        if "producer" not in features:
            for port in ("OutboxWriter", "OutboxRelayStore"):
                probes.append((f"use rss_transactional_messaging::outbox::{port};", "outbox"))
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
        require_candidate_revision(args.revision)
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
    writers = []
    for name, (features, dependencies) in selected.items():
        directory = run / name
        consumer(directory, features, dependencies, allowed)
        if name == "relay-only":
            shutil.copyfile(ROOT / "crates/examples/probes/relay-only.rs", directory / "src/main.rs")
        facts = json.loads(cargo(["metadata", "--format-version", "1"], directory))
        actual = {p["name"] for p in facts["packages"]}
        if not set(dependencies) <= actual:
            raise ValueError(f"missing consumer dependency: {set(dependencies) - actual}")
        expected = features & {"producer", "consumer"}
        forbidden = {"rss-transactional-messaging-postgres", "rss-transactional-messaging-amqp", "testkit"}
        if "providers" in features:
            expected = {"producer", "consumer", "default"}
            forbidden = {"testkit", "rss-transactional-messaging-testkit"}
        if name == "outbox-writer":
            expected = {"default", "producer", "consumer"}  # PG adapter's existing core closure.
            forbidden = {"testkit", "rss-transactional-messaging-testkit", "rss-transactional-messaging-amqp", "rss-transactional-messaging-runtime", "tokio-util"}
        if name == "relay-only":
            expected = {"producer"}
            forbidden |= {"rss-transactional-messaging-testkit", "rss-transactional-messaging-runtime"}
        if "lifecycle" not in features and "managed" not in features:
            forbidden.add("rss-runtime")
        if name in ("core", "diagnostic", "redact", "derive", "protection"):
            forbidden.add("tokio")
        validate_graph(facts, directory, allowed, expected, forbidden)
        validate_optional_features(facts, features, expected)
        (directory / "resolved.json").write_text(json.dumps(facts, indent=2) + "\n")
        if name == "outbox-writer":
            cargo(["build", "--locked", "--bin", "outbox-writer"], directory)
            writers.append(str(directory / "target/debug/outbox-writer"))
            print(f"READY {name}: isolated writer binary; runtime result pending", flush=True)
        elif name == "relay-only":
            cargo(["check", "--locked", "--bin", "rss-examples"], directory)
            print("PASS relay-only: independent delivery port without transaction or append", flush=True)
        elif "providers" in features:
            cargo(["build", "--locked", "--bin", "providers"], directory)
            providers.append(str(directory / "target/debug/providers"))
            print(f"READY {name}: graph + provider binary; runtime result pending", flush=True)
        else:
            cargo(["run", "--locked", "--quiet"], directory)
            absent_apis(directory, name, features)
            print(f"PASS {name}: graph + cargo run + absent APIs", flush=True)
    if providers or writers:
        env = dict(cargo_environment(os.environ), RSS_TEST_RUN_ID=f"extract-{run.name}")
        if providers:
            env["RSS_EXAMPLE_CONSUMERS"] = json.dumps(providers)
        if writers:
            env["RSS_OUTBOX_WRITER_CONSUMERS"] = json.dumps(writers)
        command = ["cargo", "test", "--locked", "-p", "postgres-integration", "--test", "suite", "postgres_transactional_messaging_suite", "--", "--exact", "--nocapture"]
        command = ["cargo", "run", "--locked", "-p", "testkit", "--features", "containers", "--bin", "rss-test-launcher", "--", "--", *command]
        with (run / "provider-integration.log").open("w") as log:
            run_command(command, ROOT, env, log, timeout=900).check_returncode()
        validate_execution((run / "provider-integration.log").read_text(), "postgres_transactional_messaging_suite", providers + writers)
        print(f"PASS {len(providers)} provider and {len(writers)} writer consumers: real provider behavior", flush=True)
    for name in selected:
        shutil.rmtree(run / name / "target")
    print(f"PASS {'source' if args.source else args.revision}: {len(selected)} independent scenarios", flush=True)


if __name__ == "__main__":
    main()
