#!/usr/bin/env python3
"""Consume actual Device Command package artifacts in isolated Cargo workspaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ROOTS = {"rss-device-command", "rss-device-command-postgres"}


def run(args, cwd, env):
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=300)


def closure():
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=ROOT
    ))
    packages = {p["name"]: p for p in metadata["packages"]}
    selected = set()
    todo = list(ROOTS)
    while todo:
        name = todo.pop()
        if name in selected:
            continue
        selected.add(name)
        todo.extend(d["name"] for d in packages[name]["dependencies"]
                    if d["kind"] != "dev" and d.get("path") and d["name"] in packages)
    return {name: packages[name]["version"] for name in sorted(selected)}


def candidate_archives(directory, revision, versions):
    rows = [line.split("\t") for line in (directory / "packages.tsv").read_text().splitlines()]
    if not rows or any(len(r) != 3 or r[2] != revision for r in rows):
        raise ValueError("candidate revision mismatch")
    declared = {r[0]: r[1] for r in rows}
    if len(declared) != len(rows) or any(declared.get(n) != v for n, v in versions.items()):
        raise ValueError("candidate package identity mismatch")
    digests = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.removeprefix("*")
        if name != Path(name).name or name in digests:
            raise ValueError("invalid archive identity")
        digests[name] = digest
    result = {}
    for name, version in versions.items():
        archive = directory / f"{name}-{version}.crate"
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digests.get(archive.name):
            raise ValueError("candidate archive checksum mismatch")
        result[name] = archive
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--revision")
    args = parser.parse_args()
    if bool(args.artifacts) != bool(args.revision):
        parser.error("--artifacts and --revision must be supplied together")
    versions = closure()
    env = os.environ.copy()
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(name, None)
    with tempfile.TemporaryDirectory(prefix="rss-device-artifacts-") as temporary:
        root = Path(temporary).resolve()
        if args.artifacts:
            archives = candidate_archives(args.artifacts.resolve(), args.revision, versions)
        else:
            command = ["cargo", "package", "--locked", "--offline", "--allow-dirty", "--no-verify", "--target-dir", str(root / "packaged")]
            for name in versions:
                command += ["-p", name]
            run(command, ROOT, env)
            archives = {n: root / "packaged/package" / f"{n}-{v}.crate" for n, v in versions.items()}
        extracted = root / "extracted"
        extracted.mkdir()
        for archive in archives.values():
            with tarfile.open(archive) as bundle:
                bundle.extractall(extracted, filter="data")
        patches = "\n[patch.crates-io]\n" + "".join(
            f'{n} = {{ path = {json.dumps(str(extracted / (n + "-" + v)))} }}\n' for n, v in versions.items()
        )
        for mode in ("core", "postgres"):
            consumer = root / mode
            (consumer / "src").mkdir(parents=True)
            manifest = f'[package]\nname = "device-{mode}-consumer"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\n[dependencies]\nrss-device-command = {{ version = "=0.1.0", default-features = false }}\n'
            if mode == "core":
                source = 'fn main() { assert!(rss_device_command::Coordinate::new(1, 1).is_ok()); }\n'
            else:
                manifest += 'rss-device-command-postgres = { version = "=0.1.0", default-features = false }\nrss-transactional-messaging = { version = "=0.2.0", default-features = false, features = ["producer", "consumer"] }\nrss-transactional-messaging-postgres = { version = "=0.1.0", default-features = false }\n[features]\nintegration = ["rss-transactional-messaging-postgres/integration"]\n'
                source = (extracted / "rss-device-command-postgres-0.1.0/examples/compose.rs").read_text()
            (consumer / "Cargo.toml").write_text(manifest + patches)
            (consumer / "src/main.rs").write_text(source)
            for features in ([], ["--no-default-features"], ["--all-features"]):
                run(["cargo", "check", "--offline", *features], consumer, env)
            facts = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--format-version", "1"], cwd=consumer, env=env))
            for package in facts["packages"]:
                if package["source"] is None and not Path(package["manifest_path"]).resolve().is_relative_to(root):
                    raise ValueError("consumer escaped the artifact workspace")
            if mode == "core" and any(p["name"] in {"sqlx", "rss-device-command-postgres", "diport"} for p in facts["packages"]):
                raise ValueError("core consumer acquired provider dependencies")
        print(json.dumps({"artifacts": {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in archives.items()}, "consumers": "core/postgres default/no-default/all-features passed"}, indent=2))


if __name__ == "__main__":
    main()
