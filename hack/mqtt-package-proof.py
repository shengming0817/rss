#!/usr/bin/env python3
"""Consume exact RSS MQTT artifacts without runtime or provider-test dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ROOTS = {"rss-mqtt"}


def run(args, cwd, env):
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=300)


def closure():
    facts = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=ROOT))
    packages = {p["name"]: p for p in facts["packages"]}
    accepted = {p["package"] for p in facts["metadata"]["release-surface"]["packages"]}
    todo, selected = list(ROOTS), {}
    while todo:
        name = todo.pop()
        if name in selected:
            continue
        if name not in accepted:
            raise ValueError(f"non-public dependency: {name}")
        package = packages[name]
        selected[name] = package["version"]
        todo.extend(d["name"] for d in package["dependencies"] if d.get("path") and d["kind"] != "dev")
    return selected


def archives_at(directory, revision, versions):
    rows = [line.split("\t") for line in (directory / "packages.tsv").read_text().splitlines()]
    if not rows or any(len(r) != 3 or r[2] != revision for r in rows):
        raise ValueError("candidate revision mismatch")
    declared = {r[0]: r[1] for r in rows}
    if len(declared) != len(rows) or any(declared.get(n) != v for n, v in versions.items()):
        raise ValueError("candidate package identity mismatch")
    hashes = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.removeprefix("*")
        if name != Path(name).name or name in hashes:
            raise ValueError("invalid archive identity")
        hashes[name] = digest
    result = {}
    for name, version in versions.items():
        path = directory / f"{name}-{version}.crate"
        if hashlib.sha256(path.read_bytes()).hexdigest() != hashes.get(path.name):
            raise ValueError("candidate archive checksum mismatch")
        result[name] = path
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
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="rss-mqtt-proof-") as temporary:
        root = Path(temporary).resolve()
        if args.artifacts:
            archives = archives_at(args.artifacts.resolve(), args.revision, versions)
        else:
            cmd = ["cargo", "package", "--locked", "--offline", "--allow-dirty", "--no-verify", "--target-dir", str(root / "packaged")]
            for name in versions:
                cmd += ["-p", name]
            run(cmd, ROOT, env)
            archives = {n: root / "packaged/package" / f"{n}-{v}.crate" for n, v in versions.items()}
        extracted = root / "extracted"
        extracted.mkdir()
        for archive in archives.values():
            with tarfile.open(archive) as bundle:
                bundle.extractall(extracted, filter="data")
        patch = '\n[patch.crates-io]\n' + ''.join(
            f'{n} = {{ path = {json.dumps(str(extracted / (n + "-" + v)))} }}\n'
            for n, v in versions.items())
        env["CARGO_TARGET_DIR"] = str(root / "target")
        consumer = root / "consumer"
        (consumer / "src").mkdir(parents=True)
        source = (extracted / f'rss-mqtt-{versions["rss-mqtt"]}/examples/consume.rs').read_text()
        manifest = '[package]\nname="mqtt-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[features]\nconsumer=["rss-mqtt/consumer"]\n[dependencies]\n'
        manifest += f'rss-mqtt={{version="={versions["rss-mqtt"]}",default-features=false}}\n'
        manifest += f'rss-transactional-messaging={{version="={versions["rss-transactional-messaging"]}",default-features=false,features=["producer"]}}\n'
        manifest += 'rumqttc-v5-next={version="=0.34.0",default-features=false,features=["use-rustls-ring"]}\n'
        manifest += 'tracing-subscriber={version="0.3",features=["env-filter"]}\n'
        (consumer / "Cargo.toml").write_text(manifest + patch)
        (consumer / "src/support").mkdir()
        (consumer / "src/support/logging.rs").write_text((extracted / f'rss-mqtt-{versions["rss-mqtt"]}/examples/support/logging.rs').read_text())
        (consumer / "src/main.rs").write_text(source)
        for features in ([], ["--no-default-features"], ["--features", "consumer"], ["--all-features"]):
            run(["cargo", "check", "--offline", *features], consumer, env)
        facts = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--format-version", "1"], cwd=consumer, env=env))
        for package in facts["packages"]:
            if package["source"] is None and not Path(package["manifest_path"]).resolve().is_relative_to(root):
                raise ValueError("consumer escaped artifact workspace")
            if package["source"] is None and package["name"] != "mqtt-consumer" and package["name"] not in versions:
                raise ValueError("unexpected internal dependency")
        if any(p["name"] in {"rss-runtime", "testkit", "sqlx", "testcontainers", "rumqttc"} for p in facts["packages"]):
            raise ValueError("standalone MQTT acquired unrelated or legacy dependencies")
        print(json.dumps({"artifacts": {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in archives.items()}, "consumers": "standalone MQTT/Outbox passed"}, indent=2))


if __name__ == "__main__":
    main()
