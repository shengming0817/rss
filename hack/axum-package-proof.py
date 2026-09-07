#!/usr/bin/env python3
"""Consume exact RSS Axum artifacts, including its shared Contract/platform seam."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ROOTS = {"rss-axum", "rss-platform"}


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


MODES = {
    "base": [], "managed": ["managed-server"], "http1": ["http1"],
    "http2": ["http2"], "both": ["http1", "http2"],
    "auto": ["auto-protocol"], "all": None, "platform": [],
}


def feature_args(mode):
    features = MODES[mode]
    return ["--all-features"] if features is None else (["--features", ",".join(features)] if features else [])


def expected_protocols(mode):
    return ({"http1"} if mode == "http1" else {"http2"} if mode == "http2"
            else {"http1", "http2"} if mode in {"both", "auto", "all"} else set())


def verify_features(facts, mode):
    packages = {p["id"]: p["name"] for p in facts["packages"]}
    active = {}
    for node in facts["resolve"]["nodes"]:
        active.setdefault(packages[node["id"]], set()).update(node["features"])
    if mode == "platform":
        return
    expected = expected_protocols(mode)
    for name in ("rss-axum", "hyper", "hyper-util"):
        actual = active.get(name, set()) & {"http1", "http2"}
        if actual != expected:
            raise ValueError(f"{mode}: {name} protocol features {actual}, expected {expected}")
    if ("auto-protocol" in active["rss-axum"]) != (mode in {"auto", "all"}):
        raise ValueError("unexpected Auto capability")
    managed = mode != "base"
    if ("rss-runtime" in active) != managed:
        raise ValueError("optional runtime capability mismatch")
    if ("managed-server" in active["rss-axum"]) != managed:
        raise ValueError("managed-server capability mismatch")
    if managed and "net" not in active.get("tokio", set()):
        raise ValueError("missing tokio/net transport foundation")
    for name, required in (("hyper", {"server"}), ("hyper-util", {"tokio", "service"})):
        if managed and not required <= active.get(name, set()):
            raise ValueError(f"missing {name} transport foundation")
        if not managed and name in active:
            raise ValueError(f"base acquired optional {name}")


def check_unavailable(consumer, mode, env):
    expected = expected_protocols(mode)
    unavailable = [f"serve_{p}_registration" for p in ("http1", "http2") if p not in expected]
    if mode not in {"auto", "all"}:
        unavailable.append("serve_auto_registration")
    target = consumer / "src/bin/unavailable.rs"
    target.parent.mkdir(exist_ok=True)
    for symbol in unavailable:
        target.write_text(f"use rss_axum::{symbol};\nfn main() {{}}\n")
        result = subprocess.run(
            ["cargo", "check", "--offline", "--bin", "unavailable", "--message-format=json", *feature_args(mode)],
            cwd=consumer, env=env, text=True, capture_output=True, timeout=300)
        diagnostics = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        errors = [d["message"] for d in diagnostics if d.get("reason") == "compiler-message" and d["message"]["level"] == "error"]
        if result.returncode == 0 or not errors or any(
            (e.get("code") or {}).get("code") != "E0432" or symbol not in e["message"] for e in errors
        ):
            raise ValueError(f"missing capability did not fail as unresolved import: {symbol}: {result.stderr}")
    target.unlink(missing_ok=True)


def consumer_manifest(mode, versions, features, *, smoke=False):
    manifest = f'[package]\nname="axum-{mode}-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
    names = ["rss-contract", "rss-platform", "rss-request-context"] if mode == "platform" else ["rss-axum"]
    if smoke:
        names.append("rss-contract")
    for name in names:
        manifest += f'{name}={{version="={versions[name]}", default-features=false}}\n'
    if mode == "platform":
        return manifest
    if smoke:
        manifest += f'rss-runtime={{version="={versions["rss-runtime"]}",default-features=false,optional=true}}\n'
        manifest += 'axum={version="0.8",default-features=false,features=["json"]}\ntokio={version="1",features=["rt","macros","net","time"]}\n'
        manifest += 'hyper={version="1",default-features=false,optional=true,features=["client"]}\nhyper-util={version="0.1",default-features=false,optional=true,features=["tokio"]}\nhttp-body-util={version="0.1",optional=true}\n'
    manifest += '[features]\ndefault=[]\n'
    for feature in features:
        if feature == "default":
            continue
        deps = [f"rss-axum/{feature}"]
        # Pure API features forward exactly one capability; no consumer can repair its closure.
        if smoke:
            if feature == "managed-server":
                deps += ["dep:rss-runtime"]
            elif feature in {"http1", "http2"}:
                deps += ["managed-server", "dep:hyper", f"hyper/{feature}", "dep:hyper-util", "dep:http-body-util"]
            elif feature == "auto-protocol":
                deps += ["http1", "http2"]
        manifest += f'{feature}={json.dumps(deps)}\n'
    return manifest


def api_source(mode):
    symbols = [f"serve_{protocol}_registration" for protocol in sorted(expected_protocols(mode))]
    if mode in {"auto", "all"}:
        symbols.append("serve_auto_registration")
    # Infer the external argument/return types without directly depending on their owners.
    calls = "\n".join(
        f'let _ = |listener, router| rss_axum::{symbol}(listener, router, "http", std::time::Duration::from_secs(1));'
        for symbol in symbols)
    return ('fn main() {\nlet _ = rss_axum::RequestBudget::new(std::time::Duration::from_secs(1));\n'
            + calls + '\n}\n')


def verify_example_failure(returncode, stderr):
    if returncode == 0 or "enable http1, http2, or auto-protocol" not in stderr:
        raise ValueError("lifecycle-only example must fail with protocol selection guidance")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--revision")
    args = parser.parse_args()
    if bool(args.artifacts) != bool(args.revision):
        parser.error("--artifacts and --revision must be supplied together")
    args_revision = args.revision
    versions = closure()
    env = os.environ.copy()
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="rss-axum-proof-") as temporary:
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
        features = tomllib.loads((extracted / f'rss-axum-{versions["rss-axum"]}/Cargo.toml').read_text())["features"]
        results = {}
        for mode in MODES:
            consumer = root / mode
            (consumer / "src").mkdir(parents=True)
            # Separate manifests/locks/resolution; artifacts share only the compiler cache.
            env["CARGO_TARGET_DIR"] = str(root / "target")
            manifest = consumer_manifest(mode, versions, features)
            example_root = extracted / f'rss-axum-{versions["rss-axum"]}/examples'
            source = (example_root / "platform.rs").read_text() if mode == "platform" else api_source(mode)
            (consumer / "Cargo.toml").write_text(manifest + patch)
            (consumer / "src/main.rs").write_text(source)
            args = feature_args(mode)
            run(["cargo", "check", "--offline", *args], consumer, env)
            facts = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--format-version", "1", *args], cwd=consumer, env=env))
            for package in facts["packages"]:
                if package["source"] is None and not Path(package["manifest_path"]).resolve().is_relative_to(root):
                    raise ValueError("consumer escaped artifact workspace")
                if package["source"] is None and package["name"] != f"axum-{mode}-consumer" and package["name"] not in versions:
                    raise ValueError("unexpected internal dependency")
            verify_features(facts, mode)
            if mode != "platform":
                check_unavailable(consumer, mode, env)
            if mode in {"base", "managed", "http1", "http2", "auto"}:
                # Client codec features must not participate in the preceding capability proof.
                (consumer / "Cargo.toml").write_text(consumer_manifest(mode, versions, features, smoke=True) + patch)
                (consumer / "src/main.rs").write_text((example_root / ("base.rs" if mode == "base" else "managed.rs")).read_text())
                if mode == "managed":
                    run(["cargo", "build", "--offline", *args], consumer, env)
                    executable = Path(env["CARGO_TARGET_DIR"]) / "debug" / (f"axum-{mode}-consumer" + (".exe" if os.name == "nt" else ""))
                    result = subprocess.run([str(executable)], cwd=consumer, env=env, capture_output=True, text=True, timeout=30)
                    verify_example_failure(result.returncode, result.stderr)
                else:
                    run(["cargo", "run", "--offline", *args], consumer, env)
            results[mode] = ("check/features/API passed; expected example failure passed" if mode == "managed" else
                             "check/features/API passed; run passed" if mode in {"base", "http1", "http2", "auto"} else "check/features/API passed")
        print(json.dumps({"revision": args_revision, "artifacts": {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in archives.items()}, "consumers": results}, indent=2))



if __name__ == "__main__":
    main()
