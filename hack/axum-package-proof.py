#!/usr/bin/env python3
"""Consume exact RSS Axum artifacts, including its shared Contract/platform seam."""
from package_proof import (prepare_sources, cargo, cargo_environment,
    validate_graph, run_command)
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ROOTS = {"rss-axum", "rss-platform"}
PLATFORM_PACKAGES = ("rss-contract", "rss-platform", "rss-request-context")
SCENARIO = Path("crates/examples/platform-execution")
README_START = "<!-- platform-execution:start -->"
README_END = "<!-- platform-execution:end -->"




MODES = {
    "base": [], "managed": ["managed-server"], "http1": ["http1"],
    "http2": ["http2"], "both": ["http1", "http2"],
    "auto": ["auto-protocol"], "all": None, "platform": [], "tls": ["http1"],
}


def feature_args(mode):
    features = MODES[mode]
    return ["--all-features"] if features is None else (["--features", ",".join(features)] if features else [])


def expected_protocols(mode):
    return ({"http1"} if mode in {"http1", "tls"} else {"http2"} if mode == "http2"
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
        with (consumer / 'commands.log').open('a') as log:
            result = run_command(
                ['cargo', 'check', '--locked', '--offline', '--bin', 'unavailable', '--message-format=json', *feature_args(mode)],
                consumer, env, log, capture_stdout=True)
        diagnostics = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        errors = [d["message"] for d in diagnostics if d.get("reason") == "compiler-message" and d["message"]["level"] == "error"]
        if result.returncode == 0 or not errors or any(
            (e.get("code") or {}).get("code") != "E0432" or symbol not in e["message"] for e in errors
        ):
            raise ValueError(f"missing capability did not fail as unresolved import: {symbol}: {result.stderr}")
    target.unlink(missing_ok=True)


def consumer_manifest(mode, versions, features, *, smoke=False):
    manifest = f'[package]\nname="axum-{mode}-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
    names = list(PLATFORM_PACKAGES) if mode == "platform" else ["rss-axum"]
    if smoke:
        names.extend(["rss-contract", "rss-request-context"])
    for name in names:
        manifest += f'{name}={{version="={versions[name]}", default-features=false}}\n'
    if mode == "platform":
        return manifest + 'tokio={version="1",default-features=false,features=["rt","macros","time"]}\nserde_json="1"\n'
    if smoke:
        manifest += f'rss-runtime={{version="={versions["rss-runtime"]}",default-features=false,optional=true}}\n'
        manifest += 'axum={version="0.8",default-features=false,features=["json"]}\ntokio={version="1",features=["rt","macros","net","time"]}\n'
        manifest += 'hyper={version="1",default-features=false,optional=true,features=["client"]}\nhyper-util={version="0.1",default-features=false,optional=true,features=["tokio"]}\nhttp-body-util={version="0.1",optional=true}\n'
    if smoke and mode == 'tls':
        manifest += 'tokio-rustls={version="0.26",default-features=false,features=["ring"]}\nrcgen="0.14.8"\n'
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
        f'let _ = |listener, router, policy| rss_axum::{symbol}(listener, router, rss_axum::PlainTransport, "http", policy);'
        for symbol in symbols)
    return ('fn main() {\nlet _ = rss_axum::RequestBudget::new(std::time::Duration::from_secs(1));\n'
            + calls + '\n}\n')


TLS_RECEIPT = "TLS_BEHAVIOR_PASS peer=socket certificate=verified guard=released drain=clean"


def tls_receipt(returncode, stdout):
    if returncode != 0 or stdout.splitlines().count(TLS_RECEIPT) != 1:
        raise ValueError("TLS consumer did not prove peer, certificate and owned drain")
    return "BEHAVIOR PASS"


def copy_smoke(consumer, source_root, mode):
    example = 'base.rs' if mode == 'base' else 'tls.rs' if mode == 'tls' else 'managed.rs'
    (consumer / 'src/main.rs').write_text((source_root / 'examples' / example).read_text())
    if mode == 'tls':
        support = consumer / 'src/support'
        support.mkdir()
        (support / 'tls.rs').write_text((source_root / 'examples/support/tls.rs').read_text())


def verify_example_failure(returncode, stderr):
    if returncode == 0 or "enable http1, http2, or auto-protocol" not in stderr:
        raise ValueError("lifecycle-only example must fail with protocol selection guidance")


def platform_source(revision=None, *, sync=False):
    source = (ROOT / SCENARIO / "src/main.rs").read_text()
    readme_path = ROOT / "crates/platform/README.md"
    readme = readme_path.read_text()
    before, rest = readme.split(README_START)
    _, after = rest.split(README_END)
    expected = before + README_START + "\n```rust\n" + source + "```\n" + README_END + after
    if sync:
        readme_path.write_text(expected)
    elif readme != expected:
        raise ValueError("platform README drift: run --sync-readme")
    if revision:
        head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        if head != revision:
            raise ValueError("scenario revision mismatch")
        for path in (SCENARIO / "src/main.rs", SCENARIO / "Cargo.toml", SCENARIO / "Cargo.lock",
                     Path("crates/platform/README.md")):
            committed = subprocess.check_output(["/usr/bin/git", "show", f"{revision}:{path.as_posix()}"], cwd=ROOT)
            if committed != (ROOT / path).read_bytes():
                raise ValueError("scenario differs from candidate revision")
    return source


def platform_receipt(returncode, stdout):
    if returncode:
        raise ValueError("platform consumer execution failed")
    try:
        receipt = json.loads(stdout)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid platform behavior receipt") from error
    expected = {"completed": 42, "deadlineExceeded": True, "handlerStarted": True,
                "foreignAdmissionRejected": True, "drainingRejected": True,
                "descriptorMismatchRejected": True, "duplicateModule": "inventory",
                "duplicateContract": "example.add"}
    if not isinstance(receipt, dict) or receipt.keys() != expected.keys() or any(
        type(receipt[key]) is not type(value) or receipt[key] != value for key, value in expected.items()
    ):
        raise ValueError("platform behavior receipt did not prove the scenario")
    return receipt


def verify_platform_resolution(facts, consumer, allowed):
    for package in facts["packages"]:
        manifest = Path(package["manifest_path"]).resolve()
        if manifest == (consumer / "Cargo.toml").resolve():
            continue
        name = package["name"]
        if name.startswith("rss-"):
            if name not in PLATFORM_PACKAGES or name not in allowed or package["source"] is not None or manifest != allowed[name].resolve():
                raise ValueError("platform consumer escaped selected RSS dependency closure")
        elif package["source"] is None:
            raise ValueError("unexpected internal dependency")


def run_platform(consumer, env):
    return platform_receipt(0, cargo(['run', '--locked', '--offline', '--quiet'], consumer))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--artifacts', type=Path)
    modes.add_argument('--source', action='store_true')
    modes.add_argument('--sync-readme', action='store_true')
    parser.add_argument('--revision')
    args = parser.parse_args()
    if bool(args.artifacts) != bool(args.revision):
        parser.error('--artifacts and --revision must be supplied together')
    source = platform_source(args.revision, sync=args.sync_readme)
    if args.sync_readme:
        return
    root, allowed = prepare_sources(args, ROOTS, 'axum-')
    versions = {name: tomllib.loads((path / 'Cargo.toml').read_text())['package']['version'] for name,path in allowed.items()}
    patch = '\n[patch.crates-io]\n' + ''.join(f'{n} = {{ path = {json.dumps(str(p))} }}\n' for n,p in allowed.items())
    features = tomllib.loads((allowed['rss-axum'] / 'Cargo.toml').read_text())['features']
    results = {}
    for mode in MODES:
        directory = root / mode
        (directory / 'src').mkdir(parents=True)
        env = dict(cargo_environment(os.environ), CARGO_TARGET_DIR=str(directory / 'target'))
        (directory / 'Cargo.toml').write_text(consumer_manifest(mode, versions, features) + patch)
        (directory / 'src/main.rs').write_text(source if mode == 'platform' else api_source(mode))
        flags = feature_args(mode)
        def graph():
            facts = json.loads(cargo(['metadata', '--offline', '--format-version', '1', *flags], directory))
            validate_graph(facts, directory, allowed, set(), {'testkit'})
            (directory / 'resolved.json').write_text(json.dumps(facts, indent=2) + '\n')
            return facts
        facts = graph()
        verify_features(facts, mode)
        cargo(['check', '--locked', '--offline', *flags], directory)
        if mode == 'platform':
            verify_platform_resolution(facts, directory, {name:path/'Cargo.toml' for name,path in allowed.items()})
            results[mode] = run_platform(directory, env)
        else:
            check_unavailable(directory, mode, env)
            if mode in {'base', 'managed', 'http1', 'http2', 'auto', 'tls'}:
                (directory / 'Cargo.toml').write_text(consumer_manifest(mode, versions, features, smoke=True) + patch)
                copy_smoke(directory, allowed['rss-axum'], mode)
                graph()  # Validate the actual smoke graph after adding the client capabilities.
                if mode == 'managed':
                    cargo(['build', '--locked', '--offline', *flags], directory)
                    with (directory / 'commands.log').open('a') as log:
                        result = run_command([str(directory/'target/debug'/f'axum-{mode}-consumer')], directory, env, log, timeout=30)
                    verify_example_failure(result.returncode, result.stderr)
                else:
                    stdout = cargo(['run', '--locked', '--offline', *flags], directory)
                    if mode == 'tls':
                        tls_receipt(0, stdout)
            results[mode] = 'BEHAVIOR PASS' if mode in {'base', 'managed', 'http1', 'http2', 'auto', 'tls'} else 'GRAPH PASS'
        shutil.rmtree(directory / 'target')
    tls_source = b''.join((allowed['rss-axum'] / path).read_bytes() for path in ['examples/tls.rs', 'examples/support/tls.rs'])
    print(json.dumps({'tlsScenarioSha256': hashlib.sha256(tls_source).hexdigest(), 'revision': args.revision, 'scenarioSha256': hashlib.sha256(source.encode()).hexdigest(), 'consumers': results}, indent=2))


if __name__ == '__main__':
    main()
