"""Verify a pushed RSS HEAD in four Audit and two standalone Ledger configurations."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / "hack"))
from package_proof import cargo_environment, require_candidate_revision, validate_cargo_config

REPOSITORY = "https://dev.azure.com/shengming0923/rss/_git/rss"
LIBRARIES = {"rss-audit-core", "rss-audit-postgres", "rss-ledger", "rss-ledger-postgres"}
SUITES = {"audit-postgres-integration", "ledger-postgres-integration"}
PG = "rss-transactional-messaging-postgres"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def graph(metadata, names):
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    pending = [i for i in metadata["workspace_members"] if packages[i]["name"] in names]
    require({packages[i]["name"] for i in pending} == names, f"missing workspace roots: {names}")
    seen = set()
    while pending:
        item = pending.pop()
        if item not in seen:
            seen.add(item)
            pending.extend(dep["pkg"] for dep in nodes[item]["deps"])
    return [(packages[i], nodes[i]) for i in seen]


def metadata(cwd, env, *flags):
    return json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", *flags], cwd=cwd, env=env, timeout=300))


def verify_mode(directory, features, rev, env, *, ledger_only=False):
    package = "ledger-consumer" if ledger_only else "audit-consumer"
    adapter = "rss-ledger-postgres" if ledger_only else "rss-audit-postgres"
    dependencies = {"rss-ledger", "rss-request-context", adapter} if ledger_only else {"rss-audit-core", adapter}
    manifest = ["[workspace]", 'resolver = "2"', "[package]", f'name = "{package}"',
                'version = "0.0.0"', 'edition = "2024"', "[features]",
                f'messaging = ["{adapter}/messaging"]']
    if not ledger_only:
        manifest.append('ledger = ["rss-audit-postgres/ledger"]')
        if "ledger" in features:
            dependencies.add("rss-ledger")
    if "messaging" in features:
        dependencies.update({PG, "rss-transactional-messaging"})
    manifest.append("[dependencies]")
    if ledger_only:
        manifest.append('tokio-util = "0.7"')
    for name in sorted(dependencies):
        manifest.append(f'{name} = {{ git = "{REPOSITORY}", rev = "{rev}", default-features = false }}')
    (directory / "Cargo.toml").write_text("\n".join(manifest) + "\n")
    shutil.copyfile(HERE / ("ledger_main.rs" if ledger_only else "main.rs"), directory / "src/main.rs")
    shutil.copyfile(ROOT / "Cargo.lock", directory / "Cargo.lock")
    flags = ["--features", ",".join(features)] if features else []
    env = env | {"CARGO_TARGET_DIR": str(directory / "target")}
    # Seed registry versions, then bind this consumer and its pinned Git packages in its own lock.
    metadata(directory, env, *flags)
    doc = metadata(directory, env, "--locked", *flags)
    require(Path(doc["workspace_root"]) == directory and len(doc["workspace_members"]) == 1,
            f"unexpected workspace: {doc['workspace_root']}")
    closure = graph(doc, {package})
    resolved = {p["id"]: p["name"] for p, _ in closure}
    selected = {p["name"]: node for p, node in closure}
    for pkg, _ in closure:
        if pkg["name"].startswith("rss-"):
            require(pkg["source"] == f"git+{REPOSITORY}?rev={rev}#{rev}", f"unexpected source: {pkg['id']}")
    direct = {resolved[dep["pkg"]] for dep in selected[adapter]["deps"]}
    # Metadata can list a weakly forwarded optional dependency even when Cargo
    # does not build it. Artifact messages identify the actual compilation units.
    output = subprocess.check_output(["cargo", "build", "--locked", "--offline", "--quiet",
                                      "--message-format=json-render-diagnostics", *flags],
                                     cwd=directory, env=env, timeout=900, text=True)
    artifacts = {}
    for line in output.splitlines():
        event = json.loads(line)
        if event["reason"] == "compiler-artifact" and event["package_id"] in resolved:
            name = resolved[event["package_id"]]
            artifacts.setdefault(name, set()).update(event["features"])
    messaging = "messaging" in features
    require(adapter in artifacts, f"missing {adapter} artifact")
    require((PG in artifacts) == messaging and (not messaging or PG in direct), f"messaging closure: {direct}")
    if ledger_only:
        require(not {"rss-audit-core", "rss-audit-postgres"}.intersection(selected), "Ledger depends on Audit")
    else:
        ledger = "ledger" in features
        require(("rss-ledger-postgres" in artifacts) == ledger and ("rss-ledger" in artifacts) == ledger,
                "unexpected Ledger artifacts")
        if ledger:
            require({"rss-ledger", "rss-ledger-postgres"} <= direct, f"missing Ledger dependencies: {direct}")
            require(("messaging" in artifacts["rss-ledger-postgres"]) == messaging,
                    "Ledger messaging feature forwarding")
    require("rss-audit-http-axum" not in selected, "HTTP adapter in library closure")
    binary = directory / "target/debug" / package
    output = subprocess.check_output([binary], cwd=directory, env=env, timeout=30, text=True)
    require(output.strip() == package.replace("-", " ") + " passed", f"unexpected output: {output}")
    print(f"{directory.relative_to(directory.parents[1])}: passed", flush=True)


def main():
    rev = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    require_candidate_revision(rev)
    env = cargo_environment(os.environ) | {"CARGO_NET_GIT_FETCH_WITH_CLI": "true",
                                          "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_INCREMENTAL": "0"}
    validate_cargo_config(ROOT, env)
    doc = metadata(ROOT, env, "--locked", "--all-features")
    for pkg, _ in graph(doc, LIBRARIES | SUITES):
        require(pkg["name"] != "rss-audit-http-axum" and "rss-audit" not in (pkg["source"] or ""),
                f"unexpected HTTP adapter or old Audit source: {pkg['id']}")
        if pkg["name"] in LIBRARIES:
            require(pkg["publish"] == [] and pkg["version"] == "0.1.0" and pkg["source"] is None,
                    f"unexpected library identity: {pkg['id']}")
    parent = ROOT / "rss-external-check"
    parent.mkdir(exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(dir=parent, prefix="audit-consumer-"))
    print(f"Verified six-package closure. Testing {REPOSITORY} @ {rev} in {run_dir}", flush=True)
    for mode, features in [("plain", []), ("ledger", ["ledger"]), ("messaging", ["messaging"]),
                           ("combined", ["ledger", "messaging"])]:
        scenarios = [(False, features)]
        if "ledger" in features:
            scenarios.append((True, [f for f in features if f == "messaging"]))
        for standalone, flags in scenarios:
            directory = run_dir / mode / ("ledger-consumer" if standalone else "audit-consumer")
            (directory / "src").mkdir(parents=True)
            validate_cargo_config(directory, env)
            verify_mode(directory, flags, rev, env, ledger_only=standalone)
            shutil.rmtree(directory / "target")


if __name__ == "__main__":
    main()
