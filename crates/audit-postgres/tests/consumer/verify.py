"""Run from a pushed RSS checkout: python3 crates/audit-postgres/tests/consumer/verify.py."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
REPOSITORY = "https://dev.azure.com/shengming0923/rss/_git/rss"
LIBRARIES = {"rss-audit-core", "rss-audit-postgres", "rss-ledger", "rss-ledger-postgres"}
SUITES = {"audit-postgres-integration", "ledger-postgres-integration"}
PG = "rss-transactional-messaging-postgres"


def graph(metadata, names):
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    pending = [i for i in metadata["workspace_members"] if packages[i]["name"] in names]
    assert {packages[i]["name"] for i in pending} == names
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


def verify_mode(directory, features, rev, env):
    directory.mkdir()
    manifest = ["[workspace]", 'resolver = "2"', "[package]", 'name = "audit-consumer"',
                'version = "0.0.0"', 'edition = "2024"', "[features]",
                'ledger = ["rss-audit-postgres/ledger"]', 'messaging = ["rss-audit-postgres/messaging"]',
                "[dependencies]"]
    dependencies = {"rss-audit-core", "rss-audit-postgres"}
    if "ledger" in features:
        dependencies.add("rss-ledger")
    if "messaging" in features:
        dependencies.update({PG, "rss-transactional-messaging"})
    for name in sorted(dependencies):
        manifest.append(f'{name} = {{ git = "{REPOSITORY}", rev = "{rev}", default-features = false }}')
    (directory / "Cargo.toml").write_text("\n".join(manifest) + "\n")
    (directory / "src").mkdir()
    shutil.copyfile(HERE / "main.rs", directory / "src/main.rs")
    shutil.copyfile(ROOT / "Cargo.lock", directory / "Cargo.lock")
    flags = ["--features", ",".join(features)] if features else []
    env = env | {"CARGO_TARGET_DIR": str(directory / "target")}
    # Seed registry versions from RSS, then bind this standalone consumer and git sources in its own lock.
    metadata(directory, env, *flags)
    doc = metadata(directory, env, "--locked", *flags)
    assert Path(doc["workspace_root"]) == directory and len(doc["workspace_members"]) == 1
    closure = graph(doc, {"audit-consumer"})
    resolved = {p["id"]: p["name"] for p, _ in closure}
    selected = {p["name"]: node for p, node in closure}
    for pkg, _ in closure:
        if pkg["name"].startswith("rss-"):
            assert pkg["source"] == f"git+{REPOSITORY}?rev={rev}#{rev}", pkg["id"]
    audit = selected["rss-audit-postgres"]
    direct = {resolved[dep["pkg"]] for dep in audit["deps"]}
    ledger = "ledger" in features
    messaging = "messaging" in features
    assert ("rss-ledger-postgres" in direct) == ledger and ("rss-ledger" in direct) == ledger
    assert (PG in direct) == messaging
    assert ("rss-ledger" in selected) == ledger and (PG in selected) == messaging
    if ledger:
        assert ("messaging" in selected["rss-ledger-postgres"]["features"]) == messaging
    assert "rss-audit-http-axum" not in selected
    subprocess.run(["cargo", "run", "--locked", "--offline", "--quiet", *flags],
                   cwd=directory, env=env, timeout=900, check=True)
    print(f"{directory.name}: passed", flush=True)


def main():
    rev = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    env = os.environ | {"CARGO_NET_GIT_FETCH_WITH_CLI": "true"}
    doc = metadata(ROOT, env, "--locked", "--all-features")
    for pkg, _ in graph(doc, LIBRARIES | SUITES):
        assert pkg["name"] != "rss-audit-http-axum" and "rss-audit" not in (pkg["source"] or "")
        if pkg["name"] in LIBRARIES:
            assert pkg["publish"] == [] and pkg["version"] == "0.1.0" and pkg["source"] is None
    parent = ROOT / "rss-external-check"
    parent.mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(dir=parent, prefix="audit-consumer-"))
    print(f"Verified six-package closure. Testing {REPOSITORY} @ {rev} in {directory}", flush=True)
    for mode, features in [("plain", []), ("ledger", ["ledger"]), ("messaging", ["messaging"]),
                           ("combined", ["ledger", "messaging"])]:
        verify_mode(directory / mode, features, rev, env)


if __name__ == "__main__":
    main()
