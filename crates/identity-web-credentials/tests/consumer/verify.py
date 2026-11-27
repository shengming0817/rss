"""Build and run four isolated public consumers pinned to this pushed RSS commit."""
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

REPO = "https://dev.azure.com/shengming0923/rss/_git/rss"
SCENARIOS = {
    "core": [],
    "postgres": ["rss-audit-postgres", "rss-identity-core"],
    "oidc": [],
    "web-credentials": ["http"],
}


def verify(directory, name, extra, revision, base_env, features=()):
    directory.mkdir()
    validate_cargo_config(directory, base_env)
    env = base_env | {"CARGO_TARGET_DIR": str(directory / "target")}
    root = "rss-identity-" + name
    dependencies = []
    for package in [root, *extra]:
        if package.startswith("rss-"):
            requested = json.dumps(features if package == root else ())
            dependencies.append(f'{package} = {{ git = "{REPO}", rev = "{revision}", default-features = false, features = {requested} }}')
        else:
            dependencies.append(f'{package} = "1"')
    (directory / "Cargo.toml").write_text(
        '[workspace]\nresolver="2"\n[package]\nname="identity-consumer"\nversion="0.0.0"\nedition="2024"\n'
        + "[dependencies]\n" + "\n".join(dependencies) + "\n")
    (directory / "src").mkdir()
    shutil.copyfile(HERE / (name + ".rs"), directory / "src/main.rs")
    shutil.copyfile(ROOT / "Cargo.lock", directory / "Cargo.lock")
    def cargo(*args):
        return subprocess.check_output(["cargo", *args], cwd=directory, env=env, text=True, timeout=1800)
    cargo("metadata", "--format-version", "1")
    doc = json.loads(cargo("metadata", "--locked", "--format-version", "1"))
    if Path(doc["workspace_root"]) != directory or len(doc["workspace_members"]) != 1:
        raise ValueError("non-isolated workspace")
    packages = {p["id"]: p for p in doc["packages"]}
    built = set()
    for line in cargo("build", "--locked", "--offline", "--message-format=json-render-diagnostics").splitlines():
        event = json.loads(line)
        if event["reason"] != "compiler-artifact":
            continue
        pkg = packages[event["package_id"]]
        built.add(pkg["name"])
        if pkg["name"].startswith("rss-") and pkg["source"] != f"git+{REPO}?rev={revision}#{revision}":
            raise ValueError(f"mixed RSS sources: {pkg['id']}")
    if root not in built or {"rss-identity-service-http", "rss-identity-app", "axum"} & built:
        raise ValueError(f"unexpected production closure for {name}")
    if name == "core" and {"sqlx", "webauthn-rs", "jsonwebtoken"} & built:
        raise ValueError("provider in Core closure")
    if cargo("run", "--locked", "--offline", "--quiet").strip() != "passed":
        raise ValueError(f"consumer failed: {name}")
    shutil.rmtree(directory / "target")
    print(f"{name} {features}: passed @ {revision}", flush=True)


def main():
    revision = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    require_candidate_revision(revision)
    env = cargo_environment(os.environ) | {"CARGO_NET_GIT_FETCH_WITH_CLI": "true", "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_INCREMENTAL": "0"}
    validate_cargo_config(ROOT, env)
    parent = ROOT / "rss-external-check"
    parent.mkdir(exist_ok=True)
    result = Path(tempfile.mkdtemp(prefix="identity-consumer-", dir=parent))
    for name, extra in SCENARIOS.items():
        verify(result / name, name, extra, revision, env)
        if name in ("oidc", "postgres"):
            verify(result / (name + "-test-support"), name, extra, revision, env, ("test-support",))


if __name__ == "__main__":
    main()
