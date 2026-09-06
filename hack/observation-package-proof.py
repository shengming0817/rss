#!/usr/bin/env python3
"""Consume exact Observation artifacts in isolated supported capability combinations."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MODES = ("core", "adapter", "projection", "projection-postgres")
PACKAGES = ("rss-contract", "rss-redact-derive", "rss-redact", "rss-request-context", "rss-observation", "rss-observation-postgres", "rss-projection", "rss-projection-postgres")


def candidate_archives(directory, revision):
    rows = [line.split("\t") for line in (directory / "packages.tsv").read_text().splitlines()]
    if not rows or any(len(row) != 3 or row[2] != revision for row in rows):
        raise ValueError("candidate revision mismatch")
    if len({row[0] for row in rows}) != len(rows):
        raise ValueError("duplicate candidate package")
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.removeprefix("*")
        if Path(name).name != name or name in sums:
            raise ValueError("invalid archive identity")
        sums[name] = digest
    result = {}
    for package, version, _ in rows:
        if package not in PACKAGES:
            continue
        name = f"{package}-{version}.crate"
        if version != "0.1.0" or hashlib.sha256((directory / name).read_bytes()).hexdigest() != sums.get(name):
            raise ValueError("candidate content mismatch")
        result[package] = directory / name
    if set(result) != set(PACKAGES):
        raise ValueError("candidate lacks observation dependency artifacts")
    return result


def main():
    parser = argparse.ArgumentParser(description=f"{__doc__} Modes: {', '.join(MODES)}.")
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--revision")
    options = parser.parse_args()
    if bool(options.artifacts) != bool(options.revision):
        parser.error("artifacts and revision must be supplied together")
    env = os.environ.copy()
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR"):
        env.pop(key, None)
    def run(args, cwd):
        subprocess.run(args, cwd=cwd, env=env, check=True, timeout=300)
    with tempfile.TemporaryDirectory(prefix="rss-observation-artifacts-") as temporary:
        root = Path(temporary).resolve()
        if options.artifacts:
            archives = candidate_archives(options.artifacts.resolve(), options.revision)
        else:
            args = ["cargo", "package", "--locked", "--offline", "--allow-dirty", "--no-verify", "--target-dir", str(root / "packaged")]
            for name in PACKAGES:
                args += ["-p", name]
            run(args, ROOT)
            archives = {name: root / "packaged/package" / f"{name}-0.1.0.crate" for name in PACKAGES}
        extracted = root / "extracted"
        extracted.mkdir()
        for archive in archives.values():
            with tarfile.open(archive) as bundle:
                bundle.extractall(extracted, filter="data")
        for mode in MODES:
            consumer = root / mode
            (consumer / "src").mkdir(parents=True)
            manifest = f'[package]\nname = "observation-{mode}-consumer"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\n[dependencies]\nrss-observation = {{ version = "=0.1.0", default-features = false }}\nrss-contract = "=0.1.0"\nrss-request-context = "=0.1.0"\n'
            code = '''use rss_observation::{Batch,Body,Coverage,Id,Policy,State,Error};
use rss_contract::Timepoint;
pub fn snapshot(time:Timepoint)->Result<Batch,Error>{
 let coverage=Coverage::new(Id::new("all")?,Id::new("1")?,Id::new("catalog")?,Id::new("bytes")?);
 let batch=Batch::new(Id::new("batch")?,0,time,coverage,Body::Snapshot(vec![]))?;
 State::initial().advance(&batch,10,&Policy::new(10,1,10)?)?;
 Ok(batch)
}
'''
            if mode != "core":
                manifest += 'rss-observation-postgres = { version = "=0.1.0", default-features = false }\nsqlx = { version = "=0.9.0", default-features = false, features = ["postgres", "runtime-tokio", "tls-rustls"] }\n[features]\ndefault = []\nintegration = ["rss-observation-postgres/integration"]\n'
                code += '''use rss_observation::{Clock,ObservationStore,VerifiedBatch,ReceiveOutcome};
use rss_observation_postgres::PgStore;
use rss_request_context::Deadline;
pub async fn receive<C:Clock>(pool:sqlx::PgPool,clock:C,input:&VerifiedBatch,deadline:Deadline)->Result<ReceiveOutcome,Error>{
 let store=PgStore::new(pool,clock,deadline).await?;
 let result=store.receive(input,deadline).await;
 store.close(deadline).await?;
 result
}
pub const MIGRATION:&str=rss_observation_postgres::MIGRATION_SQL;
'''
            if mode in ("projection", "projection-postgres"):
                manifest = manifest.replace('default-features = false }\nsqlx', f'default-features = false, features = ["{mode}"] }}\nsqlx')
                manifest = manifest.replace('[features]\n', 'rss-projection = { version = "=0.1.0", default-features = false }\n[features]\n')
                if mode == "projection-postgres":
                    manifest = manifest.replace('[features]\n', 'rss-projection-postgres = { version = "=0.1.0", default-features = false }\n[features]\n')
                    model = extracted / "rss-observation-postgres-0.1.0/examples/handoff/model.rs"
                    code += f'#[path = {json.dumps(str(model))}] pub mod consumer_mapping;\n'
                    installer = extracted / "rss-observation-postgres-0.1.0/examples/handoff/install.rs"
                    code += f'#[path = {json.dumps(str(installer))}] pub mod consumer_install;\n'
                    for name in ("handoff", "handoff-install"):
                        (consumer / "src/bin").mkdir(exist_ok=True)
                        binary = extracted / f"rss-observation-postgres-0.1.0/examples/{name}.rs"
                        (consumer / "src/bin" / f"{name}.rs").write_text(binary.read_text())
                    shutil.copytree(extracted / "rss-observation-postgres-0.1.0/examples/handoff", consumer / "src/bin/handoff")
                    manifest = manifest.replace('[features]\n', 'anyhow = "1"\ntokio = { version = "1", features = ["rt", "macros", "time"] }\ntokio-util = { version = "0.7", features = ["rt"] }\n[features]\n')
                    setup = (consumer / "src/bin/handoff/setup.sql").read_text()
                    if "\\ir " in setup or "\\i " in setup:
                        raise ValueError("example setup must not reference files outside the artifact")
                code += """use rss_observation::{JournalReadGrant,ApplicableRecord};
use rss_observation_postgres::PgSource;
use rss_projection::{Source,Event,SourceScope,BatchLimit,Execution,Timer,Control,RunLimit};
use std::sync::Arc;
pub fn source<C:Clock>(store:Arc<PgStore<C>>,grant:JournalReadGrant)->Result<PgSource<C>,Error>{PgSource::new(store,grant)}
pub async fn read<C:Clock>(source:&PgSource<C>,scope:&SourceScope)->Result<Vec<Event>,rss_projection::Error>{source.read(scope,None,BatchLimit::new(10)?).await}
pub async fn resolve<C:Clock>(source:&PgSource<C>,event:&Event,deadline:Deadline)->Result<ApplicableRecord,Error>{source.resolve(event,deadline).await}
pub async fn run<C:Clock,E:Execution,T:Timer>(source:&PgSource<C>,execution:&E,control:&Control<'_,T>)->Result<rss_projection::Report,rss_projection::Error>{rss_projection::run(source,execution,control,RunLimit::new(BatchLimit::new(10)?,100)?).await.into_result()}
pub const UPGRADE:&str=rss_observation_postgres::UPGRADE_SQL;
"""
            manifest += '[patch.crates-io]\n'
            for name in PACKAGES:
                manifest += f'{name} = {{ path = {json.dumps(str(extracted / (name + "-0.1.0")))} }}\n'
            (consumer / "Cargo.toml").write_text(manifest)
            (consumer / "src/lib.rs").write_text(code)
            for features in ([], ["--no-default-features"], ["--all-features"]):
                run(["cargo", "check", "--offline", *features], consumer)
            metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--format-version", "1"], cwd=consumer, env=env, timeout=60))
            for package in metadata["packages"]:
                if package["source"] is None and not Path(package["manifest_path"]).resolve().is_relative_to(root):
                    raise ValueError("consumer escaped extracted artifacts")
                if package["name"] in ("testkit", "testcontainers", "rss-transactional-messaging") or (mode in ("core", "adapter") and package["name"] == "rss-projection") or (mode != "projection-postgres" and package["name"] == "rss-projection-postgres") or (mode == "core" and package["name"] == "sqlx"):
                    raise ValueError("unexpected production dependency")
        print(json.dumps({"artifacts": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in archives.items()}, "consumers": f"{', '.join(MODES)}: default/no-default/all-features passed"}, indent=2))


if __name__ == "__main__":
    main()
