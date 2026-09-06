#!/usr/bin/env python3
"""Verify #2292's actual .crate artifacts in an independent consumer workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("rss-contract", "rss-redact-derive", "rss-redact", "rss-request-context", "rss-projection", "rss-projection-postgres")


def run(args, cwd, env):
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=300)


def candidate_archives(directory, revision):
    rows = [line.split("\t") for line in (directory / "packages.tsv").read_text().splitlines()]
    if not rows or any(len(row) != 3 or row[2] != revision for row in rows):
        raise ValueError("candidate revision does not match packages.tsv")
    names = [row[0] for row in rows]
    if len(set(names)) != len(names):
        raise ValueError("duplicate candidate package")
    digests = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.removeprefix("*")
        if Path(name).name != name or name in digests:
            raise ValueError("invalid candidate archive name")
        digests[name] = digest
    for package, version, _ in rows:
        name = f"{package}-{version}.crate"
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digests.get(name):
            raise ValueError(f"candidate checksum mismatch: {name}")
    selected = {package: directory / f"{package}-{version}.crate" for package, version, _ in rows if package in PACKAGES}
    if set(selected) != set(PACKAGES):
        raise ValueError("candidate lacks projection dependency artifacts")
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, help="consume the exact candidate upload directory; never repackage")
    parser.add_argument("--revision", help="expected candidate Git revision")
    options = parser.parse_args()
    if bool(options.artifacts) != bool(options.revision):
        parser.error("--artifacts and --revision must be supplied together")
    env = os.environ.copy()
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="rss-projection-artifacts-") as temporary:
        root = Path(temporary).resolve()
        if options.artifacts:
            archives = candidate_archives(options.artifacts.resolve(), options.revision)
        else:
            packaged = root / "packaged"
            args = ["cargo", "package", "--locked", "--offline", "--allow-dirty", "--no-verify", "--target-dir", str(packaged)]
            for package in PACKAGES:
                args += ["-p", package]
            run(args, ROOT, env)
            archives = {package: packaged / "package" / f"{package}-0.1.0.crate" for package in PACKAGES}
        extracted = root / "extracted"
        extracted.mkdir()
        receipts = []
        for package in PACKAGES:
            archive = archives[package]
            with tarfile.open(archive) as bundle:
                bundle.extractall(extracted, filter="data")
            receipts.append({"package": package, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()})
        consumer = root / "consumer"
        (consumer / "src").mkdir(parents=True)
        manifest = '''[package]
name = "projection-artifact-consumer"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
rss-request-context = "=0.1.0"
rss-projection = { version = "=0.1.0", default-features = false }
rss-projection-postgres = { version = "=0.1.0", default-features = false }
sqlx = { version = "=0.9.0", default-features = false, features = ["postgres", "runtime-tokio", "tls-rustls"] }
tokio = { version = "1", default-features = false, features = ["rt", "macros", "time"] }
tokio-util = { version = "0.7", features = ["rt"] }
[features]
default = []
integration = ["rss-projection-postgres/integration"]
[patch.crates-io]
'''
        for package in PACKAGES:
            manifest += f'{package} = {{ path = {json.dumps(str(extracted / (package + "-0.1.0")))} }}\n'
        (consumer / "Cargo.toml").write_text(manifest)
        (consumer / "src/lib.rs").write_text('''use rss_projection::{Event, SourceScope, Position, Error, Source, BatchLimit, ProjectionScope};
use rss_projection_postgres::{PgStore, PgEffect, PgEffectOutcome, PgOperationError, PgTransaction};
use rss_request_context::TenantId;
pub struct Empty;
impl Source for Empty {
    async fn high_water(&self, _: &SourceScope) -> Result<Option<Position>, Error> { Ok(None) }
    async fn read(&self, _: &SourceScope, _: Option<Position>, _: BatchLimit) -> Result<Vec<Event>, Error> { Ok(vec![]) }
}
pub struct Effect;
impl PgEffect for Effect {
    async fn apply(&self, _: &mut PgTransaction<'_>, _: &ProjectionScope, _: &Event) -> Result<PgEffectOutcome, PgOperationError> { Ok(PgEffectOutcome::Filtered) }
}
pub fn fact(tenant: TenantId) -> Result<Event, Error> {
    Event::new(SourceScope::new(tenant,"source")?,Position::new(0)?,"fact",vec![1])
}
pub async fn run_consumer<E: rss_projection::Execution, T: rss_projection::Timer>(execution: &E, control: &rss_projection::Control<'_,T>) -> Result<rss_projection::Report, Error> {
    Ok(rss_projection::run(&Empty,execution,control,rss_projection::RunLimit::new(BatchLimit::new(10)?,100)?).await)
}
pub struct Clock(std::time::Instant);
impl rss_projection::Timer for Clock {
    fn now(&self) -> std::time::Duration { self.0.elapsed() }
    async fn sleep_until(&self, deadline: std::time::Duration) { tokio::time::sleep(deadline.saturating_sub(self.0.elapsed())).await; }
}
pub async fn composition(pool: sqlx::PgPool, tenant: TenantId) -> Result<rss_projection::Report,Error> {
    let clock = Clock(std::time::Instant::now());
    let cancellation = tokio_util::sync::CancellationToken::new();
    let control = &rss_projection::Control::new(&clock,std::time::Duration::from_secs(10),&cancellation);
    let store = PgStore::new(pool.clone()).await?;
    let source = SourceScope::new(tenant,"source")?;
    let scope = ProjectionScope::new(source.clone(),"projection","v1")?;
    store.initialize(&scope,rss_projection::GenerationStart::beginning(),rss_projection::ReplayBound::Live,control).await?;
    let execution = store.projection(store.takeover(&scope,control).await?,Effect)?;
    let borrowed_source = source.clone();
    store.local_tx(&source,control,move |tx| Box::pin(async move {
        tx.append(&borrowed_source,"fact",&[1]).await?;
        tx.with_connection(|connection| Box::pin(async move {
            sqlx::query("SELECT 1").execute(connection).await?; Ok(())
        })).await
    })).await?;
    let mut transaction = pool.begin().await.map_err(|_|Error::new(rss_projection::ErrorKind::Unavailable))?;
    rss_projection_postgres::append_in_transaction(&mut transaction,&source,"fact",&[1],control).await?;
    transaction.rollback().await.map_err(|_|Error::new(rss_projection::ErrorKind::RollbackFailed))?;
    run_consumer(&execution,control).await
}
pub fn adapter_identity(_: &PgStore) -> &'static str { rss_projection_postgres::MIGRATION_SQL }
''')
        for features in ([], ["--no-default-features"], ["--all-features"]):
            run(["cargo", "check", "--offline", *features], consumer, env)
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--format-version", "1"], cwd=consumer, env=env, timeout=60))
        ids = {package["id"]: package["name"] for package in metadata["packages"]}
        forbidden = {"tokio": {"rt-multi-thread"}, "sqlx": {"any", "json", "migrate", "derive", "macros"}, "futures": {"executor"}}
        for node in metadata["resolve"]["nodes"]:
            extra = forbidden.get(ids[node["id"]], set()).intersection(node["features"])
            if extra:
                raise RuntimeError(f"unnecessary consumer features: {ids[node['id']]} {sorted(extra)}")
        for package in metadata["packages"]:
            if package["source"] is None:
                path = Path(package["manifest_path"]).resolve()
                if not path.is_relative_to(root):
                    raise RuntimeError(f"consumer escaped artifact workspace: {path}")
        print(json.dumps({"artifacts": receipts, "consumer": "default/no-default/all-features passed"}, indent=2))


if __name__ == "__main__":
    main()
