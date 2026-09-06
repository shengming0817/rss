#!/usr/bin/env python3
"""Validate #2290 artifacts and independently resolve core, PostgreSQL and messaging consumers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def metadata(cwd, *flags):
    return json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--format-version", "1", *flags], cwd=cwd, timeout=120))


def closure():
    facts = metadata(ROOT, "--no-deps")
    packages = {p["name"]: p for p in facts["packages"]}
    accepted = {p["package"] for p in facts["metadata"]["release-surface"]["packages"]}
    pending, selected = ["rss-reconcile", "rss-reconcile-postgres"], {}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        if name not in accepted:
            raise ValueError(f"non-release production dependency: {name}")
        package = packages[name]
        selected[name] = package["version"]
        pending += [d["name"] for d in package["dependencies"] if d["kind"] != "dev" and d.get("path")]
    return selected


def candidate_archives(directory, revision, versions):
    rows = [line.split("\t") for line in (directory / "packages.tsv").read_text().splitlines()]
    if not rows or any(len(row) != 3 or row[2] != revision for row in rows):
        raise ValueError("candidate revision mismatch")
    if len({row[0] for row in rows}) != len(rows):
        raise ValueError("duplicate package identity")
    digests = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.removeprefix("*")
        if Path(name).name != name or name in digests:
            raise ValueError("invalid archive identity")
        digests[name] = digest
    selected = {}
    for package, version, _ in rows:
        name = f"{package}-{version}.crate"
        if Path(name).name != name:
            raise ValueError("invalid package identity")
        archive = directory / name
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digests.get(name):
            raise ValueError("candidate checksum mismatch")
        if package in versions:
            if versions[package] != version:
                raise ValueError("candidate version mismatch")
            selected[package] = archive
    if set(selected) != set(versions):
        raise ValueError("missing dependency artifacts")
    return selected


CORE = '''use rss_reconcile::*;
pub fn named_policy()->Result<Policy,Error> {
    use std::time::Duration;
    Policy::try_from(PolicyConfig{concurrency:2,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(10),scan_interval:Duration::from_secs(1),initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(10),max_attempts:3})
}
pub struct Business;
impl<C:Claim> Reconciler<C> for Business {
    type State=u8;
    async fn observe<T:Timer>(&self,_:&C,_:&Control<'_,T>)->Result<ReconcileDiff<u8>,Error> {Ok(ReconcileDiff::between(DesiredState::present(1),ActualState::present(1)))}
    async fn apply<T:Timer>(&self,_:&C,_:ReconcileDiff<u8>,_:&Control<'_,T>)->Result<(),Error> {Ok(())}
}
pub async fn worker<S:DurableStore,T:Timer>(store:&S,scope:&Scope,policy:Policy,control:&Control<'_,T>)->Result<Report,Error> {run(store,&Business,scope,policy,control,|_| {}).await}
'''
PG = '''pub struct BorrowedBusiness<'a> {pub store:&'a rss_reconcile_postgres::PgStore,pub label:&'a str}
impl Reconciler<rss_reconcile_postgres::PgClaim> for BorrowedBusiness<'_> {
    type State=u8;
    async fn observe<T:Timer>(&self,_:&rss_reconcile_postgres::PgClaim,_:&Control<'_,T>)->Result<ReconcileDiff<u8>,Error> {Ok(ReconcileDiff::between(DesiredState::present(1),ActualState::present(1)))}
    async fn apply<T:Timer>(&self,claim:&rss_reconcile_postgres::PgClaim,_:ReconcileDiff<u8>,c:&Control<'_,T>)->Result<(),Error> {
        self.store.protect(claim,c,&self.label,|label,tx|Box::pin(async move {
            tx.with_connection(|conn|Box::pin(async move {sqlx::query("SELECT 1").execute(conn).await?;Ok(())})).await?;
            let _borrow_after_await=label.len();Ok(())
        })).await
    }
}
pub async fn pg<T:Timer>(pool:sqlx::PgPool,target:&Target,c:&Control<'_,T>)->Result<(),Error> {
    let store=rss_reconcile_postgres::PgStore::new(pool,c).await?;
    store.wake(target,c).await?;
    for claim in store.claim_due(target.scope(),1,std::time::Duration::from_secs(1),c).await? {
        store.protect(&claim,c, (),|_, tx| Box::pin(async move {tx.with_connection(|conn|Box::pin(async move {sqlx::query("SELECT 1").execute(conn).await?;Ok(())})).await})).await?;
        store.finish(&claim,Completion::Reobserve(std::time::Duration::from_millis(1)),c).await?;
    }
    let _outcome=store.close(c).await;Ok(())
}
#[cfg(feature="messaging")]
pub async fn messages<T:Timer>(runtime:&rss_transactional_messaging_postgres::PgRuntime,claim:&rss_reconcile_postgres::PgClaim,c:&Control<'_,T>,outbox:rss_transactional_messaging_postgres::PgOutboxStore<()>,message:rss_transactional_messaging::outbox::PendingMessage<Vec<u8>>)->rss_transactional_messaging::transaction::LocalTxAttempt<(),rss_transactional_messaging_postgres::PgError> {
    use rss_transactional_messaging::outbox::OutboxStore;
    rss_reconcile_postgres::messaging::protect(runtime,claim,c, (),move |_, tx|Box::pin(async move {outbox.append(tx,message).await?;Ok(())})).await
}
'''


def run(args, cwd, env):
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=300)


def profiles(with_pg):
    result = [[], ["--no-default-features"], ["--all-features"]]
    if with_pg:
        result.insert(2, ["--no-default-features", "--features", "messaging"])
        result.insert(3, ["--no-default-features", "--features", "integration"])
    return result


def permits_messaging(with_pg, flags):
    return with_pg and (flags == ["--all-features"] or "messaging" in flags)


def consumer(root, extracted, versions, with_pg, env):
    path = root / ("postgres" if with_pg else "core")
    (path / "src").mkdir(parents=True)
    manifest = '[package]\nname="reconcile-artifact-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
    manifest += f'rss-reconcile={{version="={versions["rss-reconcile"]}",default-features=false}}\n'
    if with_pg:
        manifest += f'rss-reconcile-postgres={{version="={versions["rss-reconcile-postgres"]}",default-features=false}}\n'
        manifest += 'sqlx={version="=0.9.0",default-features=false,features=["postgres","runtime-tokio","tls-rustls"]}\n'
        for name in ("rss-transactional-messaging", "rss-transactional-messaging-postgres"):
            manifest += f'{name}={{version="={versions[name]}",default-features=false,optional=true}}\n'
        manifest += '[features]\ndefault=[]\nintegration=["rss-reconcile-postgres/integration"]\nmessaging=["rss-reconcile-postgres/transactional-messaging","dep:rss-transactional-messaging","dep:rss-transactional-messaging-postgres"]\n'
    manifest += '[patch.crates-io]\n'
    for name, version in versions.items():
        manifest += f'{name}={{path={json.dumps(str(extracted / f"{name}-{version}"))}}}\n'
    (path / "Cargo.toml").write_text(manifest)
    (path / "src/lib.rs").write_text(CORE + (PG if with_pg else ""))
    for flags in profiles(with_pg):
        run(["cargo", "check", "--offline", *flags], path, env)
        facts = metadata(path, *flags)
        identities = {p["id"]: p for p in facts["packages"]}
        for node in facts["resolve"]["nodes"]:
            p = identities[node["id"]]
            if not p["source"] and not Path(p["manifest_path"]).resolve().is_relative_to(root):
                raise ValueError("consumer escaped artifact workspace")
            if not permits_messaging(with_pg, flags):
                if p["name"].startswith("rss-transactional-messaging"):
                    raise ValueError("unconditional messaging dependency")
            if not with_pg and (p["name"] == "sqlx" or p["name"] == "rss-reconcile-postgres"):
                raise ValueError("core acquired provider dependency")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--revision")
    args = parser.parse_args()
    if bool(args.artifacts) != bool(args.revision):
        parser.error("artifacts and revision must be supplied together")
    versions = closure()
    env = os.environ.copy()
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="reconcile-artifacts-") as temporary:
        root = Path(temporary).resolve()
        env["CARGO_TARGET_DIR"] = str(ROOT / "target/reconcile-artifact-proof")
        if args.artifacts:
            archives = candidate_archives(args.artifacts.resolve(), args.revision, versions)
        else:
            packaged = root / "packaged"
            command = ["cargo", "package", "--locked", "--offline", "--allow-dirty", "--no-verify", "--target-dir", str(packaged)]
            for name in sorted(versions):
                command += ["-p", name]
            run(command, ROOT, env)
            archives = {name: packaged / "package" / f"{name}-{version}.crate" for name, version in versions.items()}
        extracted = root / "extracted"
        extracted.mkdir()
        for archive in archives.values():
            with tarfile.open(archive) as bundle:
                bundle.extractall(extracted, filter="data")
        for with_pg in (False, True):
            consumer(root, extracted, versions, with_pg, env)
        print(json.dumps({"artifacts": {name: hashlib.sha256(p.read_bytes()).hexdigest() for name, p in archives.items()}, "consumer": "core/postgres/messaging: default/no-default/all-features passed"}, indent=2))


if __name__ == "__main__":
    main()
