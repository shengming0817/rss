#!/usr/bin/env python3
"""Consume #2293's actual crate archives outside the source workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("rss-contract", "rss-redact-derive", "rss-redact", "rss-request-context",
            "rss-data-protection", "rss-runtime", "rss-saga", "rss-saga-postgres")
CONSUMER = r'''
use rss_saga::*;
use rss_saga_postgres::PgStore;
use rss_request_context::TenantId;
struct Reservation(&'static str);
impl Step for Reservation {
    type Receipt = String;
    fn name(&self) -> &str { self.0 }
    fn receipt_schema(&self) -> &str { "receipt.v1" }
    async fn execute(&self, _: EffectContext) -> EffectOutcome<String> {
        // A compile-only consumer has no remote provider and proves no effect was attempted.
        EffectOutcome::NotApplied
    }
    async fn probe(&self, _: EffectContext) -> ProbeOutcome<String> { ProbeOutcome::NotApplied }
    async fn compensate(&self, _: EffectContext, _: String) -> EffectOutcome<()> { EffectOutcome::NotApplied }
    async fn probe_compensation(&self, _: EffectContext, _: String) -> ProbeOutcome<()> { ProbeOutcome::NotApplied }
}
use rss_data_protection::Plaintext;
use ring::{aead, rand::{SecureRandom, SystemRandom}};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
struct Clock(Instant);
impl Timer for Clock {
    fn now(&self) -> Duration { self.0.elapsed() }
    async fn sleep_until(&self, deadline: Duration) { tokio::time::sleep(deadline.saturating_sub(self.now())).await; }
}
struct LocalAead { key: aead::LessSafeKey, key_id: String }
impl SagaReceiptProtector for LocalAead {
    async fn seal(&self, plain: &[u8], context: &ReceiptContext) -> Result<Ciphertext, Error> {
        let mut nonce = [0_u8; 12];
        SystemRandom::new().fill(&mut nonce).map_err(|_| Error::new(ErrorKind::Protection))?;
        let mut encrypted = plain.to_vec();
        self.key.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(context.canonical_aad()), &mut encrypted)
            .map_err(|_| Error::new(ErrorKind::Protection))?;
        let mut bytes = nonce.to_vec(); bytes.extend(encrypted);
        Ciphertext::new(self.key_id.clone(), bytes)
    }
    async fn open(&self, cipher: &Ciphertext, context: &ReceiptContext) -> Result<Plaintext, Error> {
        if cipher.key_ref() != self.key_id || cipher.bytes().len() < 28 {
            return Err(Error::new(ErrorKind::Protection));
        }
        let nonce: [u8; 12] = cipher.bytes()[..12].try_into()
            .map_err(|_| Error::new(ErrorKind::Protection))?;
        let mut bytes = cipher.bytes()[12..].to_vec();
        let plain = self.key.open_in_place(aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(context.canonical_aad()), &mut bytes)
            .map_err(|_| Error::new(ErrorKind::Protection))?;
        Ok(Plaintext::new(plain.to_vec()))
    }
}
pub async fn compose(pool: sqlx::PgPool, tenant: TenantId,
    encryption_key: &[u8], integrity_key: Vec<u8>) -> Result<Report, Error>
{
    let clock = Clock(Instant::now());
    let cancel = CancellationToken::new();
    let control = &Control::new(&clock, Duration::from_secs(30), &cancel);
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, encryption_key).map_err(|_| Error::new(ErrorKind::Protection))?;
    let protector = LocalAead { key: aead::LessSafeKey::new(key), key_id: "consumer-key-v1".into() };
    let key_id = SagaReceiptIntegrityKeyId::parse("consumer-integrity-v1").map_err(|_| Error::new(ErrorKind::Protection))?;
    let integrity_key = VersionedSagaReceiptIntegrityKey::from_bytes(key_id, integrity_key).map_err(|_| Error::new(ErrorKind::Protection))?;
    let keyring = SagaReceiptIntegrityKeyring::new(integrity_key, vec![]).map_err(|_| Error::new(ErrorKind::Protection))?;
    let protection = ReceiptProtection::new(protector, keyring);
    let definition = Definition::new("orders", Identity::new(rss_contract::ContractId::from_static("orders.checkout"), rss_contract::ContractVersion::from_static_major(1), rss_contract::SchemaDigest::from_static("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), rss_saga::ActionGeneration::parse("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?),
        vec![StepSpec::new("reserve", "receipt.v1", "reserve", "release", 1)?,
             StepSpec::new("charge", "receipt.v1", "charge", "refund", 1)?])?;
    let builder = DefinitionBuilder::new(definition.clone())?
        .step(Reservation("reserve"))?.step(Reservation("charge"))?;
    let registry = Registry::builder().register(builder)?.finish();
    let store = PgStore::new(pool, control).await?;
    let scope = Scope::new(tenant, uuid::Uuid::new_v4());
    let executor = Executor::new(store, protection, registry);
    executor.register(scope, &definition, control).await?;
    let result = executor.run(scope, 20, control).await;
    let _ = executor.store().close(control).await;
    result
}
pub fn migration() -> &'static str { rss_saga_postgres::MIGRATION_SQL }
'''


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
        if any(part in package + version for part in ("/", "\\")) or ".." in package + version:
            raise ValueError("invalid candidate package identity")
        name = f"{package}-{version}.crate"
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digests.get(name):
            raise ValueError(f"candidate checksum mismatch: {name}")
    selected = {package: directory / f"{package}-{version}.crate" for package, version, _ in rows if package in PACKAGES}
    if set(selected) != set(PACKAGES):
        raise ValueError("candidate lacks Saga dependency artifacts")
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, help="consume existing candidate archives; never repackage")
    parser.add_argument("--revision", help="expected candidate revision")
    options = parser.parse_args()
    if bool(options.artifacts) != bool(options.revision):
        parser.error("--artifacts and --revision must be supplied together")
    env = os.environ.copy()
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="rss-saga-artifacts-") as temporary:
        root = Path(temporary).resolve()
        if options.artifacts:
            archives = candidate_archives(options.artifacts.resolve(), options.revision)
        else:
            packaged = root / "packaged"
            command = ["cargo", "package", "--locked", "--offline", "--allow-dirty", "--no-verify", "--target-dir", str(packaged)]
            for package in PACKAGES:
                command += ["-p", package]
            run(command, ROOT, env)
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
name = "saga-artifact-consumer"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
rss-saga = { version = "=0.1.0", default-features = false }
rss-saga-postgres = { version = "=0.1.0", default-features = false }
rss-request-context = "=0.1.0"
rss-contract = "=0.1.0"
rss-data-protection = "=0.1.0"
ring = "0.17"
tokio = { version = "1", features = ["time"] }
tokio-util = "0.7"
sqlx = { version = "=0.9.0", default-features = false, features = ["postgres", "runtime-tokio", "tls-rustls"] }
uuid = { version = "1", features = ["v4"] }
[features]
default = []
rss-runtime = ["rss-saga/rss-runtime", "rss-saga-postgres/rss-runtime"]
[patch.crates-io]
'''
        for package in PACKAGES:
            manifest += f'{package} = {{ path = {json.dumps(str(extracted / (package + "-0.1.0")))} }}\n'
        (consumer / "Cargo.toml").write_text(manifest)
        (consumer / "src/lib.rs").write_text(CONSUMER)
        for flags in ([], ["--no-default-features"], ["--features", "rss-runtime"], ["--all-features"]):
            run(["cargo", "check", "--offline", *flags], consumer, env)
            metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--format-version", "1", *flags], cwd=consumer, env=env, timeout=60))
            for package in metadata["packages"]:
                if package["name"] in {"diport", "consistency", "vocab", "secure", "eventexec", "sagaauthmint"}:
                    raise RuntimeError(f"old owner in artifact closure: {package['name']}")
                if package["source"] is None and not Path(package["manifest_path"]).resolve().is_relative_to(root):
                    raise RuntimeError("consumer escaped extracted artifacts")
        print(json.dumps({"artifacts": receipts, "consumer": "default/no-default/rss-runtime/all-features passed"}, indent=2))


if __name__ == "__main__":
    main()
