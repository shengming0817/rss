#!/usr/bin/env python3
"""Build isolated core, PostgreSQL, S3 and combined recovery consumers from actual .crate archives."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CONSUMER = r'''
use rss_transactional_messaging_recovery::*;
use rss_transactional_messaging::policy::OperationDeadline;
pub struct ProductAuthorization;
impl Authorizer for ProductAuthorization {
    async fn authorize(&self, challenge: Challenge<'_>, _: OperationDeadline) -> Result<Authorization, Error> {
        // Compile-only denial proves the product must make an explicit authorization decision.
        let _ = challenge.tenant();
        Err(Error::Unauthorized)
    }
}
pub fn request(tenant: rss_request_context::TenantId, target: Target, version: Version) -> Result<Mutation, Error> {
    Mutation::new(tenant, OperationId::new(), target, version, Action::Redrive)
}
#[cfg(feature = "postgres")]
pub async fn store<K: rss_data_protection::Aead + Send + Sync, C: rss_transactional_messaging::policy::ExecutionTimer + 'static>(config: rss_transactional_messaging_postgres::PgConfig, timer: C, key: std::sync::Arc<K>) -> Result<rss_transactional_messaging_postgres::PgRecoveryStore<K>, Error> {
    rss_transactional_messaging_postgres::PgRecoveryStore::connect(config, timer, key).await
}
#[cfg(feature = "postgres")]
pub fn consumer<H,K>(effect: H, capture: rss_transactional_messaging_postgres::PgRecoveryCapture<K>) -> rss_transactional_messaging_postgres::PgConsumerTx<H,rss_transactional_messaging_postgres::PgRecoveryCapture<K>> {
    rss_transactional_messaging_postgres::PgConsumerTx::with_recovery(effect,capture)
}
#[cfg(feature = "postgres")]
pub fn migration() -> &'static str { rss_transactional_messaging_postgres::RECOVERY_UPGRADE_SQL }
#[cfg(feature = "s3")]
pub fn s3_port(store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore) {
    fn implements<S: archive::ArchiveObjectStore>(_: &S) {}
    implements(store);
}
#[cfg(feature = "postgres")]
pub fn archive_repository(store: &rss_transactional_messaging_postgres::PgArchiveRepository) {
    fn implements<R: archive::ArchiveRepository>(_: &R) {}
    implements(store);
}

#[cfg(feature = "s3")]
pub async fn product_archive<R,H,K,C,A,O>(
    client: aws_sdk_s3::Client, bucket: String,
    wall: &impl rss_transactional_messaging_recovery_s3::Clock,
    repository: &R, hot: &archive::HotKey<H>, cold: &archive::ArchiveKey<K>,
    authorizer: &A, request: archive::Request, clock: &C,
    deadlines: rss_transactional_messaging::policy::ExecutionDeadlines, observer: &O,
) -> Result<rss_transactional_messaging::transaction::LocalTxAttempt<archive::Outcome,archive::Error>,archive::Error>
where R: archive::ArchiveRepository, H: rss_data_protection::Aead + Send + Sync,
      K: rss_data_protection::Aead + Send + Sync, C: rss_transactional_messaging::policy::ExecutionTimer,
      A: archive::Authorizer, O: archive::Observer,
{
    let store = rss_transactional_messaging_recovery_s3::Unverified::new(client,bucket)?
        .verify(wall,deadlines.operation().operation(clock)).await?;
    let request = archive::authorize(authorizer,request,deadlines.operation().operation(clock)).await?;
    Ok(archive::execute(repository,&store,hot,cold,&request,clock,deadlines,observer).await)
}
'''

def validate_selection(flags, names):
    forbidden = {
        ('--no-default-features',): {'sqlx', 'rss-transactional-messaging-postgres', 'rss-runtime', 'aws-sdk-s3'},
        ('--features', 'postgres'): {'aws-sdk-s3'},
        ('--features', 's3'): {'sqlx', 'rss-transactional-messaging-postgres', 'rss-runtime'},
        ('--all-features',): set(),
    }[tuple(flags)]
    leaked = {name for name in names if name in forbidden or ('sqlx' in forbidden and name.startswith('sqlx-'))}
    if leaked:
        raise ValueError(f'{flags} acquired forbidden dependencies: {sorted(leaked)}')

def run(args, cwd, env):
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=300)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--revision')
    options = parser.parse_args()
    if bool(options.artifacts) != bool(options.revision):
        parser.error('--artifacts and --revision must be provided together')
    env = os.environ.copy()
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'):
        env.pop(key, None)
    metadata = json.loads(subprocess.check_output(['cargo','metadata','--locked','--no-deps','--format-version','1'],cwd=ROOT,env=env))
    packages = {p['name']:p for p in metadata['packages']}
    selected = set()
    def visit(name):
        if name in selected: return
        selected.add(name)
        for dep in packages[name]['dependencies']:
            if dep.get('path') and dep['kind'] != 'dev': visit(dep['name'])
    visit('rss-transactional-messaging-recovery')
    visit('rss-transactional-messaging-postgres')
    visit('rss-transactional-messaging-recovery-s3')
    with tempfile.TemporaryDirectory(prefix='rss-recovery-proof-') as tmp:
        root = Path(tmp).resolve()
        if options.artifacts:
            source = options.artifacts.resolve()
            rows = [line.split('\t') for line in (source/'packages.tsv').read_text().splitlines()]
            if not rows or any(len(row)!=3 or row[2]!=options.revision for row in rows):
                raise ValueError('candidate revision mismatch')
            identities = {row[0]:row[1] for row in rows}
            if len(identities)!=len(rows): raise ValueError('duplicate candidate identity')
            sums = {}
            for line in (source/'SHA256SUMS').read_text().splitlines():
                digest, name = line.split(maxsplit=1)
                name = name.removeprefix('*')
                if Path(name).name != name or name in sums: raise ValueError('invalid archive name')
                sums[name] = digest
        else:
            source = root/'packaged'/'package'
            command = ['cargo','package','--offline','--locked','--allow-dirty','--no-verify','--target-dir',str(root/'packaged')]
            for name in sorted(selected): command += ['-p',name]
            run(command,ROOT,env)
            identities = {name:packages[name]['version'] for name in selected}
            sums = None
        extracted = root/'extracted'; extracted.mkdir()
        paths = {}; receipts = []
        for name in sorted(selected):
            version = identities[name]
            if any(c in name+version for c in ('/','\\')) or '..' in name+version: raise ValueError('invalid identity')
            archive = source/f'{name}-{version}.crate'
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if sums is not None and sums.get(archive.name)!=digest: raise ValueError('checksum mismatch')
            with tarfile.open(archive) as bundle: bundle.extractall(extracted,filter='data')
            paths[name] = extracted/f'{name}-{version}'
            receipts.append({'package':name,'version':version,'sha256':digest})
        consumer = root/'consumer'; (consumer/'src').mkdir(parents=True)
        manifest = '''[package]
name = "recovery-artifact-consumer"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
rss-transactional-messaging-recovery = "=0.1.0"
rss-transactional-messaging = "=0.2.0"
rss-request-context = "=0.1.0"
rss-data-protection = "=0.1.0"
rss-transactional-messaging-postgres = { version = "=0.1.0", optional = true, features = ["recovery"] }
rss-transactional-messaging-recovery-s3 = { version = "=0.1.0", optional = true }
aws-sdk-s3 = { version = "=1.142.0", default-features = false, features = ["rt-tokio"], optional = true }
[features]
default = []
s3 = ["dep:rss-transactional-messaging-recovery-s3", "dep:aws-sdk-s3"]
postgres = ["dep:rss-transactional-messaging-postgres"]
managed = ["postgres", "rss-transactional-messaging-postgres/rss-runtime"]
[patch.crates-io]
'''
        for name,path in paths.items(): manifest += f'{name} = {{ path = {json.dumps(str(path))} }}\n'
        (consumer/'Cargo.toml').write_text(manifest)
        (consumer/'src/lib.rs').write_text(CONSUMER)
        env['CARGO_TARGET_DIR'] = str(ROOT/'target'/'recovery-package-proof')
        for flags in (['--no-default-features'],['--features','postgres'],['--features','s3'],['--all-features']):
            run(['cargo','check','--offline',*flags],consumer,env)
            facts = json.loads(subprocess.check_output(['cargo','metadata','--offline','--format-version','1',*flags],cwd=consumer,env=env,timeout=60))
            active = {node['id'] for node in facts['resolve']['nodes']}
            validate_selection(flags, {p['name'] for p in facts['packages'] if p['id'] in active})
            for package in facts['packages']:
                if package['id'] not in active: continue
                if package['source'] is None and not Path(package['manifest_path']).resolve().is_relative_to(root): raise ValueError('artifact consumer escaped extracted packages')
        print(json.dumps({'artifacts':receipts,'consumer':'core/postgres/s3/combined passed'},indent=2))

if __name__ == '__main__': main()
