#!/usr/bin/env python3
"""Consume #2312 artifacts with isolated core, PG and messaging feature resolution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(args, cwd, env):
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=300)


def inventory(metadata):
    """Cargo owns the complete production/build dependency closure, including optional seams."""
    packages = {p['id']: p for p in metadata['packages']}
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    pending = [p['id'] for p in packages.values() if p['name'] in ('rss-ledger', 'rss-ledger-postgres')]
    if len(pending) != 2:
        raise ValueError('ledger roots missing')
    seen = set()
    while pending:
        identity = pending.pop()
        if identity in seen:
            continue
        seen.add(identity)
        for dep in nodes[identity]['deps']:
            if any(k['kind'] != 'dev' for k in dep['dep_kinds']):
                pending.append(dep['pkg'])
    return {packages[i]['name']: packages[i]['version'] for i in seen if packages[i]['source'] is None}


def candidate_archives(directory, revision, packages):
    rows = [line.split('\t') for line in (directory / 'packages.tsv').read_text().splitlines()]
    if not rows or any(len(r) != 3 or r[2] != revision for r in rows):
        raise ValueError('candidate revision mismatch')
    if len({r[0] for r in rows}) != len(rows):
        raise ValueError('duplicate candidate package')
    digests = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.removeprefix('*')
        if Path(name).name != name or name in digests:
            raise ValueError('invalid checksum name')
        digests[name] = digest
    selected = {}
    for package, version, _ in rows:
        if package not in packages:
            continue
        if version != packages[package]:
            raise ValueError('candidate version mismatch')
        name = f'{package}-{version}.crate'
        archive = directory / name
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digests.get(name):
            raise ValueError('candidate checksum mismatch')
        selected[package] = archive
    if set(selected) != set(packages):
        raise ValueError('candidate lacks dependency artifacts')
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--revision')
    options = parser.parse_args()
    if bool(options.artifacts) != bool(options.revision):
        parser.error('--artifacts and --revision must be supplied together')
    env = os.environ.copy()
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_TARGET_DIR'):
        env.pop(key, None)
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--offline', '--all-features', '--format-version', '1'], cwd=ROOT, env=env, timeout=60))
    packages = inventory(metadata)
    with tempfile.TemporaryDirectory(prefix='rss-ledger-artifacts-') as tmp:
        root = Path(tmp).resolve()
        if options.artifacts:
            archives = candidate_archives(options.artifacts.resolve(), options.revision, packages)
        else:
            args = ['cargo', 'package', '--locked', '--offline', '--allow-dirty', '--no-verify', '--target-dir', str(root / 'packaged')]
            for package in sorted(packages):
                args += ['-p', package]
            run(args, ROOT, env)
            archives = {p: root / 'packaged/package' / f'{p}-{v}.crate' for p, v in packages.items()}
        extracted = root / 'extracted'
        extracted.mkdir()
        receipts = []
        for p, archive in archives.items():
            with tarfile.open(archive) as bundle:
                bundle.extractall(extracted, filter='data')
            receipts.append({'package': p, 'version': packages[p], 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()})
        for profile in ('core', 'pg', 'messaging', 'all'):
            consumer = root / profile
            (consumer / 'src').mkdir(parents=True)
            manifest = '[package]\nname="ledger-artifact-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
            manifest += 'rss-ledger = { version="=0.1.0", default-features=false }\nrss-request-context="=0.1.0"\n'
            source = '''use rss_ledger::*;
pub fn verify() -> Result<(),Box<dyn std::error::Error>> {
 let a=Authenticator::new(KeyId::parse("key")?,vec![7;32])?;
 let ledger=LedgerId::new(rss_request_context::TenantId::parse("10000000-0000-4000-8000-000000000001")?,ChainId::parse("chain")?);
 let request=AppendRequest::new(ledger.clone(),RecordId::parse("r")?,vec![1])?;
 let entry=a.append(&request,None)?;
 assert_eq!(a.verify_chain(&ledger,&[entry])?.count(),1);
 Ok(())
}
#[test] fn artifact_protocol() -> Result<(),Box<dyn std::error::Error>> { verify() }
'''
            if profile != 'core':
                features = [] if profile == 'pg' else ['messaging']
                if profile == 'all':
                    features += ['integration']
                manifest += f'rss-ledger-postgres = {{ version="=0.1.0", default-features=false, features={json.dumps(features)} }}\n'
                source += '''pub async fn standalone<T:rss_ledger_postgres::Timer>(store:&rss_ledger_postgres::PgLedger,r:&AppendRequest,c:&rss_ledger_postgres::Control<'_,T>) {
 let _outcome=store.append(r,c).await;
 let _window=store.read_window(r.ledger(),Sequence::new(0),rss_ledger_postgres::ReadLimit::new(10).unwrap(),c).await;
}
pub fn migration()-> &'static str {rss_ledger_postgres::MIGRATION_SQL}
'''
            if profile in ('messaging', 'all'):
                manifest += 'rss-transactional-messaging-postgres="=0.1.0"\n'
                source += '''pub async fn borrowed(auth:std::sync::Arc<Authenticator>,tx:&mut rss_transactional_messaging_postgres::PgTransaction<'_>,r:&AppendRequest)->Result<(),rss_transactional_messaging_postgres::PgError> {
 rss_ledger_postgres::append_in(tx,auth,r).await?; Ok(())
}
'''
            manifest += '[patch.crates-io]\n'
            for p, v in sorted(packages.items()):
                manifest += f'{p} = {{ path={json.dumps(str(extracted / (p+"-"+v)))} }}\n'
            (consumer / 'Cargo.toml').write_text(manifest)
            (consumer / 'src/lib.rs').write_text(source)
            run(['cargo', 'test', '--offline', '--no-default-features'], consumer, env)
            resolved = json.loads(subprocess.check_output(['cargo', 'metadata', '--offline', '--format-version', '1'], cwd=consumer, env=env, timeout=60))
            for p in resolved['packages']:
                if p['source'] is None and not Path(p['manifest_path']).resolve().is_relative_to(root):
                    raise ValueError('consumer escaped artifact workspace')
            names = {p['name'] for p in resolved['packages']}
            if profile == 'core' and ('sqlx' in names or 'rss-transactional-messaging' in names):
                raise ValueError('core depends on provider or messaging')
            if profile == 'pg' and 'rss-transactional-messaging-postgres' in names:
                raise ValueError('standalone PG requires messaging runtime')
        print(json.dumps({'artifacts': receipts, 'profiles': ['core', 'pg', 'messaging', 'all']}, indent=2))


if __name__ == '__main__':
    main()
