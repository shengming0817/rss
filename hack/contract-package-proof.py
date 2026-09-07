#!/usr/bin/env python3
"""Run the same Contract public tests against isolated source or exact candidate artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'rss-contract'
SUITES = ('public_values', 'safe_semantics')


def candidate(directory, revision, version):
    rows = [line.split('\t') for line in (directory / 'packages.tsv').read_text().splitlines()]
    if not rows or any(len(row) != 3 or row[2] != revision for row in rows):
        raise ValueError('candidate revision mismatch')
    declared = {row[0]: row[1] for row in rows}
    if len(declared) != len(rows) or declared.get(PACKAGE) != version:
        raise ValueError('candidate package identity mismatch')
    hashes = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split()
        name = name.removeprefix('*')
        if Path(name).name != name or name in hashes or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('invalid archive identity')
        hashes[name] = digest
    archive = directory / f'{PACKAGE}-{version}.crate'
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if hashes.get(archive.name) != digest:
        raise ValueError('candidate archive checksum mismatch')
    return archive, digest


def check_resolution(facts, consumer, contract, version):
    expected = {
        'contract-consumer': ('0.0.0', (consumer / 'Cargo.toml').resolve()),
        PACKAGE: (version, (contract / 'Cargo.toml').resolve()),
    }
    packages = facts['packages']
    if len(packages) != len(expected) or {p['name'] for p in packages} != set(expected):
        raise ValueError('unexpected dependency closure')
    for package in packages:
        wanted_version, manifest = expected[package['name']]
        if (package['source'] is not None or package['version'] != wanted_version
                or Path(package['manifest_path']).resolve() != manifest):
            raise ValueError('consumer escaped exact package identity')
        for target in package['targets']:
            if not Path(target['src_path']).resolve().is_relative_to(manifest.parent):
                raise ValueError('target source escaped package')


def unpack_candidate(archive, extracted, version, revision):
    extracted.mkdir()
    extracted = extracted.resolve()
    with tarfile.open(archive) as bundle:
        bundle.extractall(extracted, filter='data')
    contract = extracted / f'{PACKAGE}-{version}'
    if contract.is_symlink() or not contract.resolve().is_relative_to(extracted):
        raise ValueError('unpacked package escaped artifact directory')
    origin = json.loads((contract / '.cargo_vcs_info.json').read_text())
    if (not isinstance(origin, dict) or origin.get('git', {}).get('sha1') != revision
            or origin['git'].get('dirty', False) is not False
            or origin.get('path_in_vcs') != 'crates/contract'):
        raise ValueError('embedded candidate origin mismatch')
    return contract.resolve()


def check_compiler_inputs(target, consumer, contract):
    roots = (consumer.resolve(), contract.resolve())
    depfiles = list((target / 'debug/deps').glob('*.d'))
    if not depfiles:
        raise ValueError('missing compiler input evidence')
    for depfile in depfiles:
        # rustc emits a phony Make rule for every transitive input, including include_str!.
        inputs = [line[:-1] for line in depfile.read_text().splitlines()
                  if line.endswith(':') and not line.startswith('#')]
        if not inputs:
            raise ValueError('empty compiler input evidence')
        for raw in inputs:
            path = Path(re.sub(r'\\(.)', r'\1', raw))
            path = (consumer / path).resolve()
            if not path.is_file() or not any(path.is_relative_to(root) for root in roots):
                raise ValueError(f'compiler input escaped consumer/artifact: {path}')


def test_count(output):
    count = sum(line.endswith(': test') for line in output.splitlines())
    if not count:
        raise ValueError('consumer discovered no tests')
    return count


def check_result(output, count):
    expected = f'test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
    if not any(line.startswith(expected) for line in output.splitlines()):
        raise ValueError('consumer did not run every discovered test')


def run(args, cwd, env):
    print(json.dumps({'command': args, 'cwd': str(cwd)}), file=sys.stderr, flush=True)
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=300)
    if 'metadata' not in args:
        print(result.stdout, file=sys.stderr, end='')
    print(result.stderr, file=sys.stderr, end='')
    result.check_returncode()
    return result.stdout


def consume(root, contract, version, env):
    manifest = tomllib.loads((contract / 'Cargo.toml').read_text())
    if manifest['package']['name'] != PACKAGE or manifest['package']['version'] != version:
        raise ValueError('unpacked package identity mismatch')
    consumer = root / 'consumer'
    (consumer / 'tests').mkdir(parents=True)
    # Keep the actual component scenarios as the only behavior owner.
    for suite in SUITES:
        source = (contract / 'tests' / f'{suite}.rs').resolve()
        if not source.is_relative_to(contract):
            raise ValueError('test source escaped package')
        (consumer / 'tests' / source.name).write_bytes(source.read_bytes())
    (consumer / 'Cargo.toml').write_text(
        '[package]\nname="contract-consumer"\nversion="0.0.0"\nedition="2024"\n'
        '[workspace]\n[dependencies]\n'
        f'{PACKAGE}={{version="={version}",default-features=false}}\n'
        f'[patch.crates-io]\n{PACKAGE}={{path={json.dumps(str(contract))}}}\n')
    run(['cargo', 'generate-lockfile', '--offline'], consumer, env)
    facts = json.loads(run(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], consumer, env))
    check_resolution(facts, consumer, contract, version)
    counts = {}
    for suite in SUITES:
        command = ['cargo', 'test', '--locked', '--offline', '--test', suite]
        run([*command, '--no-run'], consumer, env)
        check_compiler_inputs(Path(env['CARGO_TARGET_DIR']), consumer, contract)
        count = test_count(run([*command, '--', '--list', '--format', 'terse'], consumer, env))
        check_result(run([*command, '--', '--color', 'never'], consumer, env), count)
        counts[suite] = count
    return {'tests_passed': counts, 'lock_sha256': hashlib.sha256((consumer / 'Cargo.lock').read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--source', action='store_true')
    modes.add_argument('--artifacts', type=Path)
    parser.add_argument('--revision')
    args = parser.parse_args()
    if bool(args.artifacts) != bool(args.revision):
        parser.error('--artifacts requires --revision; --source does not accept it')
    revision = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if args.revision and args.revision != revision:
        raise ValueError('candidate revision does not match proof checkout')
    version = tomllib.loads((ROOT / 'crates/contract/Cargo.toml').read_text())['package']['version']
    toolchain = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    receipt = {'mode': 'source' if args.source else 'artifact', 'revision': revision, 'version': version,
               'package': PACKAGE, 'toolchain': toolchain}
    # Outside the checkout, with an empty Cargo home: no ancestor/user config, patches or runners.
    with tempfile.TemporaryDirectory(prefix='rss-contract-proof-') as temporary:
        root = Path(temporary).resolve()
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('CARGO_', 'RUSTC', 'RUSTDOC', 'RUSTFLAGS'))}
        env.update(CARGO_HOME=str(root / 'cargo-home'), CARGO_TARGET_DIR=str(root / 'target'),
                   RUSTUP_TOOLCHAIN=toolchain, CARGO_TERM_COLOR='never')
        if args.source:
            contract = ROOT / 'crates/contract'
        else:
            archive, digest = candidate(args.artifacts.resolve(), revision, version)
            contract = unpack_candidate(archive, root / 'extracted', version, revision)
            receipt['archive_sha256'] = digest
        receipt.update(consume(root, contract.resolve(), version, env))
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
