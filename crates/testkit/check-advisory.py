#!/usr/bin/env python3
"""Bound #3183/#3184 risk acceptance in RSS and fixed RSS consumers.

INVARIANT: TESTKIT-ADVISORY-3183 (Medium; Make checks/audit).
Remove each exception when its maintained replacement is adopted; remove this
checker when both have exited. SQLite acceptance covers inactive lock entries only.
ref: EmbarkStudios/cargo-deny 0.19.9 src/advisories/cfg.rs (IgnoreId).
"""
import argparse
from datetime import date, datetime, timezone
from pathlib import Path
import re
import subprocess
import sys
import tomllib

EXPIRES = date(2026, 12, 13)
EXCEPTIONS = [
    {'id': 'RUSTSEC-2026-0440', 'reason':
     '#3183: RSS testkit owns temporary unmaintained risk; expires 2026-12-13 UTC; revoke when upstream #1007 is resolved.'},
    {'id': 'RUSTSEC-2026-0459', 'reason':
     '#3184: RSS dependency owner accepts inactive SQLx SQLite lock entries only; expires 2026-12-13 UTC; revoke on activation or a compatible SQLx fix.'},
]
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
PACKAGES = {
    'astral-tokio-tar': ('0.6.4', 'b18457efd137254e016bbde5e1d88df61c4e1a5ae2223746e56123bac6af2463'),
    'testcontainers': ('0.27.3', 'bfd5785b5483672915ed5fe3cddf9f546802779fc1eceff0a6fb7321fac81c1e'),
    'libsqlite3-sys': ('0.37.0', 'b1f111c8c41e7c61a49cd34e44c7619462967221a6443b0ec299e0ac30cfb9b1'),
    'sqlx-sqlite': ('0.9.0', '488e99c397a62007e4229aec669a179816339afc6d2620ca6fa420dbee2e982c'),
    'sqlx': ('0.9.0', '378620ccc25c62c89d8be1c819e76a88d59bdcc3304733330788948e619bfd71'),
    'sqlx-macros': ('0.9.0', 'bd2b84f2bc39a5705ef27ec785a11c934a41bbd4a24941e257927cddc26b60bf'),
    'sqlx-macros-core': ('0.9.0', 'fb8d96de5fdc85a5c4ec813432b523ec637e80ba98f046555f75f7908ddac7c3'),
}
PARENTS = {
    'astral-tokio-tar': ('testcontainers',), 'testcontainers': ('testkit',),
    'libsqlite3-sys': ('sqlx-sqlite',), 'sqlx-sqlite': ('sqlx', 'sqlx-macros-core'),
    'sqlx-macros-core': ('sqlx-macros',), 'sqlx-macros': ('sqlx',),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def active_packages(root):
    # Cargo metadata can retain weak optional edges. Cargo tree reports the
    # actually enabled normal/build/dev graph, across all workspace members/targets.
    output = subprocess.check_output(
        ['cargo', 'tree', '--locked', '--workspace', '--all-features', '--target', 'all',
         '--edges', 'normal,build,dev', '--prefix', 'none', '--format', '{p}'],
        cwd=root, text=True)
    return {line.split()[0] for line in output.splitlines() if line.strip()}


def check(root, *, audit=False, today=None):
    today = today or datetime.now(timezone.utc).date()
    require(today < EXPIRES, f'#3183/#3184 exceptions expired at {EXPIRES} 00:00 UTC; re-evaluate upstream fixes')
    packages = tomllib.loads((root / 'Cargo.lock').read_text())['package']
    selected = {}
    for name, (version, checksum) in PACKAGES.items():
        matches = [p for p in packages if p['name'] == name]
        require(len(matches) == 1, f'{name}: expected exactly one approved package; remove stale exception if absent')
        package = matches[0]
        require((package['version'], package.get('source'), package.get('checksum')) ==
                (version, REGISTRY, checksum), f'{name}: version/source/checksum exceeds approved acceptance')
        selected[name] = package
    roots = [p for p in packages if p['name'] == 'testkit']
    require(len(roots) == 1 and roots[0]['version'] == '0.0.0', 'expected the single RSS testkit root')
    source = roots[0].get('source')
    if root.resolve() == Path(__file__).resolve().parents[2]:
        require(source is None, 'RSS testkit must be the local workspace package')
    else:
        require(isinstance(source, str) and re.fullmatch(
            r'git\+https://dev\.azure\.com/shengming0923/rss/_git/rss\?rev=([0-9a-f]{40})#\1', source),
            'consumer testkit must use a fixed RSS commit')
    selected['testkit'] = roots[0]
    for child, allowed in PARENTS.items():
        parents = [p for p in packages if any(d.split()[0] == child for d in p.get('dependencies', []))]
        require(parents == [selected[parent] for parent in allowed], f'{child}: only {allowed} may introduce this dependency')
    active = active_packages(root)
    require({'sqlx', 'testkit'}.issubset(active), 'Cargo graph must include the SQLx and testkit roots')
    require(not {'libsqlite3-sys', 'sqlx-sqlite'} & active, '#3184 accepts inactive SQLite lock entries only; SQLite was enabled')
    config = tomllib.loads((root / 'deny.toml').read_text())['advisories']
    require(config.get('ignore') == EXCEPTIONS, 'cargo-deny must exempt only #3183/#3184 with their risk reasons')
    require(config.get('unmaintained', 'all') == 'all', 'other unmaintained dependencies must remain checked')
    audit_path = root / '.cargo/audit.toml'
    if audit or audit_path.exists():
        config = tomllib.loads(audit_path.read_text())['advisories']
        require(config.get('ignore') == [entry['id'] for entry in EXCEPTIONS], 'cargo-audit and cargo-deny exceptions must agree')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--audit', action='store_true', help='require the cargo-audit configuration too')
    args = parser.parse_args()
    try:
        check(args.root, audit=args.audit)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f'#3183/#3184 advisory acceptance: {error}', file=sys.stderr)
        return 1
    print(f'#3183/#3184: exact dependency exceptions valid until {EXPIRES} 00:00 UTC; SQLite inactive')
    return 0


if __name__ == '__main__':
    sys.exit(main())
