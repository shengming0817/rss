#!/usr/bin/env python3
"""Bound #3183's temporary risk acceptance in RSS and fixed testkit consumers.

INVARIANT: TESTKIT-ADVISORY-3183 (Medium; Make checks/audit).
Remove this checker and both scanner exceptions when a maintained dependency
replaces astral-tokio-tar. No other advisory is exempted by this policy.
ref: EmbarkStudios/cargo-deny 0.19.9 src/advisories/cfg.rs (IgnoreId).
"""
import argparse
from datetime import date, datetime, timezone
from pathlib import Path
import re
import sys
import tomllib

ADVISORY = 'RUSTSEC-2026-0440'
EXPIRES = date(2026, 12, 13)
REASON = ('#3183: RSS testkit owns temporary unmaintained risk; expires 2026-12-13 UTC; '
          'revoke when upstream #1007 is resolved.')
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
PACKAGES = {
    'astral-tokio-tar': ('0.6.4', 'b18457efd137254e016bbde5e1d88df61c4e1a5ae2223746e56123bac6af2463'),
    'testcontainers': ('0.27.3', 'bfd5785b5483672915ed5fe3cddf9f546802779fc1eceff0a6fb7321fac81c1e'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check(root, *, audit=False, today=None):
    today = today or datetime.now(timezone.utc).date()
    require(today < EXPIRES, f'#3183 exception expired at {EXPIRES} 00:00 UTC; re-evaluate upstream #1007')
    packages = tomllib.loads((root / 'Cargo.lock').read_text())['package']
    selected = {}
    for name, (version, checksum) in PACKAGES.items():
        matches = [p for p in packages if p['name'] == name]
        require(len(matches) == 1, f'{name}: expected exactly one approved package; remove stale exception if absent')
        package = matches[0]
        require((package['version'], package.get('source'), package.get('checksum')) ==
                (version, REGISTRY, checksum), f'{name}: version/source/checksum exceeds #3183 acceptance')
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
    for child, parent in [('astral-tokio-tar', 'testcontainers'), ('testcontainers', 'testkit')]:
        parents = [p for p in packages if any(d.split()[0] == child for d in p.get('dependencies', []))]
        require(parents == [selected[parent]], f'{child}: only {parent} may introduce this dependency')
    config = tomllib.loads((root / 'deny.toml').read_text())['advisories']
    require(config.get('ignore') == [{'id': ADVISORY, 'reason': REASON}], 'cargo-deny must exempt only #3183 with its risk reason')
    require(config.get('unmaintained', 'all') == 'all', 'other unmaintained dependencies must remain checked')
    audit_path = root / '.cargo/audit.toml'
    if audit or audit_path.exists():
        config = tomllib.loads(audit_path.read_text())['advisories']
        require(config.get('ignore') == [ADVISORY], 'cargo-audit and cargo-deny exceptions must agree')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--audit', action='store_true', help='require the cargo-audit configuration too')
    args = parser.parse_args()
    try:
        check(args.root, audit=args.audit)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'#3183 advisory acceptance: {error}', file=sys.stderr)
        return 1
    print(f'#3183: exact testkit dependency exception valid until {EXPIRES} 00:00 UTC')
    return 0


if __name__ == '__main__':
    sys.exit(main())
