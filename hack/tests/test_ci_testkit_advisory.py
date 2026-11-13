"""Synthetic scope expansion and stale-exception failures for #3183."""
import copy
from datetime import date, timedelta
import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('testkit_advisory', ROOT / 'crates/testkit/check-advisory.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / '.cargo').mkdir()
        names = {'astral-tokio-tar', 'testcontainers', 'testkit'}
        self.packages = [p for p in tomllib.loads((ROOT / 'Cargo.lock').read_text())['package'] if p['name'] in names]
        self.deny = (ROOT / 'deny.toml').read_text()
        self.audit = (ROOT / '.cargo/audit.toml').read_text()
        self.clock = date(2026, 11, 13)
        self.addCleanup(patch.stopall)
        patch.object(guard, '__file__', str(self.root / 'crates/testkit/check-advisory.py')).start()

    def verify(self, *, packages=None, deny=None, audit=None, today=None):
        entries = packages if packages is not None else self.packages
        text = '\n'.join('[[package]]\n' + '\n'.join(f'{key} = {json.dumps(value)}' for key, value in p.items()) for p in entries)
        (self.root / 'Cargo.lock').write_text(text)
        (self.root / 'deny.toml').write_text(deny if deny is not None else self.deny)
        (self.root / '.cargo/audit.toml').write_text(audit if audit is not None else self.audit)
        guard.check(self.root, audit=True, today=today or self.clock)

    def test_exact_chain_accepts_local_and_fixed_consumer(self):
        self.verify()
        packages = copy.deepcopy(self.packages)
        next(p for p in packages if p['name'] == 'testkit')['source'] = (
            'git+https://dev.azure.com/shengming0923/rss/_git/rss?rev=' + 'a' * 40 + '#' + 'a' * 40)
        with patch.object(guard, '__file__', '/owner/crates/testkit/check-advisory.py'):
            self.verify(packages=packages)
        self.verify(today=guard.EXPIRES - timedelta(days=1))

    def test_changed_or_additional_package_identity_is_rejected(self):
        for name in ('astral-tokio-tar', 'testcontainers'):
            for field, value in [('version', '99.0.0'), ('source', 'git+https://example.org/fork'), ('checksum', '0' * 64)]:
                with self.subTest(name=name, field=field):
                    packages = copy.deepcopy(self.packages)
                    next(p for p in packages if p['name'] == name)[field] = value
                    with self.assertRaisesRegex(ValueError, 'version/source/checksum'):
                        self.verify(packages=packages)
            with self.subTest(name=name, duplicate=True):
                packages = copy.deepcopy(self.packages)
                packages.append(copy.deepcopy(next(p for p in packages if p['name'] == name)))
                with self.assertRaisesRegex(ValueError, 'exactly one'):
                    self.verify(packages=packages)

    def test_new_parent_or_broken_chain_is_rejected(self):
        for child in ('astral-tokio-tar', 'testcontainers'):
            with self.subTest(child=child):
                with self.assertRaisesRegex(ValueError, 'only .* may introduce'):
                    self.verify(packages=self.packages + [{'name': 'unapproved', 'version': '1.0.0', 'dependencies': [child]}])
                packages = copy.deepcopy(self.packages)
                for p in packages:
                    p['dependencies'] = [d for d in p.get('dependencies', []) if d.split()[0] != child]
                with self.assertRaisesRegex(ValueError, 'only .* may introduce'):
                    self.verify(packages=packages)

    def test_removed_dependency_does_not_leave_silent_ignore(self):
        with self.assertRaisesRegex(ValueError, 'remove stale exception'):
            self.verify(packages=[p for p in self.packages if p['name'] != 'astral-tokio-tar'])

    def test_expiry_is_a_hard_utc_date_boundary(self):
        for today in (guard.EXPIRES, guard.EXPIRES + timedelta(days=1)):
            with self.subTest(today=today), self.assertRaisesRegex(ValueError, 'expired'):
                self.verify(today=today)

    def test_scanner_exceptions_remain_narrow_and_consistent(self):
        for deny in (self.deny.replace(guard.ADVISORY, 'RUSTSEC-2000-0000'),
                     self.deny.replace('[advisories]', '[advisories]\nunmaintained = "none"')):
            with self.subTest(deny=deny), self.assertRaises(ValueError):
                self.verify(deny=deny)
        with self.assertRaisesRegex(ValueError, 'exceptions must agree'):
            self.verify(audit='[advisories]\nignore = []\n')
        self.verify()


if __name__ == '__main__':
    unittest.main()
