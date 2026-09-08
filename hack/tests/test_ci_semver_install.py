"""Real tar/checksum install, with only network and backoff replaced."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
# Bound orchestration hangs without treating shared-host process startup as a 10-second SLO.
PROCESS_TIMEOUT = 60


class InstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.payload = self.root / 'valid.tar.gz'
        with tarfile.open(self.payload, 'w:gz') as archive:
            data = b'#!/bin/sh\necho cargo-semver-checks 0.49.0\n'
            info = tarfile.TarInfo('cargo-semver-checks')
            info.size, info.mode = len(data), 0o755
            archive.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256(self.payload.read_bytes()).hexdigest()
        script = (ROOT / 'hack/semver-install.sh').read_text()
        tool = (ROOT / 'hack/ci-semver.py').read_text().replace(
            '72f6834d75d28a66e02c9fd6a230ce901bb30eee6067b85867a97445df040e4a', digest)
        (self.root / 'ci-semver.py').write_text(tool)
        self.script = self.root / 'install.sh'
        self.script.write_text(script)
        self.bin = self.root / 'fake-bin'
        self.bin.mkdir()
        (self.bin / 'curl').write_text('''#!/usr/bin/env python3
import os, pathlib, shutil, sys
counter = pathlib.Path(os.environ['COUNTER'])
n = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(n))
if n <= int(os.environ.get('FAIL_DOWNLOADS', '0')): sys.exit(35)
out = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
if os.environ.get('CORRUPT') == '1': out.write_bytes(b'corrupt')
else: shutil.copyfile(os.environ['PAYLOAD'], out)
print('http=200 redirects=1 seconds=0.01')
''')
        (self.bin / 'sleep').write_text('#!/bin/sh\nexit 0\n')
        for path in self.bin.iterdir(): path.chmod(0o755)
        self.archive = self.root / 'cache/archive.tar.gz'
        self.counter = self.root / 'counter'
        self.env = os.environ | {'PATH': f'{self.bin}:{os.environ["PATH"]}', 'PAYLOAD': str(self.payload),
            'COUNTER': str(self.counter), 'SEMVER_ARCHIVE': str(self.archive),
            'SEMVER_BIN_DIR': str(self.root / 'installed'), 'GITHUB_OUTPUT': str(self.root / 'output'), 'GITHUB_PATH': str(self.root / 'path')}

    def run_install(self, **env):
        return subprocess.run(['bash', str(self.script)], env=self.env | env, capture_output=True, text=True, timeout=PROCESS_TIMEOUT)

    def test_reset_retries_then_installs_and_cache_avoids_network(self):
        result = self.run_install(FAIL_DOWNLOADS='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.counter.read_text(), '2')
        self.assertIn('exit=35', result.stdout)
        result = self.run_install(FAIL_DOWNLOADS='99')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.counter.read_text(), '2')
        self.assertIn('source=cache', (self.root / 'output').read_text())

    def test_corrupt_cache_is_replaced_and_verified(self):
        self.archive.parent.mkdir()
        self.archive.write_bytes(b'broken')
        self.assertEqual(self.run_install().returncode, 0)
        self.assertEqual(self.archive.read_bytes(), self.payload.read_bytes())

    def test_persistent_failure_and_bad_download_never_install(self):
        for env in ({'FAIL_DOWNLOADS': '99'}, {'CORRUPT': '1'}):
            self.counter.unlink(missing_ok=True)
            result = self.run_install(**env)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.counter.read_text(), '4')
            self.assertFalse(self.archive.exists())
            self.assertFalse((self.root / 'installed/cargo-semver-checks').exists())
            self.assertFalse((self.root / 'output').exists())


if __name__ == '__main__': unittest.main()
