"""Real Rust/sccache integration; no network or workspace build required."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which('sccache'), 'optional local sccache is not installed')
class CacheProof(unittest.TestCase):
    def test_hits_invalidation_coverage_and_server_does_not_hold_slot(self):
        with tempfile.TemporaryDirectory(prefix='rss-cache-', dir='/tmp') as temporary:
            root = Path(temporary)
            work = root / 'work'
            work.mkdir()
            (work / 'src').mkdir()
            (work / 'Cargo.toml').write_text('[package]\nname="rss-cache-proof"\nversion="0.0.0"\nedition="2021"\n')
            source = work / 'src/lib.rs'
            source.write_text('pub fn value() -> u8 { 1 }')
            env = os.environ.copy()
            for key in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER',
                        'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTFLAGS',
                        'CARGO_TARGET_DIR', 'SCCACHE_CACHE_SIZE'):
                env.pop(key, None)
            env.update(RSS_COMPILER_CACHE='on', RSS_TARGET_POOL_N='1',
                       RSS_TARGET_POOL_ROOT=str(root / 'pool'), SCCACHE_DIR=str(root / 'objects'),
                       SCCACHE_SERVER_UDS=str(root / 'server.sock'))
            target = root / 'pool/slot-0'
            def build(**overrides):
                result = subprocess.run([sys.executable, str(ROOT / 'hack/ci-run.py'), '--',
                                         'cargo', 'build', '--offline'], cwd=work, env=env | overrides,
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                raw = subprocess.check_output(['sccache', '--show-stats', '--stats-format', 'json'], env=env)
                stats = json.loads(raw)['stats']
                return (sum(stats['cache_hits']['counts'].values()),
                        sum(stats['cache_misses']['counts'].values()), stats['requests_not_cacheable'])
            try:
                cold = build()
                self.assertGreater(cold[1], 0)
                shutil.rmtree(target)
                hot = build()
                self.assertGreater(hot[0], cold[0])
                source.write_text('pub fn value() -> u8 { 2 }')
                changed = build()
                self.assertGreater(changed[1], hot[1])
                coverage = build(RUSTFLAGS='-C instrument-coverage')
                self.assertEqual(coverage[0], changed[0])
                self.assertGreater(coverage[1] + coverage[2], changed[1] + changed[2])
                self.assertGreaterEqual(hot[1], cold[1])
                self.assertGreaterEqual(changed[0], hot[0])
                shutil.rmtree(target)
                coverage_hot = build(RUSTFLAGS='-C instrument-coverage')
                self.assertGreater(sum(coverage_hot), sum(coverage))
                other = root / 'other'
                other.mkdir()
                result = subprocess.run([sys.executable, str(ROOT / 'hack/ci-run.py'), '--',
                                         sys.executable, '-c', 'pass'], cwd=other, env=env,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                print(f'sccache proof cold={cold} hot={hot} changed={changed} coverage={coverage} coverage-hot={coverage_hot}')
            finally:
                subprocess.run(['sccache', '--stop-server'], env=env, capture_output=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
