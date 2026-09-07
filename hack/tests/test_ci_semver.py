"""SemVer selection and source identity, using small real Git repositories."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('semver', ROOT / 'hack/ci-semver.py')
semver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(semver)


class SemverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.com')
        self.manifest('uncommitted')
        (self.root / '.gitignore').write_text('/target/\n/proof/\n')
        self.commit()
        self.base = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(self.root), *args], text=True).strip()

    def commit(self):
        self.git('add', 'Cargo.toml', 'a', '.gitignore')
        self.git('commit', '-qm', 'fixture')

    def manifest(self, status, baseline=None):
        compatibility = f'status = "{status}", issue = 2315'
        if baseline: compatibility += f', baseline-rev = "{baseline}"'
        (self.root / 'Cargo.toml').write_text('[workspace]\nmembers=["a"]\n[workspace.metadata.release-surface]\npackages=[{package="a", compatibility={' + compatibility + '}}]\n')
        (self.root / 'a/src').mkdir(parents=True, exist_ok=True)
        (self.root / 'a/Cargo.toml').write_text('[package]\nname="a"\nversion="0.1.0"\nedition="2021"\n[features]\ndefault=[]\nextra=[]\n')
        (self.root / 'a/src/lib.rs').write_text('pub fn original() {}\n')

    def select(self, **kwargs):
        return semver.select(self.root, self.base, 'HEAD', {'full': True, 'packages': []}, **kwargs)

    def test_explicit_empty_protection_skips(self):
        result = self.select()
        self.assertFalse(result['selected'])
        self.assertEqual(result['reason'], 'no-protected-packages')

    def test_unknown_identity_is_not_experimental(self):
        self.manifest('unknown')
        self.commit()
        with self.assertRaises(ValueError): self.select()

    def test_frozen_selection_and_unrelated_skip(self):
        self.manifest('frozen', self.base)
        self.commit()
        self.assertTrue(self.select()['selected'])
        self.assertFalse(semver.select(self.root, self.base, 'HEAD', {'full': False, 'packages': []})['selected'])

    def test_declared_head_must_match_checkout(self):
        self.manifest('frozen', self.base)
        self.commit()
        with self.assertRaises(ValueError):
            semver.select(self.root, self.base, self.base, {'full': True, 'packages': []})

    def test_explicit_comparison_keeps_equal_baseline(self):
        result = self.select(requested=['a'], comparison=True)
        self.assertEqual(result['checks'][0]['baseline'], {'rev': self.base})
        self.assertEqual(result['checks'][0]['configurations'], ['default', 'all'])

    def test_protection_removal_cannot_skip(self):
        self.manifest('frozen', self.base)
        self.commit()
        self.base = self.git('rev-parse', 'HEAD')
        self.manifest('uncommitted')
        self.commit()
        with self.assertRaises(ValueError): self.select()

    def test_missing_metadata_package_fails(self):
        with patch.object(semver, 'cargo_metadata', return_value={'packages': []}):
            with self.assertRaises(ValueError): self.select()

    def test_default_all_deduplication_needs_both_sides(self):
        (self.root / 'a/Cargo.toml').write_text('[package]\nname="a"\nversion="0.1.0"\nedition="2021"\n')
        self.commit()
        self.base = self.git('rev-parse', 'HEAD')
        self.assertEqual(self.select(requested=['a'], comparison=True)['checks'][0]['configurations'], ['default'])
        self.manifest('uncommitted')
        self.commit()
        self.assertEqual(self.select(requested=['a'], comparison=True)['checks'][0]['configurations'], ['default', 'all'])

    def test_exact_exit_allows_intentional_retirement_only_for_matching_base(self):
        self.manifest('frozen', self.base)
        self.commit()
        self.base = self.git('rev-parse', 'HEAD')
        self.manifest('uncommitted')
        with (self.root / 'Cargo.toml').open('a') as stream:
            stream.write('[[workspace.metadata.semver-exits]]\npackage="a"\nbaseline-rev="' + self.base + '"\nissue=2315\n')
        self.commit()
        self.assertFalse(self.select()['selected'])
        self.base = self.git('rev-parse', 'HEAD~1~1')
        # Changing the old frozen decision requires its exact comparison base.
        self.base = self.git('rev-parse', 'HEAD~1')
        manifest = self.root / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace(self.base, '0' * 40))
        self.commit()
        with self.assertRaises(ValueError): self.select()

    def test_execution_collects_configuration_failures_and_binds_result(self):
        plan = self.select(requested=['a'], comparison=True)
        real_run = subprocess.run
        def run(command, **kwargs):
            if command == ['cargo', 'semver-checks', '--version']:
                return subprocess.CompletedProcess(command, 0, stdout='cargo-semver-checks 0.49.0\n')
            if command[:2] == ['cargo', 'semver-checks']:
                return subprocess.CompletedProcess(command, 100 if '--default-features' in command else 0)
            return real_run(command, **kwargs)
        with patch.object(semver.subprocess, 'run', run):
            self.assertEqual(semver.execute(self.root, plan, self.root / 'result'), 1)
        import json
        result = json.loads((self.root / 'result/result.json').read_text())
        self.assertEqual([r['exit'] for r in result['results']], [100, 0])
        self.assertEqual(result['plan'], plan)

    def test_breaking_authorization_binds_package_and_exact_baseline(self):
        self.manifest('frozen', self.base)
        with (self.root / 'Cargo.toml').open('a') as stream:
            stream.write('[[workspace.metadata.semver-breaking-authorizations]]\npackage="a"\nbaseline-rev="' + self.base + '"\nissue=2315\n')
        self.commit()
        self.assertEqual(self.select()['checks'][0]['major_authorization'], 2315)
        current = self.root / 'Cargo.toml'
        current.write_text(current.read_text().replace('baseline-rev="' + self.base + '"', 'baseline-rev="' + '0' * 40 + '"'))
        self.commit()
        self.assertIsNone(self.select()['checks'][0]['major_authorization'])

    def test_unsupported_macro_not_counted_as_semver_pass(self):
        package = self.root / 'a/Cargo.toml'
        package.write_text(package.read_text() + '[lib]\nproc-macro=true\n')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            self.select(requested=['a'], comparison=True)

    def test_wrong_local_tool_version_is_a_formal_failure(self):
        plan = self.select(requested=['a'], comparison=True)
        real_run = subprocess.run
        def run(command, **kwargs):
            if command == ['cargo', 'semver-checks', '--version']:
                return subprocess.CompletedProcess(command, 0, stdout='cargo-semver-checks 0.48.0\n')
            if command[:2] == ['cargo', 'semver-checks']:
                self.fail('wrong version must never run API comparison')
            return real_run(command, **kwargs)
        with patch.object(semver.subprocess, 'run', run):
            self.assertEqual(semver.execute(self.root, plan, self.root / 'result'), 1)
        import json
        result = json.loads((self.root / 'result/result.json').read_text())
        self.assertTrue(all(r['failure'] == 'tool-version' for r in result['results']))

    def test_release_uses_independent_policy_base_and_rejects_rebinding(self):
        spec = importlib.util.spec_from_file_location('pipeline_release', ROOT / 'hack/ci-pipeline.py')
        pipeline = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pipeline)
        self.manifest('frozen', self.base)
        self.commit()
        self.base = self.git('rev-parse', 'HEAD')
        (self.root / 'a/src/lib.rs').write_text('pub fn added() {}\n')
        self.commit()
        plan = {'base': self.base, 'full': True, 'packages': []}
        with patch.object(pipeline, 'ROOT', self.root), patch.dict(os.environ, {'CI_SEMVER_MODE': 'release', 'CI_HEAD': 'HEAD'}):
            self.assertTrue(pipeline.semver_selection(plan)['selected'])
            with self.assertRaisesRegex(ValueError, 'independent'):
                pipeline.semver_selection(plan | {'base': 'HEAD'})
            self.manifest('frozen', self.base)
            self.commit()
            with self.assertRaisesRegex(ValueError, 'commitment changed'):
                pipeline.semver_selection(plan)

    def test_full_modes_cannot_be_narrowed_by_package_input(self):
        spec = importlib.util.spec_from_file_location('pipeline_modes', ROOT / 'hack/ci-pipeline.py')
        pipeline = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pipeline)
        for mode, full in [('affected', '0'), ('all', '0'), ('release', '0'), ('compare', '1')]:
            with self.subTest(mode=mode, full=full), patch.object(pipeline, 'ROOT', self.root), \
                 patch.dict(os.environ, {'CI_SEMVER_MODE': mode, 'CI_SEMVER_FULL': full, 'CI_SEMVER_PACKAGES': 'a', 'CI_HEAD': 'HEAD'}):
                with self.assertRaises(ValueError):
                    pipeline.semver_selection({'base': self.base, 'full': True, 'packages': []})
        with self.assertRaises(ValueError): self.select(requested=['a'], full=True)

    def test_cancellation_persists_result_without_launching_more_checks(self):
        plan = self.select(requested=['a'], comparison=True)
        real_run = subprocess.run
        calls = []
        def run(command, **kwargs):
            if command == ['cargo', 'semver-checks', '--version']:
                return subprocess.CompletedProcess(command, 0, stdout='cargo-semver-checks 0.49.0\n')
            if command[:2] == ['cargo', 'semver-checks']:
                calls.append(command)
                raise KeyboardInterrupt()
            return real_run(command, **kwargs)
        with patch.object(semver.subprocess, 'run', run):
            self.assertEqual(semver.execute(self.root, plan, self.root / 'result'), 130)
        self.assertEqual(len(calls), 1)
        import json
        result = json.loads((self.root / 'result/result.json').read_text())
        self.assertEqual(result['exit'], 130)
        self.assertEqual([r['failure'] for r in result['results']], ['cancelled', 'not-run'])

    @unittest.skipUnless(os.environ.get('RSS_SEMVER_REAL') == '1', 'explicit Linux SemVer proof')
    def test_real_default_breaking_is_not_hidden_by_all_features(self):
        (self.root / 'a/src/lib.rs').write_text('#[cfg(not(feature="extra"))] pub fn original() {}\n')
        self.commit()
        self.base = self.git('rev-parse', 'HEAD')
        import shutil
        (self.root / 'hack').mkdir()
        shutil.copy(ROOT / 'Makefile', self.root)
        for name in ('ci-pipeline.py', 'ci-impact.py', 'ci-run.py', 'ci-semver.py'):
            shutil.copy(ROOT / 'hack' / name, self.root / 'hack')
        self.git('add', 'Makefile', 'hack')
        self.git('commit', '-qm', 'canonical Make entry')
        env = os.environ | {'RSS_TARGET_POOL_N': 'off', 'RSS_COMPILER_CACHE': 'off',
            'CI_BASE': self.base, 'CI_HEAD': 'HEAD', 'CI_SEMVER_MODE': 'compare', 'CI_SEMVER_PACKAGES': 'a',
            'CI_PLAN': '', 'CI_FILTER': 'all()', 'CI_ARTIFACTS': str(self.root / 'proof')}
        command = ['make', 'ci', 'CI_PART=semver']
        self.assertEqual(subprocess.run(command, cwd=self.root, env=env).returncode, 0)
        (self.root / 'a/src/lib.rs').write_text('pub fn replacement() {}\n')
        self.commit()
        self.assertNotEqual(subprocess.run(command, cwd=self.root, env=env).returncode, 0)
        import json
        result = json.loads((self.root / 'proof/semver/result.json').read_text())
        self.assertEqual([r['exit'] for r in result['results']], [100, 0])


if __name__ == '__main__': unittest.main()
