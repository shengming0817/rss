"""Failure boundaries of the archive pipeline, without rebuilding the workspace."""
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('pipeline', Path(__file__).resolve().parents[1] / 'ci-pipeline.py')
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.addCleanup(patch.stopall)
        patch.object(pipeline, 'ARTIFACTS', self.root).start()
        self.plan = {'filter': 'all()', 'full': True, 'packages': [], 'reasons': ['explicit-full'], 'deep': True, 'coverage': True, 'sha': 'sha', 'base': 'base'}
        self.bundle = self.root / 'build'
        self.bundle.mkdir()
        (self.bundle / 'tests.tar.zst').write_bytes(b'archive')
        self.manifest = {'plan': self.plan, 'toolchain': 'rustc', 'archive': pipeline.sha(self.bundle / 'tests.tar.zst'),
                         'launcher': None, 'supplemental': {}, 'groups': {g: {'filter': 'all()', 'tests': ['test']} for g in pipeline.GROUPS}}
        pipeline.write(self.bundle / 'manifest.json', self.manifest)

    def test_new_group_reaches_remote_matrix_from_selection(self):
        output = self.root / 'github-output'
        with patch.dict(pipeline.GROUPS, {'extra-provider': 'package(=extra-integration)'}), \
             patch.dict(os.environ, {'CI_PART': 'select', 'GITHUB_OUTPUT': str(output)}, clear=True), \
             patch.object(pipeline, 'selection', return_value=self.plan), \
             patch.object(pipeline, 'semver_selection', return_value={'selected': False}), \
             patch.object(pipeline, 'run', return_value='sha'):
            self.assertEqual(pipeline.main(), 0)
        values = dict(line.split('=', 1) for line in output.read_text().splitlines())
        matrix = json.loads(values['integration_groups'])
        self.assertEqual(sorted(matrix + ['unit', 'consumer']), sorted([*pipeline.GROUPS, 'extra-provider']))
        self.assertEqual(len(matrix), len(set(matrix)))

    def test_toolchain_install_follows_changed_repository_file(self):
        (self.root / 'rust-toolchain.toml').write_text(
            '[toolchain]\nchannel="1.99.1"\nprofile="minimal"\ncomponents=["clippy", "llvm-tools-preview"]\n')
        with patch.object(pipeline, 'ROOT', self.root), patch.object(pipeline, 'run', return_value=0) as run:
            self.assertEqual(pipeline.install_toolchain(), 0)
        self.assertEqual(run.call_args_list[0].args[0], ['rustup', 'toolchain', 'install', '1.99.1', '--profile', 'minimal',
                                                '--component', 'clippy', '--component', 'llvm-tools-preview'])
        self.assertEqual(run.call_args_list[1].args[0], ['rustup', 'default', '1.99.1'])

    def results(self):
        for group in pipeline.GROUPS:
            folder = self.root / 'results' / group
            folder.mkdir(parents=True)
            profile = folder / 'profiles/test.profraw'
            profile.parent.mkdir()
            profile.write_bytes(b'profile')
            pipeline.write(folder / 'result.json', {'group': group, 'manifest': pipeline.sha(self.bundle / 'manifest.json'),
                'exit': 0, 'execution_error': None, 'profile_error': False, 'tests': ['test'], 'profiles': {'test.profraw': pipeline.sha(profile)}})

    def report(self):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            return 'rustc' if kwargs.get('capture') else 0
        with patch.object(pipeline, 'run', run):
            status = pipeline.coverage(self.plan)
        self.assertEqual(sum('report' in c for c in calls), 1)
        self.assertFalse(any('build' in c or 'run' in c or 'nextest' in c for c in calls))
        return status

    def test_explicit_filter_overrides_empty_affected_selection(self):
        with patch.dict(os.environ, {'CI_FULL': '0', 'CI_FILTER': 'test(only_this)'}), \
             patch.object(pipeline, 'run', side_effect=[json.dumps({'full': False, 'packages': [], 'reasons': []}), 'sha']):
            plan = pipeline.selection()
        self.assertTrue(pipeline.active(plan))
        self.assertFalse(plan['coverage'])
        self.assertFalse(plan['deep'])
        self.assertEqual(plan['filter'], 'test(only_this)')

    def test_explicit_filter_with_no_matches_fails(self):
        with patch.dict(os.environ, {'CARGO_TARGET_DIR': str(self.root / 'target')}), \
             patch.object(pipeline, 'run', return_value=''), \
             patch.object(pipeline, 'inventory', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'matched no runnable tests'):
                pipeline.build(self.plan | {'coverage': False, 'filter': 'test(typo)'})

    def test_consumer_prepares_downloads_and_records_fetch_failure(self):
        for fetched in (0, 17):
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                if kwargs.get('capture'): return 'rustc'
                return fetched if command[:2] == ['cargo', 'fetch'] else 0
            with self.subTest(fetched=fetched), patch.object(pipeline, 'run', run):
                self.assertEqual(pipeline.execute(self.plan, 'consumer'), fetched)
                fetch = calls.index(['cargo', 'fetch', '--locked'])
                tests = [i for i, c in enumerate(calls) if c[:3] == ['cargo', 'nextest', 'run']]
                self.assertEqual(len(tests), int(fetched == 0))
                if tests: self.assertGreater(tests[0], fetch)
                result = json.loads((self.root / 'results/consumer/result.json').read_text())
                self.assertEqual(result['exit'], fetched)

    def test_diagnostics_do_not_change_execution_verdict(self):
        for code in (0, 9):
            for fault in ('json', 'type', 'directory', 'summary'):
                with self.subTest(code=code, fault=fault):
                    def run(command, **kwargs):
                        if kwargs.get('capture'): return 'rustc'
                        metrics = Path(kwargs['env']['RSS_TEST_METRICS_DIR'])
                        metrics.mkdir(exist_ok=True)
                        if fault == 'directory':
                            metrics.rmdir()
                            metrics.write_text('not a directory')
                        else:
                            item = {'provider': 'all', 'phase': 'cleanup', 'outcome': 'success',
                                    'seconds': 1, 'attempts': 0, 'starts': 0}
                            if fault == 'type': item['seconds'] = True
                            (metrics / '123.jsonl').write_text('broken' if fault == 'json' else json.dumps(item) + '\n')
                        return code
                    with patch.object(pipeline, 'run', run), patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(self.root)}):
                        self.assertEqual(pipeline.execute(self.plan, 'unit'), code)
                    result = json.loads((self.root / 'results/unit/result.json').read_text())
                    self.assertEqual(result['exit'], code)
                    if fault != 'summary':
                        summary = json.loads((self.root / 'results/unit/fixture-summary.json').read_text())
                        self.assertEqual(summary['status'], 'incomplete')

    def test_attachment_phase_is_complete_without_inventing_container_starts(self):
        folder = self.root / 'fixture-metrics'
        folder.mkdir()
        rows = [dict(provider='postgres', phase='network-attach', outcome=outcome,
                     seconds=0.1, starts=0, attempts=0)
                for outcome in ('success', 'error', 'cancelled')]
        (folder / '123.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        pipeline.fixture_summary(self.root)
        summary = json.loads((self.root / 'fixture-summary.json').read_text())
        self.assertEqual(summary['status'], 'complete')
        self.assertEqual(summary['records'], 3)
        self.assertEqual({row['outcome'] for row in summary['totals']}, {'success', 'error', 'cancelled'})
        self.assertEqual(sum(row['starts'] for row in summary['totals']), 0)

    def test_profile_failure_keeps_test_exit_but_blocks_gate(self):
        def run(command, **kwargs):
            if kwargs.get('capture'): return 'rustc'
            profile = self.root / 'results/unit/profiles/unreadable.profraw'
            profile.symlink_to(self.root / 'missing')
            return 9
        with patch.object(pipeline, 'run', run):
            self.assertEqual(pipeline.execute(self.plan, 'unit'), 2)
        result = json.loads((self.root / 'results/unit/result.json').read_text())
        self.assertEqual(result['exit'], 9)
        self.assertTrue(result['profile_error'])

    def test_cancelled_execution_saves_evidence_and_propagates(self):
        def run(command, **kwargs):
            if kwargs.get('capture'): return 'rustc'
            raise KeyboardInterrupt()
        with patch.object(pipeline, 'run', run), self.assertRaises(KeyboardInterrupt):
            pipeline.execute(self.plan, 'unit')
        result = json.loads((self.root / 'results/unit/result.json').read_text())
        self.assertIsNone(result['exit'])
        self.assertEqual(result['execution_error'], 'cancelled')

    def test_execution_start_failure_keeps_formal_result(self):
        def run(command, **kwargs):
            if kwargs.get('capture'): return 'rustc'
            raise OSError('sensitive-command-text')
        with patch.object(pipeline, 'run', run):
            self.assertEqual(pipeline.execute(self.plan, 'unit'), 2)
        result = json.loads((self.root / 'results/unit/result.json').read_text())
        self.assertIsNone(result['exit'])
        self.assertEqual(result['execution_error'], 'test-run')
        self.assertNotIn('sensitive', json.dumps(result))

    def test_complete_and_failed_groups_still_generate_report(self):
        self.results()
        self.assertEqual(self.report(), 0)
        path = self.root / 'results/amqp/result.json'
        result = json.loads(path.read_text())
        result['exit'] = 9
        pipeline.write(path, result)
        self.assertNotEqual(self.report(), 0)

    def test_missing_corrupt_or_mismatched_group_cannot_pass(self):
        self.results()
        path = self.root / 'results/kafka/result.json'
        good = json.loads(path.read_text())
        for key, value in [('tests', []), ('manifest', 'other-sha'), ('profiles', {}), ('profiles', []), ('profiles', 'corrupt'), ('exit', '0'), ('profiles', {'../../escape.profraw': 'digest'})]:
            with self.subTest(key=key, value=value):
                pipeline.write(path, good | {key: value})
                self.assertNotEqual(self.report(), 0)
        pipeline.write(path, good)
        (path.parent / 'profiles/test.profraw').write_bytes(b'corrupt')
        self.assertNotEqual(self.report(), 0)
        path.unlink()
        self.assertNotEqual(self.report(), 0)

    def test_affected_does_not_claim_workspace_coverage(self):
        with patch.object(pipeline, 'run', side_effect=AssertionError('must not report')):
            self.assertEqual(pipeline.coverage(self.plan | {'full': False, 'coverage': False}), 0)

    def test_semver_cancellation_stops_entire_pipeline(self):
        with patch.dict(os.environ, {'CI_PART': 'all', 'CI_PLAN': ''}), \
             patch.object(pipeline, 'selection', return_value=self.plan), \
             patch.object(pipeline, 'semver_selection', return_value={'selected': True}), \
             patch.object(pipeline, 'semver_module') as module, \
             patch.object(pipeline, 'run', return_value='sha'), \
             patch.object(pipeline, 'checks') as checks, \
             patch.object(pipeline, 'build') as build:
            module.return_value.execute.return_value = 130
            with self.assertRaises(KeyboardInterrupt): pipeline.main()
            checks.assert_not_called()
            build.assert_not_called()

    def test_tests_all_and_docs_dispatch_and_preserve_failure(self):
        for part in ('tests', 'all', 'docs'):
            for failed in (None, 'build', 'execute', 'coverage', 'docs'):
                with self.subTest(part=part, failed=failed), ExitStack() as stack:
                    stack.enter_context(patch.dict(os.environ, {'CI_PART': part, 'CI_PLAN': ''}))
                    stack.enter_context(patch.object(pipeline, 'selection', return_value=self.plan))
                    stack.enter_context(patch.object(pipeline, 'run', return_value='sha'))
                    calls = []

                    def operation(name):
                        def invoke(*args):
                            calls.append((name, args))
                            return 9 if name == failed else 0
                        return invoke

                    for name in ('semver', 'checks', 'build', 'execute', 'coverage', 'docs'):
                        stack.enter_context(patch.object(pipeline, name, side_effect=operation(name)))
                    status = pipeline.main()
                    expected = ['semver', 'checks'] if part == 'all' else []
                    if part != 'docs':
                        expected.append('build')
                        if failed != 'build':
                            expected += ['execute'] * len(pipeline.GROUPS) + ['coverage']
                    if part in ('all', 'docs'):
                        expected.append('docs')
                    self.assertEqual([name for name, _ in calls], expected)
                    self.assertEqual(status, 9 if failed in expected else 0)
                    groups = [args[1] for name, args in calls if name == 'execute']
                    self.assertEqual(groups, list(pipeline.GROUPS) if 'execute' in expected else [])

    def test_empty_selection_skips_tests_and_docs(self):
        for part in ('tests', 'all', 'docs'):
            with self.subTest(part=part), ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, {'CI_PART': part, 'CI_PLAN': ''}))
                stack.enter_context(patch.object(pipeline, 'selection',
                                                return_value=self.plan | {'full': False, 'packages': []}))
                stack.enter_context(patch.object(pipeline, 'run', return_value='sha'))
                checks = stack.enter_context(patch.object(pipeline, 'checks', return_value=0))
                semver = stack.enter_context(patch.object(pipeline, 'semver', return_value=0))
                for name in ('build', 'execute', 'coverage', 'docs'):
                    stack.enter_context(patch.object(pipeline, name, side_effect=AssertionError(name)))
                self.assertEqual(pipeline.main(), 0)
                self.assertEqual(checks.call_count, int(part == 'all'))
                self.assertEqual(semver.call_count, int(part == 'all'))

    def test_archive_or_toolchain_mismatch_rejected_before_execution(self):
        with patch.object(pipeline, 'run', return_value='wrong-toolchain'):
            with self.assertRaisesRegex(ValueError, 'identity'): pipeline.load_build(self.plan)
        (self.bundle / 'tests.tar.zst').write_bytes(b'corrupted')
        with patch.object(pipeline, 'run', return_value='rustc'):
            with self.assertRaisesRegex(ValueError, 'corrupt'): pipeline.load_build(self.plan)


if __name__ == '__main__':
    unittest.main()
