"""Failure boundaries of the archive pipeline, without rebuilding the workspace."""
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

    def results(self):
        for group in pipeline.GROUPS:
            folder = self.root / 'results' / group
            folder.mkdir(parents=True)
            profile = folder / 'profiles/test.profraw'
            profile.parent.mkdir()
            profile.write_bytes(b'profile')
            pipeline.write(folder / 'result.json', {'group': group, 'manifest': pipeline.sha(self.bundle / 'manifest.json'),
                'exit': 0, 'tests': ['test'], 'profiles': {'test.profraw': pipeline.sha(profile)}})

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

    def test_all_groups_docs_and_report_run_after_test_failure(self):
        with patch.dict(os.environ, {'CI_PART': 'tests', 'CI_PLAN': ''}), \
             patch.object(pipeline, 'selection', return_value=self.plan), \
             patch.object(pipeline, 'run', return_value='sha'), \
             patch.object(pipeline, 'build', return_value=0), \
             patch.object(pipeline, 'execute', side_effect=[0, 0, 9, 0, 0]) as execute, \
             patch.object(pipeline, 'coverage', return_value=0) as report, \
             patch.object(pipeline, 'docs', return_value=0) as docs:
            self.assertEqual(pipeline.main(), 9)
            self.assertEqual([c.args[1] for c in execute.call_args_list], list(pipeline.GROUPS))
            report.assert_called_once()
            docs.assert_called_once()

    def test_archive_or_toolchain_mismatch_rejected_before_execution(self):
        with patch.object(pipeline, 'run', return_value='wrong-toolchain'):
            with self.assertRaisesRegex(ValueError, 'identity'): pipeline.load_build(self.plan)
        (self.bundle / 'tests.tar.zst').write_bytes(b'corrupted')
        with patch.object(pipeline, 'run', return_value='rustc'):
            with self.assertRaisesRegex(ValueError, 'corrupt'): pipeline.load_build(self.plan)


if __name__ == '__main__':
    unittest.main()
