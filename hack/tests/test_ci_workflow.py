"""Execute the workflow finalizer under GitHub's shell behavior, including empty targets."""
import os
import re
import json
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
# Bound orchestration hangs without treating shared-host process startup as a 10-second SLO.
PROCESS_TIMEOUT = 60


class FinalizerTests(unittest.TestCase):
    def test_remote_matrix_and_final_gate_consume_selection(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('integration_groups: ${{ steps.select.outputs.integration_groups }}', workflow)
        integration = workflow.split('  integration:\n', 1)[1].split('  coverage:', 1)[0]
        self.assertIn('needs: [selection, build]', integration)
        self.assertIn('group: ${{ fromJSON(needs.selection.outputs.integration_groups) }}', integration)
        self.assertIn('max-parallel: 3', integration)
        # The two non-matrix partitions have intentionally different execution/cache contracts.
        self.assertRegex(workflow, r'(?s)  unit:.*?group: unit')
        self.assertRegex(workflow, r'(?s)  consumer:.*?part: consumer')
        gate = textwrap.dedent(workflow.split("          python3 - <<'PY'\n")[-1].rsplit('          PY', 1)[0])
        results = {name: {'result': 'success'} for name in ['selection', 'checks', 'semver', 'build', 'unit', 'consumer', 'integration', 'coverage']}
        results['selection']['outputs'] = {'active': 'true', 'coverage': 'true', 'semver': 'true'}
        for status in ['success', 'failure', 'cancelled', 'skipped']:
            results['integration']['result'] = status
            result = subprocess.run(['python3', '-c', gate], env=os.environ | {'RESULTS': json.dumps(results)}, capture_output=True)
            self.assertEqual(result.returncode == 0, status == 'success')

    def test_semver_required_and_skipped_gate(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        gate = textwrap.dedent(workflow.split("          python3 - <<'PY'\n")[-1].rsplit('          PY', 1)[0])
        for selected in ('true', 'false'):
            for state in ('success', 'failure', 'cancelled', 'skipped', None):
                results = {name: {'result': 'success'} for name in ('selection', 'checks', 'build', 'unit', 'consumer', 'integration', 'coverage')}
                results['selection']['outputs'] = {'active': 'true', 'coverage': 'true', 'semver': selected}
                if state: results['semver'] = {'result': state}
                result = subprocess.run(['python3', '-c', gate], env=os.environ | {'RESULTS': json.dumps(results)}, capture_output=True)
                self.assertEqual(result.returncode == 0, state == ('success' if selected == 'true' else 'skipped'))

    def test_save_summary_write_failure_is_optional_and_visible(self):
        workflow = (ROOT / '.github/workflows/ci-compile.yml').read_text()
        step = workflow.split('      - name: Record cache save outcomes\n', 1)[1]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            env = os.environ | dict.fromkeys(('CI_PART', 'DOWNLOAD_SAVE_OUTCOME', 'COMPILER_SAVE_OUTCOME',
                'DOWNLOAD_SAVE_KEY', 'COMPILER_SAVE_KEY'), 'success') | {'GITHUB_STEP_SUMMARY': directory}
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn('::warning::', result.stdout)

    def test_only_final_lcov_copy_upload_is_optional(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        uploads = re.split(r'(?m)^      - ', workflow)
        for step in uploads:
            if 'uses: actions/upload-artifact@' not in step: continue
            optional = 'name: coverage-report' in step
            self.assertEqual('continue-on-error: true' in step, optional)
            if not optional: self.assertIn('if-no-files-found: error', step)
        for name in ('ci-execute.yml', 'ci-compile.yml'):
            for step in re.split(r'(?m)^      - ', (ROOT / '.github/workflows' / name).read_text()):
                if 'uses: actions/upload-artifact@' in step:
                    self.assertNotIn('continue-on-error: true', step)
                    self.assertIn('if-no-files-found: error', step)

    def test_candidate_passes_explicit_policy_base(self):
        workflow = (ROOT / '.github/workflows/candidate-bundle.yml').read_text()
        release = workflow.split('  semver:\n', 1)[1].split('  candidate-package-proof:', 1)[0]
        self.assertIn('baseline: ${{ inputs.compatibility_base }}', release)
        self.assertIn('head: ${{ github.sha }}', release)
        self.assertIn('mode: release', release)

    def test_candidate_digest_corruption_blocks_before_optional_summary(self):
        workflow = (ROOT / '.github/workflows/candidate-bundle.yml').read_text()
        step = workflow.split('      - name: Verify package digest inventory before upload\n', 1)[1].split('      - name:', 1)[0]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'a-0.1.0.crate'
            package.write_bytes(b'package')
            (root / 'packages.tsv').write_text('a\t0.1.0\tsha\n')
            sums = root / 'SHA256SUMS'
            for digest, passed in ((hashlib.sha256(b'package').hexdigest(), True), ('0' * 64, False)):
                sums.write_text(digest + '  a-0.1.0.crate\n')
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script],
                    env=os.environ | {'RSS_PACKAGE_PROOF': directory, 'GITHUB_SHA': 'sha'}, capture_output=True)
                self.assertEqual(result.returncode == 0, passed)

    def test_all_rust_workflows_use_repository_toolchain_bootstrap(self):
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            workflow = '\n'.join(line for line in path.read_text().splitlines() if not line.lstrip().startswith('#'))
            if re.search(r'\b(cargo|rustup|rustc|make)\b', workflow):
                with self.subTest(workflow=path.name):
                    self.assertNotRegex(workflow, r'rustup (?:toolchain install|default) \d')
                    self.assertIn('python3 hack/ci-pipeline.py --install-toolchain', workflow)

    def test_empty_selection_and_failed_diagnostics_still_stop_server(self):
        workflow = (ROOT / '.github/workflows/ci-compile.yml').read_text()
        step = workflow.split('      - name: Record cache statistics and stop job server\n', 1)[1]
        body = step.split('        run: |\n', 1)[1].split('      - name:', 1)[0]
        script = textwrap.dedent(body)
        with tempfile.TemporaryDirectory(prefix='rss-finalize-') as temporary:
            root = Path(temporary).resolve()
            (root / 'rss-sccache').mkdir()
            binary = root / 'sccache'
            binary.write_text('#!/bin/sh\nif [ "$1" = --show-stats ]; then exit 1; fi\necho stopped > "$STOP_PROOF"\n')
            binary.chmod(0o755)
            env = os.environ | {'PATH': f'{root}:{os.environ["PATH"]}', 'RUNNER_TEMP': str(root),
                                'SCCACHE_DIR': str(root / 'rss-sccache'), 'CARGO_HOME': str(root / 'missing-home'),
                                'CARGO_TARGET_DIR': str(root / 'missing-target'), 'CI_PART': 'tests',
                                'GITHUB_STEP_SUMMARY': str(root / 'summary'), 'GITHUB_OUTPUT': str(root / 'outputs'),
                                'STOP_PROOF': str(root / 'stopped'), 'COLD_CACHE': 'true',
                                'CANDIDATE_SHA': 'a' * 40, 'BASELINE_SHA': 'b' * 40,
                                'EXECUTION_OUTCOME': 'failure', 'DOWNLOAD_OUTCOME': 'skipped',
                                'COMPILER_OUTCOME': 'skipped', 'DOWNLOAD_SAVE_KEY': 'download-cold',
                                'COMPILER_SAVE_KEY': 'compiler-cold'}
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], env=env,
                                    capture_output=True, text=True, timeout=PROCESS_TIMEOUT)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / 'stopped').exists())
            summary = (root / 'summary').read_text()
            self.assertIn('Cold cache: true', summary)
            self.assertIn('Candidate: ' + 'a' * 40, summary)
            self.assertIn('Baseline: ' + 'b' * 40, summary)
            self.assertIn('Cargo restore outcome: skipped; key: none', summary)
            self.assertIn('Compiler save candidate: compiler-cold', summary)
            self.assertIn('Execution: failure', summary)
            self.assertIn('Filesystem', summary)
            self.assertIn('missing-target', summary)
            self.assertIn('stopped=true', (root / 'outputs').read_text())
            self.assertIn('has_objects=false', (root / 'outputs').read_text())

    def test_save_receipts_distinguish_failure_success_and_skipped(self):
        workflow = (ROOT / '.github/workflows/ci-compile.yml').read_text()
        step = workflow.split('      - name: Record cache save outcomes\n', 1)[1]
        body = step.split('        run: |\n', 1)[1].split('\n  cargo:', 1)[0]
        script = textwrap.dedent(body)
        with tempfile.TemporaryDirectory(prefix='rss-save-summary-') as temporary:
            summary = Path(temporary) / 'summary'
            for download, compiler in [('failure', 'success'), ('skipped', 'skipped')]:
                env = os.environ | {'GITHUB_STEP_SUMMARY': str(summary), 'CI_PART': 'tests',
                                    'DOWNLOAD_SAVE_OUTCOME': download, 'COMPILER_SAVE_OUTCOME': compiler,
                                    'DOWNLOAD_SAVE_KEY': 'download-exact', 'COMPILER_SAVE_KEY': 'compiler-exact'}
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], env=env,
                                        capture_output=True, text=True, timeout=PROCESS_TIMEOUT)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = summary.read_text()
                self.assertIn(f'Cargo save action: {download}; key: download-exact', report)
                self.assertIn(f'Compiler save action: {compiler}; key: compiler-exact', report)


if __name__ == '__main__':
    unittest.main()
