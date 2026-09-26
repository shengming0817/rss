#!/usr/bin/env python3
"""Offline behavioral tests for forge.sh pr-set-status (no remote writes)."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEAD = 'a' * 40
BACKEND = r'''
_azure_pr_refs() {
    if [ "${DRIFT:-}" = before ] || { [ "${DRIFT:-}" = after ] && [ -f "$STATE_DIR/mutated" ]; }; then
        printf '{"headSha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'
    else
        printf '{"headSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    fi
}
_azure_pr_state() {
    [ "${FAIL_READ:-}" != yes ] || return 1
    cat "$STATE_DIR/state.json"
}
_azure_pr_remove_label() {
    echo remove >> "$STATE_DIR/calls"
    [ "${FAIL_REMOVE:-}" != "$2" ] || return 1
    [ "${IGNORE_REMOVE:-}" != yes ] || return 0
    jq --arg label "$2" '.labels -= [$label]' "$STATE_DIR/state.json" > "$STATE_DIR/next.json"
    mv "$STATE_DIR/next.json" "$STATE_DIR/state.json"
    touch "$STATE_DIR/mutated"
}
_azure_pr_add_label() {
    echo add >> "$STATE_DIR/calls"
    [ "${FAIL_ADD:-}" != yes ] || return 1
    jq --arg label "$2" '.labels = (.labels + [$label] | unique)' "$STATE_DIR/state.json" > "$STATE_DIR/next.json"
    mv "$STATE_DIR/next.json" "$STATE_DIR/state.json"
    touch "$STATE_DIR/mutated"
}
'''


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copy(ROOT / 'forge.sh', self.root / 'forge.sh')
        shutil.copy(ROOT / 'forge.conf', self.root / 'forge.conf')
        (self.root / 'forge').mkdir()
        (self.root / 'forge/azure.sh').write_text(BACKEND)
        self.write_state(['area-tooling', 'pr-status/needs-fix', 'pr-review/changes-requested'])

    def write_state(self, labels, state='open'):
        (self.root / 'state.json').write_text(json.dumps({'state': state, 'labels': labels}))

    def invoke(self, status='needs-check', head=HEAD, **env):
        return subprocess.run(['bash', str(self.root / 'forge.sh'), 'pr-set-status', '42', status, head],
                              env=os.environ | {'RSS_FORGE': 'azure', 'STATE_DIR': str(self.root)} | env,
                              capture_output=True, text=True)

    def labels(self):
        return json.loads((self.root / 'state.json').read_text())['labels']

    def test_cleans_legacy_and_conflicting_labels_preserves_unrelated(self):
        self.write_state(['area-tooling', 'flag-cond', 'pr-status/needs-review-again',
                          'pr-status/needs-check-fix', 'pr-status/needs-fix',
                          'pr-review/approved', 'pr-review/changes-requested'])
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(self.labels()), ['area-tooling', 'flag-cond', 'pr-status/needs-check'])

    def test_repeat_is_noop(self):
        self.assertEqual(self.invoke().returncode, 0)
        calls = (self.root / 'calls').read_text()
        self.assertEqual(self.invoke().returncode, 0)
        self.assertEqual((self.root / 'calls').read_text(), calls)

    def test_all_five_targets(self):
        for target in ('in-progress', 'needs-review', 'needs-fix', 'needs-check', 'ready'):
            with self.subTest(target=target):
                result = self.invoke(target)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(sorted(self.labels()), ['area-tooling', 'pr-status/' + target])

    def test_invalid_target_and_missing_head_do_not_mutate(self):
        for status, head in [('approved', HEAD), ('needs-check-fix', HEAD), ('ready', '')]:
            with self.subTest(status=status, head=head):
                self.assertNotEqual(self.invoke(status, head).returncode, 0)
                self.assertFalse((self.root / 'calls').exists())

    def test_closed_pr_rejected(self):
        self.write_state(['pr-status/needs-fix'], 'closed')
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse((self.root / 'calls').exists())

    def test_stale_head_rejected_before_mutation(self):
        self.assertNotEqual(self.invoke(DRIFT='before').returncode, 0)
        self.assertFalse((self.root / 'calls').exists())

    def test_head_drift_during_switch_is_reported(self):
        self.assertNotEqual(self.invoke('ready', DRIFT='after').returncode, 0)
        self.assertNotIn('pr-status/ready', self.labels())
        self.assertIn('pr-status/needs-fix', self.labels())

    def test_read_failure_does_not_mutate(self):
        self.assertNotEqual(self.invoke(FAIL_READ='yes').returncode, 0)
        self.assertFalse((self.root / 'calls').exists())

    def test_remove_failure_restores_old_status(self):
        self.assertNotEqual(self.invoke(FAIL_REMOVE='pr-review/changes-requested').returncode, 0)
        self.assertIn('pr-status/needs-fix', self.labels())
        self.assertNotIn('pr-status/needs-check', self.labels())

    def test_partial_cleanup_restores_conflicting_initial_states(self):
        original = ['area-tooling', 'pr-status/needs-fix', 'pr-status/needs-review',
                    'pr-review/changes-requested']
        self.write_state(original)
        result = self.invoke(FAIL_REMOVE='pr-status/needs-review')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sorted(self.labels()), sorted(original))

    def test_partial_cleanup_restores_legacy_conflict_when_target_existed(self):
        original = ['pr-status/needs-check', 'pr-review/approved', 'pr-review/changes-requested']
        self.write_state(original)
        result = self.invoke(FAIL_REMOVE='pr-review/changes-requested')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sorted(self.labels()), sorted(original))

    def test_add_failure_reported_and_retry_converges(self):
        self.assertNotEqual(self.invoke(FAIL_ADD='yes').returncode, 0)
        self.assertIn('pr-status/needs-fix', self.labels())
        self.assertEqual(self.invoke().returncode, 0)
        self.assertEqual(sorted(self.labels()), ['area-tooling', 'pr-status/needs-check'])

    def test_existing_ready_is_revoked_on_head_drift(self):
        self.write_state(['pr-status/ready', 'pr-review/approved'])
        self.assertNotEqual(self.invoke('ready', DRIFT='after').returncode, 0)
        self.assertNotIn('pr-status/ready', self.labels())

    def test_compensation_failure_is_reported(self):
        result = self.invoke('ready', DRIFT='after', FAIL_REMOVE='pr-status/ready')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('compensation failed', result.stderr)

    def test_readback_detects_ignored_removal(self):
        self.assertNotEqual(self.invoke(IGNORE_REMOVE='yes').returncode, 0)


if __name__ == '__main__':
    unittest.main()
