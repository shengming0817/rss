"""Contract candidate identity, isolation and non-vacuous execution proof."""
import copy
import hashlib
import importlib.util
import io
import json
import tarfile
import subprocess
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("contract_proof", Path(__file__).parents[1] / "contract-package-proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


class ContractProof(unittest.TestCase):
    def test_candidate_requires_exact_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / 'rss-contract-0.1.0.crate'
            archive.write_bytes(b'candidate')
            inventory = root / 'packages.tsv'
            inventory.write_text('rss-contract\t0.1.0\trevision\n')
            (root / 'SHA256SUMS').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
            self.assertEqual(PROOF.candidate(root, 'revision', '0.1.0')[0], archive)
            for revision, version in [('other', '0.1.0'), ('revision', '0.2.0')]:
                with self.assertRaises(ValueError):
                    PROOF.candidate(root, revision, version)
            inventory.write_text('other\t0.1.0\trevision\n')
            with self.assertRaises(ValueError):
                PROOF.candidate(root, 'revision', '0.1.0')
            inventory.write_text('rss-contract\t0.1.0\trevision\n' * 2)
            with self.assertRaises(ValueError):
                PROOF.candidate(root, 'revision', '0.1.0')
            inventory.write_text('rss-contract\t0.1.0\trevision\n')
            archive.write_bytes(b'corrupted')
            with self.assertRaises(ValueError):
                PROOF.candidate(root, 'revision', '0.1.0')

    def test_resolution_rejects_workspace_escape_and_extra_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer, contract = root / 'consumer', root / 'artifact'
            facts = {'packages': [
                {'name': 'contract-consumer', 'version': '0.0.0', 'source': None, 'manifest_path': str(consumer / 'Cargo.toml'), 'targets': [{'src_path': str(consumer / 'tests/public_values.rs')}]},
                {'name': 'rss-contract', 'version': '0.1.0', 'source': None, 'manifest_path': str(contract / 'Cargo.toml'), 'targets': [{'src_path': str(contract / 'src/lib.rs')}]},
            ]}
            PROOF.check_resolution(facts, consumer, contract, '0.1.0')
            for key, value in [('manifest_path', str(root / 'workspace/Cargo.toml')), ('version', '0.2.0'), ('source', 'registry+unexpected')]:
                bad = copy.deepcopy(facts)
                bad['packages'][1][key] = value
                with self.assertRaises(ValueError):
                    PROOF.check_resolution(bad, consumer, contract, '0.1.0')
            bad = copy.deepcopy(facts)
            bad['packages'][1]['targets'][0]['src_path'] = str(root / 'workspace/src/lib.rs')
            with self.assertRaises(ValueError):
                PROOF.check_resolution(bad, consumer, contract, '0.1.0')
            facts['packages'].append({'name': 'unexpected'})
            with self.assertRaises(ValueError):
                PROOF.check_resolution(facts, consumer, contract, '0.1.0')

    def test_execution_requires_discovered_tests_to_pass(self):
        self.assertEqual(PROOF.test_count('first: test\nsecond: test\n'), 2)
        with self.assertRaises(ValueError):
            PROOF.test_count('0 tests, 0 benchmarks\n')
        PROOF.check_result('test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s', 2)
        for result in [
            '',
            'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;',
            'test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out;',
        ]:
            with self.assertRaises(ValueError):
                PROOF.check_result(result, 2)

    def test_embedded_origin_is_bound_even_with_a_valid_checksum(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'packages.tsv').write_text('rss-contract\t0.1.0\trevision\n')
            archive = root / 'rss-contract-0.1.0.crate'
            cases = [
                ({'git': {'sha1': 'revision'}, 'path_in_vcs': 'crates/contract'}, True),
                ({'git': {'sha1': 'other'}, 'path_in_vcs': 'crates/contract'}, False),
                ({'git': {'sha1': 'revision', 'dirty': True}, 'path_in_vcs': 'crates/contract'}, False),
                ({'git': {'sha1': 'revision'}, 'path_in_vcs': 'crates/other'}, False),
                (None, False),
            ]
            for index, (origin, valid) in enumerate(cases):
                data = json.dumps(origin).encode()
                with tarfile.open(archive, 'w:gz') as bundle:
                    member = tarfile.TarInfo('rss-contract-0.1.0/.cargo_vcs_info.json')
                    member.size = len(data)
                    bundle.addfile(member, io.BytesIO(data))
                (root / 'SHA256SUMS').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
                verified, _ = PROOF.candidate(root, 'revision', '0.1.0')
                if valid:
                    PROOF.unpack_candidate(verified, root / str(index), '0.1.0', 'revision')
                else:
                    with self.assertRaises(ValueError):
                        PROOF.unpack_candidate(verified, root / str(index), '0.1.0', 'revision')

    def test_rustc_inputs_reject_transitive_module_and_include_escapes(self):
        with tempfile.TemporaryDirectory(prefix='contract proof ') as temporary:
            root = Path(temporary).resolve()
            contract, consumer, target = root / 'artifact', root / 'consumer', root / 'target'
            contract.mkdir()
            consumer.mkdir()
            deps = target / 'debug/deps'
            deps.mkdir(parents=True)
            (contract / 'module.rs').write_text('pub const VALUE: u8 = 1;')
            (root / 'escaped.rs').write_text('pub const VALUE: u8 = 2;')
            with self.assertRaises(ValueError):
                PROOF.check_compiler_inputs(target, consumer, contract)
            for code, valid in [
                ('mod module; pub use module::*;', True),
                ('#[path="../escaped.rs"] mod module; pub use module::*;', False),
                ('include!("../escaped.rs");', False),
                ('pub const TEXT: &str = include_str!("../escaped.rs");', False),
            ]:
                source = contract / 'lib.rs'
                source.write_text(code)
                subprocess.run(['rustc', '--crate-name', 'proof', '--crate-type', 'lib', '--emit=dep-info',
                                str(source), '-o', str(deps / 'proof.d')], check=True, capture_output=True)
                if valid:
                    PROOF.check_compiler_inputs(target, consumer, contract)
                else:
                    with self.assertRaises(ValueError):
                        PROOF.check_compiler_inputs(target, consumer, contract)
