import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("device_proof", Path(__file__).parents[1] / "device-command-package-proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


class CandidateIdentity(unittest.TestCase):
    def test_candidate_is_bound_to_revision_versions_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "component-0.1.0.crate"
            archive.write_bytes(b"immutable package bytes")
            (root / "packages.tsv").write_text("component\t0.1.0\tcommit\n")
            (root / "SHA256SUMS").write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n")
            self.assertEqual(PROOF.candidate_archives(root, "commit", {"component": "0.1.0"}), {"component": archive})
            for revision, versions in [("other", {"component": "0.1.0"}), ("commit", {"component": "0.1.1"}), ("commit", {"absent": "0.1.0"})]:
                with self.assertRaises(ValueError):
                    PROOF.candidate_archives(root, revision, versions)
            archive.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                PROOF.candidate_archives(root, "commit", {"component": "0.1.0"})

    def test_duplicate_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "packages.tsv").write_text("component\t0.1.0\tcommit\n" * 2)
            with self.assertRaises(ValueError):
                PROOF.candidate_archives(root, "commit", {"component": "0.1.0"})
