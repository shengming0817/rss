import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("reconcile_proof", Path(__file__).parents[1] / "reconcile-package-proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


class CandidateIdentity(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.versions = {"rss-reconcile": "0.1.0"}
        self.archive = self.root / "rss-reconcile-0.1.0.crate"
        self.archive.write_bytes(b"exact-candidate")
        self.row = "rss-reconcile\t0.1.0\trevision\n"
        (self.root / "packages.tsv").write_text(self.row)
        (self.root / "SHA256SUMS").write_text(hashlib.sha256(self.archive.read_bytes()).hexdigest() + "  " + self.archive.name + "\n")

    def test_exact_artifact_accepted(self):
        self.assertEqual(PROOF.candidate_archives(self.root, "revision", self.versions), {"rss-reconcile": self.archive})

    def test_modified_archive_rejected(self):
        self.archive.write_bytes(b"different")
        with self.assertRaises(ValueError):
            PROOF.candidate_archives(self.root, "revision", self.versions)

    def test_revision_version_missing_and_duplicate_rejected(self):
        for rows, revision, versions in [(self.row, "other", self.versions), (self.row, "revision", {"rss-reconcile": "0.1.1"}), (self.row, "revision", {"rss-reconcile-postgres": "0.1.0"}), (self.row * 2, "revision", self.versions)]:
            with self.subTest(rows=rows, revision=revision, versions=versions):
                (self.root / "packages.tsv").write_text(rows)
                with self.assertRaises(ValueError):
                    PROOF.candidate_archives(self.root, revision, versions)

    def test_archive_path_escape_rejected(self):
        (self.root / "SHA256SUMS").write_text("bad  ../escape.crate\n")
        with self.assertRaises(ValueError):
            PROOF.candidate_archives(self.root, "revision", self.versions)


class FeatureMatrix(unittest.TestCase):
    def test_messaging_has_an_independent_profile(self):
        self.assertIn(["--no-default-features", "--features", "messaging"], PROOF.profiles(True))
        self.assertIn(["--no-default-features", "--features", "integration"], PROOF.profiles(True))
        for flags in PROOF.profiles(False):
            self.assertFalse(PROOF.permits_messaging(False, flags))
        self.assertFalse(PROOF.permits_messaging(True, ["--no-default-features", "--features", "integration"]))
        self.assertTrue(PROOF.permits_messaging(True, ["--no-default-features", "--features", "messaging"]))
