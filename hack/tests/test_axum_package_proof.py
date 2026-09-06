import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("axum_proof", Path(__file__).resolve().parents[1] / "axum-package-proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


class ArtifactIdentity(unittest.TestCase):
    def test_exact_revision_and_digest_are_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "rss-axum-0.1.0.crate"
            archive.write_bytes(b"fixture")
            (root / "packages.tsv").write_text("rss-axum\t0.1.0\trevision\n")
            (root / "SHA256SUMS").write_text(hashlib.sha256(b"fixture").hexdigest() + "  " + archive.name + "\n")
            versions = {"rss-axum": "0.1.0"}
            self.assertEqual(PROOF.archives_at(root, "revision", versions), {"rss-axum": archive})
            with self.assertRaisesRegex(ValueError, "revision"):
                PROOF.archives_at(root, "other", versions)
            with self.assertRaisesRegex(ValueError, "identity"):
                PROOF.archives_at(root, "revision", {"rss-axum": "0.2.0"})
            archive.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "checksum"):
                PROOF.archives_at(root, "revision", versions)
