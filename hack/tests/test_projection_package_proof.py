"""Candidate verification rejects stale/tampered input before consumer execution."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("proof", Path(__file__).parents[1] / "projection-package-proof.py")
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)


class CandidateProof(unittest.TestCase):
    def test_candidate_identity_and_integrity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows, sums = [], []
            for package in proof.PACKAGES:
                name = f"{package}-0.1.0.crate"
                content = package.encode()
                (root / name).write_bytes(content)
                rows.append(f"{package}\t0.1.0\trevision\n")
                sums.append(f"{hashlib.sha256(content).hexdigest()}  {name}\n")
            (root / "packages.tsv").write_text("".join(rows))
            (root / "SHA256SUMS").write_text("".join(sums))
            self.assertEqual(set(proof.candidate_archives(root, "revision")), set(proof.PACKAGES))
            with self.assertRaisesRegex(ValueError, "revision"):
                proof.candidate_archives(root, "stale")
            (root / f"{proof.PACKAGES[0]}-0.1.0.crate").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                proof.candidate_archives(root, "revision")


if __name__ == "__main__":
    unittest.main()
