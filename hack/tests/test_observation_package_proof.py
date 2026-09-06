import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("observation_proof", Path(__file__).parents[1] / "observation-package-proof.py")
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class ArtifactIdentity(unittest.TestCase):
    def test_candidate_identity_and_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows, sums = [], []
            for name in proof.PACKAGES:
                filename = name + "-0.1.0.crate"
                payload = name.encode()
                (root / filename).write_bytes(payload)
                rows.append(f"{name}\t0.1.0\thead")
                sums.append(f"{hashlib.sha256(payload).hexdigest()}  {filename}")
            (root / "packages.tsv").write_text("\n".join(rows))
            (root / "SHA256SUMS").write_text("\n".join(sums))
            self.assertEqual(set(proof.candidate_archives(root, "head")), set(proof.PACKAGES))
            with self.assertRaises(ValueError):
                proof.candidate_archives(root, "old-head")
            (root / "packages.tsv").write_text("\n".join(rows + rows[:1]))
            with self.assertRaises(ValueError):
                proof.candidate_archives(root, "head")
            (root / "packages.tsv").write_text("\n".join(rows[:-1]))
            with self.assertRaises(ValueError):
                proof.candidate_archives(root, "head")
            (root / "packages.tsv").write_text("\n".join(rows))
            (root / (proof.PACKAGES[0] + "-0.1.0.crate")).write_bytes(b"corrupt")
            with self.assertRaises(ValueError):
                proof.candidate_archives(root, "head")


if __name__ == "__main__":
    unittest.main()
