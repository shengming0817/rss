"""Reject wrong candidate identity and content before compilation."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
SPEC = importlib.util.spec_from_file_location('ledger_proof',Path(__file__).parents[1]/'ledger-package-proof.py')
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)

class CandidateProof(unittest.TestCase):
    def test_integrity_and_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            packages={'rss-ledger':'0.1.0','rss-ledger-postgres':'0.1.0'}
            rows=[]; sums=[]
            for p,v in packages.items():
                name=f'{p}-{v}.crate'; data=p.encode()
                (root/name).write_bytes(data)
                rows.append(f'{p}\t{v}\trevision\n')
                sums.append(f'{hashlib.sha256(data).hexdigest()}  {name}\n')
            (root/'packages.tsv').write_text(''.join(rows))
            (root/'SHA256SUMS').write_text(''.join(sums))
            self.assertEqual(set(proof.candidate_archives(root,'revision',packages)),set(packages))
            for revision, expected in [('wrong','revision')]:
                with self.assertRaisesRegex(ValueError,expected):proof.candidate_archives(root,revision,packages)
            with self.assertRaisesRegex(ValueError,'version'):proof.candidate_archives(root,'revision',{'rss-ledger':'0.2.0'})
            (root/'packages.tsv').write_text(rows[0])
            with self.assertRaisesRegex(ValueError,'lacks'):proof.candidate_archives(root,'revision',packages)
            (root/'packages.tsv').write_text(''.join(rows))
            (root/'rss-ledger-0.1.0.crate').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError,'checksum'):proof.candidate_archives(root,'revision',packages)

    def test_closure_excludes_dev_only_dependencies(self):
        names=['rss-ledger','rss-ledger-postgres','normal','dev-only']
        metadata={'packages':[{'id':p,'name':p,'version':'0.1.0','source':None} for p in names],
                  'resolve':{'nodes':[{'id':p,'deps':[]} for p in names]}}
        metadata['resolve']['nodes'][0]['deps']=[{'pkg':'normal','dep_kinds':[{'kind':None}]},{'pkg':'dev-only','dep_kinds':[{'kind':'dev'}]}]
        self.assertEqual(set(proof.inventory(metadata)),set(names)-{'dev-only'})
