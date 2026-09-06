import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('recovery_proof', Path(__file__).parents[1] / 'recovery-package-proof.py')
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)

class ArchiveDependencyIsolation(unittest.TestCase):
    def test_s3_cannot_acquire_pg_or_runtime(self):
        for leaked in ('sqlx', 'sqlx-core', 'rss-transactional-messaging-postgres', 'rss-runtime'):
            with self.subTest(leaked=leaked), self.assertRaises(ValueError):
                proof.validate_selection(['--features', 's3'], {'aws-sdk-s3', leaked})

    def test_actual_feature_choices_remain_independent(self):
        proof.validate_selection(['--no-default-features'], {'rss-transactional-messaging-recovery'})
        proof.validate_selection(['--features', 'postgres'], {'sqlx', 'rss-transactional-messaging-postgres'})
        proof.validate_selection(['--features', 's3'], {'aws-sdk-s3', 'rss-transactional-messaging-recovery-s3'})
        proof.validate_selection(['--all-features'], {'sqlx', 'aws-sdk-s3', 'rss-runtime'})

if __name__ == '__main__':
    unittest.main()
