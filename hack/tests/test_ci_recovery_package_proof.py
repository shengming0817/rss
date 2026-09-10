import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from package_proof import example_dependencies


class RecoveryFeatureIsolation(unittest.TestCase):
    def test_s3_dependency_selection_has_no_database_or_runtime(self):
        _, dependencies = example_dependencies({"s3": ["recovery-s3"]})["s3"]
        for name in ("sqlx", "rss-transactional-messaging-postgres", "rss-runtime"):
            self.assertNotIn(name, dependencies)

    def test_postgres_does_not_select_s3(self):
        _, dependencies = example_dependencies({"pg": ["recovery-pg"]})["pg"]
        self.assertNotIn("aws-sdk-s3", dependencies)
        self.assertNotIn("rss-runtime", dependencies)
