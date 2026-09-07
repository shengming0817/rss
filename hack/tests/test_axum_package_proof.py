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


class ProtocolIsolation(unittest.TestCase):
    @staticmethod
    def facts(protocols=(), *, runtime=False, auto=False):
        features = {"rss-axum": list(protocols)}
        if runtime:
            features["rss-axum"].append("managed-server")
            features["hyper"] = ["server", *protocols]
            features["hyper-util"] = ["tokio", "service", *protocols]
            features["rss-runtime"] = []
            features["tokio"] = ["net"]
        if auto:
            features["rss-axum"].append("auto-protocol")
        return {"packages": [{"id": n, "name": n} for n in features],
                "resolve": {"nodes": [{"id": n, "features": f} for n, f in features.items()]}}

    def test_h1_resolution_rejects_accidental_h2(self):
        facts = self.facts(["http1"], runtime=True)
        PROOF.verify_features(facts, "http1")
        facts["resolve"]["nodes"][1]["features"].append("http2")
        with self.assertRaisesRegex(ValueError, "protocol features"):
            PROOF.verify_features(facts, "http1")

    def test_base_rejects_optional_runtime(self):
        PROOF.verify_features(self.facts(), "base")
        with self.assertRaisesRegex(ValueError, "optional runtime"):
            PROOF.verify_features(self.facts(runtime=True), "base")

    def test_two_protocols_do_not_imply_auto_api(self):
        facts = self.facts(["http1", "http2"], runtime=True)
        PROOF.verify_features(facts, "both")
        with self.assertRaisesRegex(ValueError, "Auto capability"):
            PROOF.verify_features(facts, "auto")
        facts["resolve"]["nodes"][0]["features"].append("auto-protocol")
        PROOF.verify_features(facts, "auto")
        with self.assertRaisesRegex(ValueError, "Auto capability"):
            PROOF.verify_features(facts, "both")

    def test_all_features_forward_to_the_dependency(self):
        import tomllib
        versions = {"rss-contract": "0.1.0", "rss-axum": "0.1.0", "rss-runtime": "0.1.0"}
        manifest = tomllib.loads(PROOF.consumer_manifest("all", versions,
            ["default", "managed-server", "http1", "http2", "auto-protocol"]))
        for feature in ["managed-server", "http1", "http2", "auto-protocol"]:
            self.assertEqual([f"rss-axum/{feature}"], manifest["features"][feature])
        self.assertEqual(PROOF.feature_args("all"), ["--all-features"])

    def test_api_proof_does_not_supply_client_protocol_features(self):
        import tomllib
        versions = {"rss-contract": "0.1.0", "rss-axum": "0.1.0", "rss-runtime": "0.1.0"}
        features = ["default", "managed-server", "http1", "http2", "auto-protocol"]
        api = tomllib.loads(PROOF.consumer_manifest("http1", versions, features))
        self.assertEqual(set(api["dependencies"]), {"rss-axum"})
        self.assertNotIn("rss-runtime", api["dependencies"])
        self.assertNotIn("dep:rss-runtime", api["features"]["managed-server"])
        self.assertNotIn("hyper", api["dependencies"])
        self.assertNotIn("hyper-util", api["dependencies"])
        self.assertNotIn("hyper/http1", api["features"]["http1"])
        smoke = tomllib.loads(PROOF.consumer_manifest("http1", versions, features, smoke=True))
        self.assertIn("hyper/http1", smoke["features"]["http1"])

    def test_managed_requires_its_own_runtime_and_transport_foundation(self):
        facts = self.facts(runtime=True)
        PROOF.verify_features(facts, "managed")
        facts["resolve"]["nodes"] = [n for n in facts["resolve"]["nodes"] if n["id"] != "rss-runtime"]
        with self.assertRaisesRegex(ValueError, "optional runtime"):
            PROOF.verify_features(facts, "managed")
        facts = self.facts(runtime=True)
        facts["resolve"]["nodes"][1]["features"].remove("server")
        with self.assertRaisesRegex(ValueError, "transport foundation"):
            PROOF.verify_features(facts, "managed")

    def test_managed_requires_its_own_tokio_net(self):
        facts = self.facts(runtime=True)
        facts["resolve"]["nodes"][-1]["features"].remove("net")
        with self.assertRaisesRegex(ValueError, "tokio/net"):
            PROOF.verify_features(facts, "managed")

    def test_lifecycle_only_example_cannot_succeed_silently(self):
        guidance = "enable http1, http2, or auto-protocol"
        PROOF.verify_example_failure(1, guidance)
        with self.assertRaisesRegex(ValueError, "must fail"):
            PROOF.verify_example_failure(0, guidance)
        with self.assertRaisesRegex(ValueError, "must fail"):
            PROOF.verify_example_failure(1, "unrelated failure")
