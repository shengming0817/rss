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


class PlatformExecution(unittest.TestCase):
    @staticmethod
    def receipt():
        return {"completed": 42, "deadlineExceeded": True, "handlerStarted": True,
                "foreignAdmissionRejected": True, "drainingRejected": True,
                "descriptorMismatchRejected": True, "duplicateModule": "inventory",
                "duplicateContract": "example.add"}

    def test_only_successful_behavior_receipt_passes(self):
        import json
        good = self.receipt()
        self.assertEqual(PROOF.platform_receipt(0, json.dumps(good)), good)
        for code, output in [(1, json.dumps(good)), (0, "passed"), (0, "{}"),
                             (0, json.dumps({**good, "deadlineExceeded": False})),
                             (0, json.dumps({**good, "completed": True})),
                             (0, json.dumps({**good, "extra": True}))]:
            with self.subTest(code=code, output=output), self.assertRaises(ValueError):
                PROOF.platform_receipt(code, output)

    def test_platform_manifest_supports_real_run_without_axum(self):
        import tomllib
        versions = {"rss-contract": "0.1.0", "rss-platform": "0.3.0", "rss-request-context": "0.1.0"}
        manifest = tomllib.loads(PROOF.consumer_manifest("platform", versions, []))
        self.assertEqual(set(manifest["dependencies"]), {*versions, "tokio", "serde_json"})
        self.assertTrue({"rt", "macros", "time"} <= set(manifest["dependencies"]["tokio"]["features"]))

    def test_scenario_is_the_readme_source(self):
        PROOF.platform_source()

    def test_platform_runs_and_never_accepts_a_compile_only_result(self):
        import json
        from unittest.mock import patch
        import subprocess
        with patch.object(PROOF.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, json.dumps(self.receipt()), "")) as run:
            self.assertEqual(PROOF.run_platform(Path("consumer"), {}), self.receipt())
            self.assertEqual(run.call_args.args[0], ["cargo", "run", "--locked", "--offline", "--quiet"])
        with patch.object(PROOF.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "failed")):
            with self.assertRaisesRegex(ValueError, "execution failed"):
                PROOF.run_platform(Path("consumer"), {})

    def test_revision_and_scenario_drift_are_rejected(self):
        from unittest.mock import patch
        with patch.object(PROOF.subprocess, "check_output", return_value="different"):
            with self.assertRaisesRegex(ValueError, "revision mismatch"):
                PROOF.platform_source("candidate")
        with patch.object(PROOF.subprocess, "check_output", side_effect=["candidate", b"changed"]):
            with self.assertRaisesRegex(ValueError, "differs from candidate"):
                PROOF.platform_source("candidate")

    def test_readme_drift_is_detected_and_sync_is_exact(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scenario = root / PROOF.SCENARIO / "src/main.rs"
            scenario.parent.mkdir(parents=True)
            scenario.write_text("fn main() {}\n")
            readme = root / "crates/platform/README.md"
            readme.parent.mkdir(parents=True)
            readme.write_text(PROOF.README_START + "\nold\n" + PROOF.README_END)
            with patch.object(PROOF, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "README drift"):
                    PROOF.platform_source()
                PROOF.platform_source(sync=True)
                self.assertEqual(PROOF.platform_source(), scenario.read_text())

    def test_resolution_cannot_escape_to_source_or_registry_rss(self):
        consumer = Path("/isolated/consumer")
        allowed = {"rss-platform": Path("/isolated/artifacts/rss-platform/Cargo.toml")}
        row = {"name": "rss-platform", "source": None, "manifest_path": str(allowed["rss-platform"])}
        PROOF.verify_platform_resolution({"packages": [row]}, consumer, allowed)
        for changed in [{**row, "manifest_path": "/workspace/crates/platform/Cargo.toml"},
                        {**row, "source": "registry+crates.io"}, {**row, "name": "rss-internal"}]:
            with self.subTest(row=changed), self.assertRaisesRegex(ValueError, "closure"):
                PROOF.verify_platform_resolution({"packages": [changed]}, consumer, allowed)

    def test_platform_rejects_other_aggregate_artifacts(self):
        consumer = Path("/isolated/consumer")
        names = ["rss-contract", "rss-platform", "rss-request-context", "rss-axum", "rss-runtime", "rss-redact", "rss-redact-derive"]
        allowed = {name: Path("/isolated/artifacts") / name / "Cargo.toml" for name in names}
        for name in names[3:]:
            facts = {"packages": [{"name": name, "source": None, "manifest_path": str(allowed[name])}]}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "closure"):
                PROOF.verify_platform_resolution(facts, consumer, allowed)

    def test_source_does_not_depend_on_aggregate_release_metadata(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp, patch.object(PROOF, "ROOT", Path(temp)), \
                patch("sys.argv", ["proof", "--source"]), \
                patch.object(PROOF, "platform_source", return_value="fn main() {}"), \
                patch.object(PROOF, "source_consumer", return_value=self.receipt()) as consumer, \
                patch.object(PROOF, "closure", side_effect=RuntimeError("unrelated release failure")):
            with redirect_stdout(StringIO()):
                PROOF.main()
            consumer.assert_called_once()
