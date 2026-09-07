"""Reject false-positive artifact/feature proofs before invoking Cargo."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "extract-package-proof.py"
spec = importlib.util.spec_from_file_location("extract_proof", SCRIPT)
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)
REVISION = "a" * 40


class ArtifactProof(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.versions = {"rss-sample": "0.1.0"}
        self.archive()

    def archive(self, revision=REVISION, dirty=False, extra=None):
        name = "rss-sample-0.1.0"
        files = {
            "Cargo.toml": b'[package]\nname="rss-sample"\nversion="0.1.0"\n',
            ".cargo_vcs_info.json": json.dumps({"git": {"sha1": revision, "dirty": dirty}}).encode(),
            "src/lib.rs": b"pub fn value() -> u8 { 1 }",
        }
        files.update(extra or {})
        path = self.root / (name + ".crate")
        with tarfile.open(path, "w:gz") as archive:
            for member, content in files.items():
                entry = tarfile.TarInfo(name + "/" + member)
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        (self.root / "packages.tsv").write_text(f"rss-sample\t0.1.0\t{REVISION}\n")
        (self.root / "SHA256SUMS").write_text(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n")
        return path

    def validate(self):
        return proof.candidate_archives(self.root, REVISION, self.versions)

    def test_exact_artifact_passes(self):
        self.assertEqual(set(self.validate()), {"rss-sample"})

    def test_checksum_corruption_and_missing_archive_fail(self):
        path = self.root / "rss-sample-0.1.0.crate"
        path.write_bytes(path.read_bytes() + b"corruption")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.validate()
        path.unlink()
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.validate()

    def test_manifest_sha_cannot_relabel_an_old_or_dirty_archive(self):
        for revision, dirty in [("b" * 40, False), (REVISION, True)]:
            with self.subTest(revision=revision, dirty=dirty):
                self.archive(revision, dirty)
                with self.assertRaisesRegex(ValueError, "revision|dirty"):
                    self.validate()

    def test_duplicate_identity_and_wrong_version_fail(self):
        rows = self.root / "packages.tsv"
        rows.write_text(rows.read_text() * 2)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.validate()
        self.archive()
        self.versions["rss-sample"] = "0.2.0"
        with self.assertRaisesRegex(ValueError, "version"):
            self.validate()

    def test_escaping_tar_path_and_normalized_source_dependency_fail(self):
        for extra in [
            {"../../escape": b"escape"},
            {"Cargo.toml": b'[package]\nname="rss-sample"\nversion="0.1.0"\n[dependencies.internal]\npath="/original/workspace"\n'},
        ]:
            with self.subTest(extra=extra):
                self.archive(extra=extra)
                with self.assertRaises(ValueError):
                    self.validate()

    def test_empty_or_mismatched_inventory_fails(self):
        for rows in ["", f"rss-sample\t0.1.0\t{'b' * 40}\n"]:
            (self.root / "packages.tsv").write_text(rows)
            with self.assertRaises(ValueError):
                self.validate()

    def test_tar_aliases_cannot_replace_the_validated_manifest(self):
        for alias in ["./Cargo.toml", "/Cargo.toml", "src\\Cargo.toml"]:
            with self.subTest(alias=alias):
                self.archive(extra={alias: b'[package]\nname="replacement"\nversion="9.9.9"\n'})
                with self.assertRaisesRegex(ValueError, "unsafe archive"):
                    self.validate()

    def test_archive_resource_budgets_reject_before_extraction(self):
        self.archive(extra={"large": b"\0" * 1024})
        for limit, value in [("MAX_COMPRESSED_BYTES", 1), ("MAX_TAR_BYTES", 1024),
                             ("MAX_MEMBERS", 2), ("MAX_MEMBER_BYTES", 512),
                             ("MAX_CONTENT_BYTES", 1024)]:
            with self.subTest(limit=limit), patch.object(proof, limit, value, create=True):
                with self.assertRaisesRegex(ValueError, "budget"):
                    self.validate()

    def test_archive_digest_does_not_read_the_entire_file_into_memory(self):
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")):
            self.validate()


class GraphProof(unittest.TestCase):
    def graph(self, root, source, features=()):
        return {
            "workspace_root": str(root),
            "packages": [
                {"id": "consumer", "name": "rss-examples", "source": None, "manifest_path": str(root / "Cargo.toml")},
                {"id": "core", "name": "rss-transactional-messaging", "source": None, "manifest_path": str(source / "Cargo.toml")},
            ],
            "resolve": {"root": "consumer", "nodes": [
                {"id": "consumer", "features": []},
                {"id": "core", "features": list(features)},
            ]},
        }

    def test_source_escape_and_unified_features_fail(self):
        root = Path("/proof/consumer")
        extracted = Path("/proof/extracted")
        allowed = {"rss-transactional-messaging": extracted / "core"}
        graph = self.graph(root, extracted / "core", ["producer"])
        proof.validate_graph(graph, root, allowed, {"producer"}, set())
        graph["packages"][1]["manifest_path"] = "/original/crates/core/Cargo.toml"
        with self.assertRaisesRegex(ValueError, "source"):
            proof.validate_graph(graph, root, allowed, {"producer"}, set())
        graph = self.graph(root, extracted / "core", ["producer", "consumer"])
        with self.assertRaisesRegex(ValueError, "feature"):
            proof.validate_graph(graph, root, allowed, {"producer"}, set())

    def test_wrong_workspace_and_forbidden_provider_fail(self):
        root = Path("/proof/consumer")
        allowed = {"rss-transactional-messaging": Path("/proof/core")}
        graph = self.graph(root, allowed["rss-transactional-messaging"])
        graph["workspace_root"] = "/original"
        with self.assertRaisesRegex(ValueError, "workspace"):
            proof.validate_graph(graph, root, allowed, set(), set())
        graph["workspace_root"] = str(root)
        with self.assertRaisesRegex(ValueError, "forbidden"):
            proof.validate_graph(graph, root, allowed, set(), {"rss-transactional-messaging"})


class ExecutionProof(unittest.TestCase):
    def test_cargo_timeout_keeps_command_partial_output_and_failure_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            error = proof.subprocess.TimeoutExpired(["cargo", "metadata"], 600, output=b"partial stdout", stderr=b"partial stderr")
            with patch.object(proof.subprocess, "run", side_effect=error), self.assertRaises(proof.subprocess.TimeoutExpired):
                proof.cargo(["metadata"], directory)
            log = (directory / "commands.log").read_text()
            for evidence in ["cargo metadata", "partial stdout", "partial stderr", "timeout=600"]:
                self.assertIn(evidence, log)

    def test_zero_tests_missing_consumer_and_duplicate_run_are_not_proof(self):
        suite = "test postgres_transactional_messaging_suite ... ok\n"
        consumer = "external-provider-consumer PASS /proof/provider\n"
        proof.validate_provider_results(suite + consumer, ["/proof/provider"])
        for log in ["test result: ok. 0 passed", suite, suite + consumer * 2]:
            with self.subTest(log=log), self.assertRaises(ValueError):
                proof.validate_provider_results(log, ["/proof/provider"])

    def test_feature_expansion_keeps_opposite_port_and_provider_out(self):
        import tomllib
        root = SCRIPT.parent.parent
        manifest = tomllib.loads((root / "crates/examples/Cargo.toml").read_text())
        workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
        for selected in ["producer", "consumer"]:
            features, dependencies = proof.selected_dependencies(manifest, [selected], workspace)
            self.assertNotIn("rss-transactional-messaging-postgres", dependencies)
            self.assertNotIn("rss-runtime", dependencies)
            for name in ["rss-transactional-messaging", "rss-transactional-messaging-runtime", "rss-transactional-messaging-testkit"]:
                self.assertFalse(dependencies[name]["default-features"])
                self.assertEqual(dependencies[name]["features"], [selected])


if __name__ == "__main__":
    unittest.main()
