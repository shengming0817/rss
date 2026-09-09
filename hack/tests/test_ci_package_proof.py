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

SCRIPT = Path(__file__).resolve().parents[1] / "package_proof.py"
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
    def test_zero_tests_missing_consumer_and_duplicate_run_are_not_proof(self):
        suite = "test postgres_transactional_messaging_suite ... ok\n"
        consumer = "external-provider-consumer PASS /proof/provider\n"
        proof.validate_execution(suite + consumer, "postgres_transactional_messaging_suite", ["/proof/provider"])
        for log in ["test result: ok. 0 passed", suite, suite + consumer * 2]:
            with self.subTest(log=log), self.assertRaises(ValueError):
                proof.validate_execution(log, "postgres_transactional_messaging_suite", ["/proof/provider"])

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

    def test_outbox_capabilities_resolve_without_algorithm_or_broker_dependencies(self):
        import tomllib
        root = SCRIPT.parent.parent
        manifest = tomllib.loads((root / "crates/examples/Cargo.toml").read_text())
        workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
        for scenario in ("outbox-writer", "relay-only"):
            _, dependencies = proof.selected_dependencies(manifest, [scenario], workspace)
            for forbidden in ("rss-transactional-messaging-runtime", "rss-transactional-messaging-testkit", "rss-transactional-messaging-amqp", "rss-runtime", "testkit", "tokio-util"):
                self.assertNotIn(forbidden, dependencies)
            self.assertFalse(dependencies["rss-transactional-messaging"]["default-features"])
            self.assertEqual(dependencies["rss-transactional-messaging"]["features"], ["producer"])
            self.assertEqual("rss-transactional-messaging-postgres" in dependencies, scenario == "outbox-writer")

    def test_writer_execution_requires_each_selected_binary_once(self):
        suite = "test postgres_transactional_messaging_suite ... ok\n"
        binary = "/proof/outbox-writer"
        receipt = f"external-provider-consumer PASS {binary}\n"
        proof.validate_execution(suite + receipt, "postgres_transactional_messaging_suite", [binary])
        for log in (suite, suite + receipt * 2, receipt):
            with self.subTest(log=log), self.assertRaises(ValueError):
                proof.validate_execution(log, "postgres_transactional_messaging_suite", [binary])




class Isolation(unittest.TestCase):
    def test_ancestor_config_source_patch_and_environment_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = root / 'checkout' / 'consumer'
            consumer.mkdir(parents=True)
            config = root / '.cargo' / 'config.toml'
            config.parent.mkdir()
            for text in ('[source.crates-io]\nreplace-with="local"', '[patch.crates-io]\nfoo={path="/other"}'):
                config.write_text(text)
                with self.assertRaises(ValueError):
                    proof.validate_cargo_config(consumer, {})
            config.write_text('[build]\ntarget-dir="target"')
            proof.validate_cargo_config(consumer, {})
            with self.assertRaises(ValueError):
                proof.validate_cargo_config(consumer, {'CARGO_SOURCE_CRATES_IO_REPLACE_WITH': 'local'})

    def test_execution_requires_suite_and_each_consumer_once(self):
        good = 'test example_consumer ... ok\nexternal-provider-consumer PASS /one\n'
        proof.validate_execution(good, 'example_consumer', ['/one'])
        for bad in ('', 'test result: ok. 0 passed', good.replace(' ... ok', ' ... FAILED'), good + good):
            with self.assertRaises(ValueError):
                proof.validate_execution(bad, 'example_consumer', ['/one'])

class ExecutionGraph(unittest.TestCase):
    def test_device_core_keeps_producer_port_without_provider_or_consumer(self):
        root = Path('/consumer')
        names = ['rss-examples', 'rss-device-command', 'rss-transactional-messaging']
        allowed = {n: Path('/extracted') / n for n in names[1:]}
        graph = {'workspace_root': str(root), 'target_directory': str(root / 'target'),
                 'packages': [{'id':n,'name':n,'source':None,'manifest_path':str((root if n==names[0] else allowed[n]) / 'Cargo.toml')} for n in names],
                 'resolve': {'root':names[0], 'nodes':[{'id':n,'features':(['producer'] if n==names[-1] else ['default'])} for n in names]}}
        proof.validate_graph(graph, root, allowed, {'producer'}, {'sqlx', 'rss-device-command-postgres'}, required_features={'rss-device-command': {'default'}})
        graph['resolve']['nodes'][-1]['features'].append('consumer')
        with self.assertRaisesRegex(ValueError, 'feature mismatch'):
            proof.validate_graph(graph, root, allowed, {'producer'}, {'sqlx', 'rss-device-command-postgres'}, required_features={'rss-device-command': {'default'}})
        graph['resolve']['nodes'][-1]['features']=['producer']
        graph['packages'][1]['manifest_path']='/original/crates/device-command/Cargo.toml'
        with self.assertRaisesRegex(ValueError, 'dependency source'):
            proof.validate_graph(graph, root, allowed, {'producer'}, {'sqlx', 'rss-device-command-postgres'}, required_features={'rss-device-command': {'default'}})

class CompilerBoundary(unittest.TestCase):
    def test_inherited_compiler_and_runner_configuration_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / '.cargo' / 'config.toml'
            config.parent.mkdir()
            for contents in ['[build]\nrustc="/fake"', '[build]\nrustc-wrapper="/fake"',
                             '[build]\nrustdocflags=["--cfg","fake"]',
                             '[target.x86_64-unknown-linux-gnu]\nrunner="/fake"',
                             '[env]\nRUSTC="/fake"']:
                config.write_text(contents)
                with self.subTest(contents=contents), self.assertRaises(ValueError):
                    proof.validate_cargo_config(root / 'consumer', {})

    def test_compiler_cache_and_target_overrides_do_not_reach_cargo(self):
        inputs = {'PATH':'/trusted', 'RUSTC':'/fake', 'RUSTDOC':'/fake-doc',
                  'RUSTC_WRAPPER':'sccache', 'RUSTFLAGS':'--cfg fake',
                  'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS':'--cfg fake',
                  'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER':'/fake',
                  'CARGO_TARGET_DIR':'/shared'}
        self.assertEqual(proof.cargo_environment(inputs), {'PATH':'/trusted'})

class ProcessBoundary(unittest.TestCase):
    def test_timeout_terminates_and_reaps_process_group_with_partial_output(self):
        import os
        import signal
        import sys
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pidfile = root / 'child.pid'
            child = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
            program = ("import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c'," + repr(child) + "]); "
                       "open(sys.argv[1],'w').write(str(p.pid)); print('partial-marker',flush=True); time.sleep(60)")
            logpath = root / 'process.log'
            with logpath.open('w') as log, self.assertRaises(proof.subprocess.TimeoutExpired):
                proof.run_command([sys.executable, '-c', program, str(pidfile)], root, os.environ,
                                  log, timeout=1, grace=1)
            self.assertIn('partial-marker', logpath.read_text())
            self.assertIn('exit=timeout', logpath.read_text())
            pid = int(pidfile.read_text())
            # A just-killed orphan can briefly be a zombie on Linux; it must not be running.
            state = proof.subprocess.run(['ps','-o','stat=','-p',str(pid)], capture_output=True, text=True).stdout.strip()
            self.assertTrue(not state or state.startswith('Z'), state)

class OutputBoundary(unittest.TestCase):
    def test_both_streams_are_drained_with_bounded_tails_and_disk(self):
        import os, sys
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logpath = root / 'command.log'
            program = "import os; [(os.write(1,b'x'*4096),os.write(2,b'y'*4096)) for _ in range(32)]"
            with logpath.open('w') as log:
                result = proof.run_command([sys.executable,'-c',program], root, os.environ, log,
                                           max_output_bytes=512*1024)
            self.assertEqual(result.returncode, 0)
            self.assertLessEqual(len(result.stdout), 65560)
            self.assertLessEqual(len(result.stderr), 65560)
            self.assertIn('[truncated]', result.stdout)
            self.assertLessEqual(logpath.stat().st_size, 512*1024)

    def test_output_overflow_fails_and_kills_the_writer(self):
        import os, sys
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pidfile = root / 'pid'
            logpath = root / 'command.log'
            # Use a short literal to keep the command itself within the log budget.
            program = "import os,sys; open(sys.argv[1],'w').write(str(os.getpid())); exec(\"while True: os.write(1,b'x'*65536)\")"
            with logpath.open('w') as log, self.assertRaisesRegex(ValueError, 'output budget'):
                proof.run_command([sys.executable,'-c',program,str(pidfile)], root, os.environ, log,
                                  timeout=10, grace=1, max_output_bytes=4096)
            self.assertLessEqual(logpath.stat().st_size, 4096)
            self.assertIn('exit=output-limit', logpath.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)

    def test_metadata_capture_is_complete_within_the_same_output_budget(self):
        import os, sys
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (root/'metadata.log').open('w') as log:
                result = proof.run_command([sys.executable,'-c',"print('x'*100000)"], root, os.environ, log,
                                           capture_stdout=True)
            self.assertEqual(len(result.stdout), 100001)

if __name__ == "__main__":
    unittest.main()
