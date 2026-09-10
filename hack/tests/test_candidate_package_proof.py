"""The five consumer entrances must reject relabelled/unsafe Cargo archives."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack
import subprocess

HACK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HACK))
import package_proof

REVISION = "a" * 40
ENTRIES = ("axum", "mqtt", "ledger", "observation", "recovery")


def bundle(root, *, sha=REVISION, dirty=False, extra=None):
    name = "rss-sample-0.1.0"
    files = {
        "Cargo.toml": b'[package]\nname="rss-sample"\nversion="0.1.0"\n',
        ".cargo_vcs_info.json": json.dumps(
            {"git": {"sha1": sha, "dirty": dirty}}
        ).encode(),
        "src/lib.rs": b"pub fn value() -> u8 { 1 }",
    }
    files.update(extra or {})
    path = root / (name + ".crate")
    with tarfile.open(path, "w:gz") as archive:
        for filename, data in files.items():
            info = tarfile.TarInfo(name + "/" + filename)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    (root / "packages.tsv").write_text(f"rss-sample\t0.1.0\t{REVISION}\n")
    (root / "SHA256SUMS").write_text(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n"
    )
    return path


class Entrances(unittest.TestCase):
    def test_each_main_rejects_relabelled_archive_before_consumer_creation(self):
        metadata = {
            "packages": [
                {"name": "rss-sample", "version": "0.1.0", "dependencies": []}
            ],
            "metadata": {"release-surface": {"packages": [{"package": "rss-sample"}]}},
        }
        for entry in ENTRIES:
            spec = importlib.util.spec_from_file_location(
                entry, HACK / f"{entry}-package-proof.py"
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with self.subTest(
                entry=entry
            ), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                root = Path(temp)
                bundle(root, sha="b" * 40)
                stack.enter_context(
                    patch.object(
                        sys,
                        "argv",
                        [entry, "--artifacts", temp, "--revision", REVISION],
                    )
                )
                stack.enter_context(patch.object(package_proof, "ROOT", root))
                stack.enter_context(
                    patch.object(package_proof, "require_candidate_revision")
                )
                stack.enter_context(
                    patch.object(
                        package_proof,
                        "run_command",
                        return_value=subprocess.CompletedProcess(
                            [], 0, json.dumps(metadata), ""
                        ),
                    )
                )
                if entry == "axum":
                    stack.enter_context(patch.object(module, "ROOTS", {"rss-sample"}))
                    stack.enter_context(
                        patch.object(
                            module, "platform_source", return_value="fn main() {}"
                        )
                    )
                else:
                    stack.enter_context(
                        patch.object(
                            module,
                            "example_dependencies",
                            return_value={
                                "core": (set(), {"rss-sample": {"version": "0.1.0"}})
                            },
                        )
                    )
                with self.assertRaisesRegex(
                    ValueError, "revision mismatch or dirty archive"
                ):
                    module.main()
                self.assertEqual(
                    list((root / "rss-external-check").rglob("Cargo.toml")), []
                )

    def test_implicit_packaging_and_ambiguous_modes_are_rejected(self):
        import subprocess

        for entry in ENTRIES:
            for flags in (
                [],
                ["--source", "--revision", REVISION],
                ["--source", "--artifacts", "/candidate"],
            ):
                with self.subTest(entry=entry, flags=flags):
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(HACK / f"{entry}-package-proof.py"),
                            *flags,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)


class FeatureForwarding(unittest.TestCase):
    def test_removed_forwarding_fails_each_entry_before_build_or_provider(self):
        """Resolve mutated consumer manifests with real Cargo; never edit the workspace."""
        import tomllib
        import copy

        root = HACK.parent
        manifest = tomllib.loads((root / "crates/examples/Cargo.toml").read_text())
        workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
        allowed = {
            tomllib.loads(path.read_text())["package"]["name"]: path.parent
            for path in (root / "crates").glob("*/Cargo.toml")
        }
        cases = (
            ("ledger", "all", "ledger-all", "rss-ledger-postgres/integration"),
            ("observation", "projection", "observation-projection", "rss-observation-postgres/projection"),
            ("observation", "projection-postgres", "observation-handoff", "rss-observation-postgres/projection-postgres"),
            ("recovery", "postgres", "recovery-pg", "rss-transactional-messaging-postgres/recovery"),
            ("recovery", "managed", "recovery-managed", "rss-transactional-messaging-postgres/rss-runtime"),
        )
        for entry, scenario, feature, forwarding in cases:
            spec = importlib.util.spec_from_file_location(entry, HACK / f"{entry}-package-proof.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            mutated = copy.deepcopy(manifest)
            mutated["features"][feature].remove(forwarding)
            features, deps = package_proof.selected_dependencies(mutated, [feature], workspace)
            with self.subTest(forwarding=forwarding), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                stack.enter_context(patch.object(sys, "argv", [entry, "--source", "--scenario", scenario]))
                stack.enter_context(patch.object(module, "example_dependencies", return_value={scenario: (features, deps)}))
                stack.enter_context(patch.object(module, "prepare_sources", return_value=(Path(temp), allowed)))
                stack.enter_context(patch.object(module, "cargo", side_effect=AssertionError("mutated graph reached build")))
                stack.enter_context(patch.object(module, "provider_consumer", side_effect=AssertionError("mutated graph reached provider")))
                with self.assertRaisesRegex(ValueError, "feature mismatch"):
                    module.main()
