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
