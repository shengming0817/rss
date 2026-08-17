import os
import importlib.util
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SUPERVISOR = REPO_ROOT / "hack" / "ci-local-supervisor.py"
SPEC = importlib.util.spec_from_file_location("ci_local_supervisor", SUPERVISOR)
assert SPEC is not None and SPEC.loader is not None
SUPERVISOR_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUPERVISOR_MODULE)


def wait_for_file(path: Path, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_for_process_exit(pid: int, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_exists(pid):
            return
        time.sleep(0.01)
    raise AssertionError(f"process {pid} survived supervisor cleanup")


@unittest.skipUnless(os.name == "posix", "process-group supervision is POSIX-only")
class CiLocalSupervisorTests(unittest.TestCase):
    def initialize_clean_repo(self, root: Path) -> None:
        subprocess.run(["/usr/bin/git", "init", "-q"], cwd=root, check=True)
        subprocess.run(
            [
                "/usr/bin/git",
                "-c",
                "user.name=CI Local",
                "-c",
                "user.email=ci-local@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "fixture",
            ],
            cwd=root,
            check=True,
        )

    def supervisor_command(self, repo_root: Path, *command: str) -> list[str]:
        return [
            "/usr/bin/python3",
            str(SUPERVISOR),
            "--repo-root",
            str(repo_root),
            "--budget-seconds",
            "0.15",
            "--term-grace-seconds",
            "0.05",
            "--",
            *command,
        ]

    def local_ci_command(
        self, repo_root: Path, cargo_wrapper: Path, *arguments: str
    ) -> list[str]:
        return [
            "/usr/bin/python3",
            str(SUPERVISOR),
            "--repo-root",
            str(repo_root),
            "--budget-seconds",
            "10",
            "--local-ci",
            "--cargo-wrapper",
            str(cargo_wrapper),
            "--",
            *arguments,
        ]

    def commit_all(self, root: Path, message: str) -> None:
        subprocess.run(["/usr/bin/git", "add", "."], cwd=root, check=True)
        subprocess.run(
            [
                "/usr/bin/git",
                "-c",
                "user.name=CI Local",
                "-c",
                "user.email=ci-local@example.invalid",
                "commit",
                "-qm",
                message,
            ],
            cwd=root,
            check=True,
        )

    def test_timeout_kills_a_term_ignoring_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.initialize_clean_repo(root)
            pid_file = root / "worker.pid"
            started = time.monotonic()
            completed = subprocess.run(
                self.supervisor_command(
                    root,
                    "/bin/sh",
                    "-c",
                    f"trap '' TERM; echo $$ > {pid_file!s}; sleep 30",
                ),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 124)
            self.assertIn("reason=timeout", completed.stderr)
            self.assertIn("phase=command", completed.stderr)
            self.assertIn("budget_seconds=0.150", completed.stderr)
            self.assertIn("elapsed_seconds=", completed.stderr)
            self.assertLess(time.monotonic() - started, 2.0)
            wait_for_file(pid_file)
            wait_for_process_exit(int(pid_file.read_text().strip()))

    def test_successful_leader_exit_still_cleans_its_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.initialize_clean_repo(root)
            pid_file = root / "descendant.pid"
            completed = subprocess.run(
                self.supervisor_command(
                    root,
                    "/bin/sh",
                    "-c",
                    f"trap '' TERM; sleep 30 & echo $! > {pid_file!s}; exit 0",
                ),
                check=False,
            )
            self.assertEqual(completed.returncode, 0)
            wait_for_file(pid_file)
            wait_for_process_exit(int(pid_file.read_text().strip()))

    def test_sigterm_is_forwarded_and_the_worker_group_is_reaped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.initialize_clean_repo(root)
            pid_file = root / "worker.pid"
            supervisor = subprocess.Popen(
                self.supervisor_command(
                    root,
                    "/bin/sh",
                    "-c",
                    f"trap '' TERM; echo $$ > {pid_file!s}; sleep 30",
                )
            )
            try:
                wait_for_file(pid_file)
                supervisor.send_signal(signal.SIGTERM)
                self.assertEqual(supervisor.wait(timeout=2.0), 128 + signal.SIGTERM)
                wait_for_process_exit(int(pid_file.read_text().strip()))
            finally:
                if supervisor.poll() is None:
                    supervisor.kill()
                    supervisor.wait()

    def test_reserved_worker_environment_cannot_bypass_supervision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "ran"
            environment = os.environ.copy()
            environment["RSS_CI_LOCAL_WORKER"] = "1"
            completed = subprocess.run(
                self.supervisor_command(root, "/usr/bin/touch", str(marker)),
                env=environment,
                check=False,
            )
            self.assertEqual(completed.returncode, 78)
            self.assertFalse(marker.exists())

    def test_hidden_worker_rejects_environment_only_handshake(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.initialize_clean_repo(root)
            wrapper = root / "wrapper.sh"
            wrapper.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            wrapper.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "RSS_CI_LOCAL_SUPERVISED": "1",
                    "RSS_CI_LOCAL_HANDSHAKE_FD": "0",
                    "RSS_CI_LOCAL_HANDSHAKE_TOKEN": "00" * 32,
                    "RSS_CI_LOCAL_DEADLINE": str(time.monotonic() + 10),
                }
            )
            completed = subprocess.run(
                [
                    "/usr/bin/python3",
                    str(SUPERVISOR),
                    "--repo-root",
                    str(root),
                    "--local-ci-worker",
                    "--cargo-wrapper",
                    str(wrapper),
                ],
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 78)
            self.assertIn("session and process-group leader", completed.stderr)

    def test_worker_deadline_cannot_extend_the_fixed_budget(self) -> None:
        now = time.monotonic()
        self.assertEqual(
            SUPERVISOR_MODULE.bounded_worker_deadline(now + 10_000, now),
            now + 600,
        )
        self.assertEqual(
            SUPERVISOR_MODULE.bounded_worker_deadline(now + 10, now),
            now + 10,
        )

    def test_non_finite_outer_budget_is_rejected(self) -> None:
        for value in ("nan", "inf", "-inf"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                completed = subprocess.run(
                    [
                        "/usr/bin/python3",
                        str(SUPERVISOR),
                        "--repo-root",
                        temporary,
                        f"--budget-seconds={value}",
                        "--",
                        "/usr/bin/true",
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn("budgets must be positive", completed.stderr)

    def test_dirty_xtask_runner_is_rejected_before_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "xtask" / "src").mkdir(parents=True)
            source = root / "xtask" / "src" / "main.rs"
            source.write_text("fn main() {}\n")
            subprocess.run(["/usr/bin/git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["/usr/bin/git", "add", "."], cwd=root, check=True)
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-c",
                    "user.name=CI Local",
                    "-c",
                    "user.email=ci-local@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                cwd=root,
                check=True,
            )
            source.write_text("fn main() { println!(\"dirty\"); }\n")
            marker = root / "ran"
            completed = subprocess.run(
                [
                    "/usr/bin/python3",
                    str(SUPERVISOR),
                    "--repo-root",
                    str(root),
                    "--budget-seconds",
                    "1",
                    "--",
                    "/usr/bin/touch",
                    str(marker),
                ],
                check=False,
            )
            self.assertEqual(completed.returncode, 78)
            self.assertFalse(marker.exists())

    def test_local_ci_runs_one_wrapper_from_the_committed_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            root = fixture / "caller"
            root.mkdir()
            self.initialize_clean_repo(root)
            (root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
            (root / "crates" / "workspacefacts" / "src").mkdir(parents=True)
            dependency = root / "crates" / "workspacefacts" / "src" / "lib.rs"
            dependency.write_text("pub const SOURCE: &str = \"committed\";\n")
            (root / ".github" / "scripts").mkdir(parents=True)
            adapter = root / ".github" / "scripts" / "ci-tool-adapters.sh"
            adapter.write_text("committed-adapter\n", encoding="utf-8")
            (root / "hack").mkdir()
            wrapper = root / "hack" / "cargo.sh"
            wrapper.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "{\n"
                "  printf 'cwd=%s\\n' \"$(pwd -P)\"\n"
                "  printf 'args=%s\\n' \"$*\"\n"
                "  printf 'dependency=%s\\n' \"$(cat crates/workspacefacts/src/lib.rs)\"\n"
                "  printf 'adapter=%s\\n' \"$(cat .github/scripts/ci-tool-adapters.sh)\"\n"
                "  printf 'untracked=%s\\n' \"$(test -e untracked.txt && echo present || echo absent)\"\n"
                "  printf 'ignored=%s\\n' \"$(test -e ignored.txt && echo present || echo absent)\"\n"
                "  printf 'injected=%s\\n' \"$(test -e injected.sh && echo present || echo absent)\"\n"
                "  printf 'worker=%s\\n' \"${RSS_CI_LOCAL_WORKER-unset}\"\n"
                "} >> \"$RSS_CAPTURE\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            self.commit_all(root, "committed runner")

            dependency.write_text("pub const SOURCE: &str = \"dirty\";\n")
            adapter.write_text("dirty-adapter\n", encoding="utf-8")
            (root / "untracked.txt").write_text("caller-only\n", encoding="utf-8")
            (root / "ignored.txt").write_text("caller-only\n", encoding="utf-8")

            capture = fixture / "capture.txt"
            environment = os.environ.copy()
            environment["RSS_CAPTURE"] = str(capture)
            head = subprocess.run(
                ["/usr/bin/git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            completed = subprocess.run(
                self.local_ci_command(root, wrapper, "--base", "HEAD"),
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            lines = capture.read_text(encoding="utf-8").splitlines()
            self.assertEqual(sum(line.startswith("cwd=") for line in lines), 1)
            cwd = Path(next(line.removeprefix("cwd=") for line in lines if line.startswith("cwd=")))
            self.assertNotEqual(cwd, root.resolve())
            self.assertEqual(
                [line for line in lines if line.startswith("args=")],
                [f"args=__ci-local-worker --base {head}"],
            )
            self.assertIn('dependency=pub const SOURCE: &str = "committed";', lines)
            self.assertIn("adapter=committed-adapter", lines)
            self.assertIn("untracked=absent", lines)
            self.assertIn("ignored=absent", lines)
            self.assertIn("injected=absent", lines)
            self.assertIn("worker=1", lines)
            for phase in (
                "revision.resolve",
                "snapshot.checkout",
                "xtask.worker",
                "total",
            ):
                self.assertIn(f"ci-local-profile: phase={phase} seconds=", completed.stderr)

            (cwd / "injected.sh").write_text("exit 99\n", encoding="utf-8")
            repeated = subprocess.run(
                self.local_ci_command(root, wrapper, "--base", "HEAD"),
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            repeated_lines = capture.read_text(encoding="utf-8").splitlines()
            self.assertEqual(sum(line.startswith("cwd=") for line in repeated_lines), 2)
            self.assertEqual(
                [line for line in repeated_lines if line.startswith("injected=")],
                ["injected=absent", "injected=absent"],
            )

            dependency_in_snapshot = cwd / "crates" / "workspacefacts" / "src" / "lib.rs"
            dependency_in_snapshot.write_text(
                'pub const SOURCE: &str = "poisoned-cache";\n', encoding="utf-8"
            )
            recovered = subprocess.run(
                self.local_ci_command(root, wrapper, "--base", "HEAD"),
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            recovered_lines = capture.read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                [line for line in recovered_lines if line.startswith("dependency=")],
                [
                    'dependency=pub const SOURCE: &str = "committed";',
                    'dependency=pub const SOURCE: &str = "committed";',
                    'dependency=pub const SOURCE: &str = "committed";',
                ],
            )

    def test_concurrent_cold_snapshot_publish_is_serialized_and_reused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            root = fixture / "caller"
            root.mkdir()
            self.initialize_clean_repo(root)
            (root / "hack").mkdir()
            wrapper = root / "hack" / "cargo.sh"
            wrapper.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "marker=$RSS_CAPTURE/$$\n"
                "printf '%s\\n' \"$(pwd -P)\" > \"$marker.cwd\"\n"
                "touch \"$marker.begin\"\n"
                "sleep 0.25\n"
                "touch \"$marker.end\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            self.commit_all(root, "committed runner")
            capture = fixture / "capture"
            capture.mkdir()
            environment = os.environ.copy()
            environment["RSS_CAPTURE"] = str(capture)
            command = self.local_ci_command(root, wrapper, "--base", "HEAD")
            first = subprocess.Popen(command, env=environment)
            try:
                deadline = time.monotonic() + 3
                while not list(capture.glob("*.begin")) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(list(capture.glob("*.begin")))
                second = subprocess.Popen(command, env=environment)
                self.assertEqual(first.wait(timeout=5), 0)
                self.assertEqual(second.wait(timeout=5), 0)
            finally:
                for process in (first, locals().get("second")):
                    if process is not None and process.poll() is None:
                        process.kill()
                        process.wait()
            begins = sorted(capture.glob("*.begin"), key=lambda path: path.stat().st_mtime_ns)
            ends = sorted(capture.glob("*.end"), key=lambda path: path.stat().st_mtime_ns)
            self.assertEqual(len(begins), 2)
            self.assertEqual(len(ends), 2)
            self.assertGreaterEqual(begins[1].stat().st_mtime_ns, ends[0].stat().st_mtime_ns)
            roots = {path.read_text(encoding="utf-8").strip() for path in capture.glob("*.cwd")}
            self.assertEqual(len(roots), 1)
            cache = Path(next(iter(roots))).parent.parent
            self.assertEqual(len([path for path in cache.iterdir() if len(path.name) == 40]), 1)

    def test_snapshot_retention_skips_active_revision_then_reclaims_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            revisions = [f"{index:040x}" for index in range(10)]
            for index, revision in enumerate(revisions):
                snapshot = cache / revision
                snapshot.mkdir()
                os.utime(snapshot, (index, index))
            active = SUPERVISOR_MODULE.acquire_snapshot_ownership(
                cache, revisions[0], time.monotonic() + 1
            )
            self.assertIsNotNone(active)
            SUPERVISOR_MODULE.collect_snapshot_cache(
                cache, revisions[-1], time.monotonic() + 1
            )
            self.assertTrue((cache / revisions[0]).is_dir())
            active.release()
            SUPERVISOR_MODULE.collect_snapshot_cache(
                cache, revisions[-1], time.monotonic() + 1
            )
            self.assertFalse((cache / revisions[0]).exists())
            self.assertLessEqual(len(SUPERVISOR_MODULE.snapshot_revisions(cache)), 8)

    def test_snapshot_lock_deadline_returns_timeout_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.initialize_clean_repo(root)
            wrapper = root / "wrapper.sh"
            wrapper.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            wrapper.chmod(0o755)
            revision = subprocess.run(
                ["/usr/bin/git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            cache = SUPERVISOR_MODULE.repository_cache_root(root)
            SUPERVISOR_MODULE.ensure_private_directory(cache)
            ownership = SUPERVISOR_MODULE.acquire_snapshot_ownership(
                cache, revision, time.monotonic() + 1
            )
            self.assertIsNotNone(ownership)
            reader, writer = os.pipe()
            token = b"d" * 32
            os.write(writer, token * 3)
            os.close(writer)
            environment = os.environ.copy()
            environment.update(
                {
                    "RSS_CI_LOCAL_SUPERVISED": "1",
                    "RSS_CI_LOCAL_HANDSHAKE_FD": str(reader),
                    "RSS_CI_LOCAL_HANDSHAKE_TOKEN": token.hex(),
                    "RSS_CI_LOCAL_DEADLINE": str(time.monotonic() + 0.15),
                }
            )
            try:
                completed = subprocess.run(
                    [
                        "/usr/bin/python3",
                        str(SUPERVISOR),
                        "--repo-root",
                        str(root),
                        "--local-ci-worker",
                        "--cargo-wrapper",
                        str(wrapper),
                        "--",
                        "--base",
                        "HEAD",
                    ],
                    env=environment,
                    pass_fds=(reader,),
                    start_new_session=True,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            finally:
                os.close(reader)
                ownership.release()
            self.assertEqual(completed.returncode, 124, completed.stderr)
            self.assertIn("timed out waiting for committed snapshot ownership", completed.stderr)


if __name__ == "__main__":
    unittest.main()
