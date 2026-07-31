import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SUPERVISOR = REPO_ROOT / "hack" / "ci-local-supervisor.py"


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
            )
            self.assertEqual(completed.returncode, 124)
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

    def test_ambient_ledger_capability_is_rejected_as_pair_or_partial(self) -> None:
        cases = (
            {"RSS_LOCAL_CI_LEDGER_PATH": "/tmp/foreign-ledger"},
            {"RSS_LOCAL_CI_LEDGER_BRANCH": "foreign-branch"},
            {
                "RSS_LOCAL_CI_LEDGER_PATH": "/tmp/foreign-ledger",
                "RSS_LOCAL_CI_LEDGER_BRANCH": "foreign-branch",
            },
        )
        for injected in cases:
            with self.subTest(injected=injected), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                marker = root / "ran"
                environment = os.environ.copy()
                environment.update(injected)
                completed = subprocess.run(
                    self.supervisor_command(root, "/usr/bin/touch", str(marker)),
                    env=environment,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(completed.returncode, 78)
                self.assertFalse(marker.exists())

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


if __name__ == "__main__":
    unittest.main()
