#!/usr/bin/env python3
"""Whole-command target lease; Cargo/Make remain the owners of CI checks.

Extracted from baseline 5b63e10a1b396b0ff70b7d1e6e55db296cd7a891,
hack/target-pool.py. Kernel locks replace its PID leases and age-broken locks.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

SCCACHE_VERSION = "0.15.0"


def log(message):
    print(f"rss-ci: {message}", file=sys.stderr, flush=True)


def directory(path):
    if path.is_symlink():
        raise ValueError(f"refusing symlink directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def lock_file(path, blocking=True):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
    except BlockingIOError:
        os.close(fd)
        return None
    except BaseException:
        os.close(fd)
        raise
    return fd


def metadata(root, index):
    try:
        path = root / f"slot-{index}.json"
        if path.is_symlink():
            raise ValueError(f"refusing symlink metadata: {path}")
        value = json.loads(path.read_text())
        if (type(value) is dict and type(value.get("worktree")) is str
                and type(value.get("last_used")) in (int, float)):
            return value
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def write_metadata(root, index, value):
    temporary = root / f".lease-{index}-{os.getpid()}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream)
    os.replace(temporary, root / f"slot-{index}.json")


def pool_identity(root, initialize=False):
    marker = root / '.rss-target-pool-v1'
    if not marker.exists() and not marker.is_symlink() and initialize:
        if any(p.name != '.pool.lock' for p in root.iterdir()):
            raise ValueError('refusing unmarked nonempty pool directory')
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write('rss-target-pool:1\n')
    fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        if stream.read() != 'rss-target-pool:1\n':
            raise ValueError('invalid pool identity')


def wipe(root, index):
    pool_identity(root)
    slot = root / f"slot-{index}"
    if slot.is_symlink():
        raise ValueError(f"refusing symlink slot: {slot}")
    if slot.exists():
        shutil.rmtree(slot)
    slot.mkdir()


def acquire(root, slots, worktree):
    root = directory(root)
    global_fd = lock_file(root / ".pool.lock")
    held = {}
    try:
        if any(root.glob("slot-*/lease.json")):
            raise ValueError("legacy pool detected; stop old builds and reset the pool explicitly")
        pool_identity(root, initialize=True)
        locks = directory(root / ".locks")
        indices = set(range(slots))
        indices.update(int(p.name[5:]) for p in root.glob("slot-*")
                       if re.fullmatch(r"slot-[0-9]+", p.name))
        candidates = []
        for index in sorted(indices):
            slot = root / f"slot-{index}"
            if slot.is_symlink():
                raise ValueError(f"refusing symlink slot: {slot}")
            value = metadata(root, index)
            fd = lock_file(locks / str(index), blocking=False)
            if fd is None:
                if value and value["worktree"] == str(worktree):
                    raise ValueError("this worktree already has an active CI run")
                continue
            held[index] = fd
            if index >= slots:
                pool_identity(root)
                if slot.exists():
                    shutil.rmtree(slot)
                (root / f"slot-{index}.json").unlink(missing_ok=True)
                continue
            rank = (0 if value and value["worktree"] == str(worktree) else
                    1 if value is None else
                    2 if not Path(value["worktree"]).exists() else 3)
            candidates.append((rank, value["last_used"] if value else 0, index))
        if not candidates:
            raise ValueError(f"pool full ({slots} slots)")
        rank, _, index = min(candidates)
        if rank != 0:
            wipe(root, index)
        else:
            directory(root / f"slot-{index}")
        write_metadata(root, index, {"worktree": str(worktree), "last_used": time.time(), "pid": None})
        return root, index, held.pop(index)
    finally:
        for fd in held.values():
            os.close(fd)
        os.close(global_fd)


def target_config(env, worktree):
    raw = env.get("RSS_TARGET_POOL_N", "6")
    if raw in ("off", "0"):
        return None, Path(env.get("CARGO_TARGET_DIR", str(worktree / "target"))).absolute()
    if not re.fullmatch(r"[1-9][0-9]*", raw):
        raise ValueError("RSS_TARGET_POOL_N must be positive, 0 or off")
    if "CARGO_TARGET_DIR" in env:
        if "RSS_TARGET_POOL_N" in env:
            raise ValueError("explicit pool and CARGO_TARGET_DIR conflict")
        if not env["CARGO_TARGET_DIR"]:
            raise ValueError("CARGO_TARGET_DIR must not be empty")
        return None, Path(env["CARGO_TARGET_DIR"]).absolute()
    root = Path(env.get("RSS_TARGET_POOL_ROOT", str(Path.home() / ".cache/rss-cargo-target-pool")))
    return (root.absolute(), int(raw)), None


def compiler_cache(env):
    mode = env.get("RSS_COMPILER_CACHE", "auto")
    if mode not in ("auto", "on", "off"):
        raise ValueError("RSS_COMPILER_CACHE must be auto, on or off")
    if mode == "off":
        return None
    wrappers = ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER",
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")
    reason = "custom rustc wrapper" if any(env.get(k) for k in wrappers) else None
    binary = shutil.which("sccache", path=env.get("PATH"))
    if reason is None:
        try:
            version = subprocess.run([binary, "--version"], env=env, capture_output=True,
                                     text=True, timeout=10) if binary else None
            if version is None or version.returncode or version.stdout.strip() != f"sccache {SCCACHE_VERSION}":
                reason = f"sccache {SCCACHE_VERSION} unavailable"
        except (OSError, subprocess.TimeoutExpired):
            reason = f"sccache {SCCACHE_VERSION} unavailable"
    if reason:
        if mode == "on":
            raise ValueError(reason)
        log(f"compiler-cache disabled: {reason}")
        return None
    root = Path.home() / ".cache/rss-sccache"
    env.setdefault("SCCACHE_DIR", str(root / "objects"))
    env.setdefault("SCCACHE_SERVER_UDS", str(root / "server.sock"))
    env["SCCACHE_DIR"] = str(directory(Path(env["SCCACHE_DIR"])))
    uds = Path(env["SCCACHE_SERVER_UDS"])
    env["SCCACHE_SERVER_UDS"] = str(directory(uds.parent) / uds.name)
    # Start before acquiring any slot: the persistent daemon must never inherit its lock.
    try:
        if len(os.fsencode(env["SCCACHE_SERVER_UDS"])) >= 100:
            raise OSError("sccache socket path is too long")
        startup_fd = lock_file(Path(env["SCCACHE_SERVER_UDS"] + ".lock"))
        try:
            def connect():
                with socket.socket(socket.AF_UNIX) as connection:
                    connection.settimeout(5)
                    connection.connect(env["SCCACHE_SERVER_UDS"])
            try:
                connect()
            except (FileNotFoundError, ConnectionRefusedError):
                # --start-server unlinks an existing Unix socket: never call it on a live server.
                subprocess.run([binary, "--start-server"], env=env, capture_output=True, timeout=15)
                connect()
        finally:
            os.close(startup_fd)
        probe = subprocess.run([binary, "--show-stats", "--stats-format", "json"],
                               env=env, capture_output=True, text=True, timeout=15)
        stats = json.loads(probe.stdout)
        expected = f'Local disk: "{Path(env["SCCACHE_DIR"]).resolve()}"'
        if probe.returncode or stats.get("version") != SCCACHE_VERSION or stats.get("cache_location") != expected:
            raise OSError("server version/cache directory differs; restart the RSS server explicitly")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        if mode == "on":
            raise ValueError(f"sccache startup failed: {error}") from error
        log(f"compiler-cache disabled: {error}")
        return None
    env.update(RUSTC_WRAPPER=binary, CARGO_INCREMENTAL="0", SCCACHE_IGNORE_SERVER_IO_ERROR="1")
    log(f"compiler-cache enabled version={SCCACHE_VERSION} dir={env['SCCACHE_DIR']}")
    return binary


def main(argv):
    if not argv or argv[0] != "--" or len(argv) < 2:
        raise ValueError("usage: ci-run.py -- COMMAND [ARG...]")
    env = os.environ.copy()
    worktree = Path.cwd().resolve()
    pool, target = target_config(env, worktree)
    binary = compiler_cache(env)
    lease = acquire(*pool, worktree) if pool else None
    try:
        if lease:
            root, index, fd = lease
            target = root / f"slot-{index}"
        env["CARGO_TARGET_DIR"] = str(target)
        log(f"target={target} pool={'enabled' if lease else 'off'}")
        process = None
        pending = []
        previous = {}
        def forward(sig, _frame):
            if process is None:
                pending.append(sig)
                return
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[sig] = signal.signal(sig, forward)
        try:
            process = subprocess.Popen(argv[1:], env=env, start_new_session=True,
                                       pass_fds=(lease[2],) if lease else ())
            for sig in pending:
                forward(sig, None)
            if lease:
                write_metadata(root, index, {"worktree": str(worktree), "last_used": time.time(), "pid": process.pid})
            result = process.wait()
        finally:
            if process is not None and process.poll() is None:
                forward(signal.SIGTERM, None)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    forward(signal.SIGKILL, None)
                    process.wait()
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        if binary and env.get("GITHUB_ACTIONS") != "true":
            log("sccache server cumulative statistics (shared by concurrent runs)")
            try:
                subprocess.run([binary, "--show-stats"], env=env, timeout=10, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                log(f"statistics unavailable: {error}")
        return result if result >= 0 else 128 - result
    finally:
        if lease:
            # Never LOCK_UN: descendants may still own this same open file description.
            os.close(lease[2])


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError) as error:
        log(str(error))
        sys.exit(2)
