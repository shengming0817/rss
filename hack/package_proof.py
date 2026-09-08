#!/usr/bin/env python3
"""Run the extraction examples against independently resolved sources or exact archives."""

import hashlib
import gzip
from contextlib import contextmanager
import json
import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import selectors
import time
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
MAX_COMPRESSED_BYTES = 16 * 1024 * 1024
MAX_TAR_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_CONTENT_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 4096

def archive_digest(path):
    if path.stat().st_size > MAX_COMPRESSED_BYTES:
        raise ValueError("compressed archive budget exceeded")
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


@contextmanager
def bounded_archive(path):
    """Bound decompression, including PAX headers/padding, before tarfile parses it."""
    if path.stat().st_size > MAX_COMPRESSED_BYTES:
        raise ValueError("compressed archive budget exceeded")
    with tempfile.TemporaryFile() as raw, gzip.open(path, "rb") as source:
        size = 0
        while block := source.read(min(1024 * 1024, MAX_TAR_BYTES + 1 - size)):
            size += len(block)
            if size > MAX_TAR_BYTES:
                raise ValueError("decompressed archive budget exceeded")
            raw.write(block)
        raw.seek(0)
        with tarfile.open(fileobj=raw, mode="r:") as archive:
            yield archive


def checked_members(archive, prefix):
    seen, total = set(), 0
    for member in archive:
        total += member.size
        if (len(seen) >= MAX_MEMBERS or member.size < 0 or member.size > MAX_MEMBER_BYTES
                or total > MAX_CONTENT_BYTES):
            raise ValueError("archive member budget exceeded")
        parts = PurePosixPath(member.name).parts
        canonical = "/".join(parts)
        spelling = member.name.removesuffix("/") if member.isdir() else member.name
        if (not parts or parts[0] != prefix or ".." in parts
                or "\\" in member.name or spelling != canonical or member.issparse()
                or not (member.isfile() or member.isdir()) or canonical in seen):
            raise ValueError(f"unsafe archive member: {member.name}")
        seen.add(canonical)
        yield member


def candidate_archives(directory, revision, versions):
    """Validate inventory, bytes, Cargo identity and safe extraction before using any archive."""
    rows = {}
    for line in (directory / "packages.tsv").read_text().splitlines():
        name, version, sha = line.split("\t")
        if name in rows:
            raise ValueError(f"duplicate package: {name}")
        if sha != revision:
            raise ValueError(f"revision mismatch: {name}")
        rows[name] = version
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, filename = line.split()
        if filename in sums:
            raise ValueError(f"duplicate checksum: {filename}")
        sums[filename] = digest
    result = {}
    for name, version in versions.items():
        if rows.get(name) != version:
            raise ValueError(f"missing package or version mismatch: {name}")
        path = directory / f"{name}-{version}.crate"
        if archive_digest(path) != sums.get(path.name):
            raise ValueError(f"checksum mismatch: {path.name}")
        prefix = f"{name}-{version}"
        with bounded_archive(path) as archive:
            list(checked_members(archive, prefix))
            vcs = json.load(archive.extractfile(f"{prefix}/.cargo_vcs_info.json"))["git"]
            if vcs.get("sha1") != revision or vcs.get("dirty", False):
                raise ValueError(f"revision mismatch or dirty archive: {name}")
            manifest = tomllib.loads(archive.extractfile(f"{prefix}/Cargo.toml").read().decode())
            if (manifest["package"]["name"], manifest["package"]["version"]) != (name, version):
                raise ValueError(f"archive package version mismatch: {name}")
            reject_source_dependencies(manifest)
        result[name] = path
    if not result:
        raise ValueError("empty artifact selection")
    return result


def reject_source_dependencies(table):
    """Normalized packaged dependencies must resolve without original source paths."""
    for key, value in table.items():
        if key in ("dependencies", "build-dependencies", "dev-dependencies"):
            for dependency in value.values():
                if isinstance(dependency, dict) and ("path" in dependency or "workspace" in dependency):
                    raise ValueError("normalized archive contains a source dependency")
        elif isinstance(value, dict):
            reject_source_dependencies(value)


def validate_graph(facts, consumer_root, allowed_paths, expected_message_features, forbidden_names, *, required_features=None, required_dependencies=()):
    """Reject workspace leakage, provider leakage and unintended feature unification."""
    if Path(facts["workspace_root"]).resolve() != consumer_root.resolve():
        raise ValueError("consumer joined another workspace")
    if "target_directory" in facts and Path(facts["target_directory"]).resolve() != (consumer_root / "target").resolve():
        raise ValueError("consumer uses another workspace target directory")
    root_id = facts["resolve"]["root"]
    nodes = {node["id"]: node for node in facts["resolve"]["nodes"]}
    for package in facts["packages"]:
        if package["id"] not in nodes:
            continue
        name = package["name"]
        if name in forbidden_names:
            raise ValueError(f"forbidden dependency: {name}")
        source = Path(package["manifest_path"]).parent.resolve()
        if package["id"] == root_id:
            if source != consumer_root.resolve():
                raise ValueError("wrong consumer source")
        elif name.startswith("rss-") or package["source"] is None:
            if name not in allowed_paths or source != allowed_paths[name].resolve():
                raise ValueError(f"unexpected dependency source: {name}: {source}")
        if name == "rss-transactional-messaging":
            actual = set(nodes[package["id"]]["features"])
            if actual != expected_message_features:
                raise ValueError(f"message feature mismatch: {actual} != {expected_message_features}")

    resolved = {p['name']: set(nodes[p['id']]['features']) for p in facts['packages'] if p['id'] in nodes}
    if not set(required_dependencies) <= resolved.keys():
        raise ValueError('consumer dependency missing')
    for name, expected in (required_features or {}).items():
        actual = resolved.get(name)
        if actual != expected:
            raise ValueError(f'feature mismatch for {name}: {actual} != {expected}')


def selected_dependencies(manifest, selected, workspace):
    """Expand this example's additive feature declarations into explicit consumer dependencies."""
    features, dependencies, additions = set(), set(), {}
    pending = list(selected)
    while pending:
        feature = pending.pop()
        if feature in features:
            continue
        features.add(feature)
        for item in manifest["features"][feature]:
            if item.startswith("dep:"):
                dependencies.add(item[4:])
            elif "/" in item:
                dependency, enabled = item.split("/", 1)
                dependencies.add(dependency)
                additions.setdefault(dependency, set()).add(enabled)
            else:
                pending.append(item)
    resolved = {}
    for name, value in manifest["dependencies"].items():
        if value.get("optional") and name not in dependencies:
            continue
        if value.get("workspace"):
            inherited = workspace["dependencies"][name]
            inherited = {"version": inherited} if isinstance(inherited, str) else inherited
            value = {**inherited, **value, "features": list(set(inherited.get("features", [])) | set(value.get("features", [])))}
        else:
            value = dict(value)
        value.pop("workspace", None)
        value.pop("optional", None)
        value["features"] = sorted(set(value.get("features", [])) | additions.get(name, set()))
        resolved[name] = value
    return features, resolved


def run_command(command, directory, environment, log, *, timeout=600, grace=60,
                max_output_bytes=16 * 1024 * 1024, capture_stdout=False):
    """Bound log + scratch bytes; return 64 KiB tails, or explicitly bounded metadata.

    ref: CPython Lib/subprocess.py Popen._communicate@v3.14.6 (selector pipe drain).
    TERM allows the fixture launcher's 20s child + 30s resource cleanup before KILL.
    """
    header = '$ ' + ' '.join(command) + '\n'
    remaining = max_output_bytes - log.tell() - len(header.encode()) - 512
    if remaining < 0:
        raise ValueError('command output budget exhausted')
    log.write(header)
    log.flush()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, selectors.DefaultSelector() as selector:
        process = subprocess.Popen(command, cwd=directory, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        for pipe, spool in ((process.stdout, out), (process.stderr, err)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, spool)

        def signal_group(sig):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass

        def drain_until(deadline, *, collect):
            nonlocal remaining
            while selector.get_map() or process.poll() is None:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in selector.select(min(wait, 0.1)):
                    try:
                        block = os.read(key.fd, 32768)
                    except BlockingIOError:
                        continue
                    if not block:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    elif collect:
                        accepted = block[:remaining]
                        key.data.write(accepted)
                        remaining -= len(accepted)
                        if len(block) != len(accepted):
                            raise ValueError('command output budget exceeded')

        def log_output():
            # Preserve per-stream ordering: libtest's stdout result must not be split by stderr.
            log.flush()
            for spool in (out, err):
                spool.seek(0)
                shutil.copyfileobj(spool, log.buffer, length=32768)
            log.buffer.flush()

        def interrupt(_signal, _frame):
            raise KeyboardInterrupt

        previous = signal.signal(signal.SIGTERM, interrupt)
        try:
            try:
                drain_until(time.monotonic() + timeout, collect=True)
            except BaseException as error:
                signal_group(signal.SIGTERM)
                try:
                    drain_until(time.monotonic() + grace, collect=False)
                except subprocess.TimeoutExpired:
                    signal_group(signal.SIGKILL)
                    drain_until(time.monotonic() + 5, collect=False)
                finally:
                    signal_group(signal.SIGKILL)
                    kind = ('timeout' if isinstance(error, subprocess.TimeoutExpired) else
                            'output-limit' if isinstance(error, ValueError) else 'process-error')
                    log_output()
                    log.write(f'\nexit={kind} timeout={timeout}\n')
                    log.flush()
                raise
        finally:
            signal.signal(signal.SIGTERM, previous)
            for pipe in (process.stdout, process.stderr):
                pipe.close()
            if process.poll() is None:
                signal_group(signal.SIGKILL)
                process.wait(timeout=5)
        log_output()
        log.write(f'\nexit={process.returncode}\n')
        log.flush()

        def captured(spool, complete=False):
            size = spool.tell()
            start = 0 if complete else max(0, size - 65536)
            spool.seek(start)
            return ('[truncated]\n' if start else '') + spool.read(max_output_bytes).decode(errors='replace')

        return subprocess.CompletedProcess(command, process.returncode,
                                           captured(out, capture_stdout), captured(err))


def cargo(command, directory, *, success=True):
    validate_cargo_config(directory, os.environ)
    env = cargo_environment(os.environ)
    env["CARGO_TARGET_DIR"] = str(directory / "target")
    with (directory / "commands.log").open("a") as log:
        result = run_command(["cargo", *command], directory, env, log, capture_stdout=command[0] == "metadata")
    if (result.returncode == 0) != success:
        raise ValueError(f"unexpected Cargo result: {directory}/commands.log\n{result.stderr[-4000:]}")
    return result.stdout if success else result.stderr


def inline_table(value):
    return "{ " + ", ".join(f"{json.dumps(key)} = {json.dumps(item)}" for key, item in value.items()) + " }"


def consumer(directory, features, dependencies, allowed):
    directory.mkdir()
    shutil.copytree(ROOT / "crates/examples/src", directory / "src")
    shutil.copytree(ROOT / "crates/examples/fixtures", directory / "fixtures")
    lines = ['[package]', 'name = "rss-examples"', 'version = "0.0.0"', 'edition = "2024"', 'autobins = false', 'default-run = "rss-examples"', '[workspace]', 'resolver = "2"', '[features]', 'default = ' + json.dumps(sorted(features))]
    declared = tomllib.loads((ROOT / "crates/examples/Cargo.toml").read_text())["features"]
    lines += [f'{json.dumps(feature)} = []' for feature in sorted(set(declared) - {"default"})]
    lines += ['[dependencies]']
    for name, dependency in dependencies.items():
        dependency = dict(dependency)
        if name in allowed:
            dependency.pop("path", None)
            dependency["version"] = "=" + dependency["version"].lstrip("=")
        lines.append(f'{json.dumps(name)} = {inline_table(dependency)}')
    lines.append('[patch.crates-io]')
    lines += [f'{json.dumps(name)} = {{ path = {json.dumps(str(path))} }}' for name, path in sorted(allowed.items())]
    lines += ['[[bin]]', 'name = "rss-examples"', 'path = "src/main.rs"']
    targets = tomllib.loads((ROOT / "crates/examples/Cargo.toml").read_text()).get("bin", [])
    for target in targets:
        if set(target.get("required-features", [])) <= features:
            lines += ['[[bin]]', 'name = ' + json.dumps(target['name']), 'path = ' + json.dumps(target['path'])]
    (directory / "Cargo.toml").write_text("\n".join(lines) + "\n")
    # A copied lock is a seed, never a shared lock. Cargo independently resolves this manifest.
    shutil.copyfile(ROOT / "Cargo.lock", directory / "Cargo.lock")


def package_closure(metadata, seeds):
    packages = {p["name"]: p for p in metadata["packages"]}
    selected, pending = {}, list(seeds)
    release = {p["package"] for p in metadata["metadata"]["release-surface"]["packages"]}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        if name not in release:
            raise ValueError(f"internal dependency is not a candidate: {name}")
        package = packages[name]
        selected[name] = package
        pending.extend(dep["name"] for dep in package["dependencies"] if dep["kind"] != "dev" and dep.get("path"))
    return selected


def validate_cargo_config(directory, environment):
    """Inspect every inherited config; final metadata remains the source-of-truth check."""
    configs = {parent / '.cargo' / name for parent in (directory, *directory.parents)
               for name in ('config', 'config.toml')}
    cargo_home = Path(environment.get('CARGO_HOME', str(Path.home() / '.cargo'))).resolve()
    configs.update(cargo_home / name for name in ('config', 'config.toml'))
    for path in sorted(configs):
        if path.is_file():
            config = tomllib.loads(path.read_text())
            if any(key in config for key in ('source', 'patch', 'paths', 'include')) or compiler_config(config):
                raise ValueError(f'inherited Cargo dependency override: {path}')
    for key in environment:
        if key.startswith(('CARGO_SOURCE_', 'CARGO_PATCH_', 'CARGO_ALIAS_')):
            raise ValueError(f'Cargo execution/source override: {key}')


def validate_execution(log, test_name, binaries):
    if log.count(f'test {test_name} ... ok') != 1:
        raise ValueError('provider test did not run exactly once')
    for binary in binaries:
        if log.count(f'external-provider-consumer PASS {binary}\n') != 1:
            raise ValueError('consumer did not run exactly once')

def require_candidate_revision(revision):
    head = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(['/usr/bin/git', 'status', '--porcelain'], cwd=ROOT, text=True)
    if head != revision or dirty:
        raise ValueError('artifact scenarios require the same clean candidate revision')


def proof_arguments(scenarios):
    parser = argparse.ArgumentParser(description='Independent public consumer proof')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--source', action='store_true')
    mode.add_argument('--artifacts', type=Path)
    parser.add_argument('--revision')
    parser.add_argument('--scenario', choices=scenarios, action='append')
    args = parser.parse_args()
    if bool(args.artifacts) != bool(args.revision):
        parser.error('--revision must accompany --artifacts only')
    return args


def example_dependencies(scenarios):
    manifest = tomllib.loads((ROOT / 'crates/examples/Cargo.toml').read_text())
    workspace = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']
    return {name: selected_dependencies(manifest, features, workspace) for name, features in scenarios.items()}


def prepare_sources(args, dependencies, prefix):
    """Validate and materialize source paths; does not select or execute scenarios."""
    if args.artifacts:
        require_candidate_revision(args.revision)
    validate_cargo_config(ROOT, os.environ)
    output = ROOT / 'rss-external-check'
    output.mkdir(exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=prefix + ('source-' if args.source else 'artifact-'), dir=output))
    with (root / 'metadata.log').open('w') as log:
        result = run_command(['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'],
                             ROOT, cargo_environment(os.environ), log, capture_stdout=True)
        result.check_returncode()
    facts = json.loads(result.stdout)
    closure = package_closure(facts, {name for name in dependencies if name.startswith('rss-')})
    if args.source:
        allowed = {name: Path(p['manifest_path']).parent for name, p in closure.items()}
    else:
        archives = candidate_archives(args.artifacts.resolve(), args.revision, {n:p['version'] for n,p in closure.items()})
        extracted = root / 'extracted'
        extracted.mkdir()
        for name, path in archives.items():
            with bounded_archive(path) as archive:
                members = list(checked_members(archive, path.stem))
                archive.extractall(extracted, members=members, filter='data')
            print(f'artifact\t{name}\t{closure[name]["version"]}\t{args.revision}\t{archive_digest(path)}', flush=True)
        allowed = {name: extracted / f'{name}-{p["version"]}' for name,p in closure.items()}
    print(f'proof output: {root}', flush=True)
    return root, allowed


def compiler_override(key):
    return key in {'RUSTC', 'RUSTDOC', 'RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTC_WRAPPER',
                   'RUSTC_WORKSPACE_WRAPPER', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS'} or (
        key.startswith(('CARGO_BUILD_', 'CARGO_TARGET_')) and key.endswith(
            ('RUSTC', 'RUSTDOC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS', 'RUSTDOCFLAGS', 'RUNNER', 'LINKER')))


def cargo_environment(environment):
    # Source/build overrides, including a trusted CI cache wrapper, do not enter isolated consumers.
    return {key: value for key, value in environment.items()
            if key != 'CARGO_TARGET_DIR' and not compiler_override(key)}


def compiler_config(table):
    for key, value in table.items():
        if key in {'rustc', 'rustdoc', 'rustc-wrapper', 'rustc-workspace-wrapper',
                   'rustflags', 'rustdocflags', 'runner', 'linker'} or compiler_override(key):
            return True
        if isinstance(value, dict) and compiler_config(value):
            return True
    return False
