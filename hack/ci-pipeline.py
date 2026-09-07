#!/usr/bin/env python3
"""Canonical selection, archive execution and coverage aggregation behind Make.

ref: cargo-llvm-cov v0.8.7 src/report.rs (nextest archive objects), nextest archive metadata.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
import tomllib
import uuid

INTEGRATION = 'package(/-integration$/)'
COMPILER = 'binary(/(^trybuild$|_trybuild$|^optional_features$|^feature_matrix$|^consumer$)/)'
AMQP = 'package(=amqp-integration)'
KAFKA = 'package(=kafka-integration)'
# One partition definition, consumed by both inventory verification and execution.
GROUPS = {
    'unit': f'not ({INTEGRATION}) and not ({COMPILER})',
    'consumer': f'not ({INTEGRATION}) and ({COMPILER})',
    'amqp': AMQP,
    'kafka': KAFKA,
    'providers': f'({INTEGRATION}) and not ({AMQP}) and not ({KAFKA})',
}
ROOT = Path.cwd().resolve()
ARTIFACTS = Path(os.environ.get('CI_ARTIFACTS', ROOT / '.local-ci-runs/current')).resolve()


def run(command, *, env=None, capture=False):
    started = time.monotonic()
    result = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE if capture else None)
    print(f'ci: phase={command[0]} operation={command[1] if len(command)>1 else ""} seconds={time.monotonic()-started:.3f} exit={result.returncode}', file=sys.stderr)
    if capture and result.returncode:
        raise RuntimeError(f'command failed: {command[0]} {command[1]}')
    return result.stdout if capture else result.returncode


def integration_groups():
    # Unit and independent Cargo consumers have distinct execution/cache contracts.
    # Every other partition uses the fixture launcher and the remote integration matrix.
    return [group for group in GROUPS if group not in ('unit', 'consumer')]


def install_toolchain():
    # ref: rustup src/config.rs ToolchainSection; the repository file is the only pin.
    config = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']
    command = ['rustup', 'toolchain', 'install', config['channel'], '--profile', config['profile']]
    for component in config['components']:
        command += ['--component', component]
    # Standalone consumer workspaces are outside the repository override directory.
    return run(command) or run(['rustup', 'default', config['channel']])


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def selection():
    full = os.environ.get('CI_FULL') == '1'
    if full:
        d = {'full': True, 'packages': [], 'reasons': ['explicit-full']}
    else:
        try:
            d = json.loads(run(['python3', 'hack/ci-impact.py', '--base', os.environ.get('CI_BASE', 'origin/develop'), '--head', os.environ.get('CI_HEAD', 'HEAD')], capture=True))
            assert set(d) == {'full', 'packages', 'reasons'}
            assert type(d['full']) is bool and type(d['packages']) is list and type(d['reasons']) is list
            assert all(type(p) is str and re.fullmatch(r'[A-Za-z0-9_-]+', p) for p in d['packages'])
            assert d['packages'] == sorted(set(d['packages']))
            assert all(type(r) is str and r for r in d['reasons'])
            assert not d['full'] or (not d['packages'] and d['reasons'])
        except (AssertionError, ValueError, TypeError, RuntimeError):
            d = {'full': True, 'packages': [], 'reasons': ['invalid-selection']}
    expression = os.environ.get('CI_FILTER', 'all()')
    if expression != 'all()':
        d = {'full': True, 'packages': [], 'reasons': ['explicit-filter']}
    return d | {'filter': expression, 'coverage': d['full'] and expression == 'all()', 'deep': full, 'sha': run(['/usr/bin/git', 'rev-parse', 'HEAD'], capture=True).strip(),
                'base': os.environ.get('CI_BASE', 'origin/develop')}


def packages(plan):
    return ['--workspace'] if plan['full'] else [v for p in plan['packages'] for v in ('-p', p)]


def active(plan):
    return plan['full'] or bool(plan['packages'])


def coverage_env(target):
    env = os.environ | {'CARGO_TARGET_DIR': str(target)}
    raw = run(['cargo', 'llvm-cov', 'show-env', '--sh'], env=env, capture=True)
    for line in raw.splitlines():
        words = shlex.split(line)
        if len(words) != 2 or words[0] != 'export' or '=' not in words[1]:
            raise ValueError('invalid cargo-llvm-cov environment')
        key, value = words[1].split('=', 1)
        env[key] = value
    return env


def metadata_args(extracted):
    meta = extracted / 'target/nextest'
    return ['--binaries-metadata', str(meta / 'binaries-metadata.json'), '--cargo-metadata', str(meta / 'cargo-metadata.json'), '--workspace-remap', str(ROOT), '--target-dir-remap', str(extracted / 'target')]


def inventory(arguments, expression='all()'):
    data = json.loads(run(['cargo', 'nextest', 'list', *arguments, '-E', expression, '--message-format', 'json'], capture=True))
    return sorted([f'{binary}\t{name}' for binary, suite in data['rust-suites'].items()
                   for name, test in suite.get('testcases', {}).items()
                   if test['filter-match']['status'] == 'matches' and not test['ignored']])


def build(plan):
    bundle = ARTIFACTS / 'build'
    if bundle.exists():
        shutil.rmtree(bundle)
    bundle.mkdir(parents=True)
    target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target')) / ('ci-coverage' if plan['coverage'] else 'ci-tests')
    env = coverage_env(target) if plan['coverage'] else os.environ | {'CARGO_TARGET_DIR': str(target)}
    target.mkdir(parents=True, exist_ok=True)
    for old in target.glob('*.profraw'):
        old.unlink()
    args = packages(plan)
    has_providers = plan['full'] or any(p.endswith('-integration') for p in plan['packages'])
    if has_providers and not plan['full'] and 'testkit' not in plan['packages']:
        args += ['-p', 'testkit'] # build the fixture executable once, without expanding selected tests
    archive = bundle / 'tests.tar.zst'
    messages = run(['cargo', 'nextest', 'archive', '--locked', '--all-features', *args, '--cargo-message-format', 'json', '--archive-file', str(archive)], env=env, capture=True)
    supplemental = {}
    if plan['coverage']:
        # Proc-macro execution belongs to the original build coverage, but nextest does not archive these objects.
        for line in messages.splitlines():
            message = json.loads(line)
            if message.get('reason') == 'compiler-artifact' and message['target']['kind'] == ['proc-macro'] and not message['profile']['test'] and Path(message['manifest_path']).is_relative_to(ROOT):
                for name in message['filenames']:
                    source = Path(name)
                    relative = Path('objects') / source.name
                    (bundle / relative).parent.mkdir(exist_ok=True)
                    shutil.copy2(source, bundle / relative)
                    supplemental[str(relative)] = sha(source)
        for source in target.glob('*.profraw'):
            relative = Path('profiles') / source.name
            (bundle / relative).parent.mkdir(exist_ok=True)
            shutil.copyfile(source, bundle / relative)
            supplemental[str(relative)] = sha(source)
    selected = 'all()' if plan['full'] else ' or '.join(f'package(={p})' for p in plan['packages'])
    selected = f'({selected}) and ({plan["filter"]})'
    extracted = ARTIFACTS / 'inventory'
    if extracted.exists():
        shutil.rmtree(extracted)
    extracted.mkdir()
    all_tests = inventory(['--archive-file', str(archive), '--extract-to', str(extracted), '--workspace-remap', str(ROOT)], selected)
    if plan['filter'] != 'all()' and not all_tests:
        raise ValueError('explicit CI_FILTER matched no runnable tests')
    groups = {}
    for group, expression in GROUPS.items():
        expression = f'({selected}) and ({expression})'
        groups[group] = {'filter': expression, 'tests': inventory(metadata_args(extracted), expression)}
    union = [test for group in groups.values() for test in group['tests']]
    if sorted(union) != all_tests or len(union) != len(set(union)):
        raise ValueError('test groups omit or duplicate selected tests')
    if has_providers:
        shutil.copy2(extracted / 'target/debug/rss-test-launcher', bundle / 'rss-test-launcher')
    manifest = {'plan': plan, 'toolchain': run(['rustc', '-Vv'], capture=True),
                'archive': sha(archive), 'groups': groups, 'supplemental': supplemental,
                'launcher': sha(bundle / 'rss-test-launcher') if has_providers else None}
    write(bundle / 'manifest.json', manifest)
    print(f'ci: inventory selected={len(all_tests)} groups=' + str({g: len(v['tests']) for g, v in groups.items()}))
    return 0


def load_build(plan):
    bundle = ARTIFACTS / 'build'
    manifest = json.loads((bundle / 'manifest.json').read_text())
    if manifest['plan'] != plan or manifest['toolchain'] != run(['rustc', '-Vv'], capture=True):
        raise ValueError('build identity mismatch')
    if manifest['archive'] != sha(bundle / 'tests.tar.zst'):
        raise ValueError('corrupt test archive')
    if manifest['launcher'] and manifest['launcher'] != sha(bundle / 'rss-test-launcher'):
        raise ValueError('corrupt fixture launcher')
    for name, digest in manifest['supplemental'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or path.parts[0] not in ('objects', 'profiles') or sha(bundle / path) != digest:
            raise ValueError('corrupt supplemental coverage artifact')
    return bundle, manifest


def execute(plan, group):
    bundle, manifest = load_build(plan)
    chosen = manifest['groups'][group]
    output = ARTIFACTS / 'results' / group
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    profiles = output / 'profiles'
    profiles.mkdir()
    env = os.environ | {'LLVM_PROFILE_FILE': str(profiles / '%p-%m.profraw'),
                        'RSS_TEST_RUN_ID': f'rss-{uuid.uuid4().hex}',
                        'RSS_TEST_METRICS': str(output / 'fixtures.jsonl')}
    # Instrumented binaries need only the profile destination; independent consumers keep their own compiler environment.
    for key in list(env):
        if key.startswith(('__CARGO_LLVM_COV', 'CARGO_LLVM_COV')) or key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'):
            env.pop(key)
    start = time.monotonic()
    code = 0
    if chosen['tests']:
        command = ['cargo', 'nextest', 'run', '--archive-file', str(bundle / 'tests.tar.zst'), '--workspace-remap', str(ROOT), '-E', chosen['filter'], '--no-fail-fast', '--no-tests', 'fail']
        if group != 'unit':
            command += ['--test-threads', '1']
        if group in integration_groups():
            providers = sorted({match.group(1) for test in chosen['tests'] for match in re.finditer(r'(?:\t|::)shared_(amqp|kafka|mqtt)_', test)})
            launcher = bundle / 'rss-test-launcher'
            launcher.chmod(0o755)
            command = [str(launcher), *providers, '--', *command]
        # Consumer proofs resolve/build independently and intentionally use offline Cargo.
        # A fresh execution runner needs source downloads, not a second workspace build.
        if group == 'consumer':
            code = run(['cargo', 'fetch', '--locked'], env=env)
        if code == 0:
            code = run(command, env=env)
    metrics = output / 'fixtures.jsonl'
    if metrics.exists():
        totals = {}
        for line in metrics.read_text().splitlines():
            item = json.loads(line)
            key = (item['provider'], item['phase'], item['outcome'])
            aggregate = totals.setdefault(key, {'seconds': 0, 'starts': 0, 'attempts': 0})
            aggregate['seconds'] += item['seconds']
            aggregate['starts'] += item['starts']
            aggregate['attempts'] += item['attempts']
        summary = '\n'.join(f'{group}: {provider} {phase} {outcome}: {v["seconds"]:.3f}s; attempts={v["attempts"]} ready={v["starts"]}' for (provider, phase, outcome), v in sorted(totals.items()))
        print(summary)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
                stream.write(summary + '\n')
    write(output / 'result.json', {'group': group, 'manifest': sha(bundle / 'manifest.json'),
                                  'exit': code, 'tests': chosen['tests'], 'seconds': time.monotonic()-start,
                                  'profiles': {p.name: sha(p) for p in profiles.glob('*.profraw')}})
    return code


def coverage(plan):
    if not plan['coverage']:
        print('ci: affected selection; workspace coverage gate is not applicable')
        return 0
    bundle, manifest = load_build(plan)
    target = ARTIFACTS / 'coverage'
    if target.exists():
        shutil.rmtree(target)
    target.mkdir()
    if run(['tar', '-xf', str(bundle / 'tests.tar.zst'), '-C', str(target)]):
        raise ValueError('coverage object extraction failed')
    for name in manifest['supplemental']:
        path = Path(name)
        destination = target / 'target/debug/deps' / path.name if path.parts[0] == 'objects' else target / f'build-{path.name}'
        shutil.copy2(bundle / path, destination)
        if path.parts[0] == 'objects': destination.chmod(0o755)
    status = 0
    for group, chosen in manifest['groups'].items():
        folder = ARTIFACTS / 'results' / group
        try:
            result = json.loads((folder / 'result.json').read_text())
            if not isinstance(result, dict) or type(result.get('exit')) is not int or not isinstance(result.get('profiles'), dict):
                raise ValueError('invalid test result schema')
            if not all(isinstance(name, str) and isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) for name, digest in result['profiles'].items()):
                raise ValueError('invalid profile manifest')
            if result['group'] != group or result['manifest'] != sha(bundle / 'manifest.json') or result['tests'] != chosen['tests']:
                raise ValueError('test result identity mismatch')
            if result['exit'] != 0:
                status = 1
            if chosen['tests'] and not result['profiles']:
                raise ValueError('missing required raw profiles')
            for name, digest in result['profiles'].items():
                if Path(name).name != name or not name.endswith('.profraw'):
                    raise ValueError('invalid profile filename')
                source = folder / 'profiles' / name
                if sha(source) != digest:
                    raise ValueError('corrupt raw profile')
                shutil.copyfile(source, target / f'{group}-{name}')
        except (OSError, ValueError, KeyError) as error:
            print(f'ci: coverage group={group}: {error}', file=sys.stderr)
            status = 1
    # report uses original archived objects and never builds or executes tests.
    env = os.environ | {'CARGO_TARGET_DIR': str(target), 'CARGO_LLVM_COV_TARGET_DIR': str(target), 'CARGO_LLVM_COV_BUILD_DIR': str(target)}
    code = run(['cargo', 'llvm-cov', 'report', '--locked', '--nextest-archive-file', str(bundle / 'tests.tar.zst'), '--failure-mode', 'any', '--fail-under-lines', '80', '--lcov', '--output-path', str(target / 'lcov.info')], env=env)
    return code or status


def checks(plan):
    status = run(['python3', '-m', 'unittest', 'discover', '-s', 'hack/tests', '-p', 'test_ci_*.py'])
    if active(plan):
        status = run(['make', '--no-print-directory', '_ci-checks', 'CI_PACKAGES=' + ' '.join(packages(plan)), f'CI_FULL={int(plan["deep"])}', f'CI_BASE={plan["base"]}']) or status
    return status


def docs(plan):
    return run(['cargo', 'test', '--doc', '--locked', '--all-features', *packages(plan), '--no-fail-fast']) if active(plan) else 0


def attempt(operation, *args):
    try:
        return operation(*args)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f'ci: {operation.__name__}: {error}', file=sys.stderr)
        return 2


def main():
    part = os.environ.get('CI_PART', 'all')
    if part not in ('all', 'select', 'checks', 'build', 'docs', 'tests', 'coverage', *GROUPS):
        raise ValueError('invalid CI_PART')
    plan_path = Path(os.environ['CI_PLAN']) if os.environ.get('CI_PLAN') else None
    plan = json.loads(plan_path.read_text()) if plan_path else selection()
    if plan['sha'] != run(['/usr/bin/git', 'rev-parse', 'HEAD'], capture=True).strip():
        raise ValueError('selection SHA mismatch')
    if part == 'select':
        write(ARTIFACTS / 'plan.json', plan)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
                out.write(f'active={str(active(plan)).lower()}\ncoverage={str(plan["coverage"]).lower()}\n')
                out.write('integration_groups=' + json.dumps(integration_groups()) + '\n')
        return 0
    if part == 'checks':
        return checks(plan)
    if not active(plan):
        print('ci: no selected Cargo packages')
        return checks(plan) if part == 'all' else 0
    if part == 'build': return build(plan)
    if part == 'docs': return docs(plan)
    if part in GROUPS: return execute(plan, part)
    if part == 'coverage': return coverage(plan)
    status = checks(plan) if part == 'all' else 0
    built = attempt(build, plan)
    status = built or status
    if not built:
        for group in GROUPS:
            status = attempt(execute, plan, group) or status
        status = attempt(coverage, plan) or status
    return attempt(docs, plan) or status


if __name__ == '__main__':
    try:
        sys.exit(install_toolchain() if sys.argv[1:] == ['--install-toolchain'] else main())
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f'ci: {error}', file=sys.stderr)
        sys.exit(2)
