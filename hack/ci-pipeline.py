#!/usr/bin/env python3
"""Canonical selection, archive execution and coverage aggregation behind Make.

ref: cargo-llvm-cov v0.8.7 src/report.rs (nextest archive objects), nextest archive metadata.
"""
import hashlib
import importlib.util
import json
import math
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


def semver_module():
    spec = importlib.util.spec_from_file_location('ci_semver', Path(__file__).with_name('ci-semver.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def semver_selection(plan):
    requested = os.environ.get('CI_SEMVER_PACKAGES')
    mode = os.environ.get('CI_SEMVER_MODE', 'affected')
    if mode not in ('affected', 'all', 'compare', 'release'):
        raise ValueError('invalid SemVer mode')
    full = mode in ('all', 'release') or os.environ.get('CI_SEMVER_FULL') == '1'
    if requested is not None and (mode != 'compare' or full):
        raise ValueError('explicit SemVer packages require compare mode without full selection')
    if mode == 'compare' and requested is None:
        raise ValueError('explicit SemVer comparison requires packages')
    if mode == 'release':
        module = semver_module()
        if module.revision(ROOT, plan['base']) == module.revision(ROOT, os.environ.get('CI_HEAD', 'HEAD')):
            raise ValueError('release requires an independent accepted compatibility base')
    return semver_module().select(ROOT, plan['base'], os.environ.get('CI_HEAD', 'HEAD'), plan,
                                  full=full,
                                  requested=requested.split(',') if requested is not None else None,
                                  comparison=mode == 'compare')


def semver(plan):
    selected = semver_selection(plan)
    if 'semver' in plan and selected != plan['semver']:
        raise ValueError('SemVer selection identity mismatch')
    if not selected['selected']:
        print('SemVer: skipped (' + selected['reason'] + ')')
        return 0
    status = semver_module().execute(ROOT, selected, ARTIFACTS / 'semver')
    if status == 130:
        raise KeyboardInterrupt
    return status


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
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    temporary.replace(path)


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
                        'RSS_TEST_METRICS_DIR': str(output / 'fixture-metrics')}
    # Instrumented binaries need only the profile destination; independent consumers keep their own compiler environment.
    for key in list(env):
        if key.startswith(('__CARGO_LLVM_COV', 'CARGO_LLVM_COV')) or key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'):
            env.pop(key)
    start = time.monotonic()
    code = 0
    execution_error = None
    phase = 'test-run'
    try:
        if chosen['tests']:
            phase = 'test-run'
            command = ['cargo', 'nextest', 'run', '--archive-file', str(bundle / 'tests.tar.zst'), '--workspace-remap', str(ROOT), '-E', chosen['filter'], '--no-fail-fast', '--no-tests', 'fail']
            if group != 'unit':
                command += ['--test-threads', '1']
            if group in integration_groups():
                providers = sorted({match.group(1) for test in chosen['tests'] for match in re.finditer(r'(?:\t|::)shared_(amqp|kafka|mqtt)_', test)})
                launcher = bundle / 'rss-test-launcher'
                phase = 'launcher-setup'
                launcher.chmod(0o755)
                command = [str(launcher), *providers, '--', *command]
            # Consumer proofs resolve/build independently and intentionally use offline Cargo.
            # A fresh execution runner needs source downloads, not a second workspace build.
            if group == 'consumer':
                phase = 'fetch'
                code = run(['cargo', 'fetch', '--locked'], env=env)
            if code == 0:
                phase = 'test-run'
                code = run(command, env=env)
    except KeyboardInterrupt:
        code = None
        execution_error = 'cancelled'
    except OSError:
        code = None
        execution_error = phase
    profile_error = False
    digests = {}
    try:
        for profile in profiles.iterdir():
            if profile.suffix == '.profraw':
                digests[profile.name] = sha(profile)
    except OSError:
        profile_error = True
    write(output / 'result.json', {'group': group, 'manifest': sha(bundle / 'manifest.json'),
                                  'exit': code, 'execution_error': execution_error,
                                  'profile_error': profile_error, 'tests': chosen['tests'],
                                  'seconds': time.monotonic()-start, 'profiles': digests})
    if execution_error == 'cancelled':
        raise KeyboardInterrupt
    fixture_summary(output)
    return 2 if execution_error or profile_error else code


def fixture_summary(output):
    """Optional diagnostics only; never change the already persisted verdict."""
    totals = {}
    complete = True
    records = 0
    folder = output / 'fixture-metrics'
    try:
        complete = not folder.with_suffix('.incomplete').exists()
        files = sorted(folder.iterdir())
        for path in files:
            try:
                if path.suffix != '.jsonl' or not path.is_file():
                    raise ValueError('invalid metric file')
                raw = path.read_text()
                if not raw or not raw.endswith('\n'):
                    raise ValueError('truncated metrics')
                for line in raw.splitlines():
                    item = json.loads(line)
                    if not isinstance(item, dict): raise ValueError('invalid record')
                    if set(item) != {'provider', 'phase', 'outcome', 'seconds', 'starts', 'attempts'}:
                        raise ValueError('invalid fields')
                    if not all(type(item[k]) is str and item[k] and re.fullmatch(r'[A-Za-z0-9_./:-]+', item[k])
                               for k in ('provider', 'phase', 'outcome')):
                        raise ValueError('invalid labels')
                    if item['phase'] not in ('image', 'start-ready', 'cleanup') or item['outcome'] not in ('success', 'error', 'cancelled'):
                        raise ValueError('invalid metric kind')
                    if type(item['seconds']) not in (int, float) or not math.isfinite(item['seconds']) or item['seconds'] < 0:
                        raise ValueError('invalid duration')
                    if any(type(item[k]) is not int or item[k] < 0 for k in ('starts', 'attempts')) or item['starts'] > item['attempts']:
                        raise ValueError('invalid count')
                    key = (item['provider'], item['phase'], item['outcome'])
                    total = totals.setdefault(key, {'seconds': 0, 'starts': 0, 'attempts': 0})
                    updated = {k: total[k] + item[k] for k in total}
                    if not math.isfinite(updated['seconds']): raise ValueError('duration overflow')
                    total.update(updated)
                    records += 1
            except (OSError, ValueError, TypeError, OverflowError):
                complete = False
    except OSError:
        complete = False
    status = 'complete' if complete and records else 'incomplete'
    value = {'status': status, 'records': records,
             'totals': [dict(zip(('provider', 'phase', 'outcome'), key)) | value for key, value in sorted(totals.items())]}
    try:
        write(output / 'fixture-summary.json', value)
        summary = f'Fixture metrics ({status}): ' + json.dumps(value, allow_nan=False)
        print(summary)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
                stream.write(summary + '\n')
    except (OSError, ValueError):
        print('::warning::fixture diagnostic output unavailable', file=sys.stderr)
    if status == 'incomplete':
        print('::warning::fixture metrics incomplete; raw files retained', file=sys.stderr)


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
            if not isinstance(result, dict) or type(result.get('exit')) is not int or not isinstance(result.get('profiles'), dict) or type(result.get('profile_error')) is not bool or result.get('execution_error') not in (None, 'test-run', 'fetch', 'launcher-setup'):
                raise ValueError('invalid test result schema')
            if not all(isinstance(name, str) and isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) for name, digest in result['profiles'].items()):
                raise ValueError('invalid profile manifest')
            if result['group'] != group or result['manifest'] != sha(bundle / 'manifest.json') or result['tests'] != chosen['tests']:
                raise ValueError('test result identity mismatch')
            if result['exit'] != 0 or result['execution_error'] is not None or result['profile_error']:
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
    if part not in ('all', 'select', 'checks', 'build', 'docs', 'tests', 'coverage', 'semver', *GROUPS):
        raise ValueError('invalid CI_PART')
    plan_path = Path(os.environ['CI_PLAN']) if os.environ.get('CI_PLAN') else None
    plan = json.loads(plan_path.read_text()) if plan_path else selection()
    if plan['sha'] != run(['/usr/bin/git', 'rev-parse', 'HEAD'], capture=True).strip():
        raise ValueError('selection SHA mismatch')
    if part == 'select':
        plan['semver'] = semver_selection(plan)
        write(ARTIFACTS / 'plan.json', plan)
        print('ci: SemVer ' + json.dumps(plan['semver']))
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
                out.write(f'active={str(active(plan)).lower()}\ncoverage={str(plan["coverage"]).lower()}\n')
                out.write(f'semver={str(plan["semver"]["selected"]).lower()}\n')
                out.write('integration_groups=' + json.dumps(integration_groups()) + '\n')
        return 0
    if part == 'semver':
        return semver(plan)
    if part == 'checks':
        return checks(plan)
    semver_status = attempt(semver, plan) if part == 'all' else 0
    if not active(plan):
        print('ci: no selected Cargo packages')
        return (checks(plan) or semver_status) if part == 'all' else 0
    if part == 'build': return build(plan)
    if part == 'docs': return docs(plan)
    if part in GROUPS: return execute(plan, part)
    if part == 'coverage': return coverage(plan)
    status = (checks(plan) or semver_status) if part == 'all' else 0
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
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f'ci: {error}', file=sys.stderr)
        sys.exit(2)
