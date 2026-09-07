#!/usr/bin/env python3
"""RSS SemVer scope and execution; Cargo metadata owns package facts.

ref: cargo-semver-checks v0.49.0 src/main.rs (explicit features and exit 100/101).
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import tomllib


# One fixed CI tool package; this is not a general tool catalog.
TOOL = {'version': '0.49.0', 'platform': 'x86_64-unknown-linux-gnu',
        'sha256': '72f6834d75d28a66e02c9fd6a230ce901bb30eee6067b85867a97445df040e4a'}


def git(root, *args):
    result = subprocess.run(['/usr/bin/git', '-C', str(root), *args], text=True, capture_output=True)
    if result.returncode: raise ValueError('SemVer Git identity unavailable')
    return result.stdout.strip()


def revision(root, value):
    return git(root, 'rev-parse', '--verify', '--end-of-options', value + '^{commit}')


def cargo_metadata(root):
    result = subprocess.run(['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'],
                            cwd=root, capture_output=True, text=True)
    if result.returncode: raise ValueError('SemVer Cargo metadata unavailable')
    return json.loads(result.stdout)


def manifest(root, rev, path='Cargo.toml'):
    return tomllib.loads(git(root, 'show', f'{rev}:{path}'))


def surface(document):
    entries = document['workspace']['metadata']['release-surface']['packages']
    result = {}
    for entry in entries:
        name = entry['package']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', name) or name in result:
            raise ValueError('invalid Release Surface package')
        result[name] = entry
    return result


def commitment(entry):
    value = entry.get('compatibility')
    if not isinstance(value, dict) or value.get('status') not in ('uncommitted', 'frozen', 'published'):
        raise ValueError('unknown SemVer compatibility commitment')
    if type(value.get('issue')) is not int or value['issue'] <= 0:
        raise ValueError('compatibility decision needs issue')
    expected = {'status', 'issue'}
    if value['status'] != 'uncommitted':
        keys = set(value) & {'baseline-rev', 'baseline-version'}
        if len(keys) != 1 or (value['status'] == 'frozen' and keys != {'baseline-rev'}):
            raise ValueError('protected package needs exact baseline')
        expected |= keys
        if 'baseline-rev' in keys and not re.fullmatch(r'[0-9a-f]{40}', value['baseline-rev']):
            raise ValueError('baseline must be immutable commit')
        if 'baseline-version' in keys and not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', value['baseline-version']):
            raise ValueError('invalid published baseline version')
    if set(value) != expected: raise ValueError('unknown compatibility fields')
    return value


def exact_authorizations(metadata, key, packages):
    result = {}
    for item in metadata.get(key, []):
        if (set(item) != {'package', 'baseline-rev', 'issue'} or item['package'] not in packages
                or item['package'] in result or not re.fullmatch(r'[0-9a-f]{40}', item['baseline-rev'])
                or type(item['issue']) is not int or item['issue'] <= 0):
            raise ValueError('invalid exact SemVer authorization')
        result[item['package']] = item
    return result


def equivalent_features(features):
    """Deduplicate only when default reaches every declared/implicit feature."""
    reached = set()
    pending = ['default'] if 'default' in features else []
    while pending:
        feature = pending.pop()
        if feature in reached: continue
        reached.add(feature)
        pending.extend(value for value in features.get(feature, []) if value in features)
    return reached == set(features)


def baseline_features(document):
    # Be conservative about optional dependency feature synthesis on historical Cargo.
    tables = [document, *document.get('target', {}).values()]
    if any(value.get('optional') for table in tables for kind in ('dependencies', 'build-dependencies', 'dev-dependencies')
           for value in table.get(kind, {}).values() if isinstance(value, dict)):
        return None
    return document.get('features', {})


def select(root, base_ref, head_ref, impact, *, full=False, requested=None, comparison=False):
    root = root.resolve()
    base, head = revision(root, base_ref), revision(root, head_ref)
    if revision(root, 'HEAD') != head: raise ValueError('SemVer head does not match checkout')
    if git(root, 'status', '--porcelain', '--untracked-files=no'):
        raise ValueError('SemVer selection requires a clean tracked checkout')
    current_doc, old_doc = manifest(root, head), manifest(root, base)
    current, old = surface(current_doc), surface(old_doc)
    metadata = current_doc['workspace']['metadata']
    decisions = {name: commitment(entry) for name, entry in current.items()}
    exits = exact_authorizations(metadata, 'semver-exits', set(old))
    adoption = metadata.get('release-surface', {}).get('compatibility-adoption', {})
    for name, entry in old.items():
        if 'compatibility' not in entry:
            if not (adoption == {'baseline-rev': base, 'issue': 2315} and name in current
                    and decisions[name] == {'status': 'uncommitted', 'issue': 2315}):
                raise ValueError('historical compatibility identity requires explicit adoption')
            continue
        prior = commitment(entry)
        if prior['status'] != 'uncommitted' and (name not in decisions or decisions[name] != prior):
            if exits.get(name, {}).get('baseline-rev') != base:
                raise ValueError('protected package removed or commitment changed without exact exit')
    facts = cargo_metadata(root)
    packages = {p['name']: p for p in facts['packages']}
    if not set(current) <= set(packages): raise ValueError('Release Surface package missing in Cargo metadata')
    protected = {name for name, value in decisions.items() if value['status'] != 'uncommitted'}
    authorizations = exact_authorizations(metadata, 'semver-breaking-authorizations', protected)
    if requested is not None:
        if not comparison or full:
            raise ValueError('explicit SemVer packages require compare mode without full selection')
        if not requested or len(requested) != len(set(requested)) or not set(requested) <= set(current):
            raise ValueError('invalid explicit SemVer package selection')
        selected = set(requested)
    else:
        selected = protected if full or impact['full'] else protected & set(impact['packages'])
    checks = []
    for name in sorted(selected):
        package, decision = packages[name], decisions[name]
        kinds = {kind for target in package['targets'] for kind in target['kind']}
        if 'lib' not in kinds:
            raise ValueError(f'{name}: target unsupported by SemVer; independent consumer proof required')
        baseline = ({'rev': base} if comparison else
                    {'rev': decision['baseline-rev']} if 'baseline-rev' in decision else
                    {'version': decision['baseline-version']})
        configurations = ['default', 'all']
        if 'rev' in baseline:
            baseline['rev'] = revision(root, baseline['rev'])
            path = Path(package['manifest_path']).relative_to(root).as_posix()
            previous = manifest(root, baseline['rev'], path)
            if previous['package']['name'] != name: raise ValueError('baseline package identity mismatch')
            features = baseline_features(previous)
            if features is not None and equivalent_features(features) and equivalent_features(package['features']):
                configurations = ['default']
        authorization = authorizations.get(name, {})
        major = (decision['status'] == 'frozen' and authorization.get('baseline-rev') == baseline.get('rev'))
        checks.append({'package': name, 'baseline': baseline, 'configurations': configurations,
                       'major_authorization': authorization['issue'] if major else None})
    return {'selected': bool(checks), 'reason': 'selected' if checks else 'no-protected-packages' if not protected else 'unaffected',
            'head': head, 'base': base, 'checks': checks}


def execute(root, plan, output):
    if revision(root, 'HEAD') != plan['head']: raise ValueError('SemVer execution head mismatch')
    if git(root, 'status', '--porcelain', '--untracked-files=no'):
        raise ValueError('SemVer requires a clean tracked checkout')
    output.mkdir(parents=True, exist_ok=True)
    results = []
    status = 0
    started = time.monotonic()
    tool_error = None
    cancelled = False
    try:
        version = subprocess.run(['cargo', 'semver-checks', '--version'], cwd=root, capture_output=True, text=True)
        if version.returncode or version.stdout.strip() != 'cargo-semver-checks ' + TOOL['version']:
            tool_error = 'tool-version'
    except KeyboardInterrupt:
        cancelled = True
    except OSError:
        tool_error = 'tool-unavailable'
    if tool_error:
        status = 1
        print(f'SemVer: {tool_error}; expected cargo-semver-checks ' + TOOL['version'], file=sys.stderr)
    for item in plan['checks']:
        for configuration in item['configurations']:
            command = ['cargo', 'semver-checks', 'check-release', '--package', item['package'],
                       '--default-features' if configuration == 'default' else '--all-features']
            for kind, value in item['baseline'].items(): command += ['--baseline-' + kind, value]
            if item['major_authorization'] is not None: command += ['--release-type', 'major']
            begin = time.monotonic()
            try:
                if cancelled or tool_error:
                    results.append({'package': item['package'], 'configuration': configuration,
                                    'exit': None, 'failure': 'not-run' if cancelled else tool_error, 'seconds': 0})
                    continue
                code = subprocess.run(command, cwd=root).returncode
                failure = None if code == 0 else 'compatibility' if code == 100 else 'tool-or-rustdoc'
            except KeyboardInterrupt:
                code, failure = None, 'cancelled'
                cancelled = True
            except OSError:
                code, failure = None, 'execution'
            results.append({'package': item['package'], 'configuration': configuration, 'exit': code,
                            'failure': failure, 'seconds': time.monotonic()-begin})
            if code != 0: status = 1
    if cancelled:
        status = 130
    value = {'plan': plan, 'required_tool_version': TOOL['version'], 'results': results, 'exit': status, 'seconds': time.monotonic()-started}
    temporary = output / 'result.json.tmp'
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(output / 'result.json')
    print(f'SemVer: packages={len(plan["checks"])} configurations={len(results)} seconds={value["seconds"]:.3f} exit={status}')
    return status


if __name__ == '__main__':
    if sys.argv[1:] != ['--tool-spec']: raise SystemExit('expected --tool-spec')
    print(TOOL['version'], TOOL['platform'], TOOL['sha256'], sep='\t')
