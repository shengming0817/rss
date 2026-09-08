#!/usr/bin/env python3
"""Run independent reconcile consumers against sources or fixed candidate archives."""
import json
import os
import shutil
from package_proof import (ROOT, cargo, cargo_environment, consumer, example_dependencies,
    prepare_sources, proof_arguments, run_command, validate_execution, validate_graph)

SCENARIOS = {'core': ['reconcile-core'], 'pg': ['reconcile-pg'], 'messaging': ['reconcile-messaging']}


def main():
    args = proof_arguments(SCENARIOS)
    selected = example_dependencies({name: SCENARIOS[name] for name in (args.scenario or SCENARIOS)})
    root, allowed = prepare_sources(args, {dep for _, deps in selected.values() for dep in deps}, 'reconcile-')
    for name, (features, dependencies) in selected.items():
        directory = root / name
        consumer(directory, features, dependencies, allowed)
        if name == 'core':
            shutil.copyfile(ROOT / 'crates/examples/probes/reconcile-core.rs', directory / 'src/main.rs')
        if name == 'messaging':
            shutil.copyfile(ROOT / 'crates/examples/probes/reconcile-messaging.rs', directory / 'src/bridge.rs')
            with (directory / 'src/lib.rs').open('a') as source:
                source.write('\nmod bridge;\n')
        resolved = json.loads(cargo(['metadata', '--format-version', '1'], directory))
        forbidden = ['rss-device-command', 'rss-device-command-postgres', 'rss-projection', 'rss-projection-postgres', 'rss-saga', 'rss-saga-postgres', 'testkit']
        forbidden = set(forbidden)
        required = {'rss-reconcile': {'default'}}
        message = set()
        if name == 'messaging':
            message = {'default', 'producer', 'consumer'}
        if name == 'core':
            forbidden |= {'sqlx', 'rss-reconcile-postgres', 'rss-transactional-messaging-postgres'}
        else:
            required['rss-reconcile-postgres'] = {'default'}
        if not message:
            forbidden |= {'rss-transactional-messaging', 'rss-transactional-messaging-postgres'}
        forbidden.add('rss-runtime')
        if name == 'messaging':
            required['rss-reconcile-postgres'].add('transactional-messaging')
        validate_graph(resolved, directory, allowed, message, forbidden,
                       required_features=required, required_dependencies=dependencies)
        (directory / 'resolved.json').write_text(json.dumps(resolved, indent=2) + '\n')
        if name == 'core':
            cargo(['run', '--locked', '--bin', 'rss-examples'], directory)
            shutil.rmtree(directory / 'target')
            print('PASS reconcile/core: provider-free public behavior', flush=True)
            continue
        cargo(['build', '--locked', '--bin', 'reconcile'], directory)
        binary = str(directory / 'target/debug/reconcile')
        env = dict(cargo_environment(os.environ), RSS_RECONCILE_EXAMPLE=binary,
                   RSS_TEST_RUN_ID=f'{root.name}-{name}')
        command = ['cargo', 'run', '--locked', '-p', 'testkit', '--features', 'containers', '--bin', 'rss-test-launcher', '--', '--',
                   'cargo', 'test', '--locked', '-p', 'reconcile-postgres-integration', '--test', 'suite',
                   'examples::example_consumer', '--', '--exact', '--nocapture']
        with (directory / 'provider-integration.log').open('w') as log:
            run_command(command, ROOT, env, log, timeout=900).check_returncode()
        validate_execution((directory / 'provider-integration.log').read_text(), 'examples::example_consumer', [binary])
        shutil.rmtree(directory / 'target')
        print(f'PASS reconcile/{name}: independent graph + real PostgreSQL behavior', flush=True)


if __name__ == '__main__':
    main()
