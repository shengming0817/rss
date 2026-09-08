#!/usr/bin/env python3
"""Run independent device-command consumers against sources or fixed candidate archives."""
import json
import os
import shutil
from package_proof import (ROOT, cargo, cargo_environment, consumer, example_dependencies,
    prepare_sources, proof_arguments, run_command, validate_execution, validate_graph)

SCENARIOS = {'core': ['device-command-core'], 'pg': ['device-command-pg']}


def main():
    args = proof_arguments(SCENARIOS)
    selected = example_dependencies({name: SCENARIOS[name] for name in (args.scenario or SCENARIOS)})
    root, allowed = prepare_sources(args, {dep for _, deps in selected.values() for dep in deps}, 'device-command-')
    for name, (features, dependencies) in selected.items():
        directory = root / name
        consumer(directory, features, dependencies, allowed)
        if name == 'core':
            shutil.copyfile(ROOT / 'crates/examples/probes/device-command-core.rs', directory / 'src/main.rs')
        resolved = json.loads(cargo(['metadata', '--format-version', '1'], directory))
        forbidden = ['rss-projection', 'rss-projection-postgres', 'rss-reconcile', 'rss-reconcile-postgres', 'rss-saga', 'rss-saga-postgres', 'testkit']
        forbidden = set(forbidden)
        required = {'rss-device-command': {'default'}}
        message = set()
        message = {'producer'} if name == 'core' else {'default', 'producer', 'consumer'}
        if name == 'core':
            forbidden |= {'sqlx', 'rss-device-command-postgres', 'rss-transactional-messaging-postgres'}
        else:
            required['rss-device-command-postgres'] = {'default'}
        if not message:
            forbidden |= {'rss-transactional-messaging', 'rss-transactional-messaging-postgres'}
        forbidden.add('rss-runtime')
        validate_graph(resolved, directory, allowed, message, forbidden,
                       required_features=required, required_dependencies=dependencies)
        (directory / 'resolved.json').write_text(json.dumps(resolved, indent=2) + '\n')
        if name == 'core':
            cargo(['run', '--locked', '--bin', 'rss-examples'], directory)
            shutil.rmtree(directory / 'target')
            print('PASS device-command/core: provider-free public behavior', flush=True)
            continue
        cargo(['build', '--locked', '--bin', 'device-command'], directory)
        binary = str(directory / 'target/debug/device-command')
        env = dict(cargo_environment(os.environ), RSS_DEVICE_COMMAND_EXAMPLE=binary,
                   RSS_TEST_RUN_ID=f'{root.name}-{name}')
        command = ['cargo', 'run', '--locked', '-p', 'testkit', '--features', 'containers', '--bin', 'rss-test-launcher', '--', '--',
                   'cargo', 'test', '--locked', '-p', 'device-command-postgres-integration', '--test', 'suite',
                   'examples::example_consumer', '--', '--exact', '--nocapture']
        with (directory / 'provider-integration.log').open('w') as log:
            run_command(command, ROOT, env, log, timeout=900).check_returncode()
        validate_execution((directory / 'provider-integration.log').read_text(), 'examples::example_consumer', [binary])
        shutil.rmtree(directory / 'target')
        print(f'PASS device-command/{name}: independent graph + real PostgreSQL behavior', flush=True)


if __name__ == '__main__':
    main()
