#!/usr/bin/env python3
"""Run the same time series public behavior against isolated source/exact artifacts."""
import shutil
from package_proof import (
    cargo, consumer, example_dependencies, prepare_sources, proof_arguments, record_graph,
)

SCENARIOS = {"core": ["timeseries-core"]}


def main():
    args = proof_arguments(SCENARIOS)
    selected = example_dependencies(SCENARIOS)
    root, allowed = prepare_sources(
        args, {dep for _, deps in selected.values() for dep in deps}, "timeseries-"
    )
    for name, (features, deps) in selected.items():
        directory = root / name
        consumer(directory, features, deps, allowed)
        record_graph(
            directory, allowed, set(),
            {"testkit", "testcontainers", "sqlx", "rss-runtime", "rss-observation",
             "rss-transactional-messaging", "rss-timeseries-postgres", "rss-timeseries-clickhouse"},
            required_features={"rss-timeseries": {"default"}, "serde_json": {"default", "std", "float_roundtrip"}}, required_dependencies=deps,
        )
        cargo(["run", "--locked", "--bin", "timeseries"], directory)
        shutil.rmtree(directory / "target")
        print(f"BEHAVIOR PASS timeseries/{name}", flush=True)


if __name__ == "__main__":
    main()
