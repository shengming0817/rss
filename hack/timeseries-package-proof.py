#!/usr/bin/env python3
"""Run the same time series public behavior against isolated source/exact artifacts."""
import shutil
from package_proof import (
    cargo, consumer, example_dependencies, prepare_sources, proof_arguments, record_graph, provider_consumer,
)

SCENARIOS = {"core": ["timeseries-core"], "pg": ["timeseries-pg"]}


def main():
    args = proof_arguments(SCENARIOS)
    selected = example_dependencies({name: SCENARIOS[name] for name in (args.scenario or SCENARIOS)})
    root, allowed = prepare_sources(
        args, {dep for _, deps in selected.values() for dep in deps}, "timeseries-"
    )
    for name, (features, deps) in selected.items():
        directory = root / name
        consumer(directory, features, deps, allowed)
        forbidden = {"testkit", "testcontainers", "rss-runtime", "rss-observation", "rss-transactional-messaging", "rss-timeseries-clickhouse"}
        required = {"rss-timeseries": {"default"}, "serde_json": {"default", "std", "float_roundtrip"}}
        if name == "core":
            forbidden |= {"sqlx", "rss-timeseries-postgres"}
        else:
            required["rss-timeseries-postgres"] = {"default"}
        record_graph(
            directory, allowed, set(),
            forbidden, required_features=required, required_dependencies=deps,
        )
        if name == "core":
            cargo(["run", "--locked", "--bin", "timeseries"], directory)
        else:
            cargo(["build", "--locked", "--bin", "timeseries-pg", "--bin", "timeseries-install"], directory)
            provider_consumer(directory, "timeseries-postgres-integration", "suite", "examples::example_consumer", {
                "RSS_TIMESERIES_INSTALL": "timeseries-install", "RSS_TIMESERIES_EXAMPLE": "timeseries-pg",
            })
        shutil.rmtree(directory / "target")
        print(f"BEHAVIOR PASS timeseries/{name}", flush=True)


if __name__ == "__main__":
    main()
