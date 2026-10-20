#!/usr/bin/env python3
"""Run the same time series public behavior against isolated source/exact artifacts."""
import shutil
from package_proof import (
    cargo, consumer, example_dependencies, prepare_sources, proof_arguments, record_graph, provider_consumer,
)

SCENARIOS = {"clickhouse": ["timeseries-clickhouse"],"core": ["timeseries-core"], "pg": ["timeseries-pg"], "timescale-shared": ["timeseries-timescaledb"], "timescale-native": ["timeseries-timescaledb"]}


def main():
    args = proof_arguments(SCENARIOS)
    selected = example_dependencies({name: SCENARIOS[name] for name in (args.scenario or SCENARIOS)})
    root, allowed = prepare_sources(
        args, {dep for _, deps in selected.values() for dep in deps}, "timeseries-"
    )
    for name, (features, deps) in selected.items():
        directory = root / name
        consumer(directory, features, deps, allowed)
        forbidden = {"testkit", "testcontainers", "rss-runtime", "rss-observation", "rss-transactional-messaging"}
        required = {"rss-timeseries": {"default"}, "serde_json": {"default", "std", "float_roundtrip"}}
        if name != "clickhouse":
            forbidden.add("rss-timeseries-clickhouse")
        if name == "clickhouse":
            forbidden.add("rss-timeseries-postgres")
            required["rss-timeseries-clickhouse"] = {"default"}
        elif name == "core":
            forbidden |= {"sqlx", "rss-timeseries-postgres"}
        else:
            required["rss-timeseries-postgres"] = {"default"} | ({"timescaledb"} if name.startswith("timescale-") else set())
            required["serde_json"].add("raw_value")
        record_graph(
            directory, allowed, set(),
            forbidden, required_features=required, required_dependencies=deps,
        )
        if name == "clickhouse":
            cargo(["build", "--locked", "--bin", "timeseries-clickhouse", "--bin", "timeseries-clickhouse-schema"], directory)
            provider_consumer(directory, "timeseries-clickhouse-integration", "suite", "examples::example_consumer", {
                "RSS_CH_EXAMPLE": "timeseries-clickhouse", "RSS_CH_SCHEMA": "timeseries-clickhouse-schema",
            })
        elif name == "core":
            cargo(["run", "--locked", "--bin", "timeseries"], directory)
        else:
            native = name.startswith("timescale-")
            install = "timeseries-timescale-install" if native else "timeseries-install"
            run = "timeseries-timescale" if native else "timeseries-pg"
            target = {"pg": "example_consumer", "timescale-shared": "timescale_shared_consumer", "timescale-native": "timescale_native_consumer"}[name]
            cargo(["build", "--locked", "--bin", run, "--bin", install], directory)
            provider_consumer(directory, "timeseries-postgres-integration", "suite", f"examples::{target}", {
                "RSS_TIMESERIES_INSTALL": install, "RSS_TIMESERIES_EXAMPLE": run,
            })
        shutil.rmtree(directory / "target")
        print(f"BEHAVIOR PASS timeseries/{name}", flush=True)


if __name__ == "__main__":
    main()
