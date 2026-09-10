#!/usr/bin/env python3
"""Run independent MQTT public consumers against source or exact candidate archives."""
import shutil
from package_proof import (
    ROOT,
    cargo,
    consumer,
    example_dependencies,
    prepare_sources,
    proof_arguments,
    provider_consumer,
    record_graph,
)

SCENARIOS = {"base": ["mqtt"], "consumer": ["mqtt-consumer"]}


def main():
    args = proof_arguments(SCENARIOS)
    selected = example_dependencies(
        {name: SCENARIOS[name] for name in (args.scenario or SCENARIOS)}
    )
    root, allowed = prepare_sources(
        args, {dep for _, deps in selected.values() for dep in deps}, "mqtt-"
    )
    for name, (features, deps) in selected.items():
        directory = root / name
        consumer(directory, features, deps, allowed)
        record_graph(
            directory,
            allowed,
            {"producer"} | ({"consumer"} if name == "consumer" else set()),
            {"rss-runtime", "testkit", "testcontainers", "sqlx", "rumqttc"},
            required_features={
                "rss-mqtt": {"default"}
                | ({"consumer"} if name == "consumer" else set())
            },
            required_dependencies=deps,
        )
        cargo(["build", "--locked", "--bin", "mqtt"], directory)
        provider_consumer(
            directory,
            "mqtt-integration",
            "suite",
            "examples::example_consumer",
            {"RSS_MQTT_EXAMPLE": "mqtt"},
        )
        shutil.rmtree(directory / "target")
        print(f"PASS mqtt/{name}: exact graph and real broker behavior", flush=True)


if __name__ == "__main__":
    main()
