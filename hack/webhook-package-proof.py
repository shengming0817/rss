#!/usr/bin/env python3
"""Run the same PG/HTTPS public consumer against source or exact candidate archives."""
import shutil
from package_proof import (
    cargo, consumer, example_dependencies, prepare_sources,
    proof_arguments, provider_consumer, record_graph,
)

SCENARIOS = {"pg-https": ["webhook"]}


def main():
    args = proof_arguments(SCENARIOS)
    selected = example_dependencies(SCENARIOS)
    root, allowed = prepare_sources(
        args, {dep for _, deps in selected.values() for dep in deps}, "webhook-"
    )
    for name, (features, deps) in selected.items():
        directory = root / name
        consumer(directory, features, deps, allowed)
        record_graph(
            directory, allowed, {"default", "producer", "consumer"},
            {"testkit", "testcontainers", "rss-runtime", "rss-transactional-messaging-amqp"},
            required_features={"rss-transactional-messaging-runtime": {"producer"}},
            required_dependencies=deps,
        )
        cargo(["build", "--locked", "--bin", "webhook"], directory)
        provider_consumer(
            directory, "webhook-integration", "suite", "examples::example_consumer",
            {"RSS_WEBHOOK_EXAMPLE": "webhook"},
        )
        shutil.rmtree(directory / "target")
        print(f"BEHAVIOR PASS webhook/{name}: exact graph, PG and HTTPS signature", flush=True)


if __name__ == "__main__":
    main()
