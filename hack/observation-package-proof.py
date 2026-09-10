#!/usr/bin/env python3
"""Run the shared Observation handoff through independent sources or exact archives."""
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

SCENARIOS = {
    "core": ["observation-core"],
    "adapter": ["observation-pg"],
    "projection": ["observation-projection"],
    "projection-postgres": ["observation-handoff"],
}


def main():
    args = proof_arguments(SCENARIOS)
    selected = example_dependencies(
        {name: SCENARIOS[name] for name in (args.scenario or SCENARIOS)}
    )
    root, allowed = prepare_sources(
        args, {dep for _, deps in selected.values() for dep in deps}, "observation-"
    )
    for name, (features, deps) in selected.items():
        directory = root / name
        consumer(directory, features, deps, allowed)
        forbidden = {
            "testkit",
            "testcontainers",
            "rss-transactional-messaging",
            "rss-runtime",
        }
        if name == "core":
            forbidden |= {"sqlx", "rss-observation-postgres"}
        if name in {"core", "adapter"}:
            forbidden.add("rss-projection")
        if name != "projection-postgres":
            forbidden.add("rss-projection-postgres")
        # Independent scenario contract: a missing forwarding edge must fail.
        required = {"rss-observation": {"default"}}
        if name != "core":
            required["rss-observation-postgres"] = {
                "adapter": {"default"},
                "projection": {"default", "projection"},
                "projection-postgres": {"default", "projection", "projection-postgres"},
            }[name]
        if name in {"projection", "projection-postgres"}:
            required["rss-projection"] = {"default"}
        if name == "projection-postgres":
            required["rss-projection-postgres"] = {"default"}
        record_graph(directory, allowed, set(), forbidden, required_features=required, required_dependencies=deps)
        if name == "core":
            shutil.copyfile(
                ROOT / "crates/examples/probes/observation-core.rs",
                directory / "src/main.rs",
            )
            cargo(["run", "--locked", "--bin", "rss-examples"], directory)
        elif name == "projection-postgres":
            cargo(
                [
                    "build",
                    "--locked",
                    "--bin",
                    "observation",
                    "--bin",
                    "observation-install",
                ],
                directory,
            )
            provider_consumer(
                directory,
                "postgres-integration",
                "observation_projection",
                "observation_projection::examples::example_consumer",
                {
                    "RSS_OBSERVATION_INSTALL": "observation-install",
                    "RSS_OBSERVATION_EXAMPLE": "observation",
                },
            )
        else:
            shutil.copyfile(
                ROOT / "crates/examples/probes/observation-api.rs",
                directory / "src/main.rs",
            )
            cargo(["check", "--locked", "--bin", "rss-examples"], directory)
        shutil.rmtree(directory / "target")
        kind = "GRAPH" if name in {'adapter', 'projection'} else "BEHAVIOR"
        print(f"{kind} PASS observation/{name}", flush=True)


if __name__ == "__main__":
    main()
