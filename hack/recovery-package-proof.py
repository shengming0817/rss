#!/usr/bin/env python3
"""Execute core, PG redrive and PG/S3 archive scenarios against exact public dependencies."""
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
    "core": ["recovery-core"],
    "postgres": ["recovery-pg"],
    "s3": ["recovery-s3"],
    "combined": ["recovery-archive"],
    "managed": ["recovery-managed"],
}


def main():
    args = proof_arguments(SCENARIOS)
    selected = example_dependencies(
        {name: SCENARIOS[name] for name in (args.scenario or SCENARIOS)}
    )
    root, allowed = prepare_sources(
        args, {dep for _, deps in selected.values() for dep in deps}, "recovery-"
    )
    for name, (features, deps) in selected.items():
        directory = root / name
        consumer(directory, features, deps, allowed)
        forbidden = {"testkit", "testcontainers"}
        if name in {"core", "s3"}:
            forbidden |= {"sqlx", "rss-transactional-messaging-postgres"}
        if name in {"core", "postgres"}:
            forbidden.add("aws-sdk-s3")
        if name != "managed":
            forbidden.add("rss-runtime")
        record_graph(
            directory,
            allowed,
            {"default", "producer", "consumer"},
            forbidden,
            required_dependencies=deps,
        )
        probe = "recovery-core.rs" if name == "core" else "recovery-api.rs"
        shutil.copyfile(
            ROOT / "crates/examples/probes" / probe, directory / "src/main.rs"
        )
        cargo(
            ["run" if name == "core" else "check", "--locked", "--bin", "rss-examples"],
            directory,
        )
        if name == "postgres":
            cargo(
                ["build", "--locked", "--bin", "recovery", "--bin", "recovery-install"],
                directory,
            )
            provider_consumer(
                directory,
                "postgres-integration",
                "recovery",
                "examples::example_consumer",
                {
                    "RSS_RECOVERY_INSTALL": "recovery-install",
                    "RSS_RECOVERY_EXAMPLE": "recovery",
                },
            )
        if name == "combined":
            cargo(
                [
                    "build",
                    "--locked",
                    "--bin",
                    "recovery-archive",
                    "--bin",
                    "recovery-install",
                ],
                directory,
            )
            provider_consumer(
                directory,
                "archive-integration",
                "archive",
                "examples::example_consumer",
                {
                    "RSS_RECOVERY_INSTALL": "recovery-install",
                    "RSS_ARCHIVE_EXAMPLE": "recovery-archive",
                },
            )
        shutil.rmtree(directory / "target")
        kind = "GRAPH" if name in {'s3', 'managed'} else "BEHAVIOR"
        print(f"{kind} PASS recovery/{name}", flush=True)


if __name__ == "__main__":
    main()
