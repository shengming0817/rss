#!/usr/bin/env python3
"""Verify standalone and borrowed-transaction ledger consumers from one scenario source."""
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
    "core": ["ledger-core"],
    "pg": ["ledger-pg"],
    "messaging": ["ledger-messaging"],
    "all": ["ledger-all"],
}


def main():
    args = proof_arguments(SCENARIOS)
    selected = example_dependencies(
        {name: SCENARIOS[name] for name in (args.scenario or SCENARIOS)}
    )
    root, allowed = prepare_sources(
        args, {dep for _, deps in selected.values() for dep in deps}, "ledger-"
    )
    for name, (features, deps) in selected.items():
        directory = root / name
        consumer(directory, features, deps, allowed)
        forbidden = {"testkit", "testcontainers", "rss-runtime"}
        if name == "core":
            forbidden |= {"sqlx", "rss-ledger-postgres", "rss-transactional-messaging"}
        if name in {"core", "pg"}:
            forbidden.add("rss-transactional-messaging-postgres")
        # Independent scenario contract: a missing forwarding edge must fail.
        required = {"rss-ledger": {"default"}}
        if name != "core":
            required["rss-ledger-postgres"] = {
                "pg": {"default"},
                "messaging": {"default", "messaging"},
                "all": {"default", "messaging", "integration"},
            }[name]
        if name in {"messaging", "all"}:
            required["rss-transactional-messaging-postgres"] = {"default"}
        record_graph(
            directory,
            allowed,
            (
                {"default", "producer", "consumer"}
                if name in {"messaging", "all"}
                else set()
            ),
            forbidden,
            required_features=required,
            required_dependencies=deps,
        )
        if name == "core":
            shutil.copyfile(
                ROOT / "crates/examples/probes/ledger-core.rs",
                directory / "src/main.rs",
            )
            cargo(["run", "--locked", "--bin", "rss-examples"], directory)
        else:
            cargo(
                ["build", "--locked", "--bin", "ledger", "--bin", "ledger-install"],
                directory,
            )
            if name != "all":
                provider_consumer(
                    directory,
                    "ledger-postgres-integration",
                    "suite",
                    "examples::example_consumer",
                    {
                        "RSS_LEDGER_INSTALL": "ledger-install",
                        "RSS_LEDGER_EXAMPLE": "ledger",
                    },
                    environment={"RSS_LEDGER_MESSAGING": str(int(name == "messaging"))},
                )
        shutil.rmtree(directory / "target")
        kind = "GRAPH" if name in {'all'} else "BEHAVIOR"
        print(f"{kind} PASS ledger/{name}", flush=True)


if __name__ == "__main__":
    main()
