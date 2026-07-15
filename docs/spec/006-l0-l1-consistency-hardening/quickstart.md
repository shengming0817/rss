# Quickstart: L0/L1 Consistency Verification

Use the typed verification entrypoints below. `xtask/src/ci_lanes.rs` is the machine source for membership; this guide intentionally does not enumerate the repository's complete gate catalog.

## Gate Matrix

| Level | L0/L1 evidence | Compilation and backend boundary |
|-------|----------------|----------------------------------|
| Fast | Contract validate/breaking review, codegen drift, LocalTx closure, LocalOnly effect proof | The inner typed plan contains no workspace build/test compilation gate; Cargo may build or rebuild the xtask launcher. No runtime conformance, Docker, or live Postgres |
| Full | Fast evidence plus workspace/default behavior checks and integration-target compilation | Integration targets are compiled but real backends are not executed |
| Live Postgres | SecretRepo and Identity matrices plus the scoped #1706 validation journey | Runs the `postgres-domain` shard against real Postgres; required tools and test inventory fail closed |

Canonical commands:

```bash
make verify-fast
./hack/cargo.sh xtask verify
./hack/cargo.sh xtask ci run --job integration/postgres-domain
```

Do not use `--allow-missing-tools` for closeout acceptance. `cargo xtask ci full` is a local full aggregation; it is not a claim that GitHub Shadow, Azure, or every live Integration job ran locally.

## Adoption Order

When adding or changing a consistency contract:

1. Declare the consistency level and closed evidence in the contract manifests.
2. Regenerate and review consistency, effect, and LocalTx registries.
3. Bind the generated metadata to exactly one production route/mount and classify captured ports.
4. Add LocalOnly or LocalTx conformance proof at the domain boundary.
5. Add real adapter matrices when the contract depends on Postgres transaction behavior.
6. Admit only the scoped active contracts to the durable journey and keep metrics/traces on closed labels.
7. Run fast, then full, then live validation according to the changed boundary.

Cross-tenant behavior is never inferred from an ordinary read classification. It must retain `CrossTenantPrivilege` and tenant evidence through production binding, which makes that capability ineligible for LocalOnly and requires the governed non-L0 path.

## Focused Diagnostics

```bash
./hack/cargo.sh xtask contract validate
./hack/cargo.sh xtask contract breaking --against origin/develop
./hack/cargo.sh xtask localtx-coverage
./hack/cargo.sh xtask consistency local-only-effects
```

The consistency report is an evidence artifact, not the blocking LocalOnly gate. Parse its JSON status explicitly because a report process exit code alone is not the verdict:

```bash
report_file="$(mktemp)"
trap 'rm -f "$report_file"' EXIT
./hack/cargo.sh xtask consistency report --format json >"$report_file"
jq -e '.status == "passed"' "$report_file"
jq -e '
  .schemaVersion == 3 and
  .localOnlyReceiptCoverage.enforcement == "failClosed" and
  .localOnlyReceiptCoverage.evidence == "sourceRegistered"
' "$report_file"
```

The top-level `status` includes blocking receipt findings. `registered` means a canonical source site exists, not that this invocation
ran the route test. The Medium source certificate additionally closes marker/ID/mounted-ROUTE proof,
three direct observers, a module-qualified factory that proves and finalizes the same routes before
returning the same router/proof tuple, and the same generated GET operation
per receipt site. A `missing` receipt produces a blocking finding; malformed, duplicate, stale,
unknown, mismatched, decoy/bait, aliased, wrapped, or unawaited evidence fails provenance collection.

## Failure Modes

Fast verification fails closed for:

- Missing, empty, duplicate, unknown, or stray consistency/effect/LocalTx evidence.
- Generated registry drift or an active contract's route, owner, mount, test, backend profile, or provider probe that does not close.
- A status-board admitted journey whose board, fixture, runner, or `postgres-domain` lane evidence does not close.
- A LocalOnly forbidden effect, unclassified capture, ambiguous production mount, or untrusted state/provenance claim.
- An active consistency/effect review finding without the exact `Contract-Review-Ack`; non-L0 or wire-breaking changes remain deny findings.

Full verification additionally catches compile, lint, default-feature conformance, and integration-target compile failures. It does not prove a live backend transaction.

The live Postgres shard catches rollback/concurrency behavior, empty compiled test inventory, missing required infrastructure, and journey drift. `commit_unknown` and `rollback_failed` remain attempt-one terminal outcomes: neither may be replayed, and neither may be presented as a proven no-write outcome.

The #1706 journey covers its admitted Settings and Identity contracts; it does not claim every active LocalTx contract is globally journey-covered. The logout concurrency/idempotency path must not be relabeled as a synthetic conflict.

## Supply-Chain Diagnostics

```bash
./hack/cargo.sh deny check
./hack/cargo.sh tree --workspace --all-features -i spin@0.9.9
./hack/cargo.sh tree --workspace --all-features -i spin@0.10.1
```

The accepted closeout resolves the `flume` chains to `spin 0.9.9` and the `crc-fast`/AWS S3 chain to `spin 0.10.1`. It does not change `lapin`, `rumqttc`, AWS SDK declarations, `Cargo.toml`, or `deny.toml`.

## Source Material

- [L0 LocalOnly rule](../../rules/consistency-l0.md)
- [L1 LocalTx rule](../../rules/localtx.md)
- [Architecture verification ladder](../../rules/architecture.md)
- [Current CI status](../../ops/202607130824-1765-diff-adaptive-ci.md)

External benchmark:

`ref: rust-lang/rust-analyzer xtask/src/flags.rs@63a6f0d4bcfd3bbcf36383fcbcbcd93456ed1653`
