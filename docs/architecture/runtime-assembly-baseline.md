# Runtime Assembly Baseline

The runtime baseline is a v2 static inventory plus a small set of cross-file escape guards. Update
and verify it with:

```bash
cargo xtask runtime-baseline update
cargo xtask runtime-baseline verify
```

`update` has no path, force, stdout, or compatibility mode. It first loads the production
Assembly Governance IR and collects the complete report. Collection errors, an empty dependency
inventory, or any finding abort before the committed file is opened. A valid report is published
to `runtime-baseline/runtime.txt` through the repository's symlink-safe atomic replace primitive.
Running update twice is idempotent. The removed `list` and `write` spellings are errors.

## Static inventory

The generated file owns only:

- `[runtime.dependencies]` from `assemblies/runtime/Cargo.toml`
- `[sharedRuntimeDeps.fields]` from `SharedRuntimeDeps`
- `[domainModuleResult.fields]`, including complete `merge` coverage

`RUNTIME-BASELINE-DRIFT-01` rejects a missing file, byte-level semantic drift after newline
normalization, empty dependencies, a non-production runtime assembly, and missing structural
evidence. There is no v1 reader, ordered-anchor section, alternate output path, or parallel
provider/domain inventory.

## Canonical proof owners

Internal runtime relations do not belong to this gate:

- `RUNTIME-CONFIG-SNAPSHOT-LIVE-01` lives beside the private snapshot types and config behavior
  tests in `assemblies/runtime/src/config.rs` and `config_tests.rs`.
- `RUNTIME-PROVIDER-BIJECTION-LIVE-01` lives beside the one-shot permits and transactional
  provider behavior tests in `provider_output.rs`.
- `RUNTIMEEXEC-LAUNCH-OWNERSHIP-01` lives beside `LaunchTransaction`,
  `StartupTransaction`, cancellation transfer, readiness, exact-once LIFO drain, and total-budget
  tests in `runtimeexec`.
- `RUNTIME-PLAN-LIVE-CLOSURE-01` lives beside generated wire → validate → compose exact-relation
  tests in `plan/domain_exec.rs`.

The Hard carriers `RUNTIME-CONFIG-SNAPSHOT-01`,
`EVENT-TRANSPORT-OUTPUT-TYPE-01`, `RUNTIME-PHASE-TRANSITION-01`, and
`RUNTIME-LISTENER-PLAN-EXECUTION-01` make their internal typed handoffs unforgeable. The
`WorkflowRuntimePlan` and activation tests own workflow selection. Private helper names, local
bindings, statement counts, equivalent aliases, non-protocol call order, and source positions are
not governance facts.

## Cross-file residuals

Rust ownership and visibility cannot prove that a new production file never opens a parallel
escape. The baseline therefore keeps exactly six risk-centric residuals:

| Residual | Sole risk |
|---|---|
| `RUNTIME-CONFIG-ESCAPE-01` | ambient environment readers, secret-profile crossing, and demo/no-op/in-memory fallback |
| `RUNTIME-SECRET-TRANSFER-01` | extraction-site → typed-sink provenance, additional handoff, destructuring/helper propagation, assertions/macros, and unredacted diagnostics |
| `RUNTIME-PROVIDER-BYPASS-01` | raw/legacy construction plus the unique from-plan → event-output receipt → completed-owner production edges |
| `RUNTIME-LIFECYCLE-BYPASS-01` | second launch/startup/signal/shutdown owner, raw launch listeners, public lifecycle capability, and rss binary classify/help-before-prepare → typed run/shutdown handoff |
| `RUNTIME-PLAN-BINDING-BYPASS-01` | handwritten compose/wire/catalog paths, second activation owner, or fingerprint bypass |
| `RUNTIME-SERVICE-TOKEN-REPLAY-BYPASS-01` | process-local replay state or raw verifier/store |

Each residual scans its complete production reachability boundary (including the `rss` binary for
its lifecycle join), ignores cfg-test bodies, has closed-mutation synthetic reds, and shares a
real-workspace anti-vacuity receipt. Private implementation shape is ignored outside the declared
protocol edges and typed handoffs.

`POSTGRES-SETUP-TRANSACTION-LIVE-01` and
`AUDIT-SECURITY-FACT-BOUNDARY-01` remain because no stronger owner yet proves their transaction
and side-channel risks; their closed mutations cover individual transaction edges and cross-file
relation construction. `PROJECTION-TARGET-ENROLLMENT-01` remains independently
implemented in `projection_target_enrollment`; runtime-baseline only aggregates its findings.

## CI boundary

`cargo xtask runtime-baseline verify` remains the only CI selector. Update is an explicit
developer action and is not registered as a gate. This T1/T2 proof-owner convergence does not
change production lifecycle joins, T3 journeys, artifact selectors, contracts, migrations, or
runtime behavior.
