# Runtime Assembly Baseline

This document records the current runtime assembly shape after the `runtime::run()` decomposition,
#1677 PG lifecycle-ownership hardening, the startup owner funnel, #1794 full RuntimePlan live
closure, and #1795 provider-independent `runtimeexec` launch ownership. The machine-readable
inventory lives in `runtime-baseline/runtime.txt` and is regenerated with:

```bash
cargo xtask runtime-baseline list > runtime-baseline/runtime.txt
cargo xtask runtime-baseline verify
```

## Scope

The v2 static inventory is machine-owned by
[`runtime-baseline/runtime.txt`](../../runtime-baseline/runtime.txt). Its
`[runtime.dependencies]`, `[sharedRuntimeDeps.fields]`, and `[domainModuleResult.fields]`
sections are the complete source of truth;
this document only explains the architectural meaning of those facts.

Runtime wiring is deliberately absent from the rendered baseline. The canonical owners are the
closed RuntimePlan/phase/provider/listener/runtimeexec types plus their focused cross-file AST
invariants. There is no v1 reader, ordered-anchor compatibility section, or second provider
inventory.

Dynamic state is not asserted by this gate: environment variables, live provider health,
generated event subscriptions, topology-specific routing, socket bind results, and OS signal
behavior remain runtime facts.

## Current Typed Phase Inventory

The public `runtime::run()` only accepts `ServingRuntimeInputs` and transfers it into
`RuntimeLifecycleOwner`; `OperatorRuntimeInputs` is a distinct, unforgeable profile without the
password-policy capability and cannot enter serving. The owner always finishes the unique
`run_startup(&mut ServingRuntimeInputs)` result through pending-exporter
cleanup. `run_startup()` contains no assembly body or compatibility path: it enters
`phase::execute`, whose exact consuming chain is
`Planned → ProvidersBuilt → InfraBuilt → DomainsWired → Finalized → runtimeexec::RuntimeOutputs`.
The private `PhaseContext` retains the same mutable serving input and owned `RuntimePlan` through
launch. The provider transition projects the sole private `ListenerExecutionPlan`; the mandatory
carrier then moves through `ProvidersBuilt → InfraBuilt → DomainsWired` and is consumed by the
single listener finalizer. It also mints the private `DomainExecutionPlan`, which crosses
`InfraBuilt` and consumes generated domain bindings into a private validated wrapper before the
canonical composition helper. Exact declaration order and local placement are mandatory; rejected
bindings remain owned for transactional rollback. Each phase file owns one transition:
plan-selected RSS/Federated access-token provider preflight, infrastructure construction plus
Service Token replay-store completion, domain wiring, listener finalization, then launch. The
selected profiles retain distinct typed providers, resources, and readiness signals throughout
that chain. Infrastructure capabilities are complete
before domain composition begins; module probes enter the registry before listener finalization;
and only the launch phase may consume `Finalized` and transfer lifecycle ownership to the sole
`runtimeexec` `ShutdownStack` owner. Exact production calls and ordering are enforced by
`RUNTIME-PHASE-TRANSITION-LIVE-01`, `RUNTIME-PLAN-LIVE-CLOSURE-01`, and
`RUNTIMEEXEC-LAUNCH-OWNERSHIP-01`; they are not repeated in a text inventory.

## Governance And Live Closure

Assembly intent and provider declarations are owned by the repository Assembly Governance IR,
not repeated in the runtime baseline. `cargo xtask assembly validate` checks every closed role
against the private provider registry.
Each assembly also compiles an internal, active-only `providers_gen.rs` catalog whose const checked
entries bind the role to its canonical factory/capability evidence;
`cargo xtask assembly generate-providers --check` is its independent drift gate.
This catalog does not construct instances or read configuration/secrets, and it is not a fallback
for the current `modules_gen.rs` live output carrier. #1792 owns live dispatch and bypass removal.
The runtime-owned closure test executes the real generated wire → validate → compose path, then
compares provider, listener, domain, and placement relations through typed exact-set differences.
Missing, extra, duplicate, or wrong IDs fail directly; there is no renderer, parser, text fixture,
second inventory format, or parallel generated-domains invariant. `RUNTIME-PLAN-LIVE-CLOSURE-01`
alone owns wire/validate/compose; phase projections and listener finalization retain their separate
canonical owners.

## Shared Inputs And Module Outputs

The exact shared capability fields live in `[sharedRuntimeDeps.fields]`; the exact lifecycle result
shape and merge coverage live in `[domainModuleResult.fields]`. Neither list is duplicated here.
The architectural boundary is that shared inputs contain infrastructure capabilities, not domain
services or repositories. `cargo xtask runtime-deps guard` enforces that semantic allowlist
(`WIRING-DEPS-INFRA-ONLY-01`), while the baseline detects structural drift.

`PgRuntimeDeps` remains the non-Clone lifecycle owner, but `BuildInfra` now consumes it immediately
after external preflight and migration. `build_pg_runtime_module` converts the ordered pool guards
and non-Clone sampler factory into `DomainModuleResult`, and that output enters the same
`ProviderBuild` transaction as Redis, S3, Vault, DLX, token, event, and zero-output providers.
`PgRuntimeHandle` exposes only domain/infra/readiness projections; lifecycle ownership never crosses
the phase boundary as a parallel PG field.

`ProviderBuild::from_plan` is the sole active construction entry. It exact-joins every
`RuntimePlan::provider_plans()` declaration with the generated `PROVIDER_CATALOG`, mints one private
typed permit per factory, and accepts output only through owned `ProviderOutput` receipt bundles.
The closed `ProviderFactoryDispatch` has one consuming accessor for each of the 14 generated
factories, including the zero-output rate limiter. `finish(self)` rejects every declared-but-
unproduced or produced-but-undeclared channel before creating `CompletedProviderBuild`.

Every fallible phase keeps the transaction owner. Failure performs async LIFO cleanup of already
constructed resources while preserving the primary startup error; worker closures are never
started during rollback. Only the completed owner can release the provider `DomainModuleResult` to
the canonical `runtimeexec::LaunchPlan`. The kernel registers provider output before domain
output, so LIFO drains listeners and domain workers before provider workers/resources and flushes
tracing last.

## Listener, Health, And Shutdown Order

`RuntimePlan → ListenerExecutionPlan → FinalizedListenerSet + FinalizedProbeReceipt →
runtimeexec::LaunchPlan` is the only listener execution path. The execution projection carries
private listener id, kind, auth, and ordered
domains. Domain wiring compares the plan, generated bindings, and live registry exactly; the
finalizer drains live groups, consumes every plan spec in canonical order, derives provider,
auth bridge, and transport selection from plan auth, and rejects leftovers or drift before address
resolution or bind. A domain-free Internal spec still produces an empty router and reaches bind.

Health has no separate constructor or append path. Only a plan-declared domain-free
`Health + NoAuth` spec can produce it, and the finalizer does so after non-Health listener
finalization and mTLS probe registration. Taking the finalized health reporter also mints the
assembly-private, non-Clone `FinalizedProbeReceipt`; both values move together into `Finalized`.
`phase/launch.rs` must consume that receipt when it constructs the canonical runtimeexec plan; a
plain `Vec<AssembledListener>` or an unfinalized probe registry cannot enter launch.

The full-runtime `LaunchAdapter` owns address resolution, socket binding, mTLS preparation and the
private activation-ready listener state. Its `prepare` performs bind-all plus preflight-all before
the state can exist; its infallible `activate` registers non-Health listeners before Health only
through `LaunchRegistrar`. The associated private inventory is consumed exactly once by the
required ready hook. `runtimeexec` contains none of the HTTP, auth, route, provider, DTO, or
inventory-wire types.

`runtimeexec::LaunchPlan` transfers the completed provider and domain lifecycle batches into its
private `ShutdownStack` before propagating either batch's validation result, so an earlier invalid
batch cannot synchronously drop the later
batch. Registration remains LIFO: externally visible listeners drain before background work and
provider resources, with tracing flushed last. `RUNTIMEEXEC-LAUNCH-OWNERSHIP-01` is the sole
cross-file owner for registration, signal, and drain ordering.

## Machine Gate

`cargo xtask runtime-baseline verify` fails when:

- `runtime-baseline/runtime.txt` is missing
- regenerated baseline text differs from the committed file
- runtime dependencies are empty
- the runtime assembly is absent or is not the typed production assembly selected by Assembly
  Governance IR before runtime source scanning begins
- the exact outer `runtime::run()` owner, sole `run_startup() → phase::execute` entry, typed
  transition chain, runtimeexec handoff, or full-adapter evidence is missing or out of order in
  its canonical invariant
- the generated 14-factory exact set drifts, the plan/catalog join is not unique, a typed permit is
  missing/duplicated, one of the eight sealed output batches disappears, `finish`/async rollback/handoff
  becomes non-unique, or a legacy static binding/trait/fallback seam returns
- the unique PG conversion moves out of `BuildInfra`, a parallel PG lifecycle field crosses phases,
  or provider output registers after domain output
- event transport restores a parallel output type, exposes its production wiring API outside the
  crate, bypasses the publisher/subscriber receipts, or registers lifecycle primitives outside the
  common helper

- `DomainModuleResult::merge` is absent or stops merging a field
- listener execution gains a second projection/finalizer, loses its mandatory private carrier or
  finalized probe receipt, accepts a plain listener vector at launch, restores an assembly-owned
  executor/raw-value/config auth decision/manual Health construction, or stops enforcing exact
  plan/generated/live domain evidence

The former text-anchor risks are partitioned without overlap: configuration snapshots belong to
`RUNTIME-CONFIG-SNAPSHOT-LIVE-01`; plan/phase projections to
`RUNTIME-PHASE-TRANSITION-LIVE-01`; provider construction/output to
`RUNTIME-PROVIDER-BIJECTION-LIVE-01`; wire/validate/compose to
`RUNTIME-PLAN-LIVE-CLOSURE-01`; event output to `EVENT-TRANSPORT-OUTPUT-FUNNEL-01`;
listener/finalize/adapter to `RUNTIME-LISTENER-PLAN-EXECUTION-LIVE-01`; and
launch/signal/drain to `RUNTIMEEXEC-LAUNCH-OWNERSHIP-01`. Each owner carries real-workspace
anti-vacuity and focused synthetic red coverage.

`cargo xtask runtime-root guard` is the independent root-responsibility ratchet. Its closed,
append-only policy records the pre-#1794 baseline and every accepted revision. #1794 moves raw root
LOC from 9,428 to 260; its frozen responsibility vector is
`11 functions / 1 type / 2 const-static / 3 impl methods / 8 public modules / 10 public re-export leaves / 0 inline production modules`.
#1795 keeps every structural count fixed while removing the old `RuntimeOutputs` re-export, so the
current public re-export count is 9. Every later revision must be component-wise non-increasing.
Policy deletion, truncation, metric increases, unknown fields, Rust or TOML parse failures, and
comment/string/dead-helper bait fail closed.

`cargo xtask ci full` and the remote/full owner run this gate before `archrules`; the fixed repository-fast plan deliberately excludes it. `RUNTIME-BASELINE-DRIFT-01` remains indexed by `cargo xtask archrules verify`.
