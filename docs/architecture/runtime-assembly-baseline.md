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

The complete static inventory is machine-owned by
[`runtime-baseline/runtime.txt`](../../runtime-baseline/runtime.txt). Its
`[runtime.dependencies]`, `[assembly.diportProviders]`, `[sharedRuntimeDeps.fields]`,
`[domainModuleResult.fields]`, and `[runtime.run.orderedAnchors]` sections are the source of truth;
this document only explains the architectural meaning of those facts.

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
`runtimeexec` `ShutdownStack` owner. The exact production calls and ordering are intentionally not
repeated here; see `[runtime.run.orderedAnchors]` in the machine baseline.

## Provider Inventory

The exact DI declarations, including lifecycle and durability metadata, live in
`[assembly.diportProviders]` in the machine baseline and are derived from `assembly.toml`.
`cargo xtask assembly validate` checks every closed role against the private provider registry.
Each assembly also compiles an internal, active-only `providers_gen.rs` catalog whose const checked
entries bind the role to its canonical factory/capability evidence;
`cargo xtask assembly generate-providers --check` is its independent drift gate.
This catalog does not construct instances or read configuration/secrets, and it is not a fallback
for the current `modules_gen.rs` live output carrier. #1792 owns live dispatch and bypass removal.
`runtime-baseline verify` prevents later runtime-root movement from silently changing the derived
inventory.

The aggregate live inventory freezes all four plan families together: provider declarations,
generated active catalog, and consumed outputs; listener declarations and generated/live
membership; domain declarations, local projection, and live bindings; placement declarations and
local/remote projections. This is one closure proof, not four summary counts.

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
provider resources, with tracing flushed last. Exact registration anchors and their order live in
`[runtime.run.orderedAnchors]`.

## Machine Gate

`cargo xtask runtime-baseline verify` fails when:

- `runtime-baseline/runtime.txt` is missing
- regenerated baseline text differs from the committed file
- runtime dependencies or assembly providers are empty
- the exact outer `runtime::run()` owner, sole `run_startup() → phase::execute` entry, typed
  transition chain, phase-owner anchors, runtimeexec handoff, or full-adapter anchors are missing
  or out of order
  (phase-method anchors expand same-impl private `Self::helper` calls in call order before
  ordering; `launch.rs` keeps its separate multi-lane order keys)
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

`cargo xtask runtime-root guard` is the independent root-responsibility ratchet. Its closed,
append-only policy records the pre-#1794 baseline and every accepted revision. #1794 moves raw root
LOC from 9,428 to 260; its frozen responsibility vector is
`11 functions / 1 type / 2 const-static / 3 impl methods / 8 public modules / 10 public re-export leaves / 0 inline production modules`.
#1795 keeps every structural count fixed while removing the old `RuntimeOutputs` re-export, so the
current public re-export count is 9. Every later revision must be component-wise non-increasing.
Policy deletion, truncation, metric increases, unknown fields, Rust or TOML parse failures, and
comment/string/dead-helper bait fail closed.

`cargo xtask verify --fast` and `cargo xtask ci full` run this gate before `archrules`, so `RUNTIME-BASELINE-DRIFT-01` is indexed by `cargo xtask archrules verify`.
