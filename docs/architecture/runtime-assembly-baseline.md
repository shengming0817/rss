# Runtime Assembly Baseline

This document records the current runtime assembly shape after the `runtime::run()` decomposition, #1677 PG lifecycle-ownership hardening, and the startup owner funnel. The machine-readable inventory lives in `runtime-baseline/runtime.txt` and is regenerated with:

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

Dynamic state is not asserted by this gate: environment variables, live provider health, generated event subscriptions, topology-specific routing, socket bind results, and OS signal behavior remain runtime facts.

## Current Typed Phase Inventory

The public `runtime::run()` only accepts `ServingRuntimeInputs` and transfers it into
`RuntimeLifecycleOwner`; `OperatorRuntimeInputs` is a distinct, unforgeable profile without the
password-policy capability and cannot enter serving. The owner always finishes the unique
`run_startup(&mut ServingRuntimeInputs)` result through pending-exporter
cleanup. `run_startup()` contains no assembly body or compatibility path: it enters
`phase::execute`, whose exact consuming chain is
`Planned → ProvidersBuilt → InfraBuilt → DomainsWired → Finalized → RuntimeOutputs`.
The private `PhaseContext` retains the same mutable serving input and owned `RuntimePlan` through
launch. Each phase file owns one transition: listener-selected RSS/Federated access-token provider
preflight, infrastructure construction plus Service Token replay-store completion, domain wiring,
listener finalization, then launch. The selected profiles retain distinct typed providers,
resources, and readiness signals throughout that chain. Infrastructure capabilities are complete
before domain composition begins; module probes enter the registry before listener finalization;
and only the launch phase may consume `Finalized` and transfer lifecycle ownership to the sole
`ShutdownStack` owner. The exact production calls and ordering are intentionally not repeated
here; see `[runtime.run.orderedAnchors]` in the machine baseline.

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

## Shared Inputs And Module Outputs

The exact shared capability fields live in `[sharedRuntimeDeps.fields]`; the exact lifecycle result
shape and merge coverage live in `[domainModuleResult.fields]`. Neither list is duplicated here.
The architectural boundary is that shared inputs contain infrastructure capabilities, not domain
services or repositories. `cargo xtask runtime-deps guard` enforces that semantic allowlist
(`WIRING-DEPS-INFRA-ONLY-01`), while the baseline detects structural drift.

`PgRuntimeDeps` moves by value through `InfraBuilt → DomainsWired → Finalized` as the non-Clone
lifecycle owner; it is not a second shared input. The owner directly wraps the same
`PgRuntimeHandle` used by capability consumers and is retained until the launch transition
consumes it. `PgRuntimeHandle` exposes only domain/infra/readiness projections;
the replay consume store is intentionally owner-only.
Pool guards and the readiness sampler can only leave the owner through
`into_runtime_parts(self, period)`.

PG intentionally does not implement the runtime-local generic `ProviderOutput` trait. The unique
`build_pg_runtime_module` helper converts its ordered pool guards and non-Clone sampler factory
directly into `DomainModuleResult`; no parallel PG output type exists. `LaunchPlanParts` requires the
PG module batch and the normal domain module batch, and both use the same resources-then-workers
registration helper. Keeping them as ordered batches preserves the PG sampler-before-domain-module
dependency without creating a second output seam. Event transport itself returns the normal domain
module type directly: AMQP guards are resources and event loops are workers, with no parallel runtime wrapper.

All domain/provider lifecycle contributions converge on one `DomainModuleResult` merge path. The
machine baseline checks that every lifecycle field participates in that merge, so an expanded
result cannot silently leave a lifecycle carrier behind.

## Listener, Health, And Shutdown Order

Authenticated listeners are built through `assemble_authed_routers`. Health and metrics use a
dedicated plain listener from `health_listener`, after route groups are drained. Only
`phase/launch.rs` can consume `Finalized` into a `LaunchPlan` and hand it to `launch::launch`.

`LaunchPlan::register` transfers both lifecycle batches into `ShutdownStack` before propagating
either batch's validation result, so an earlier invalid batch cannot synchronously drop the later
batch. Registration remains LIFO: externally visible listeners drain before background work and
provider resources, with tracing flushed last. Exact registration anchors and their order live in
`[runtime.run.orderedAnchors]`.

## Machine Gate

`cargo xtask runtime-baseline verify` fails when:

- `runtime-baseline/runtime.txt` is missing
- regenerated baseline text differs from the committed file
- runtime dependencies or assembly providers are empty
- the exact outer `runtime::run()` owner, sole `run_startup() → phase::execute` entry, typed
  transition chain, phase-owner anchors, or `launch.rs` anchors are missing or out of order
- the unique PG helper or its unique production call is missing/duplicated, PG implements generic
  `ProviderOutput`, lifecycle primitives escape the helper, a parallel PG output type appears, or
  PG module registration moves after the unified domain module
- event transport restores a parallel output type, exposes its production wiring API outside the
  crate, extracts channels outside `phase/domains.rs`, bypasses the single merge, or registers
  lifecycle primitives outside the common helper
- `DomainModuleResult::merge` is absent or stops merging a field

`cargo xtask verify --fast` and `cargo xtask ci full` run this gate before `archrules`, so `RUNTIME-BASELINE-DRIFT-01` is indexed by `cargo xtask archrules verify`.
