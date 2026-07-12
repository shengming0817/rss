# Runtime Assembly Baseline

This document records the current runtime assembly shape after the `runtime::run()` decomposition and #1677 PG lifecycle-ownership hardening. The machine-readable inventory lives in `runtime-baseline/runtime.txt` and is regenerated with:

```bash
cargo xtask runtime-baseline list > runtime-baseline/runtime.txt
cargo xtask runtime-baseline verify
```

## Scope

The baseline locks static repository facts only:

- `assemblies/runtime/Cargo.toml` `[dependencies]`
- `assemblies/runtime/assembly.toml` `[[diportProviders]]`
- `assemblies/runtime/src/module.rs` `SharedRuntimeDeps` fields
- `crates/bootstrap/src/module.rs` `DomainModuleResult` fields plus `merge`
- ordered anchors inside `assemblies/runtime/src/lib.rs` `runtime::run()`
- the unique PG lifecycle-output helper and production call
- ordered launch anchors inside `assemblies/runtime/src/launch.rs`

Dynamic state is not asserted by this gate: environment variables, live provider health, generated event subscriptions, topology-specific routing, socket bind results, and OS signal behavior remain runtime facts.

## Current `runtime::run()` Inventory

The current production runtime assembly has these phases:

1. Build provider bundles and transport handles:
   - OIDC `build_provider()`
   - Postgres non-Clone owner from `PgRuntimeDeps::setup_with_audit_admin_config`, then its
     cloneable `PgRuntimeHandle` capability projection
   - Vault `build_vault_runtime_deps`
   - Redis `build_redis_runtime_deps`
   - S3 `build_s3_runtime_deps_from`
   - outbound domain transport from event topology
2. Build `SharedRuntimeDeps` from infrastructure-only inputs.
3. Wire domain roots:
   - `modules_gen::wire_domains(&deps)`
4. Compose the generated bindings and lifecycle output with `bootstrap::compose_bindings`.
5. Merge module results, with generated domain output first:
   - generated domain output
   - session sweeper
   - S3 canary
   - provider runtime resources for Redis, S3, and Vault
   - outbound domain transport module result
   - event transport module result
6. Register direct framework probes for RLS and Redis readiness.
7. Call `wire_distributed`, bridge generated event subscriptions, then call `event_transport::wire_event_transport`.
8. Drain module probes into `Registry` before `take_health_reporter`.
9. Assemble authenticated routers and the dedicated health listener.
10. Consume the retained PG owner once through `build_pg_runtime_module(owner, period)` into the
    existing `DomainModuleResult` type, pass that required module batch to `LaunchPlan`, and serve
    listeners through `launch::launch`.

## Provider Inventory

The committed baseline records the current DI provider declarations from `assembly.toml`:

- `diport::RevocationStore`: `softca::InMemRevocationLedger`, draft, ephemeral-memory
- `diport::Publisher`: `amqp::AmqpPublisher`, active, persistent
- `diport::AckableSubscriber`: `amqp::AmqpSubscriber`, active, persistent
- `diport::Signer`: `vault::VaultSigner`, active, persistent
- `diport::KeyProvider`: `vault::VaultKeyProvider`, active, persistent
- `diport::Pdp`: `oidc::OidcProvider`, active, persistent
- `diport::RateLimiter`: `ratelimit::GovernorLimiter`, active, ephemeral-memory
- `diport::LockStore`: `redis::RedisLockStore`, active, persistent
- `diport::CasStore`: `postgres::PgCasStore`, active, persistent
- `diport::CasStore`: `redis::RedisCasStore`, draft, persistent
- `diport::ObjectStore`: `s3::S3Store`, active, persistent

`cargo xtask assembly validate` remains the provider correctness gate. `runtime-baseline verify` prevents later runtime root movement from silently changing this inventory.

## Shared Inputs And Module Outputs

`SharedRuntimeDeps` currently carries:

- `PgRuntimeHandle`
- `RedisRuntimeDeps`
- `S3RuntimeDeps`
- `VaultRuntimeDeps`
- `KeyName` for settings config-value encryption
- outbound `DomainTransport`

The infrastructure-only input boundary is enforced by `cargo xtask runtime-deps guard`
(`WIRING-DEPS-INFRA-ONLY-01`). The baseline remains an inventory drift gate; semantic field
allowlisting belongs to the runtime deps guard.

`PgRuntimeDeps` remains local to `run()` as the non-Clone lifecycle owner; it is not a second shared
input. The owner directly wraps the same `PgRuntimeHandle` used by capability consumers and is retained
until launch assembly consumes it. `PgRuntimeHandle` exposes only domain/infra/readiness projections.
Pool guards and the readiness sampler can only leave the owner through
`into_runtime_parts(self, period)`.

PG intentionally does not implement the runtime-local generic `ProviderOutput` trait. The unique
`build_pg_runtime_module` helper converts its ordered pool guards and non-Clone sampler factory
directly into `DomainModuleResult`; no parallel PG output type exists. `LaunchPlanParts` requires the
PG module batch and the normal domain module batch, and both use the same resources-then-workers
registration helper. Keeping them as ordered batches preserves the PG sampler-before-domain-module
dependency without creating a second output seam. Event transport itself returns the normal domain
module type directly: AMQP guards are resources and event loops are workers, with no parallel runtime wrapper.

`DomainModuleResult` currently carries:

- probes
- detached managed resources
- cancel-token workers

`DomainModuleResult::merge` extends every field. The baseline checks the field list and merge extension list so later module result expansion cannot drift silently.

## Listener, Health, And Shutdown Order

Authenticated listeners are built through `assemble_authed_routers`. Health and metrics use a dedicated plain listener from `health_listener`, after route groups are drained and before `run()` hands a `LaunchPlan` to `launch::launch`.

`LaunchPlan::register` transfers non-listener resources into `ShutdownStack` before
`launch_until` binds listener sockets. Shutdown is registered in LIFO order:

1. optional OTEL exporter
2. PG `DomainModuleResult`: primary pool guard, optional audit-admin pool guard, then readiness sampler
3. unified module resources, including AMQP publisher/subscriber guards
4. unified module workers
5. listeners, registered inside `launch_until`

The effective shutdown drain order is the reverse: listeners first, then workers, module resources
(including AMQP guards), PG sampler, pool guards, and finally OTEL flushing.

## Machine Gate

`cargo xtask runtime-baseline verify` fails when:

- `runtime-baseline/runtime.txt` is missing
- regenerated baseline text differs from the committed file
- runtime dependencies or assembly providers are empty
- required `runtime::run()` or `launch.rs` anchors are missing or out of order
- the unique PG helper or its unique production call is missing/duplicated, PG implements generic
  `ProviderOutput`, lifecycle primitives escape the helper, a parallel PG output type appears, or
  PG module registration moves after the unified domain module
- event transport restores a parallel output type, exposes its production wiring API outside the crate,
  extracts channels in `run()`, bypasses the single merge, or registers lifecycle primitives outside the common helper
- `DomainModuleResult::merge` is absent or stops merging a field

`cargo xtask verify --fast` and `cargo xtask ci` run this gate before `archrules`, so `RUNTIME-BASELINE-DRIFT-01` is indexed by `cargo xtask archrules verify`.
