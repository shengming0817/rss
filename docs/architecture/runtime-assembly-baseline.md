# Runtime Assembly Baseline

This document records the current runtime assembly shape before the `runtime::run()` decomposition series. The machine-readable inventory lives in `runtime-baseline/runtime.txt` and is regenerated with:

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
- ordered launch anchors inside `assemblies/runtime/src/launch.rs`

Dynamic state is not asserted by this gate: environment variables, live provider health, generated event subscriptions, topology-specific routing, socket bind results, and OS signal behavior remain runtime facts.

## Current `runtime::run()` Inventory

The current production runtime assembly has these phases:

1. Build provider bundles and transport handles:
   - OIDC `build_provider()`
   - Postgres `PgRuntimeDeps::setup_with_audit_admin_config`
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
10. Build `LaunchPlan` and serve listeners through `launch::launch`.

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

- `PgRuntimeDeps`
- `RedisRuntimeDeps`
- `S3RuntimeDeps`
- `VaultRuntimeDeps`
- `KeyName` for settings config-value encryption
- outbound `DomainTransport`

The infrastructure-only input boundary is enforced by `cargo xtask runtime-deps guard`
(`WIRING-DEPS-INFRA-ONLY-01`). The baseline remains an inventory drift gate; semantic field
allowlisting belongs to the runtime deps guard.

`DomainModuleResult` currently carries:

- probes
- detached managed resources
- cancel-token workers

`DomainModuleResult::merge` extends every field. The baseline checks the field list and merge extension list so later module result expansion cannot drift silently.

## Listener, Health, And Shutdown Order

Authenticated listeners are built through `assemble_authed_routers`. Health and metrics use a dedicated plain listener from `health_listener`, after route groups are drained and before `run()` hands a `LaunchPlan` to `launch::launch`.

`LaunchPlan::register` transfers non-listener resources into `ShutdownStack` before
`launch_until_observed` binds listener sockets. Shutdown is registered in LIFO order:

1. optional OTEL exporter
2. Postgres pool guards
3. Postgres readiness sampler
4. event infra guards
5. module resources
6. module workers
7. listeners, registered inside `launch_until`

The effective shutdown drain order is the reverse: listeners first, then workers/resources, event infra, sampler, pool guards, and finally OTEL flushing.

## Machine Gate

`cargo xtask runtime-baseline verify` fails when:

- `runtime-baseline/runtime.txt` is missing
- regenerated baseline text differs from the committed file
- runtime dependencies or assembly providers are empty
- required `runtime::run()` or `launch.rs` anchors are missing or out of order
- `DomainModuleResult::merge` is absent or stops merging a field

`cargo xtask verify --fast` and `cargo xtask ci` run this gate before `archrules`, so `RUNTIME-BASELINE-DRIFT-01` is indexed by `cargo xtask archrules verify`.
