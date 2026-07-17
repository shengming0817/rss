# Runtime Wiring Rules

This document governs runtime composition wiring that is too specific for the general crate-layering rules in `docs/rules/architecture.md`. It is a rule source for assembly/runtime wiring changes, especially the `SharedRuntimeDeps` infra-only boundary.

## SharedRuntimeDeps Infra-Only Gate

INVARIANT: WIRING-DEPS-INFRA-ONLY-01 { level = "Medium", exec = "verify", source = "code" }.

- `SharedRuntimeDeps` is an inbound parameter object for shared infrastructure and provider value objects only.
- Domain service, domain repo, and domain-owned runtime output types must not be added to `SharedRuntimeDeps`; keep domain services inside their `wire_X` function or expose cross-domain behavior only through contracts.
- `cargo xtask runtime-deps guard` discovers every `SharedRuntimeDeps` under `assemblies/*/src` with `syn` and fails if a carrier is missing, unnamed, empty, or contains a disallowed field type. New assemblies are covered automatically; an empty discovery set fails closed.
- The allowlist source is `xtask/runtime-deps-guard.toml`. Missing, malformed, or schema-invalid config fails closed; there is no hardcoded fallback.
- `allowedRoots` may name adapter crate roots that exist at `adapters/<root>/Cargo.toml`, or basis/engine/DI-infra crate roots from `xtask/src/layers.rs`. Domain roots, service roots, `std`, `core`, `alloc`, and broad `distributed` are forbidden.
- `exactExceptions` is intentionally closed. The current set is exactly `Arc<secure::DigestPasswordBlocklist>`, `Arc<dyn distributed::DomainTransport>`, `Arc<oidc::OidcProvider>`, and `Arc<vault::VaultSigner>`; it does not allow an entire root or any other wrapper/bound. The password digest set is a concrete immutable `secure` value; loading stays in the crypto adapter and does not widen this exception to a provider trait or adapter-owned alias.

## Extension Flow

1. Add or change the provider/value-object type in `SharedRuntimeDeps`.
2. If the root is new, update `xtask/runtime-deps-guard.toml` and ensure it is either an existing adapter crate or an allowed basis/engine/DI-infra crate.
3. Add green and red tests in `xtask/src/runtime_deps_guard.rs`, including a synthetic red case for the nearest forbidden domain service/repo shape.
4. Run `cargo test -p xtask runtime_deps_guard`, `cargo xtask runtime-deps guard`, and `cargo xtask archrules verify`.

## Xtask And Dylint Boundary

- `runtime-deps guard` is an xtask Medium gate because this rule is a declared-field policy over discovered assembly carriers plus a small config file.
- The guard is a Rust source scan, not rustc type analysis. It does not expand macros, resolve glob imports, inspect provider bundle internals, or prove constructor/callsite capture behavior.
- Use dylint only for a future callsite/impl/macro-expanded rule that cannot be expressed as this field/config scan. Do not move this allowlist policy into dylint.
