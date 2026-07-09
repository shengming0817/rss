# Runtime Wiring Rules

> Thin reference. Complete rule source: [`docs/rules/runtime-wiring.md`](../../../docs/rules/runtime-wiring.md).
>
> `SharedRuntimeDeps` must remain infra/provider-only. Do not add domain service or repo types to it; changes must pass `cargo xtask runtime-deps guard`.
