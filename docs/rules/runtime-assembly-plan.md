# Runtime Assembly Plan Rules

This document governs the runtime assembly optimization series rooted at `docs/spec/001-runtime-assembly-plan/`. It supplements the architecture single source in `docs/rules/architecture.md`; it does not replace crate graph, contract, tenancy, observability, or eventbus rules. Review context also exposes this rule through `.claude/rules/rss/runtime-assembly-plan.md`.

## Scope Boundaries

### Phase 0

- Only create planning artifacts, baseline inventory, and baseline drift gates.
- No runtime behavior change.
- No assembly schema expansion before the baseline gate exists.
- No generated runtime module output before the generator PR exists.

### Phase 1

- Decompose `runtime::run()` by phase without behavior change.
- Move-only PRs may move functions and update imports, module declarations, and test paths.
- Move-only PRs must not change auth policy, listener shape, provider selection, shutdown order, readiness semantics, event topology, or error handling.

### Phase 2

- Guard `SharedRuntimeDeps` against becoming a domain service locator.
- Infra-only wiring is enforced by `WIRING-DEPS-INFRA-ONLY-01` via `cargo xtask runtime-deps guard`; its allowlist and extension flow are governed by `docs/rules/runtime-wiring.md`.
- Changes to the guard must keep a Medium or Hard carrier plus red/green tests.

### Phase 3

- `assembly.toml` must declare static assembly intent through required `name`, `profile`, `domains`, `topology`, `listeners`, and `diportProviders` fields.
- `domains`, `topology`, and `listeners` are declaration and validation inputs only. They do not replace contracts, Cargo dependencies, env/secrets, listener bind config, or Rust constructor wiring.
- Manifest intent validation is carried by `ASSEMBLY-MANIFEST-INTENT-01` in `xtask/src/assembly.rs` and runs through `cargo xtask assembly validate`, `cargo xtask verify`, and CI.
- Domain required capability validation is carried by `ASSEMBLY-REQUIRED-CAPABILITY-01` in `xtask/src/assembly.rs`: declared domains/topology must have the minimum provider/dependency facts needed by generated live composition.
- Domain closure validation is evaluated per assembly target package, using its normal Cargo tree and explicitly selected dependency features. Workspace-wide feature unification is a CI compile surface, not an individual assembly deployment closure.
- This phase must not make runtime read `assembly.toml` to decide topology, route mounting, auth scheme, provider construction, or live readiness.

### Phase 4

- Domain construction converges on private-field `bootstrap::DomainBinding` values created by `DomainBinding::new`; do not introduce a second runtime output type, DI container, generic service bag, `Any`, or compatibility alias.
- `compose_bindings` is the only public output transition: it borrows domains in declared manifest order, drains and extends outputs only after compose succeeds, and leaves bindings/outputs unchanged on failure.
- `DomainModuleResult` remains the sole probes/resources/workers output. Merge/extend preserves manifest order and each domain's internal order, including duplicates; generators must not lexically sort domains.
- Domain services and routes remain typed and are captured by the domain/route funnel; they must not enter `SharedRuntimeDeps` or `DomainModuleResult`.
- `cargo xtask assembly generate-modules` derives each assembly's committed `src/generated/modules_gen.rs` from the manifest domain order. `ASSEMBLY-MODULES-CODEGEN-01` is the Hard codegen/golden carrier; `--check` runs in verify/CI and fails on missing, changed, hand-edited, or owned orphan outputs.
- The generated file contains the ordered async `domains::<name>::module(deps)` calls plus a `#[cfg(test)]` hermetic factory emitted by the same loop to exercise that exact order. It does not derive providers, environment access, features, compose/merge behavior, or a typed-handle sidecar; the test factory also returns ordinary `DomainBinding` values.
- Defining the binding/output shape does not itself change live `runtime::run()` behavior. Moving wire functions, generating the module list, and switching the live path remain separate dependent changes with baseline verification.
- The generated artifact is the live domain-order carrier. `RUNTIME-GENERATED-DOMAINS-LIVE-01` rejects handwritten fallback and requires `compose_bindings` plus output merge; typed route/subscriber declaration funnels preserve the single `RouteAuthorizer` / `SettingsService` instances without a service bag.
- Reusable `composition/*` crates may own a domain's typed provider-to-`DomainBinding` construction when multiple assemblies consume it. They remain Root-layer code, use mandatory typed inputs, and must not introduce a DI container, generic bag, manifest reader, or launch entrypoint.
- `identityaudit` is a demo/test assembly with `domains = ["identity", "audit"]` and `topology = "demo"`; it proves generated module, Cargo, and declared provider capability closure without claiming a launch path, authenticated listener finalization, or durable event transport.

## PR Size Planning Budget

- This section is a planning and review budget, not a current `INVARIANT:` or machine-enforced merge gate.
- A later CI governance PR must add a Medium carrier before this budget becomes blocking enforcement.
- Normal PR target: no more than 2000 net changed lines.
- PRs above that target should name one exception class in the PR body:
  - move-only runtime split,
  - generated module output,
  - PG provider bundle standardization,
  - CI governance wiring.
- Exception notes should state the reason, affected file family, and validation command.
- A PR that mixes an exception with unrelated behavior changes is outside this plan and should be split.

## Non-Negotiable Architecture Rules

- Domains remain isolated bounded-context crates.
- Cross-domain communication remains contract-driven through `contracts/**` and `generated`.
- `assembly.toml` is a deployment/provider fact source; it does not become a wire contract source.
- Runtime assembly may depend on adapters and domains as a composition root, but domain crates must not depend on adapters or sibling domains.
- Provider declarations must remain machine-readable and validated against assembly dependencies, required features, lifecycle, durability, and consumer.

## AI-HARD Policy

- New enforcement claims must have a Hard or Medium carrier.
- Do not add Soft-only governance rules.
- A documentation-only statement may describe a desired future guard, but it must not use `INVARIANT:` until the carrier exists.
- Every new Medium gate must include an anti-vacuity red case or fixture.
- Every generated artifact must have a drift check before later PRs depend on it.

## Security Production Closeout Gate

INVARIANT: SECURITY-PRODUCTION-CLOSEOUT-01 { level = "Medium", exec = "verify", source = "code" }.

- For `profile = "production"`, `assembly validate` must require active persistent backend providers for `oidc::OidcProvider`, `vault::VaultSigner`, and `vault::VaultKeyProvider`.
- For `profile = "production"`, `assembly validate` must find `run()`-reachable Rust AST evidence for local JWKS file source wiring, `oidc_jwks_ready`, and OIDC managed-resource wiring.
- For `profile = "production"`, `assembly validate` must find `run()`-reachable Rust AST evidence for SPIFFE/mTLS Internal/domain transport wiring and must reject legacy Internal service-token migration constants.
- Comment, string, dead-helper, and `#[cfg(test)]` bait are not evidence. The xtask fixture suite must keep red cases for missing critical providers, missing JWKS evidence, missing SPIFFE evidence, bait-only sources, and evidence outside the `run()` call chain.
- `profile = "demo"` assemblies are not blocked by this production-only closeout gate.

## Runtime Baseline Policy

- Baseline inventory must lock stable current facts before runtime root decomposition.
- The baseline must distinguish machine-checkable anchors from explanatory ordering rationale.
- Runtime wiring drift must fail through an xtask gate before behavior-preserving refactors proceed.
- Dynamic runtime facts that depend on environment, live providers, generated subscriptions, or topology must be documented as dynamic and not asserted as static baseline facts.

## Validation

- Documentation foundation PRs run `cargo xtask verify --fast`.
- Baseline PRs additionally run `cargo xtask runtime-baseline verify` and `cargo xtask archrules verify`.
- Runtime code PRs run focused crate tests, `cargo test -p runtime` when touching runtime assembly, and `cargo xtask verify --fast`.
- CI/governance PRs update the relevant xtask tests and verify plan membership tests.
