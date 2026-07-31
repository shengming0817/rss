# Runtime Assembly Plan Rules

This document governs the runtime assembly optimization series rooted at `docs/spec/001-runtime-assembly-plan/`. It supplements the architecture single source in `docs/rules/architecture.md`; it does not replace crate graph, contract, tenancy, observability, or eventbus rules.

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

- Assembly manifest schema v2 must declare static assembly intent through required `schemaVersion = 2`, `name`, `profile`, `domains`, `topology`, `frameworkContracts`, `workflowActivations`, `listeners`, and `diportProviders` fields. Every listener must explicitly carry its `domains` (including `[]`), every provider must explicitly carry its closed `outputs` channel set (including `[]`), and every assembly must explicitly carry its assembly-local workflow activation set (including `[]`).
- Provider `id` and `consumer` are closed `ProviderRole` and `ProviderConsumer` values. One private role registry binds every role to its lifecycle, port, constructor, provider crate, required features, consumer, durability, optional scope and failure posture, complete output set, and optional factory symbol. Active roles require exactly one factory; draft roles cannot carry one. There is no free-form role, consumer, factory path, alias, or unknown extension point.
- Contract lifecycle describes a repository definition; `WorkflowActivation` describes one assembly's deployment intent. Projection activation is closed to `disabled | capture-only | shadow | active`, Saga activation to `disabled | active`. Each activation binds the exact definition ID, version, and schema digest, and repository verification rejects unknown definitions, mode mismatches, digest drift, and invalid lifecycle × activation combinations. Topology and provider declarations do not supply an activation default.
- Assembly manifest v2, AssemblyLock v2, and RuntimePlan v2 are one protocol chain. The lock binds the canonical manifest to the verified repository definition; `RuntimePlanV2::compile_v2` requires `workflowPlans` to exactly equal the canonical activation set while also seeding provider candidates from active manifest declarations and enforcing their exact bijection. Executable JSON readers must bind the wire value to the canonical manifest and AssemblyLock and recompile through that funnel; the unbound wire/fingerprint validator returns no executable plan. Draft provider declarations can remain planning facts in non-production assemblies but can never enter executable provider state; no runtime selector or compatibility fallback exists.
- Production workflow activation is compiled exactly once by the private-field `eventexec::WorkflowRuntimePlan`, joining the sealed RuntimePlan to generated definitions and typed capabilities. PostgreSQL capture, Projection operator/DLQ, Saga runtime, and runtime inventory consume only borrowed views minted by that plan. Omitted or disabled workflows have no registry, provider, worker, route, probe, capture, or inventory side effect; direct production consumption of raw generated workflow catalogs is forbidden outside the compiler.
- `scope` and `failurePosture` are closed manifest validation facts, not runtime selection switches. The active `service-token-replay-store` role requires `scope = "cluster-global"` and `failurePosture = "fail-closed"` in addition to a persistent PostgreSQL provider. Missing facts, `process-local`, or `fail-open` fail `PdpReplayStoreCapability` validation before assembly generation; the assembly graph and runtime baseline expose the selected posture for review.
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
- `cargo xtask assembly generate-modules` first compiles `assembly.toml` into `CanonicalAssemblyManifestV2`, then derives each assembly's committed `src/generated/modules_gen.rs` from that sole semantic view. Domain/listener/framework-contract order remains semantic; `diportProviders` sort by `(port, provider, providerCrate, consumer)`, and provider `requiredFeatures`/`outputs` are duplicate-free sorted sets. The generated provenance header carries `Source-Manifest-Digest`, never a raw-TOML hash, so key/table/set order cannot create false drift. `ASSEMBLY-MODULES-CODEGEN-01` is the Hard codegen/golden carrier; `--check` runs in verify/CI and fails on missing, changed, hand-edited, or owned orphan outputs.
- The generated file contains the ordered async `domains::<name>::module(deps)` calls, typed domain-listener/provider-output evidence, plus a `#[cfg(test)]` hermetic factory emitted by the same manifest plan. It does not derive environment access, runtime instances, features, or compose/merge behavior; the test factory also returns ordinary `DomainBinding` values.
- `cargo xtask assembly generate-providers` independently derives committed `src/generated/providers_gen.rs` files, sorted by role ID and containing active entries only. Every entry explicitly supplies typed role, port, constructor, factory symbol, provider crate/features, consumer, durability, optional scope/failure posture, and the complete output set (including `[]`) to `ProviderCatalogEntry::checked`. The generated grammar is data-only: imports plus a const catalog, with no function body, environment/config/secret access, instance construction, `Any`, `TypeId`, map, dynamic callback, or service locator.
- The provider catalog is compiled privately into each assembly crate and is not an external SDK/API. The provider gate parses each crate root and requires one unconditional private `providers_gen` module plus one unconditional non-empty const assertion; deleting or `cfg`-disabling the compile link fails before generation. `ProviderCapabilityEvidence` cannot be arbitrarily constructed; the role declaration cardinality, registry tuple, and constructor feature/crate/port/durability/scope/failure-posture facts are const-checked, and the const catalog entry forms the Hard carrier. The generator validates an exact AST grammar rather than relying on a token denylist, and its filesystem planner scans the complete ownership-marker universe without following symlinks. Manifest validation, committed goldens, independent `--check`, and rustc typecheck are the Medium/codegen backstop. The aggregate order is fixed as `assembly validate → artifacts check → modules check → providers check → lock check → graph check`, and both generated families enter the AssemblyLock byte universe; the artifact matrix does not.
- `modules_gen.rs` remains the current live output-composition carrier. It is neither copied into the role registry nor accepted as a provider-catalog fallback. #1792 owns live catalog dispatch, handwritten bypass deletion, and the output bijection; #1791 does not instantiate providers.
- Defining the binding/output shape does not itself change live `runtime::run()` behavior. Moving wire functions, generating the module list, and switching the live path remain separate dependent changes with baseline verification.
- The generated artifact is the live domain-order carrier. `RUNTIME-GENERATED-DOMAINS-LIVE-01` rejects handwritten fallback and requires `compose_bindings` plus output merge; typed route/subscriber declaration funnels preserve the single `RouteAuthorizer` / `SettingsService` instances without a service bag.
- Reusable `composition/*` crates may own a domain's typed provider-to-`DomainBinding` construction when multiple assemblies consume it. They remain Root-layer code, use mandatory typed inputs, and must not introduce a DI container, generic bag, manifest reader, or launch entrypoint.
- #1796 and #1797 make `settingsonly` and `identityaudit` executable subset assemblies on the shared `runtimeexec` launch/signal/drain kernel. Their closed configuration schemas, image stages, Health listener/inventory ownership, and lifecycle journeys are live carriers; their existing provider, authentication, readiness, and behavior guards remain assembly-specific. `topology = "demo"` still does not claim production durability or the production posture owned by #1801.

## Assembly Definition of Done

- Every direct `assemblies/*` target is classified exactly once in schema-v1 `assemblies/artifacts.toml`; an unknown, omitted, duplicate, or ghost target fails closed. Artifact-matrix versioning is independent of assembly manifest/lock/RuntimePlan v2.
- A `supported` assembly closes five identities: an exact Cargo binary target, a unique nonroot distroless Docker stage with matching entrypoint, a validated configuration carrier, exact `runtimeexec` Health listener/inventory ownership, and a non-vacuous journey. `runtime` uses the typed environment catalog guarded by the runtime-env gate; `settingsonly` and `identityaudit` use recursively closed Draft-07 JSON schemas.
- `compile-only` is an explicit lifecycle with a non-empty reason and cannot carry deployable artifact fields. There is no default lifecycle, compatibility alias, fallback reader, report-only mode, or alternate CLI.
- The Assembly Governance IR owns the closed production identity ratchet and requires its exact set to remain `supported` with a non-vacuous journey. New non-production targets may be explicit `compile-only` rows, but changing both profile and artifact lifecycle cannot downgrade an existing production carrier.
- `ASSEMBLY-ARTIFACT-MATRIX-01` in `xtask/src/assembly_artifacts.rs` is the Medium enforcement carrier. It validates application-owned binary, image, configuration, health/inventory, and journey facts and returns only a verified supported-row count; external delivery/release tooling owns every deployment projection. `cargo xtask assembly artifacts check` is the focused gate, and typed verify/CI execute it after manifest validation.
- Artifact classification is an application validation boundary, not a deployment plan. It is not an input to canonical `AssemblyManifest`, generated modules/providers, AssemblyLock, or RuntimePlan and therefore cannot rotate those identities. Its internal Health inventory is not #1806's authorized public RuntimeInventory, and a supported row is not #1801 production-posture evidence.

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
- Provider declarations must remain machine-readable and validated against assembly dependencies, required features, lifecycle, durability, scope, failure posture, and consumer.
- Provider catalog changes are code-only. They require no database, secret, configuration, or external wire-contract migration. Rollback reverts the binary/catalog/lock/fingerprint diff as one unit; it must not add an alias, old reader, dual write, free-form factory path, or runtime fallback.

## AI-HARD Policy

- New enforcement claims must have a Hard or Medium carrier.
- Do not add Soft-only governance rules.
- A documentation-only statement may describe a desired future guard, but it must not use `INVARIANT:` until the carrier exists.
- Every new Medium gate must include an anti-vacuity red case or fixture.
- Every generated artifact must have a drift check before later PRs depend on it.

The provider catalog design follows
[Typify's programmatic code generation](https://github.com/oxidecomputer/typify/blob/aec3da53c4319164542b393a86d552424be24384/typify/src/lib.rs)
and [Omicron's explicit package manifest](https://github.com/oxidecomputer/omicron/blob/9932e3633a3417d130af44dfce12672eb8e0ec00/package-manifest.toml)
as comparison points. RSS adopts closed programmatic output and explicit manifest identity, not
their public API or package model.

## Security Production Closeout Gate

INVARIANT: SECURITY-PRODUCTION-CLOSEOUT-01 { level = "Medium", exec = "check", source = "code" }.

- For `profile = "production"`, `assembly validate` must require active persistent backend providers for `oidc::OidcProvider`, `vault::VaultSigner`, and `vault::VaultKeyProvider`.
- For `profile = "production"`, every declared provider must be active and persistent except the exact active `GovernorLimiter` replica-local rate limiter. Full runtime additionally requires the persistent PostgreSQL revocation store and Vault secret resolver. Required Cargo features are derived from the closed provider constructor registry rather than duplicated in production policy.
- For `profile = "production"`, `assembly validate` must find `run()`-reachable Rust AST evidence for typed profile-specific provider/binding wiring, local JWKS file sources, `rss_access_token_jwks_ready` / `federated_access_token_jwks_ready`, and their managed resources.
- For `profile = "production"`, `assembly validate` must find `run()`-reachable Rust AST evidence for SPIFFE/mTLS Internal/domain transport wiring and must reject legacy Internal service-token migration constants.
- For production `assemblies/runtime`, `assembly validate` must keep egress TLS downgrade knobs (`RSS_AMQP_ALLOW_PLAINTEXT`, `RSS_REDIS_ALLOW_PLAINTEXT`, `RSS_S3_ALLOW_PLAINTEXT`, `RSS_PG_SSL_MODE`) inside `FORBIDDEN_SERVING_KEYS` and out of `FIXED_SERVING_KEYS`. Ingress `RSS_LISTENER_ALLOW_PLAINTEXT` remains allowed. When runtime Redis/AMQP/S3 wiring sources exist, production AST must reference the private-CA funnels (`RedisPrivateCa` / `AmqpPrivateCa` / `PrivateCaS3ClientFactory` / `connect_with_private_ca`).
- Comment, string, dead-helper, and `#[cfg(test)]` bait are not evidence. The xtask fixture suite must keep red cases for missing critical providers, missing JWKS evidence, missing SPIFFE evidence, bait-only sources, evidence outside the `run()` call chain, and egress TLS catalog / private-CA regressions.
- `profile = "demo"` assemblies are not blocked by this production-only closeout gate.

## Runtime Baseline Policy

- Baseline inventory must lock stable current facts before runtime root decomposition.
- The baseline must distinguish machine-checkable anchors from explanatory ordering rationale.
- Runtime wiring drift must fail through an xtask gate before behavior-preserving refactors proceed.
- Dynamic runtime facts that depend on environment, live providers, generated subscriptions, or topology must be documented as dynamic and not asserted as static baseline facts.
- Assembly intent and provider facts belong to the Assembly Governance IR and generated plan/catalog gates; the runtime baseline must not render a second copy. Runtime live closure is proved by typed exact-set comparisons over the real wire → validate → compose path, without a text inventory fixture.

## Validation

- Documentation foundation PRs run `cargo xtask verify --fast`.
- Baseline PRs additionally run `cargo xtask runtime-baseline verify` and `cargo xtask archrules verify`.
- Runtime code PRs run focused crate tests, `cargo test -p runtime` when touching runtime assembly, and `cargo xtask verify --fast`.
- CI/governance PRs update the relevant xtask tests and verify plan membership tests.
