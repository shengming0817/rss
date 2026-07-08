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
- The current infra-only statement is a convention until a Medium or Hard carrier lands.
- New `INVARIANT:` text for infra-only wiring is allowed only in the PR that adds the carrier and red/green tests.

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
