# Feature Specification: Platform vNext application waist

**Created**: 2026-08-08
**Rebased**: 2026-08-11
**Status**: RSS cutover implemented by #2107; merge pending #2108 first-green receipt
**Decision owner**: #2102
**Implementation owners**: #2107 (RSS atomic cutover), #2108 (external first-green)

## Purpose

Platform vNext establishes one typed application waist without taking ownership from contract, security, runtime or
composition. This specification consumes the complete external backlog disposition from [`research.md`](research.md)
and the only implementation DAG/carrier handoff from [`plan.md`](plan.md); it does not duplicate either source.

## Normative owner model

- Foundation `rss-contract` uniquely defines `ContractId`, `ContractVersion`, `SchemaDigest` and
  descriptor/admission identity.
- Foundation `rss-request-context` uniquely defines tenant, request, principal reference/kind, deadline,
  cancellation, obligation values and read-only views. It may depend on `rss-contract` only when an obligation's
  public signature needs contract identity.
- Both Foundation packages sit below Platform and have no internal workspace dependency.
- Official OIDC integration uniquely owns JWT/JWS verification and JWKS fetch/refresh/freshness. AuthN/AuthZ funnel
  owns a private sealed capability that alone can mint `TrustedRequestContext`.
- Platform owns descriptor admission, typed async `Handler<C>`, closed dispatch outcome/error semantics,
  module/dispatch and stable host-view ports. It consumes and propagates Foundation deadline/cancellation values
  without redefining their types. It never receives raw token/JWKS, validates credentials or mints identity.
- RuntimeExec uniquely owns startup, signals, readiness, admission stop, the total drain budget, shutdown and live
  inventory. Platform only reads the projection supplied through an internal bridge.
- Assembly/composition is the sole wiring owner. RuntimePlan, provider catalog, constructors, inventory publisher and
  third-party SPI remain internal.

Public value types carry data, not authority. A caller cannot construct trusted context by assembling Foundation
values, and a Platform handler cannot bypass AuthN/AuthZ admission or RuntimeExec lifecycle ownership.

## Async dispatch semantics

`Handler<C>` is async and receives the admitted descriptor plus a read-only trusted request view. Dispatch returns a
closed typed outcome and propagates typed deadline/cancellation. New admission fails closed while RuntimeExec is
draining; admitted work shares RuntimeExec's single total drain budget. Platform does not create another counter,
condition variable, signal path or shutdown state machine.

## Breaking cutover

vNext is a breaking 0.x Release API change. #2107 deletes duplicate identities, Platform JWT/JWKS authority,
synchronous Handler/lifecycle ownership and the old baseline in the same merge that introduces their final owners.
No alias, shim, conversion compatibility, feature flag, dual read/write, dual dispatch or v0.2 fallback is permitted.
The concrete package version is derived from Cargo metadata.

The cutover-specific order and exact-check additions are defined in [`plan.md`](plan.md). The canonical cross-repository
first-green receipt and immutable artifact rollback remain owned by
[`ADR-026`](../../architecture/202608111253-026-rss-incubator-ownership-migration.md); this specification does not define
a reduced receipt schema or an alternate artifact lifecycle.

## Release and proof

The cutover reuses the current Release Surface closure planner, dependency-first stable order, `public-api` release
check and package-proof exact selected/planned/executed set. It creates no release group, registry, runner, schema or
handwritten order source. #2108 is the real external consumer; workspace path dependencies are forbidden. Its proof
must satisfy ADR-026's complete same-result provenance and canonical CI contract, not merely a package
version/checksum/lock tuple.

## Non-goals

- Public provider/host SPI, DI container, service locator or second composition root.
- Platform-owned crypto, OIDC provider lifecycle, RuntimeExec lifecycle or live inventory publisher.
- Eventing/TestKit public extraction, unrequested capability relocation or speculative external surfaces.
- A Markdown scanner or an unimplemented `INVARIANT`; planned carriers remain inactive until their owner PBI lands.

## Acceptance

- Every public identity/value and every authority/lifecycle action has exactly one owner above.
- The old v0.2 model appears only as labelled history, never as a normative alternative.
- Atomic delivery and external proof conform to the single protocol in `plan.md`.
- Cargo/rustc and deterministic T1/T2 proofs implement all carrier rows in `plan.md`; documentation is not enforcement.
