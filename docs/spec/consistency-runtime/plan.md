# Implementation Plan: Consistency Runtime SpecKit Entry

**Branch**: `docs/1614-consistency-runtime-entry` | **Date**: 2026-07-01 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `docs/spec/consistency-runtime/spec.md`

**Note**: This plan follows the active SpecKit plan template while intentionally omitting optional runtime design artifacts that do not apply to this docs-only PBI.

## Summary

Create the SpecKit single entry for RSS consistency runtime planning. The entry records L0-L4 semantics, mechanism boundaries, layer ownership, tenant-aware failure modes, benchmark references, and executable documentation tasks. It does not change runtime behavior, migrations, adapters, generated code, or `docs/rules/**` rule bodies.

## Technical Context

**Language/Version**: Markdown documentation in a Rust workspace pinned by `rust-toolchain.toml`

**Primary Dependencies**: SpecKit templates under `.specify/templates/`; RSS rule sources under `docs/rules/`; Azure Boards issue #1614

**Storage**: N/A for runtime storage; documentation is stored under `docs/spec/consistency-runtime/`

**Testing**: `cargo xtask verify --fast`

**Target Platform**: RSS repository documentation and local/CI governance gates

**Project Type**: Rust workspace documentation / governance planning feature

**Performance Goals**: N/A; no runtime code is changed

**Constraints**: Docs-only scope; no `docs/rules/**` body changes; no Soft-only governance claims; avoid old tenantless or actorless command/outbox snippets

**Scale/Scope**: One SpecKit feature directory, one `.specify/feature.json` pointer update, and no optional runtime design artifacts

## Constitution Check

*GATE: RSS has no separate constitution file. `CLAUDE.md`, `docs/rules/**`, and executable `xtask`/Cargo gates are the applicable governance sources.*

- **Layering / crate graph**: PASS. The plan records ownership without changing dependencies. `consistency` remains engine-only; runtime harness stays in `eventexec`; provider ports stay in `diport`; implementations stay in adapters; composition stays in bootstrap/assembly.
- **Contract-only cross-domain communication**: PASS. The entry states that domains communicate through `contracts/**` and `generated`; it does not introduce hand-written cross-domain DTOs or a parallel registry.
- **L0-L4 single source**: PASS. The entry links L0-L4 to `contract.toml` `consistencyLevel` and existing `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps` semantics instead of defining a second rule source.
- **AI-HARD governance**: PASS. Each planning constraint is tied to existing Hard/Medium carriers where applicable, or kept as documentation acceptance for future tasks. No new Soft-only rule is introduced.
- **Docs-only blast radius**: PASS. The file set is limited to `docs/spec/consistency-runtime/**` and `.specify/feature.json`.
- **Open-source benchmark requirement**: PASS. The plan includes real benchmark references for saga, reconcile, and CQRS/projection concepts.

## Benchmark References

- `ref: steno src/saga_action_generic.rs@5b0d1be32fb3e3047ff4e4f972b59dc52f9c89ba` — finite saga actions, undo compensation, journal/resume, and idempotent action expectations.
- `ref: kube-rs/kube kube-runtime/src/controller/mod.rs@8e6c86ee2d3e8a14a4e61da88b8d9920ba29b9cc` — reconcile action lifecycle, requeue semantics, controller error handling, and watch-driven convergence.
- `ref: cqrs-es src/cqrs.rs@d6bc03ca1cd7a6538fedb51fd4c592126527a3c0` — command handling, event commit, query/view dispatch, and replay-oriented CQRS flow.

RSS adopts the conceptual lifecycle from these references but keeps its own crate graph, native AFIT strategy traits, tenant authority, generated contract topology, lease/fencing, and Hard/Medium governance carriers.

## Project Structure

### Documentation (this feature)

```text
docs/spec/consistency-runtime/
├── spec.md
├── checklists/
│   └── requirements.md
├── plan.md
└── tasks.md
```

`specs/consistency-runtime/**` resolves to the same content because `specs` is a symlink to `docs/spec`.

### Source Code (repository root)

```text
.specify/
└── feature.json          # points follow-up SpecKit commands at docs/spec/consistency-runtime
```

No Rust source, migrations, adapters, generated contracts, or `docs/rules/**` rule bodies are in scope.

**Structure Decision**: Use the explicit issue target `docs/spec/consistency-runtime` rather than sequential `006-*`, because #1614 names the feature directory and the repository already exposes it through the `specs` symlink. Updating `.specify/feature.json` intentionally changes the repository default SpecKit feature; continuing an older feature requires setting `SPECIFY_FEATURE_DIRECTORY` explicitly or restoring the pointer.

## Mechanism Boundary Map

| Mechanism | Level | Rule Source | Owner / Carrier |
|-----------|-------|-------------|-----------------|
| Newtypes and pure state machines | L0 | `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps` | `crates/consistency`, private fields, constructors, table tests |
| Local transaction + outbox append | L1/L2 | `contracts/**/contract.toml`、`generated` 与 `crates/consistency` | transaction funnel, outbox entry, adapter store tests |
| Inbox idempotency and consumer lease | L0/L2 | `contracts/**/contract.toml`、`generated` 与 `crates/consistency` | lease token CAS, ConsumerBase, integration/gov tests |
| Saga executor and journal | L3 | generated / diport::SagaDurableStore / saga conformance | `eventexec`, journal append/resume, contract governance |
| Projection and checkpoint | L3 | `contracts/**/contract.toml`、`generated` 与 `crates/consistency` | serial in-order witness, checkpoint CAS, append-only storage |
| Reconcile control loop | L4 | `consistency::Reconciler`、`diport::FencedWriter` 与 provider conformance | required tenancy/trigger, leader-gated run, `FencedWriter` |
| Tenant-aware consistency | cross-cutting | `TenantId`、`RowScope`、`pg_tenant_tx_guard` 与 PostgreSQL RLS/ACL, `crates/observ`、`secure::redact_error` 与 typed metric enums | tenant authority, partition key scope, DLX encryption, low-cardinality metrics |
| Domain crates | all levels | `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps` | own bounded-context behavior; communicate cross-domain only through `contracts/**` and `generated` |
| `contracts/**` | declaration source | `contracts/README.md`, `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps` | authoring source for `kind`, `owner`, schema, lifecycle, topic/path, and `consistencyLevel` |
| `generated` crate | derived contract surface | `contracts/README.md`, `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps` | committed codegen output consumed by domains/runtime; must not become a handwritten runtime registry |
| Bootstrap / assembly | composition | `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`, `contracts/**/contract.toml`、`generated` 与 `crates/consistency` | topology selection, provider injection, consumer registration, and executable assembly validation |

## AI-HARD Carrier Map

| Constraint | Rule Source | Hard / Medium Carrier | Residual Boundary |
|------------|-------------|-----------------------|-------------------|
| Broker tenant authority before app DLX writes | `eventexec::TenantAuthority` and consumer preflight | **Hard/Medium**: reserved `tenantAuthority` HMAC binds `iss/aud/tenantId/domain/contractId/topic/messageId/iat/exp`; consumer verifies issuer/audience, TTL, topic, contract, message ID and tenant before app DLX. Failure skips app DLX, releases the claim, broker-rejects, and emits a closed-set reason metric. | Covers broker-to-consumer-to-DLX trust only; HTTP challenger and service-token tenant claims use separate verifier funnels. This plan adds no verifier. |
| Tenant-scoped outbox partition ordering | `OUTBOX-PARTITION-ORDER-01` and outbox provider guards | **Medium + future Hard**: the head-of-partition gate keeps one in-flight entry per `(domain, partition_key)`; DLX blocks that partition until redrive. `partition_key` carries tenant scope or global uniqueness. | A typed tenant-scoped `PartitionKey` or outbox `tenant_id` plus RLS remains future hardening; this plan does not claim it exists. |
| DLX payload confidentiality and operator boundary | `DlqOperatorAuthorization`, `dlqauthmint`, and runtime DLQ flow | **Hard/Medium**: durable runtime requires configured payload encryption; plaintext byte-array payloads are forbidden. Each operator action consumes a move-only authorization binding action, tenant, caller, verified operator and durable start audit ID; only runtime can mint it. Mutation and finish audit commit in one tenant transaction and return a typed durable receipt. | Exact runtime ordering and durable audit persistence are Medium; cross-crate mint authority and action/tenant binding are Hard. Tenant dead-letter writes stay inside the tenant-scoped PG funnel. |
| Inbox lease CAS and leaseLost hard-fence | `LeaseToken`, `InboxStore`, and `LeaseOutcome` | **Hard**: `LeaseToken::mint()` is the only constructor and mints UUID-v4 behind a private field. **Medium**: provider CAS for claim/extend/commit/release and `LeaseOutcome::Lost` cancellation/requeue paths. | Handlers can overlap during the TTL/renewal race window; effects must remain idempotent or reentrant. This plan adds no conformance testkit. |
| Projection serial delivery and checkpoint safety | `ProjectionHarness`, `SerialInOrderGuarantor`, and partition-serial lint | **Hard + Medium**: `PROJECTION-SERIAL-WITNESS-01` requires the harness to receive a sealed serial witness; `PARTITION-SERIAL-IMPL-ALLOWLIST-01` restricts witness sources. Append-only storage is backed by database privilege and code guards. | Witness authenticity depends on allowlisted adapter/assembly implementations. This plan adds no projection runtime or new witness source. |
| Reconcile tenancy and stale-writer fencing | `consistency::Reconciler`, `diport::FencedWriter`, and provider conformance | **Hard**: `RECONCILE-TENANCY-REQ-01` requires tenancy and trigger as positional builder inputs. **Hard/Medium**: `RECONCILE-FENCE-MONO-01` injects a monotonic epoch and `FencedWriter` performs per-key CAS. | Tenant-scoped reconcilers must encode tenant in command identity; the framework does not inspect command bodies. This plan adds no adapter. |
| Low-cardinality observability for consistency failures | typed metric enums and metric schema | **Medium**: metric labels are frozen or typed enum values. DLX skip/write/release metrics use closed domain, reason and outcome values; handler error, tenant, message ID and payload values are forbidden labels. | New metrics or values must update schema, tests, dashboards and ops artifacts in their implementation PR; this plan only records the carrier boundary. |

## SpecKit Artifact Decision

Generate only the required artifacts for #1614:

- `spec.md`
- `checklists/requirements.md`
- `plan.md`
- `tasks.md`

Do not generate `research.md`, `data-model.md`, `quickstart.md`, or `contracts/` for this issue. The benchmark research is compact enough for this plan, there is no new data model or interface contract, and no runnable runtime scenario is delivered by the docs-only change.

## Complexity Tracking

No Constitution Check violations.
