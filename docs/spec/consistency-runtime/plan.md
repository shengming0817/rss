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

**Constraints**: Docs-only scope; no `docs/rules/**` body changes; no Soft-only governance claims; avoid old command/outbox snippets blocked by `doc-contracts`

**Scale/Scope**: One SpecKit feature directory, one `.specify/feature.json` pointer update, and no optional runtime design artifacts

## Constitution Check

*GATE: RSS has no separate constitution file. `CLAUDE.md`, `docs/rules/**`, and executable `xtask`/Cargo gates are the applicable governance sources.*

- **Layering / crate graph**: PASS. The plan records ownership without changing dependencies. `consistency` remains engine-only; runtime harness stays in `eventexec`; provider ports stay in `diport`; implementations stay in adapters; composition stays in bootstrap/assembly.
- **Contract-only cross-domain communication**: PASS. The entry states that domains communicate through `contracts/**` and `generated`; it does not introduce hand-written cross-domain DTOs or a parallel registry.
- **L0-L4 single source**: PASS. The entry links L0-L4 to `contract.toml` `consistencyLevel` and existing `docs/rules/architecture.md` semantics instead of defining a second rule source.
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
| Newtypes and pure state machines | L0 | `docs/rules/architecture.md` | `crates/consistency`, private fields, constructors, table tests |
| Local transaction + outbox append | L1/L2 | `docs/rules/eventbus.md` | transaction funnel, outbox entry, adapter store tests |
| Inbox idempotency and consumer lease | L0/L2 | `docs/rules/eventbus.md` | lease token CAS, ConsumerBase, integration/gov tests |
| Saga executor and journal | L3 | `docs/rules/saga.md` | `eventexec`, journal append/resume, contract governance |
| Projection and checkpoint | L3 | `docs/rules/eventbus.md` | serial in-order witness, checkpoint CAS, append-only storage |
| Reconcile control loop | L4 | `docs/rules/reconcile.md` | required tenancy/trigger, leader-gated run, `FencedWriter` |
| Tenant-aware consistency | cross-cutting | `docs/rules/tenancy.md`, `docs/rules/observability.md` | tenant authority, partition key scope, DLX encryption, low-cardinality metrics |
| Domain crates | all levels | `docs/rules/architecture.md` | own bounded-context behavior; communicate cross-domain only through `contracts/**` and `generated` |
| `contracts/**` | declaration source | `contracts/README.md`, `docs/rules/architecture.md` | authoring source for `kind`, `owner`, schema, lifecycle, topic/path, and `consistencyLevel` |
| `generated` crate | derived contract surface | `contracts/README.md`, `docs/rules/architecture.md` | committed codegen output consumed by domains/runtime; must not become a handwritten runtime registry |
| Bootstrap / assembly | composition | `docs/rules/architecture.md`, `docs/rules/eventbus.md` | topology selection, provider injection, consumer registration, and executable assembly validation |

## AI-HARD Carrier Map

| Constraint | Rule Source | Hard / Medium Carrier | Residual Boundary |
|------------|-------------|-----------------------|-------------------|
| Broker tenant authority before app DLX writes | `docs/rules/tenancy.md` §Broker tenant authority, `docs/rules/eventbus.md` §DLX 与幂等, `docs/rules/observability.md` §Outbox Envelope | **Hard/Medium**: reserved `tenantAuthority` HMAC binds `iss/aud/tenantId/domain/contractId/topic/messageId/iat/exp`; consumer must verify issuer/audience, TTL, topic, contract, message id, and tenant before app DLX; failure must skip app DLX, release claim, broker `Reject`, and emit closed-set `consumer_dlx_skip_total{reason=tenant_authority_*}`. | Covers broker-to-consumer-to-DLX trust only; HTTP `X-Tenant-ID` and service-token tenant MAC remain governed by `docs/rules/tenancy.md` §Tenant source. This docs-only entry adds no new verifier. |
| Tenant-scoped outbox partition ordering | `docs/rules/tenancy.md` §RLS 与 PG scope, `docs/rules/eventbus.md` §投递顺序保证 | **Medium + future Hard**: `OUTBOX-PARTITION-ORDER-01` head-of-partition gate keeps one in-flight entry per `(domain, partition_key)` and DLX blocks the partition until redrive. `partition_key` must carry tenant scope or global uniqueness. | A typed tenant-scoped `PartitionKey` or outbox `tenant_id` + RLS hardening is future work tracked by the existing rule-source backlog; this plan must not claim that hardening is already complete. |
| DLX payload confidentiality and replay boundary | `docs/rules/eventbus.md` §DLX 与幂等, `docs/rules/tenancy.md` §持久化模式 tenant 作用域合约 | **Hard/Medium**: durable runtime requires `RSS_DLX_PAYLOAD_KEY_NAME` and Vault transit configuration; plaintext `{"bytes":[...]}` DLX payload shape is forbidden; replay requires `OperatorDlqCapability`, typed `DeadLetterId`, a caller-supplied new `IdemKey`, and the same `KeyProvider`. Tenant dead-letter writes stay inside the tenant-scoped PG funnel. | This feature adds no migration, key provider, or replay API. Future runtime work must cite the executable guard or rustdoc invariant that enforces each boundary. |
| Inbox lease CAS and leaseLost hard-fence | `docs/rules/eventbus.md` §租约续租 + leaseLost hard-fence, §DLX 与幂等; `crates/consistency/src/idempotency.rs` token rustdoc + `crates/consistency/src/inbox.rs` store rustdoc | **Hard**: `LeaseToken::mint()` is the only token constructor and mints uuid-v4 values behind a private field. **Medium**: backend `InboxStore::try_claim/extend/commit/release` CAS behavior, `LeaseOutcome::Lost` handling, and leaseLost requeue/cancel paths are runtime/provider conformance. | During the TTL/renewal race window, handlers can run twice; side effects must remain idempotent or reentrant. This plan documents the requirement without adding a conformance testkit. |
| Projection serial delivery and checkpoint safety | `docs/rules/eventbus.md` §Projection | **Hard + Medium**: `PROJECTION-SERIAL-WITNESS-01` requires `ProjectionHarness::new` to receive sealed `SerialInOrderGuarantor`; `PARTITION-SERIAL-IMPL-ALLOWLIST-01` keeps witness sources on the allowlist via `rss_partition_serial_allowlist`; append-only projection storage is backed by DB `REVOKE UPDATE, DELETE` plus code-level lint. | Witness authenticity depends on allowed adapter/assembly implementations. This feature does not add a projection runtime or new `PartitionSerialDelivery` source. |
| Reconcile tenancy and stale-writer fencing | `docs/rules/reconcile.md` §Builder 强制, §Leader-elect | **Hard**: `RECONCILE-TENANCY-REQ-01` makes `Builder::new(r, tenancy, trigger)` require `Tenancy` and `Trigger` as positional arguments; trybuild compile-fail tests cover missing tenancy/trigger. **Hard/Medium**: `RECONCILE-FENCE-MONO-01` injects monotonic epoch and `FencedWriter` performs per-key CAS for stale writer rejection. | Tenant-scoped reconcilers must encode tenant dimension in command id; the framework does not inspect command body. This docs-only PR does not add new reconcile adapters. |
| Low-cardinality observability for consistency failures | `docs/rules/observability.md` §Metrics Label, §Consumer Settle Metrics, §Outbox Envelope | **Medium**: metric labels are frozen or typed enum values. DLX skip/write/release metrics use closed `domain`, `reason`, and `outcome` value sets; handler error, tenant, message id, and payload-derived values are forbidden as labels. | New metrics or label values must update schema, tests, dashboards, and ops docs in their implementation PR; this plan only names the carrier and acceptance boundary. |

## SpecKit Artifact Decision

Generate only the required artifacts for #1614:

- `spec.md`
- `checklists/requirements.md`
- `plan.md`
- `tasks.md`

Do not generate `research.md`, `data-model.md`, `quickstart.md`, or `contracts/` for this issue. The benchmark research is compact enough for this plan, there is no new data model or interface contract, and no runnable runtime scenario is delivered by the docs-only change.

## Complexity Tracking

No Constitution Check violations.
