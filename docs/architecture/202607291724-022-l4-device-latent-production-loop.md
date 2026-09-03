# ADR-022: DeviceLatent L4 production-loop boundary and proof carriers

- Status: Accepted
- Date: 2026-07-29
- Last amended: 2026-08-12 by
  [project-scope](../rules/project-scope.md)
- Scope: #1892 and implemented T1/T2 PBIs #1893–#1909; product activation handoff is external

## Context

RSS has an empty draft L4 reconcile contract, an in-memory device command loop, a persistent PostgreSQL revocation store, unfinished certificate signer seams and a development MQTT path. The received specification package predated the current migration head and treated several already-completed or repository-wide capabilities as new L4 work.

The production loop must preserve the distinction between accepted intent, transport acknowledgement and reported convergence. It must also prevent stale workers, unauthorised certificate material and non-durable ingress from producing authoritative facts.

## Decision

RSS will model certificate policy as monotonic desired and reported generations. A generation-bound command is additionally fenced by an epoch. Command acknowledgement advances command receipt/state only; readiness requires a matching reported generation and certificate state.

The target API and fact set remains draft until ADR-028's candidate implementation, hardening and atomic activation
conditions are independently satisfied. #1894 directly replaces the empty draft `identity.reconcile-loop`; no alias,
shim, dual reader or dual write is retained.

External PKI owns CA, EST/CSR, SAN and key-usage authorization, signing, CRL/OCSP and certificate lifecycle. RSS now has a
candidate-level provider closure sealed over provider identity, production configuration
and conformance evidence. Each command separately requires an `AuthorizedCertificateArtifact` sealed over tenant, device,
generation, policy, authorization receipt, public key, chain and expiry. Neither capability may substitute for the other.
The #2116 T1/T2 carrier implements this closure and formal mint, while assembly-required wiring and activation remain future.
The simulator is not a production
credential provider, and a future candidate assembly may have no SoftCA, plaintext, in-memory or missing-provider fallback.

The current persistent revocation store remains RSS's sole decision-side revocation projection/cache/lookup. It is not the PKI lifecycle or publication authority, which remains External. Scheduling is purpose-specific and durable; public commands and ingress receipts are emitted through transaction-bound outbox outcomes. MQTT production transport is a direct replacement: the production client is always compiled and exposes one `MqttSession` with one driver, mandatory MQTTS/mTLS material, a certificate-CN-bound stable client ID, `clean_start=false`, bounded session expiry, manual ACK, closed readiness/reload state and one non-empty exact per-device topic policy. Plaintext, random identity, separate publisher/subscriber clients, fallback implementations and environment-selected external MQTT test brokers do not remain.

The Mosquitto v5 plugin is part of that transport trust boundary. It derives the only device principal from the peer certificate's unique URI SAN `urn:rss:mqtt-device:v1:{tenant}:{device}:{generation}`, verifies that principal against the exact uplink topic and rejects client-supplied reserved assertion properties. It then signs principal, topic, correlation, payload digest, QoS and retain with a broker-only Ed25519 key. RSS receives only the public verification key and can mint `AuthenticatedDeviceDelivery` only after exact policy and signature verification. Topic and payload coordinates can constrain the credential-derived principal but can never construct or override it.

The downlink PUBACK capability is named `BrokerAccepted` to preserve FR-022: it proves broker acceptance only. #1902 does
not create a device ACK or an application receipt, does not own #1903's durable ingress transaction, and does not satisfy ADR-028's future assembly-level provider closure,
typed candidate construction or component-lifecycle requirements, much less the later designated-process T3 join.

Inbound success PUBACK remains gated by the non-forgeable authenticated delivery capability. MQTT
v5 negative PUBACK is a separate adapter-private terminal-rejection path for invalid broker
assertions/topics: it prevents persistent poison replay but never creates `BrokerAccepted`, durable
commit, device ACK, or application receipt authority. If its transport outcome is unknown, the
session stops fail-closed without automatic reconnect.

Closure extends existing typed registry/code generation, validation, CI-impact and evidence paths. There is no subsystem-only gate, required CI job or additional deployment platform.

#1895 performs an atomic, deliberately breaking cutover. Generated event payloads can only enter the production fact path through a sealed per-contract emit wrapper and the private `ReviewedEvent` carrier; production providers do not accept ordinary `EventEntry`. Manifest subscriptions can only enter `bootstrap::Registry` through their generated typed wrapper. The former open generated-payload conversion and raw subscriber registration APIs are deleted without aliases, adapters, dual paths or feature flags. The only Service → Generated bridge owners are `eventexec` and `bootstrap`, guarded as exact directed edges.

## Enforcement carriers

| Constraint | Owner | Minimum carrier |
|---|---:|---|
| Generation, epoch, condition and command state cannot be forged | #1893 | Private fields/newtypes/sealed constructors (Hard); table-driven state-machine and property tests (Medium) |
| L4 HTTP and L2 facts retain the declared kind, links and schema identity | #1894/#1895 | Contract schema, code generation and golden outputs (Hard); validator synthetic-red tests (Medium) |
| Callers cannot forge contract ID, topic, schema hash or transport coordinate | #1895 | Generated sealed emit/subscribe/reconcile seams plus private `ReviewedEvent`/provider boundary (Hard); exact `eventexec|bootstrap → generated` bridge-owner guard (Medium) |
| Desired/reported monotonicity, tenant isolation, RLS and CAS-zero-write behavior | #1896/#1897 | Database checks, uniqueness, FORCE RLS and grants (Hard); real-PostgreSQL conformance tests (Medium) |
| Retry schedule survives restart and target wake is repairable | #1898 | Durable schedule transaction/CAS plus PostgreSQL restart and lost-wake tests (Medium) |
| Concurrency is bounded, one target has one executor and drain is deterministic | #1899 | Validated closed configuration (Hard); scheduler concurrency/drain tests (Medium) |
| Generation/epoch fencing and system producer identity survive takeover | #1900 | Typed command/fence coordinate (Hard); stale-worker/takeover PostgreSQL tests (Medium) |
| Raw signer, SoftCA or simulator receipt cannot impersonate a per-command authorized artifact | #1901 | Sealed `AuthorizedCertificateArtifact` binding and incompatible provider types (Hard); command-authoring substitution tests (Medium) |
| Production MQTT requires mTLS, stable persistent session, manual ACK, exact typed topics and a credential-derived principal | #1902 | Required non-optional configuration, private topic constructors and non-forgeable delivery/ack capabilities (Hard); hermetic Mosquitto mTLS/plugin/ACL/session/reload tests (Medium) |
| Application receipt follows durable commit | #1903 | Typed transaction outcome and receipt funnel (Hard); crash/duplicate/saturation tests (Medium) |
| Draft pilot composition cannot omit or substitute its declared providers | #1904 | Compile-only assembly manifest/code generation and required provider types (Hard); no startup, readiness, drain, binary, image, or production artifact claim |
| Metrics and operator inspection are closed, authorized and redacted | #1905 | Closed enums and typed read permission (Hard); authorization/redaction tests (Medium) |
| Independent PostgreSQL/worker joins (authorized-artifact return vs lease takeover; postcommit crash before attempt-result/lease release) | #1907 | Existing generation/epoch/sealed-artifact/transaction-funnel Hard owners reused; real PostgreSQL + deterministic barrier + worker/artifact-return and real-worker postcommit abort then second-worker LeaseReclaim-to-terminal-result tests (Medium); T3 owner=N/A |
| L4 closure does not become a parallel gate | #1909 | Existing typed registry/codegen exact-set (Hard); verify/CI-impact synthetic-red tests (Medium) |

These carriers are implementation obligations, not Markdown checks. Every invariant has one canonical primary proof whose minimum sufficient carrier is Hard or Medium. Hard is sufficient when a type, generated seam, schema, or database constraint prevents the invalid construction. A separate behavioral Medium carrier is required only for independent runtime hazards that Hard enforcement cannot establish, including transaction joins, real network/broker behavior, restart or takeover, concurrency, and drain. An owner that cannot supply its assigned sufficient carrier must narrow the claim or defer it.

The assembly-level provider closure and per-command authorization are now separate #2116 candidate carriers, with substitution
compile-fail tests and real Vault T2 conformance. They are deliberately not wired as a required assembly dependency here;
#2117 owns that construction boundary. The `ProductionEligibility` marker alone still cannot stand in for either authority.

## Consequences

- Policy acceptance can succeed while status remains progressing or degraded; clients must read local status for observed convergence.
- Durable facts and fencing add storage and transaction work, but remove process-local authority and ambiguous recovery.
- Candidate assembly wiring waits for #2117 even though the external PKI closure/mint carrier exists;
  activation additionally waits for ADR-028's independent hardening/T3 first-green and atomic transition.
- Rollout and rollback operations, including the rule that active contract lifecycle never regresses to draft, are owned by [plan.md](../spec/007-l4-device-latent-production-loop/plan.md#rollback).

## Documentation ownership

Provenance and current evidence live in [source-baseline.md](../spec/007-l4-device-latent-production-loop/source-baseline.md). Requirements, logical state, proposal shapes, delivery sequencing and proof ownership remain in their dedicated documents under the same specification directory; this ADR owns only cross-PBI architecture, security boundaries and carrier policy.
