# L4 DeviceLatent Production Loop Specification

**Status:** Candidate capability specification; contracts remain Draft

**Scope:** device certificate desired-state convergence

**Issue:** #1892

This specification freezes the intended capability semantics for RSS's first device-latent certificate convergence loop. It
does not activate a contract or production path. Candidate product identity, public waist, external consumer and activation
handoff are owned by [ADR-028](../../architecture/202608120423-028-device-security-candidate-scope.md).

## User stories

### US-1 — Accept a desired certificate policy

An operator authorized for the authenticated tenant can replace a device's desired certificate policy with an expected-generation compare-and-swap and a tenant/device-bound idempotency key. A successful request returns the newly accepted generation and makes convergence work durably due in the same transaction. Acceptance means only that RSS recorded the desired state; it does not claim that the device has received or applied it.

Success means:

- the accepted generation is strictly newer than the previous generation;
- an expected-generation mismatch changes neither desired state nor scheduler state;
- replaying the same idempotency key with the same canonical policy and expected generation returns the same accepted result, while reuse for a different request is rejected;
- a device identifier from another tenant does not reveal resource existence;
- the response identifies an accepted desired state, not device convergence.

### US-2 — Converge after disconnection or restart

An offline device can later receive the newest certificate command, acknowledge command receipt, report its applied certificate state, and receive an application receipt only after RSS durably commits the ingress fact. Process or broker restarts do not erase command, retry, deadline, receipt, or convergence state.

Success means:

- ACK advances command receipt/state only;
- `Ready=True` requires a positive reported generation and state matching the current desired state, an unexpired authorized certificate, and a current non-revoked result from `PgRevocationStore`;
- duplicate ingress is idempotent and returns a deterministic receipt outcome;
- loss of a notification or exact-target wake is repaired by periodic resynchronization;
- transport acknowledgement is never interpreted as device application or durable application commit.

### US-3 — Fence stale workers and stale device facts

Concurrent workers, lease takeover, repeated desired updates, delayed commands, delayed ACKs, and delayed reports cannot move the current resource backward. Generation and fence epoch travel with every device-facing intent or fact that can mutate state.

Success means:

- accepting a newer desired generation supersedes older nonterminal command intent;
- a worker that has lost its epoch cannot publish a state-changing intent accepted as current;
- stale ACKs and reports remain auditable but do not mutate the high-water state;
- convergence targets the newest accepted generation only.

### US-4 — Inspect a non-converged device

An authorized operator can use the `LocalOnly` status read to inspect desired/reported generations, closed conditions, and payload-free command summaries. This proposal defines no operator mutation contract: resync, quarantine, unquarantine, cancel, supersede, and delete are not promised as manual recovery actions. Automatic lost-wake repair and fenced supersession remain internal loop behavior.

### US-5 — Prepare only a production-eligible candidate assembly

Release engineering can run a simulator-backed pilot while every contract remains draft. A future candidate assembly may be
constructed only after it consumes a sealed assembly-wide provider closure proving provider/configuration/conformance and the
selected provider returns a distinct `AuthorizedCertificateArtifact` for each command. Missing providers fail closed; no
demo, in-memory, plaintext, or locally signed fallback may impersonate candidate production eligibility. This candidate
closure is T1/T2 and does not itself authorize contract activation or T3.

## Functional requirements

### Desired and reported state

- **FR-001:** RSS MUST maintain a strictly monotonic desired generation for each authenticated tenant and path device.
- **FR-002:** A desired update MUST use expected-generation compare-and-swap; a mismatch MUST produce zero writes across desired state, its idempotency record, and scheduling state.
- **FR-003:** A successful desired update and its durable target wake MUST commit atomically within the same authenticated tenant transaction after their stores exist.
- **FR-004:** A report event MUST carry a positive observed generation, and accepted reported high-water state MUST never decrease. The logical initial state is absence of a reported row; generation zero MUST NOT be represented by an event, nullable field, or compatibility variant.
- **FR-005:** A report ahead of the accepted desired generation MUST be rejected or quarantined as a protocol violation, never adopted as desired truth.
- **FR-006:** `Ready=True` MUST require the current reported generation and state to match the current desired generation and policy-bound artifact state, the authorized certificate's `CertNotAfter` to be later than authoritative server time, and the current `PgRevocationStore` result for its typed `CertScope` and `CertSerial` to be not revoked. Revocation lookup failure MUST fail closed as non-ready with `Degraded` condition evidence.
- **FR-007:** Conditions MUST use the closed types `Ready`, `Reconciling`, `PendingDevice`, `Degraded`, `Quarantined`, and `Deleting`, with closed status and reason values.

### Contracts and identity

- **FR-008:** The two HTTP proposal identities MUST retain the kind and consistency frozen in [contracts/contract-set.md](contracts/contract-set.md).
- **FR-009:** HTTP payloads MUST use a `data` envelope. Tenant identity MUST come only from authenticated scope, and the path device identity MUST NOT be repeated in the payload as an authorization fact.
- **FR-010:** Every command and event identity MUST have one stable generated envelope source and MUST NOT be duplicated in its payload; an ACK `commandId` correlates to the command envelope identity.
- **FR-011:** The materialized contract set MUST remain the direct replacement for the former empty draft `identity.reconcile-loop`; it MUST NOT introduce an alias, compatibility shim, second reader, dual write, or parallel contract.
- **FR-012:** Command, ACK, report, and application-receipt contracts MUST remain distinct facts. ACK MUST NOT imply reported convergence.

### Commands, fencing, and durable execution

- **FR-013:** A device certificate command MUST bind its opaque artifact reference and digest to desired generation, fence epoch, intent, policy digest, and deadline.
- **FR-014:** `fenceEpoch` MUST be positive. Generation and epoch mismatches MUST prevent current-state mutation.
- **FR-015:** A command MUST NOT contain a private key, raw CSR, or unapproved certificate material.
- **FR-016:** The fenced command transaction for a newer accepted desired generation MUST atomically supersede older nonterminal command intent before publishing the new command.
- **FR-017:** Command state, ingress-receipt state, optimistic version, and command deadline MUST be durable across process restart.
- **FR-018:** Retry scheduling MUST support exact-target wake and periodic resynchronization so a lost wake cannot permanently strand a target.
- **FR-019:** Execution MUST have bounded concurrency and at most one active attempt for a target.
- **FR-020:** Reconcile action and typed command outbox publication MUST retain the same transaction and lease-CAS boundary.

### Device ingress and transport

- **FR-021:** Production MQTT MUST use mutual TLS, stable session identity, persistent session semantics, and typed topic/ACL coordinates. Its certificate verifier MUST derive a sealed `(tenant, device, credentialGeneration)` principal from the authenticated credential; payload or topic fields MUST NOT construct or override that principal, and scope mismatch or stale credential generation MUST fail closed. Credential staleness MUST be decided against transport credential policy, never against the desired certificate generation being installed.
- **FR-022:** Broker acknowledgement MUST represent broker acceptance only; it MUST NOT represent device ACK or durable RSS ingress.
- **FR-023:** A critical inbound ACK or report without a stable envelope identity MUST fail closed.
- **FR-024:** RSS MUST publish an application receipt only after the corresponding ingress outcome commits durably.
- **FR-025:** Queue saturation or pre-commit failure MUST NOT emit an application receipt; device retry MUST be able to repair delivery.
- **FR-026:** Ingress deduplication and high-water checks MUST be tenant-, device-, command-, generation-, and epoch-safe as applicable.

### Security, inspection, and ownership

- **FR-027:** The `LocalOnly` operator inspection MUST be authorized by authenticated subject and tenant and MUST redact payload and certificate material. This six-contract proposal exposes no operator recovery mutation.
- **FR-028:** Metrics MUST use crate-owned closed labels and MUST NOT label by tenant, device, command, artifact, or other unbounded identity.
- **FR-029:** Automatic repair and fenced command supersession MUST remain internal loop transitions and MUST NOT be presented as operator resync, quarantine, unquarantine, cancel, supersede, or delete APIs.
- **FR-030:** The existing PostgreSQL model keyed by `(tenant_id, device_id, serial)` with `not_after` MUST remain the sole RSS decision-side revocation projection/cache/lookup; External PKI MUST remain the lifecycle/publication authority, and this feature MUST NOT introduce a parallel RSS revocation table or identity.
- **FR-032:** A future candidate assembly MUST require persistent state providers and secure transport providers; absence MUST fail typed construction or provider-seam/component readiness without fallback. This T1/T2 requirement MUST NOT claim designated binary/image process startup or readiness.
- **FR-033:** Policy PUT MUST require a UUID `idempotencyKey` bound to authenticated tenant and path device. New acceptance and identical canonical replay MUST return the same `200` accepted result; expected-generation conflict or key reuse with different canonical input MUST return `409`; a hidden cross-tenant device MUST be indistinguishable from absence at `404`.
- **FR-034:** Policy validity MUST be between 300 and 31,536,000 seconds, renew-before MUST be between 60 and 31,535,999 seconds, and `renewBeforeSeconds` MUST be strictly less than `validitySeconds`.
- **FR-035:** The existing verification-path closure MUST prove the six-contract identity/kind/consistency exact set and reject missing or extra members before activation.
- **FR-036:** The four command/event proposal identities MUST retain the kind, consistency, links, and distinct payload shapes frozen in [contracts/contract-set.md](contracts/contract-set.md).
- **FR-037:** `AuthorizedCertificateArtifact` MUST be a per-command sealed capability bound to authenticated tenant, path device, desired generation, policy digest, public-key digest, certificate-chain digest, and expiry; it MUST NOT prove assembly-wide provider eligibility.
- **FR-038:** Candidate production eligibility MUST require a separate sealed assembly-wide provider closure bound to the selected external provider, production configuration, and conformance evidence; it MUST NOT substitute for any per-command artifact authorization. #2116 implements the candidate T1/T2 closure and receipt-bound mint carrier; #2117 still owns making it a required candidate assembly dependency, without activation.
- **FR-039:** A public application receipt MUST collapse unknown-command, unauthorized, and scope-mismatch failures to `NotAccepted`; only separately authorized internal audit evidence may distinguish them.
- **FR-040:** #1893 MUST include a behavioral red proof that neither its reported-state constructor nor state transition can construct or persist generation zero; absence of the reported row is the only initial state.
- **FR-041:** #1895 MUST include a schema/validator synthetic red proof that a report with `observedGeneration: 0` is rejected before registration or emission.
- **FR-042:** #1902 MUST prove with verifier and broker integration tests that the sealed mTLS principal is credential-derived, cannot be overridden by payload coordinates, and rejects tenant/device mismatch and stale `credentialGeneration`.

## Non-functional requirements

- **NFR-001:** Delivery semantics MUST be documented and implemented as at-least-once plus idempotency; RSS MUST NOT claim exactly-once delivery.
- **NFR-002:** One slow or disconnected device MUST NOT block unrelated targets.
- **NFR-003:** Wait, retry, drain, and fault paths MUST have validated finite bounds.
- **NFR-004:** Generation, epoch, condition, and command-state values MUST be constructible only through closed types and validated transitions.
- **NFR-005:** A per-command production artifact dependency MUST be unrepresentable by raw signer, SoftCA, or simulator artifact types. Its sealed internal receipt MUST expose typed `CertScope`, `CertSerial`, and `CertNotAfter` capabilities (or an equally non-forgeable equivalent) needed for readiness and revocation checks, while the device command remains limited to opaque artifact ID and digest.
- **NFR-006:** Logs, traces, status views, audit, and operator output MUST redact certificate material, CSR data, credentials, transport payloads, and unbounded identifiers where they would create unsafe disclosure or metric cardinality.
- **NFR-007:** Persistent state mutation MUST use server-authoritative transaction time and authenticated tenant scope; device clocks are observation metadata only.
- **NFR-008:** Future candidate components MUST expose T2 disable and bounded-drain semantics while retaining durable facts, receipts, audit, and evidence. Designated binary/image process disable/drain/restart and any later contract activation/rollback lifecycle are governed by ADR-028's separately authorized T3 and MUST NOT be inferred from this component requirement.
- **NFR-009:** Contract ID, topic, schema hash, transport coordinate, command envelope identity, and event envelope identity MUST be supplied only by generated sealed seams, not callers.
- **NFR-010:** Candidate assembly dependencies MUST be unrepresentable by plaintext, simulator, missing-provider, or in-memory provider variants.
- **NFR-012:** PostgreSQL fault evidence MUST cover only cross-transaction, cross-worker, or crash-boundary join hazards not already owned by a single capability proof, and MUST map each hazard to one observable assertion and one primary owner.

Every implementation claim above must have one lowest-sufficient canonical Hard or Medium carrier at its assigned owner. Independent transaction, network, restart, concurrency, or drain hazards require a behavioral Medium proof; constraints made unrepresentable by a Hard carrier do not require a duplicate behavioral proof. A claim that cannot meet this policy is narrowed or deferred rather than treated as proven by prose.

## Boundary

RSS owns desired/reported state, command and receipt facts, convergence scheduling, tenant-scoped authorization, and consumption of an authorized public certificate artifact.

External PKI owns CA hierarchy, EST/CSR onboarding and authorization, SAN and key-usage authorization, signing, CRL/OCSP,
and certificate lifecycle. A future RSS candidate assembly must consume a sealed assembly-wide provider closure bound to
provider identity, production configuration digest, and conformance evidence. Separately, each command consumes an
`AuthorizedCertificateArtifact` bound to authenticated tenant, path device, desired generation, policy digest, device
public-key digest, certificate-chain digest, and expiry. Neither capability substitutes for the other, and RSS does not
manufacture either from a raw signer or software CA.

Resource Security Fact source, authoring lifecycle and management remain External. RSS may consume a narrow tenant/resource
projection through Common ABAC, but this six-contract specification contains no public fact write ingress. Incubator
bootstrap is candidate/test fixture input only and cannot become production freshness or authorization authority.

Operator recovery is federated without widening the contract set: RSS owns authorized `LocalOnly` inspection, automatic
repair and fail-closed pause/drain seams; the incubator product owns authorized recovery orchestration and its runbook;
External control planes own resource/PKI remediation actions and audit receipts. Production activation requires evidence of
that joined recovery path, not an RSS mutation contract or MDM/fleet control plane.

Out of scope:

- fleet grouping, staged rollout, canary policy, or a device operations control plane;
- generic OTA or package distribution;
- CA, EST, CSR, CRL, or OCSP lifecycle ownership;
- multi-region command ordering or active-active reconciliation;
- a new generic scheduler, wake-store, CI platform, or production delivery projection;
- compatibility support for the empty pre-GA draft contract.

## Success semantics

The proposal is successful when downstream implementation can demonstrate all of the following without changing these semantics:

- accepted desired state is distinct from device receipt and device convergence;
- matching reported state, not ACK, is the sole positive convergence signal;
- generation and epoch fencing prevent stale effects across concurrency and restart;
- durable ingress commit precedes application receipt publication;
- authenticated tenant scope and path device identity cannot be overridden by body fields;
- simulator evidence cannot mint candidate production eligibility or activate a production contract;
- candidate production eligibility is impossible without the assembly-level external PKI provider closure and required persistent, secure providers;
- no command is authored without its own tenant/device/generation-bound authorized artifact;
- activation remains blocked on ADR-028's independent hardening/T3 first-green, federated operator-recovery evidence, and atomic six-contract transition.
