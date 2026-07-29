# DeviceLatent L4 research decisions

This document owns technical choices and rejected alternatives for the #1892 specification. Current-code evidence belongs to [source-baseline.md](./source-baseline.md); normative requirements belong to [spec.md](./spec.md).

## Decision: desired and reported state are separate monotonic facts

A policy write accepts a desired generation. It does not claim that a device received, applied, or reported it. Command acknowledgement records receipt/state only. Readiness is derived when the reported generation and reported certificate state match the current desired generation and policy.

This prevents transport success from masquerading as convergence and gives retry, takeover and automatic repair a stable coordinate.

Rejected alternatives:

- A single mutable status row loses the distinction between intent and observation.
- Treating ACK as success cannot distinguish queue receipt from device application.
- Device timestamps as ordering authority are unsafe under clock skew and replay.

## Decision: generation and fence epoch jointly protect effects

Generation identifies policy intent. Fence epoch identifies the currently authorized execution ownership. Any stale worker, command or report must fail to advance the current state when either coordinate is stale.

Rejected alternatives:

- Generation alone cannot fence two workers acting on the same desired state.
- Lease time alone cannot prevent a delayed worker from publishing after takeover.
- Process-local locks do not survive restart or multi-replica execution.

## Decision: durable schedule and outbox facts share transaction boundaries

Retries must survive restart without resetting their attempt schedule. Work acquisition uses a purpose-specific durable schedule with compare-and-swap ownership. Public commands and ingress receipts become outbox facts only from a committed transaction outcome.

Rejected alternatives:

- An in-memory timer loses retry state on restart.
- A generic wake-store interface generalizes a single consumer before its semantics are stable.
- Publishing before commit permits a public fact for state that was rolled back.

## Decision: contract kinds follow their consistency semantics

The policy endpoint is `DeviceLatent`: it accepts durable desired state whose device convergence is asynchronous. The status endpoint is `LocalOnly`: it reads RSS-owned desired, reported and condition projections without contacting a device. Commands, acknowledgements, reports and application receipts are `OutboxFact` because their public identities must be bound to durable publication.

The six identities and proposal shapes are owned by [contract-set.md](./contracts/contract-set.md). #1894 replaces the empty draft `identity.reconcile-loop` directly; compatibility aliases, dual readers and dual writes are deliberately excluded.

## Decision: provider closure and command authorization are distinct

External PKI owns CA policy, EST/CSR processing, SAN and key-usage authorization, signing, CRL/OCSP, and certificate lifecycle. A sealed assembly-level `ExternalPkiProviderClosure` proves the selected provider, production configuration and conformance evidence required for activation. It grants no tenant/device authorization. Each command separately requires a sealed `AuthorizedCertificateArtifact` bound to tenant, device, desired generation, policy, public key, certificate chain and expiry. Its internal receipt exposes non-forgeable `CertScope`, `CertSerial`, and `CertNotAfter` capabilities for readiness and the existing revocation lookup. Commands still carry only its opaque artifact identity and digest; private keys, raw CSRs, serial authorization, and unapproved certificate material are excluded.

The simulator planned by #1904 proves orchestration only and stays draft. #1910 may activate the runtime path only after external PKI supplies `ExternalPkiProviderClosure` and the production assembly requires it. Possessing any one authorized artifact cannot unlock the assembly, and possessing provider closure cannot authorize an individual command.

Rejected alternatives:

- A single artifact-shaped receipt used both for global activation and command authorization lets one command accidentally unlock the assembly.
- A raw `Signer` or SoftCA production seam lets an unqualified provider impersonate an authorized artifact.
- A simulator fallback makes missing production authorization fail open.
- Copying PKI lifecycle into RSS creates a second authority and exceeds project scope.

## Decision: reuse the persistent revocation model

The existing PostgreSQL revocation key `(tenant_id, device_id, serial)` and `not_after` retention semantics remain the only revocation model. This effort neither adds a second `serial_digest/reason` table nor reopens persistence as unfinished work.

## Decision: MQTT production behavior is explicit and closed

Production MQTT requires mTLS, stable session identity, typed ACL/configuration, bounded delivery, and readiness that reflects durable subscriber health. Missing required configuration fails startup. Plaintext, random identity, clean-session fallback and silent saturation are not degraded operating modes.

The mTLS verifier derives a sealed `(tenant, device, credentialGeneration)` principal only from the authenticated credential. A topic or payload coordinate can be checked against that principal but cannot construct or override it. Tenant/device mismatch and a stale credential generation fail closed. #1902 must demonstrate these failures through verifier and broker integration tests, rather than treating configuration prose as proof.

## Decision: operator surface is inspection-only

The frozen six-contract set contains one authorized `LocalOnly` status read and no operator mutation ingress. Therefore this proposal promises inspection, not manual resync, quarantine, unquarantine, cancel, supersede, or delete recovery. Lost-wake repair and generation-fenced supersession remain automatic internal loop behavior.

Rejected alternatives:

- Describing an operation without an ingress contract creates an unverifiable API promise.
- Adding a seventh recovery contract would widen the approved contract set and is excluded from this proposal.

## Decision: use existing delivery and verification architecture

L4 closure extends the repository's typed registry, code generation, exact-set validation, CI-impact selection and evidence conventions. It does not introduce a subsystem-only verification path, a parallel required CI job, or another deployment platform.

Metric labels use only closed operation/reason/state enums and exclude tenant, device and command identifiers. Generation lag, drift age, queue age, ACK latency and lease churn are bounded numeric observations, not labels. The `LocalOnly` inspection edge requires typed read permission and redaction.

## Proof strategy

Human-readable documents explain intent but are not enforcement. Constraints that callers must not forge are represented through sealed/private types, constructors, schemas, generated coordinates, database constraints or required assembly dependencies. Runtime behavior that cannot be made unrepresentable is exercised through table-driven, property, real-PostgreSQL, broker or journey tests. If an implementation PBI cannot supply at least such a behavioral carrier, it must narrow or defer its claim.
