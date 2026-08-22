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

External PKI owns CA policy, EST/CSR processing, SAN and key-usage authorization, signing, CRL/OCSP, and certificate
lifecycle. #2116 provides a sealed candidate-level provider closure proving the selected provider,
production configuration and conformance evidence. It grants no tenant/device authorization. Each command separately requires
a sealed `AuthorizedCertificateArtifact` bound to tenant, device, desired generation, policy, authorization receipt, public key, certificate chain and
expiry. Its internal receipt exposes non-forgeable `CertScope`, `CertSerial`, and `CertNotAfter` capabilities for readiness and
the existing revocation lookup. Commands still carry only its opaque artifact identity and digest; private keys, raw CSRs,
serial authorization, and unapproved certificate material are excluded. The type and formal production mint are implemented;
#2117 still owns making the closure a required candidate assembly dependency.

The simulator delivered by #1904 proves orchestration only and stays draft. ADR-028 supersedes #1910's direct activation
route: the separate closure and official Vault provider bridge/conformance path now have T1/T2 carriers; a real external consumer receipt, candidate assembly wiring, hardening/T3
and atomic activation remain independent. Possessing any one authorized artifact cannot unlock the assembly, and possessing
provider closure cannot authorize an individual command.

Rejected alternatives:

- A single artifact-shaped receipt used both for global activation and command authorization lets one command accidentally unlock the assembly.
- A raw `Signer` or SoftCA production seam lets an unqualified provider impersonate an authorized artifact.
- A simulator fallback makes missing production authorization fail open.
- Copying PKI lifecycle into RSS creates a second authority and exceeds project scope.

## Decision: reuse the persistent revocation model

The existing PostgreSQL revocation key `(tenant_id, device_id, serial)` and `not_after` retention semantics remain the sole RSS decision-side projection/cache/lookup. External PKI retains lifecycle/publication authority. This effort neither adds a second `serial_digest/reason` table nor reopens persistence as unfinished work.

## Decision: MQTT production behavior is explicit and closed

Production MQTT is always compiled and exposes one `MqttSession`, not interchangeable publisher and subscriber clients. The session owns one rumqttc eventloop/driver, a stable client ID bound to the RSS client certificate CN, `clean_start=false`, an explicit `60s..=7d` expiry, manual ACK, bounded queues/reconnect, closed readiness and single-flight credential reload with last-good rollback. Construction requires MQTTS authority, CA/certificate/private key, broker assertion public key, a non-empty exact device policy and a strictly increasing credential revision. Missing required configuration fails closed; plaintext, random identity, clean-session, feature-disabled runtime fallback and `RSS_MQTT_TEST_URL` are not degraded operating modes.

`MqttTopicPolicy` is the only topic mint. For each canonical `(tenant, device, credentialGeneration)` it produces one certificate-command downlink and the command-acked/certificate-reported uplinks under `rss/v1/...`; it rejects an empty set and duplicate tenant/device scopes, and exposes no raw string or wildcard constructor. The same exact set drives subscription, broker ACL and assertion verification.

The device credential carries exactly one URI SAN `urn:rss:mqtt-device:v1:{tenant}:{device}:{generation}`. A formal Mosquitto v5 message plugin obtains that peer certificate from the broker API, checks the SAN against the exact uplink topic, rejects client-supplied reserved assertion properties and signs principal, topic, correlation, SHA-256 payload digest, QoS and retain with Ed25519. The signing key remains broker-only; RSS receives the public verification key. Only a valid assertion for the current policy can produce a non-forgeable `AuthenticatedDeviceDelivery`, whose one-shot capability performs success PUBACK. A topic, payload or user property can be checked against the credential-derived principal but cannot construct or override it. Pre-authentication assertion/topic rejection is terminally settled with MQTT v5 negative PUBACK by a move-only adapter-private carrier; it does not mint authenticated delivery, durable commit, receipt, or broker-acceptance authority. An unknown negative-ACK transport outcome fails closed and stops rather than reconnecting the poison delivery.

Downlink PUBACK yields only the non-copyable `BrokerAccepted` transport capability. It does not mean device acknowledgement,
durable ingress or application receipt. #1902 owns the standalone transport, authentication, session and broker proof; #1903
owns durable ingress and post-commit receipt; #1908 owns only cross-boundary broker/backpressure/ingress hazards. ADR-028
hands typed candidate construction, provider seams and component lifecycle to future T1/T2 implementation; designated
binary/image process startup/readiness/restart/drain and activation wait for a hardening-authorized T3 owner.

#1902's behavioral carrier is the hermetic Docker broker lane using the same mTLS/plugin image and persistence contract. An external URL cannot substitute for its PKI, ACL, signing-key or restart evidence, so there is no environment fallback. Documentation records this proof obligation but does not assert a test result; the actual command result and shard evidence remain authoritative.

## Decision: operator surface is inspection-only

The frozen six-contract set contains one authorized `LocalOnly` status read and no operator mutation ingress. Therefore this proposal promises inspection, not manual resync, quarantine, unquarantine, cancel, supersede, or delete recovery. Lost-wake repair and generation-fenced supersession remain automatic internal loop behavior.

Production operator recovery is a later federated join, not a seventh RSS contract: RSS contributes inspection, automatic
repair and fail-closed pause/drain seams; the incubator product contributes authorized orchestration/runbook; External
control planes contribute resource/PKI remediation actions and audit receipts. ADR-028 requires that join as hardening/T3
activation evidence.

Rejected alternatives:

- Describing an operation without an ingress contract creates an unverifiable API promise.
- Adding a seventh recovery contract would widen the approved contract set and is excluded from this proposal.

## Decision: Resource Security Fact is not a seventh contract

Device authorization may consume a narrow tenant/resource projection through the existing Common ABAC PIP seam, but the
fact source, authoring lifecycle and management plane remain External. The `rss-incubator` reference environment may seed
facts and policy as disposable candidate/T2 bootstrap; that bootstrap is neither an RSS Release API nor production authority.

Rejected alternatives:

- Adding a Resource Security Fact write contract would break the approved six-contract exact set without a proven RSS
  runtime consumer or authority model.
- Treating bootstrap data as current production truth erases freshness, replay, audit and ownership failure modes.
- Exposing the existing internal resource-attribute write repository would leak an implementation seam and create a generic
  device inventory/control-plane surface.

## Decision: use existing delivery and verification architecture

L4 closure extends the repository's typed registry, code generation, exact-set validation, CI-impact selection and evidence conventions. It does not introduce a subsystem-only verification path, a parallel required CI job, or another deployment platform.

Metric labels use only closed operation/reason/state enums and exclude tenant, device and command identifiers. Generation lag, drift age, queue age, ACK latency and lease churn are bounded numeric observations, not labels. The `LocalOnly` inspection edge requires typed read permission and redaction.

## Proof strategy

Human-readable documents explain intent but are not enforcement. Constraints that callers must not forge are represented through sealed/private types, constructors, schemas, generated coordinates, database constraints or required assembly dependencies. Runtime behavior that cannot be made unrepresentable is exercised through table-driven, property, real-PostgreSQL, broker or journey tests. If an implementation PBI cannot supply at least such a behavioral carrier, it must narrow or defer its claim.
