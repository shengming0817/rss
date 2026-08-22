# DeviceLatent Target Contract Set

**Lifecycle:** Materialized Draft candidate set

These files freeze target identities, kinds, consistency, and payload shapes. The six identities now have `contracts/**`
manifests and generated candidate bindings, but every lifecycle remains `draft`; they are not mounted transport routes,
active public contracts, or evidence that a production path exists. ADR-028 reserves a future
`rss-device-security-contracts` candidate package derived from this exact set without making that package a current artifact;
its internal-to-public identity and registry owner are defined only by
[`architecture.md` §公开发布命名](../../../rules/architecture.md#公开发布命名).

## Frozen set

| Contract identity | Kind | Consistency | Proposal schemas | Meaning |
|---|---|---|---|---|
| `identity.device-certificate-policy-put` | HTTP | `DeviceLatent` | `device-certificate-policy-put.request.schema.json`, `device-certificate-policy-put.response.schema.json` | Accept desired policy by generation CAS; acceptance does not claim convergence |
| `identity.device-certificate-status-get` | HTTP | `LocalOnly` | `device-certificate-status-get.request.schema.json`, `device-certificate-status-get.response.schema.json` | Read desired/reported state, conditions, and a payload-free active-command summary |
| `identity.apply-device-certificate` | command | `OutboxFact` | `apply-device-certificate.command.schema.json` | Emit a generation- and epoch-bound public artifact intent |
| `identity.device-command-acked` | event | `OutboxFact` | `device-command-acked.event.schema.json` | Record device receipt or rejection of a command; never assert convergence |
| `identity.device-certificate-reported` | event | `OutboxFact` | `device-certificate-reported.event.schema.json` | Report the device's applied generation and public state |
| `identity.device-ingress-receipted` | event | `OutboxFact` | `application-receipt.schema.json` | Publish a deterministic application outcome after durable ingress commit |

`identity.device-certificate-status-get` is `LocalOnly`: it is a pure authorized read of already durable identity/deviceloop state. It publishes no fact and performs no business mutation.

The materialized manifests directly replaced the empty draft `identity.reconcile-loop`. There is no alias, compatibility
shim, dual contract, old reader, or dual write. The resulting identities remain Draft candidates until the independent
activation transition.

This exact set has no Resource Security Fact write ingress. Resource fact source/authoring lifecycle remains External;
candidate/test bootstrap may prepare a narrow Common ABAC projection but is not a production authority or a seventh
contract. Adding a real RSS runtime ingress requires a separate scope/ADR/PBI and an atomic exact-set replacement, never a
parallel six/seven path.

## Shared wire decisions

- HTTP responses have exactly one top-level `data` member.
- HTTP body schemas do not repeat the path device identifier or tenant identifier as authorization facts. Tenant comes from authenticated scope and device comes from the validated route.
- Policy PUT requires a UUID `idempotencyKey` scoped to authenticated tenant and path device. Same key plus the same canonical policy/expected generation returns the same `200` accepted result; different canonical input returns `409`. Expected-generation conflict also returns `409`. A cross-tenant or otherwise hidden device returns the same `404` surface as an absent device.
- Policy duration fields have finite schema bounds; the sealed policy constructor additionally enforces `renewBeforeSeconds < validitySeconds`, which Draft-07 cannot express between sibling properties.
- A command ID is the generated stable command-envelope identity and is not duplicated in its payload. An ACK's `commandId` correlates to that envelope identity. Likewise, the event envelope identity is the single event ID and event payloads do not duplicate it. The application receipt's `ingressEnvelopeId` is correlation to the receipted inbound envelope, not the receipt event's own identity.
- Event and command payloads do not accept a tenant field. Authenticated transport scope and generated transport coordinates establish tenant scope.
- Reported observations and accepted desired/command generations are positive. The initial reported state is row absence; a generation-zero report has no nullable or compatibility representation. Every `fenceEpoch` is positive.
- Condition type/status/reason, command state, ACK result, and receipt outcome/reason are closed values in these proposals.
- ACK and receipt results are closed sums rather than independent enum products: `received` pairs only with `None`; `rejected` pairs only with an ACK failure reason. Application receipt pairs are `committed→None`, `duplicate→AlreadyCommitted`, `stale→{GenerationStale,FenceEpochStale,DeviceSequenceStale}`, and `rejected→{NotAccepted,SchemaRejected,ProtocolViolation}`. No cross-variant reason pair is valid.
- ACK advances command receipt/state only. Only a positive-generation report matching the current desired generation, policy-bound state, and artifact, with an unexpired typed `CertNotAfter` and a current not-revoked `PgRevocationStore` result for typed `CertScope`/`CertSerial`, can establish `Ready=True`. Revocation lookup failure is non-ready and `Degraded`.
- An ACK-triggered reconcile wake awaits a current `received` command's report and does not issue a same-generation replacement. That exact command's generation/fence remains authoritative for its report across reconcile lease renewal; unrelated old fences remain stale.
- Commands carry an opaque artifact ID and digest only. Private keys, raw CSRs, and unapproved certificate bytes cannot be represented.
- Public application-receipt reasons do not distinguish unknown commands, unauthorized callers, or scope mismatch; all use `NotAccepted`. More detailed reasons belong only in authorized internal audit evidence.
- Production MQTT authentication derives a sealed `(tenant, device, credentialGeneration)` principal from the verified mTLS credential. Payload and topic fields cannot override it; mismatch or stale credential generation fails closed against transport credential policy. Credential generation is not the desired certificate generation being installed.
- The authorized operator surface in this frozen set is the `LocalOnly` status read only. Automatic repair and fenced supersession are internal behavior, not manual resync, quarantine, unquarantine, cancel, supersede, or delete contracts.

## Candidate and activation boundary

A deterministic simulator can exercise a draft pilot but cannot mint candidate production eligibility or activate these
contracts. Candidate implementation requires an assembly-level sealed provider closure proving the selected provider,
production configuration, and conformance closure. Every command separately requires a sealed
`AuthorizedCertificateArtifact` bound to tenant, device, generation, policy, public key, certificate chain, and expiry. Its
internal sealed receipt supplies typed `CertScope`, `CertSerial`, and `CertNotAfter` (or an equally non-forgeable capability)
for readiness and revocation checks; the device command remains limited to opaque artifact ID and digest. Neither capability
can substitute for the other. External PKI owns CA hierarchy, EST/CSR authorization, SAN/key-usage authorization, signing,
CRL/OCSP, and certificate lifecycle. RSS consumes the authorized public artifact reference and receipt only.

The repository implements that closure and formal receipt-bound production mint as a candidate T1/T2 carrier. It is not yet a
required dependency of a candidate assembly; #2117 owns that wiring. Activation still requires ADR-028's independent
hardening/T3 first-green and atomic six-contract transition.

The current PostgreSQL revocation store keyed by `(tenant_id, device_id, serial)` with `not_after` remains the only RSS revocation model. None of these shapes creates a second revocation identity.
