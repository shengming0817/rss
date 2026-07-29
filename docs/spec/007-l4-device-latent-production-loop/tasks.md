# DeviceLatent L4 implementation checklist

This document groups executable work by implementation PBI. Requirements are owned by [spec.md](./spec.md), ordering and budgets by [plan.md](./plan.md), logical state by [data-model.md](./data-model.md), target wire shapes by [contracts/contract-set.md](./contracts/contract-set.md), and carrier policy by [ADR-022](../../architecture/202607291724-022-l4-device-latent-production-loop.md).

## #1893 — Closed vocabulary and pure state machines

- [ ] Add failing tests for generation monotonicity, stale observations, positive epochs, and closed transitions.
- [ ] Introduce non-forgeable desired/observed generation and fence coordinate types.
- [ ] Make an absent reported row the only initial state; reject generation zero in reported-state constructors and transitions with a synthetic-red test.
- [ ] Separate command receipt from application and matching reported convergence.
- [ ] Define closed condition, status, reason, command-state, and restore-snapshot models.
- [ ] Define bounded certificate-policy durations and enforce `renewBeforeSeconds < validitySeconds` in a sealed constructor with negative boundary cases.
- [ ] Prove deterministic restore and low-cardinality label projection at the component owner.

## #1894 — Desired-policy and status HTTP contracts

- [ ] Add validator red cases for empty DeviceLatent schemas and broken linked identities.
- [ ] Replace the empty draft HTTP declaration directly with desired-policy PUT and local status GET contracts.
- [ ] Materialize request/response schemas with authenticated tenant scope, path device authority, and `data` responses.
- [ ] Freeze UUID idempotency-key replay/reuse behavior, HTTP success/CAS-conflict/hidden-device semantics, and finite policy-duration bounds.
- [ ] Generate bindings and lock schema, route authorization, kind, consistency, and breaking-change behavior.
- [ ] Remove the superseded draft identity without alias, shim, second reader, or compatibility route.

## #1895 — Device command and fact contracts

- [ ] Materialize apply-certificate command, command-ACK, certificate-report, and ingress-receipt manifests and schemas.
- [ ] Reject `observedGeneration: 0` at report schema validation before registration or emission.
- [ ] Generate sealed emit, register, subscribe, and reconcile seams from the canonical contract identities.
- [ ] Bind command artifact reference/digest to desired generation, fence epoch, intent, policy digest, and deadline.
- [ ] Prevent callers from supplying contract identity, topic, schema hash, transport coordinate, or event identity.
- [ ] Generate the stable command envelope identity at the sealed authoring seam; keep it out of command payload and correlate ACK `commandId` to it in golden and synthetic-red tests.
- [ ] Replace seed-only reconcile evidence with the typed certificate command and run schema/codegen golden tests.

## #1896 — Desired, reported, and condition persistence

- [ ] Allocate migrations from the then-current repository head; add tenant-scoped desired, reported, and condition storage.
- [ ] Enforce uniqueness, monotonic high-water rules, database checks, FORCE RLS, and least-privilege grants.
- [ ] Implement storage-level expected-generation desired CAS with zero writes on conflict.
- [ ] Keep command and schedule writes outside this PBI; expose only the storage/domain constraints consumed by their later owners.
- [ ] Prove rollback, stale/ahead generation, cross-tenant denial, and RLS behavior against real PostgreSQL.

## #1897 — Durable command lifecycle and ingress evidence

- [ ] Allocate migrations from the then-current head for commands and append-once ingress outcomes.
- [ ] Persist closed command transitions, optimistic versions, deadlines, and receipt state.
- [ ] Restore owned command snapshots after restart without resetting authority or retry-related state.
- [ ] Enforce one canonical current nonterminal intent for the applicable tenant/device/generation/intent coordinate.
- [ ] Prove restart, duplicate, late, rejection, and scope-mismatch behavior against real PostgreSQL.

## #1898 — Durable retry and repairable wake

- [ ] Add restart-backoff and lost-notification red cases.
- [ ] Extend the existing purpose-specific target state with durable failure streak and monotonic wake version; reuse its current next-run, lease, epoch, and terminal-result evidence.
- [ ] Own the tenant/device-bound idempotency record and atomic desired-update plus existing-target-due transaction now that desired and reconcile stores are available.
- [ ] Return the stored accepted result for identical canonical replay, reject key reuse with different input, and preserve zero writes on CAS conflict.
- [ ] Update failure streak and wake version through the existing durable transaction/CAS seam; keep notifications a latency optimization over target-due state.
- [ ] Remove process-local retry authority while retaining optional notifications as latency optimization only.
- [ ] Prove periodic due scanning repairs a lost exact-target notification.

## #1899 — Bounded scheduler and deterministic drain

- [ ] Add validated closed concurrency and fairness configuration to the existing durable worker.
- [ ] Execute its already-claimed targets with bounded structured concurrency while preserving the existing target lease/epoch single-executor fence.
- [ ] Apply a starvation-bounded fairness policy across existing due-claim batches without replacing their deterministic PostgreSQL ordering.
- [ ] Prove slow-target isolation, the configured concurrency bound, and fairness under sustained due work; reuse the existing claim, pause, drain, release, and lost-lease evidence unchanged.

## #1900 — End-to-end generation and epoch fencing

- [ ] Carry typed generation and epoch through command authoring, stable deduplication, and ingress checks.
- [ ] Atomically supersede older nonterminal intent when a newer desired generation is accepted.
- [ ] Reject stale worker output and stale ACK/report state mutation while retaining auditable receipt evidence.
- [ ] Use a stable typed system-producer identity across restart and lease takeover.
- [ ] Prove takeover, delayed ACK/report, supersede, and same-generation newer-epoch behavior against PostgreSQL.

## #1901 — Certificate reconciler and authorized artifact boundary

- [ ] Replace unfinished signer seams with a per-command sealed provider-neutral `AuthorizedCertificateArtifact` bound to tenant/device/generation/policy/key/chain/expiry and carrying typed `CertScope`, `CertSerial`, and `CertNotAfter` capabilities internally.
- [ ] Implement observe, diff, action, and condition behavior in the identity owner; derive `Ready` only while the matching artifact is unexpired and the current `PgRevocationStore` answer is not revoked.
- [ ] Fail closed to a non-ready `Degraded` condition when the revocation provider cannot return a current answer.
- [ ] Emit certificate commands only through the generated attempt-scoped seam.
- [ ] Reuse the existing PostgreSQL revocation store and preserve retained evidence through external terminal outcomes.
- [ ] Make raw signer, software-CA, and simulator artifact types unable to satisfy production dependencies.

## #1902 — Production MQTT security and sessions

- [ ] Require sealed mutual-TLS, CA, client credential, stable identity, session, and bounded reconnect configuration.
- [ ] Have the TLS verifier mint the only sealed `(tenant, device, credentialGeneration)` principal; reject stale credentials or payload/topic attempts to override that principal.
- [ ] Bind per-device topics and ACL coordinates through generated/typed values.
- [ ] Expose certificate, connection, and persistent-session readiness without leaking credentials.
- [ ] Preserve broker acknowledgement as transport acceptance only.
- [ ] Prove wrong credentials, wrong ACL, certificate rotation/revocation, persistent reconnect, and redaction with a real broker.

## #1903 — Durable device ingress and application receipts

- [ ] Introduce the durable ACK/report executor under authenticated transport scope and stable envelope identity.
- [ ] Validate device, command, generation, epoch, sequence, idempotency, and high-water coordinates transactionally.
- [ ] Persist deterministic ingress outcome, conditional state mutation, condition update, wake, and receipt outbox fact together.
- [ ] Collapse unauthorized, scope-mismatch, and unknown-command public receipt reasons to `NotAccepted`; retain detail only in authorized internal audit and prove the public surface is non-oracular.
- [ ] Publish application receipt only from committed transaction outcome; emit none on saturation or pre-commit failure.
- [ ] Prove crash, duplicate, stale, missing identity, and queue-saturation recovery behavior.

## #1904 — Draft simulator-backed pilot assembly

- [ ] Wire only explicitly declared persistent stores, draft simulator artifact provider, secure transport, worker, and ingress dependencies.
- [ ] Keep every proposal contract draft and prevent simulator output from satisfying production artifact types.
- [ ] Fail startup/readiness when any declared provider is absent; do not fall back.
- [ ] Implement bounded lifecycle ordering for ingress, claims, transport, readiness, and drain.
- [ ] Prove draft pilot startup, convergence, restart, missing-provider rejection, readiness, and graceful drain.

## #1905 — Operations, metrics, and inspection

- [ ] Project closed condition/operation/reason labels and bounded numeric observations for generation lag, drift age, queue age, ACK latency, and lease churn.
- [ ] Apply authenticated tenant scope and typed permission to the read-only inspection surface defined by the six-contract proposal.
- [ ] Keep any future operator mutation out of this contract set until it has a separately reviewed ingress, authorization, audit, and receipt owner.
- [ ] Keep status, logs, traces, metrics, audit, and CLI output payload-free and redacted.
- [ ] Prove cross-tenant inspection denial, redaction, and label closure at their canonical owners.

## #1906 — Programmable device simulator and journeys

- [ ] Provide only the deterministic simulator controls needed for the canonical offline-to-convergence join journey; component semantics remain proven by their earlier T1/T2 owners.
- [ ] Own one canonical journey hazard: offline device → reconnect → latest generation/epoch command → ACK without convergence → matching report → application receipt only after durable commit.
- [ ] Assert the journey observes no readiness at ACK, exactly the matching reported generation at readiness, and no application receipt before its commit boundary.
- [ ] Keep simulator artifacts and receipts explicitly production-ineligible and document the reproducible local command without introducing a delivery projection.

## #1907 — PostgreSQL and scheduler fault evidence

- [ ] Freeze the exact set of independent PostgreSQL joins from NFR-012, excluding every single-capability hazard already owned by #1898 or #1900, and record each as `hazard → lowest sufficient layer → unique owner → observable assertion`.
- [ ] Authorized-artifact return racing lease takeover/worker restart → real PostgreSQL plus the worker/artifact seam → #1907 → the stale return appends no action or command, while the current holder emits at most one command carrying the current generation and epoch.
- [ ] Crash after action/command-outbox commit but before attempt-result recording or lease release → real PostgreSQL plus worker crash/reclaim → #1907 → the committed action/command remains singular, reclaim does not duplicate it, and append-only attempt/result evidence exposes the interrupted boundary.
- [ ] Use deterministic barriers and current persistence/outbox seams; reference earlier component proofs instead of replaying their desired/wake atomicity, restart-backoff, lost-wake, fenced-command transaction, supersede, or state-machine T2 cases.

## #1908 — MQTT and backpressure fault evidence

- [ ] Freeze the exact set of independent broker/session/backpressure joins from NFR-013, excluding every single-capability hazard already owned by #1902 or #1903, and record each as `hazard → lowest sufficient layer → unique owner → observable assertion`.
- [ ] Broker acknowledgement followed by disconnect before application commit → real MQTT broker plus durable ingress → #1908 → no application receipt exists before commit and replay yields one canonical committed receipt.
- [ ] Saturated ingress followed by persistent-session reconnect → bounded subscriber plus real broker and durable ingress → #1908 → saturation emits no premature receipt, the broker retains/replays accepted delivery, and recovery reaches one canonical outcome.
- [ ] Reuse #1902/#1903 component evidence for credentials, ACL, certificate lifecycle, sequence, duplicate, and redaction behavior; use deterministic barriers rather than sleep-only assertions.

## #1909 — Existing verification-path closure

- [ ] Extend the existing typed registry/code-generation exact-set with the active-candidate contract and evidence identities.
- [ ] Extend existing contract validation, verification, CI-impact selection, and receipt aggregation for the new owners.
- [ ] Add synthetic-red and anti-vacuity coverage at those existing machine carriers.
- [ ] Prove missing/extra identities and missing affected evidence fail in their canonical owner.
- [ ] Own the six-contract identity/kind/consistency exact-set proof before activation.
- [ ] Do not introduce a subsystem-specific parallel gate, required job, or duplicated evidence inventory.

## #1910 — Conditional production activation

- [ ] Require an assembly-level sealed `ExternalPkiProviderClosure` bound to selected provider, production configuration, and provider-conformance evidence.
- [ ] Keep that closure type non-interchangeable with per-command `AuthorizedCertificateArtifact`; neither one can satisfy the other's dependency.
- [ ] Require production persistent-state, revocation, secure MQTT, authorization, audit, readiness, and drain providers by non-optional type.
- [ ] Reject raw signer, software-CA, simulator, plaintext, missing-provider, and in-memory assembly variants.
- [ ] Activate proposal contracts only after the production assembly and existing verification paths prove their join hazards.
- [ ] Prove disable, pause, and drain of the active runtime path while retaining durable facts and evidence; keep active contracts active or advance them only through formal deprecation.
