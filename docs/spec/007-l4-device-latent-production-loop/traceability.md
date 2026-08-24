# DeviceLatent requirement traceability

This table assigns every requirement in [spec.md](./spec.md) either to one implemented PBI and canonical primary proof or to one explicit ADR-028 future handoff. A future-handoff row is an acknowledged proof gap, not evidence of implementation or permission to claim candidate, T3, or active status. Higher-level tests may cover a join hazard, but they do not become duplicate primary proofs for requirements already closed below.

Proof tiers follow the repository ADR-024: T1 is design/component proof, T2 is capability/seam proof, and T3 is production assembly/acceptance proof. Carrier strength and concrete mechanisms are owned by [ADR-022](../../architecture/202607291724-022-l4-device-latent-production-loop.md).

#2110 supplies the T1 authorization-lineage prerequisite for the draft desired-policy path: private opaque
provenance, explicit authorizer basis, canonical contributing policy/obligation/time metadata, and move-only
device policy/status receipts. It intentionally makes no PostgreSQL, wire-schema, mounted-handler or T3 claim;
#2113 now supplies the T2 PostgreSQL handoff: one append-only authorization/idempotency ledger, normalized policy
basis, atomic desired-generation lineage for policy accept and rotation, deterministic replay, and typed unsafe
settlement. #2114 closes the Draft public-schema/candidate-package handoff and the internal command/application-receipt
lineage joins; #2115 supplies an unmounted typed candidate component and T1/T2 proof only. #2117 supplies the
production candidate assembly and its two Draft route mounts; T3 evidence and activation remain a separate handoff.
The #2113 T1 boundary proves that denied or unavailable authorization cannot construct
`AcceptDesiredPolicy`; #2115 owns a test-only Primary harness proof that Deny, NoMatch, resource-fact
Missing/Stale/Future/type-mismatch, and PIP/store errors never invoke the repository. Those cases
must not be represented by forged database inputs in this persistence PBI. This harness is not serving evidence.

| Requirement | Owner | Primary proof |
|---|---:|---|
| FR-001 | #1896 | T2 — real-PostgreSQL desired-generation monotonicity and tenant-scope conformance |
| FR-002 | #2113 | T2 — `desired_accept_replays_without_writes_and_conflicts_roll_back_the_bundle` proves CAS and digest conflicts preserve desired, receipt/policy/lineage, and durable wake snapshots |
| FR-003 | #2113 | T2 — `desired_accept_has_one_winner_and_write_fault_rolls_back` and `desired_accept_replays_without_writes_and_conflicts_roll_back_the_bundle` prove receipt/desired/condition/wake transaction atomicity |
| FR-004 | #1896 | T2 — reported high-water PostgreSQL conformance |
| FR-005 | #1896 | T2 — ahead-of-desired rejection/quarantine transaction test |
| FR-006 | #1901 | T2 — sealed Ready proof plus PostgreSQL round-trip requiring matching generation/report/artifact/current-command, server-time expiry and fail-closed revocation evidence |
| FR-007 | #1893 | T1 — closed condition type/status/reason construction and golden projection |
| FR-008 | #1894 | T1 — two HTTP contract kind/consistency schema and code-generation golden |
| FR-009 | #1894 | T1 — HTTP schema and route-auth golden/red validation |
| FR-010 | #2114 | T1/T2 — generated command binds desired R/G into canonical intent; ACK/report reject receipt injection; PostgreSQL enqueue exact-joins durable lineage before writes |
| FR-011 | #1894 | T1 — direct-replacement golden rejecting alias, shim, second reader, and dual write |
| FR-012 | #2114 | T1 — distinct generated command/ACK/report/closed application-receipt variants plus six-module public package proof |
| FR-013 | #2114 | T1/T2 — required command R/G schema, desired-snapshot authoring, canonical digest and PostgreSQL substitution rejection |
| FR-014 | #1893 | T1 — positive epoch constructor and generation/epoch transition property test |
| FR-015 | #2114 | T1 — command schema admits only opaque R/G and artifact coordinates; ACK/report injection and forbidden fields fail closed |
| FR-016 | #1900 | T2 — PostgreSQL newer-generation supersede atomicity test |
| FR-017 | #1897 | T2 — command/receipt restart restoration PostgreSQL conformance |
| FR-018 | #1898 | T2 — durable schedule restart and lost-notification repair test |
| FR-019 | #1899 | T1 — scheduler bounded-concurrency and single-target-executor component test |
| FR-020 | #1900 | T2 — lease-CAS/action/command-outbox transaction test |
| FR-020a | #1906 | T2 — journey/runtime ACK-await-report plus old-fence authority after received |
| FR-021 | #1902 | T2 — hermetic Mosquitto mutual-TLS, stable `clean_start=false` session/restart, manual-ACK and exact typed topic/ACL conformance |
| FR-022 | #1902 | T1/T2 — non-copyable `BrokerAccepted` surface plus broker PUBACK proof that cannot mint device ACK, durable ingress or application receipt |
| FR-023 | #1903 | T2 — missing stable envelope identity fail-closed ingress test |
| FR-024 | #2114 | T2 — commit-unknown exact readback restores application lineage; pre-commit lineage/store failure rolls back receipt publication |
| FR-025 | #1903 | T2 — saturation/pre-commit failure and replay-repair test |
| FR-026 | #1903 | T2 — tenant/device/command/generation/epoch dedup and high-water conformance |
| FR-027 | #1905 | T2 — authenticated tenant-scoped LocalOnly inspection authorization and redaction test |
| FR-028 | #1905 | T1 — closed metric-label type and cardinality projection test |
| FR-029 | #1909 | T1 — six-contract exact-set and synthetic-red proof rejecting an undeclared operator mutation surface |
| FR-030 | #1901 | T2 — schema inventory plus deletion transaction proving retained artifact receipts reuse the existing PostgreSQL decision-side revocation projection |
| FR-031 | #1906 | T2 — programmable simulator journey keeps draft artifacts production-ineligible; #1904 owns compile-only draft pilot assembly |
| FR-032 | #2117 | T1/T2 — generated provider-role closure, exact runtime inventory, construction/readiness probes and missing-provider rejection; no designated-process T3 claim |
| FR-033 | #2113 | T2 — `desired_accept_replays_without_writes_and_conflicts_roll_back_the_bundle` proves same-key deterministic receipt replay, digest reuse conflict, 65-policy projection, and both unsafe-settlement recovery outcomes |
| FR-034 | #1893 | T1 — bounded duration and sealed cross-field policy-constructor boundary/property test |
| FR-035 | #1909 | T2 — existing typed registry/codegen six-contract exact-set synthetic-red proof |
| FR-036 | #1895 | T1 — four command/event identity, link, kind, consistency, and shape golden |
| FR-037 | #1901 | T2 — append-once per-generation artifact binding, stale-fence PostgreSQL tests and incompatible-provider compile proof |
| FR-038 | #2116 | T1/T2 — isolated mint capability + non-interchangeable provider closure/artifact compile reds; real Vault `/sign` evidence joins the current desired-generation receipt into a durable production artifact snapshot |
| FR-039 | #1903 | T2 — public receipt non-oracle equivalence plus authorized internal-audit detail test |
| FR-040 | #1893 | T1 — reported-state constructor/transition synthetic red rejecting generation zero |
| FR-041 | #1895 | T1 — report schema/validator synthetic red rejecting `observedGeneration: 0` |
| FR-042 | #1902 | T2 — Mosquitto peer-certificate URI-SAN principal plus Ed25519 assertion proof rejecting reserved-property/payload override, topic mismatch and stale generation |
| NFR-001 | #1903 | T2 — duplicate/replay conformance proving at-least-once plus idempotency |
| NFR-002 | #1899 | T1 — slow-target isolation under bounded scheduler concurrency |
| NFR-003 | #1899 | T1 — validated finite configuration and deterministic retry/drain component tests |
| NFR-004 | #1893 | T1 — non-forgeable vocabulary plus table/property transition proof |
| NFR-005 | #1901 | T2 — private eligibility/receipt/Ready/completion proofs plus generic-command and production-provider substitution rejection |
| NFR-006 | #1905 | T2 — authorized output, audit, log/trace, and metric redaction test |
| NFR-007 | #1896 | T2 — authenticated tenant transaction and server-time ordering PostgreSQL test |
| NFR-008 | #2117 | T2 — runtimeexec-supervised listeners/workers, admission/unready transition, bounded LIFO drain and library-level durable restart; later T3 owns process/signal/image rollback proof |
| NFR-009 | #1895 | T1 — generated sealed-coordinate compile/golden proof and caller-forgery synthetic red |
| NFR-010 | #2117 | T1/T2 — production-typed PostgreSQL/External CSR/Vault/OIDC/MQTT/audit/Redis closure plus draft-provider compile rejection |
| NFR-011 | #1906 | T2 — canonical offline/reconnect/newest-command/ACK/report/post-commit-receipt journey join proof |
| NFR-012 | #1907 | T2 — exact PG join-hazard table mapping each cross-boundary failure to one observable assertion |
| NFR-013 | #1908 | T2 — exact cross-boundary MQTT join-hazard table mapping broker/backpressure plus durable-ingress failures to one observable assertion, reusing rather than duplicating #1902/#1903 component proofs |

## Exact-set rule

This table contains every FR/NFR declared in [spec.md](./spec.md) exactly once. Existing proofs and explicit future handoffs are deliberately distinct: a handoff cannot satisfy acceptance. The one-time specification smoke derives both sets dynamically rather than encoding a count; it is not a repository enforcement mechanism.

## MQTT proof boundary

#1902 closes the standalone MQTTS/mTLS, peer-certificate assertion, exact ACL/topic, persistent-session,
manual-ACK, readiness and credential-reload behavior. #1903 begins only after an authenticated delivery exists
and owns durable ingress plus post-commit application receipt. #1908 owns only independent joins that require
both those capabilities. #2117 closes production candidate integration and required-provider readiness/drain at
T1/T2 only; ADR-028 still leaves activation to a separately authorized T3 owner. A broker PUBACK is
`BrokerAccepted`; none of these assignments permits treating it as an application receipt.
