# DeviceLatent requirement traceability

This table assigns every requirement in [spec.md](./spec.md) to exactly one implementation PBI and one canonical primary proof. Higher-level tests may cover a join hazard, but they do not become duplicate primary proofs for requirements already closed below.

Proof tiers follow the repository [verification scope matrix](../../rules/project-scope.md#验证范围矩阵): T1 is design/component proof, T2 is capability/seam proof, and T3 is production assembly/acceptance proof. Carrier strength and concrete mechanisms are owned by [ADR-022](../../architecture/202607291724-022-l4-device-latent-production-loop.md).

| Requirement | Owner | Primary proof |
|---|---:|---|
| FR-001 | #1896 | T2 — real-PostgreSQL desired-generation monotonicity and tenant-scope conformance |
| FR-002 | #1898 | T2 — PostgreSQL CAS-conflict test proving zero writes across desired, operation, and schedule state |
| FR-003 | #1898 | T2 — desired-update/durable-target-wake transaction atomicity test |
| FR-004 | #1896 | T2 — reported high-water PostgreSQL conformance |
| FR-005 | #1896 | T2 — ahead-of-desired rejection/quarantine transaction test |
| FR-006 | #1901 | T2 — matching generation/artifact plus server-time expiry and fail-closed revocation readiness conformance |
| FR-007 | #1893 | T1 — closed condition type/status/reason construction and golden projection |
| FR-008 | #1894 | T1 — two HTTP contract kind/consistency schema and code-generation golden |
| FR-009 | #1894 | T1 — HTTP schema and route-auth golden/red validation |
| FR-010 | #1895 | T1 — generated command/event envelope identity, ACK correlation, and payload-exclusion golden/synthetic-red proof |
| FR-011 | #1894 | T1 — direct-replacement golden rejecting alias, shim, second reader, and dual write |
| FR-012 | #1895 | T1 — distinct generated command/ACK/report/receipt type and link golden |
| FR-013 | #1895 | T1 — generated command schema and typed-authoring compile/golden proof |
| FR-014 | #1893 | T1 — positive epoch constructor and generation/epoch transition property test |
| FR-015 | #1895 | T1 — command schema exclusion golden and validator red case |
| FR-016 | #1900 | T2 — PostgreSQL newer-generation supersede atomicity test |
| FR-017 | #1897 | T2 — command/receipt restart restoration PostgreSQL conformance |
| FR-018 | #1898 | T2 — durable schedule restart and lost-notification repair test |
| FR-019 | #1899 | T1 — scheduler bounded-concurrency and single-target-executor component test |
| FR-020 | #1900 | T2 — lease-CAS/action/command-outbox transaction test |
| FR-021 | #1902 | T2 — real-broker mutual-TLS, stable-session, and typed-ACL conformance |
| FR-022 | #1902 | T2 — broker-ack versus application-state transport seam test |
| FR-023 | #1903 | T2 — missing stable envelope identity fail-closed ingress test |
| FR-024 | #1903 | T2 — commit-before-application-receipt crash test |
| FR-025 | #1903 | T2 — saturation/pre-commit failure and replay-repair test |
| FR-026 | #1903 | T2 — tenant/device/command/generation/epoch dedup and high-water conformance |
| FR-027 | #1905 | T2 — authenticated tenant-scoped LocalOnly inspection authorization and redaction test |
| FR-028 | #1905 | T1 — closed metric-label type and cardinality projection test |
| FR-029 | #1909 | T1 — six-contract exact-set and synthetic-red proof rejecting an undeclared operator mutation surface |
| FR-030 | #1901 | T2 — existing PostgreSQL revocation provider reuse/conformance proof |
| FR-031 | #1904 | T2 — draft pilot assembly/journey rejects production artifact substitution while all proposals stay draft |
| FR-032 | #1910 | T3 — production assembly missing-provider startup/readiness rejection |
| FR-033 | #1898 | T2 — authenticated tenant/device idempotency replay/reuse PostgreSQL conformance |
| FR-034 | #1893 | T1 — bounded duration and sealed cross-field policy-constructor boundary/property test |
| FR-035 | #1909 | T2 — existing typed registry/codegen six-contract exact-set synthetic-red proof |
| FR-036 | #1895 | T1 — four command/event identity, link, kind, consistency, and shape golden |
| FR-037 | #1901 | T2 — per-command sealed artifact binding and incompatible-provider compile/runtime proof |
| FR-038 | #1910 | T3 — assembly-level external PKI provider/config/conformance closure activation proof |
| FR-039 | #1903 | T2 — public receipt non-oracle equivalence plus authorized internal-audit detail test |
| FR-040 | #1893 | T1 — reported-state constructor/transition synthetic red rejecting generation zero |
| FR-041 | #1895 | T1 — report schema/validator synthetic red rejecting `observedGeneration: 0` |
| FR-042 | #1902 | T2 — credential-derived sealed mTLS principal, payload non-override, mismatch, and stale-generation broker tests |
| NFR-001 | #1903 | T2 — duplicate/replay conformance proving at-least-once plus idempotency |
| NFR-002 | #1899 | T1 — slow-target isolation under bounded scheduler concurrency |
| NFR-003 | #1899 | T1 — validated finite configuration and deterministic retry/drain component tests |
| NFR-004 | #1893 | T1 — non-forgeable vocabulary plus table/property transition proof |
| NFR-005 | #1901 | T2 — per-command artifact type-incompatibility and authoring substitution rejection |
| NFR-006 | #1905 | T2 — authorized output, audit, log/trace, and metric redaction test |
| NFR-007 | #1896 | T2 — authenticated tenant transaction and server-time ordering PostgreSQL test |
| NFR-008 | #1910 | T3 — disable/pause/drain runtime rollback retaining facts while lifecycle never regresses to draft |
| NFR-009 | #1895 | T1 — generated sealed-coordinate compile/golden proof and caller-forgery synthetic red |
| NFR-010 | #1910 | T3 — production assembly dependency type and prohibited-provider substitution rejection |
| NFR-011 | #1906 | T2 — canonical offline/reconnect/newest-command/ACK/report/post-commit-receipt journey join proof |
| NFR-012 | #1907 | T2 — exact PG join-hazard table mapping each cross-boundary failure to one observable assertion |
| NFR-013 | #1908 | T2 — exact MQTT join-hazard table mapping each broker/backpressure/ingress failure to one observable assertion |

## Exact-set rule

This table contains every FR/NFR declared in [spec.md](./spec.md) exactly once. The one-time specification smoke derives both sets dynamically rather than encoding a count; it is not a repository enforcement mechanism.
