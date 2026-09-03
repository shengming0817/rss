# DeviceLatent L4 delivery plan

This document owns implementation ordering, parallel boundaries, review budgets, rollout, and rollback for the proposal frozen by [spec.md](./spec.md). It does not restate requirements, logical state, contract shapes, proof carriers, or task status.

## Dependency graph

Implementation proceeds in the following waves. At most two PBIs may execute in parallel; an arrow is a completion dependency, while `||` marks work that may proceed concurrently after all preceding dependencies are satisfied.

```text
Wave 1: #1893 || #1894
Wave 2: #1895 || #1896
Wave 3: #1897 || #1902
Wave 4: #1898 -> #1899 -> #1900 -> #1901 -> #1903 -> #1904
Wave 5: #1905
Wave 6: #1907 -> #1909
Future handoff: ADR-028 candidate integration -> separately authorized hardening/T3 activation
```

The linear presentation is a safety schedule, not permission to ignore direct prerequisites:

- #1895 consumes the vocabulary and HTTP identities established by #1893 and #1894.
- #1896 owns only desired/reported/condition storage and domain constraints; it does not write command or schedule state. #1897 independently owns durable command/ingress storage.
- #1898 begins only after #1896 and #1897 have landed. It extends the existing durable reconcile substrate only with wake version/failure streak and the atomic desired-update plus existing-target-due join; it does not recreate next-run, claim, lease/epoch, pause, drain, or release behavior.
- #1899 adds only the missing bounded concurrent execution and fairness behavior over the existing claim/lease worker. It does not introduce a second scheduler.
- #1900 first owns the provider-neutral fencing carrier, stable system producer identity, and atomic command transaction. Its draft command fixture carries only the existing opaque public artifact reference.
- #1901 then binds its sealed authorized-artifact capability into that already-fenced authoring seam; it does not redefine command identity, generation, epoch, or producer authority.
- #1903 consumes the shared ingress/reconcile surface and cannot precede #1900.
- #1902 can proceed beside #1897 because its transport security and session work does not own domain persistence.
- #1904 is a draft simulator-backed pilot only. It does not activate the proposal contracts.
- #1909 extends the existing registry, code-generation, verification, CI-impact, and evidence paths; it does not create a parallel gate or required job.
- Waves 1–6 close the implemented T1/T2 capability baseline. They do not authorize a production candidate, T3, or activation. ADR-028 owns the future candidate-integration and activation DAG; each command must still require its own `AuthorizedCertificateArtifact`, separate from any future assembly-wide provider closure.

When two nominally parallel PBIs discover an overlapping schema, migration, transaction, generated output, or assembly surface, their work is serialized at that surface. The earlier owner lands the shared shape; the dependent owner rebases and consumes it instead of introducing a second fact source.

## Review budgets

Changed-line ranges are design and review budgets. They help keep a PBI cohesive and determine review depth; they are not acceptance gates. Generated output is accounted separately where it materially changes diff size.

| PBI | Design/review budget |
|---:|---:|
| #1893 | 1,500–1,850 |
| #1894 | 1,450–1,800 |
| #1895 | 900–1,200 handwritten; 2,200–3,500 generated |
| #1896 | 1,700–1,980 |
| #1897 | 1,750–1,990 |
| #1898 | 1,750–1,990 |
| #1899 | 1,350–1,700 |
| #1900 | 1,700–1,980 |
| #1901 | 1,700–1,990 |
| #1902 | 1,650–1,950 |
| #1903 | 1,700–1,990 |
| #1904 | 1,700–1,990 |
| #1905 | 1,550–1,850 |
| #1907 | 1,700–1,990 |
| #1909 | 1,450–1,800 |

Exceeding a range prompts scope and ownership review, not an automated failure. Splitting is appropriate only when it preserves one semantic owner and does not create compatibility layers or duplicate proofs.

## Rollout

1. Land vocabulary, proposal contract implementation, and persistent models while every DeviceLatent contract remains draft.
2. Introduce durable scheduling, fencing, the authorized-artifact boundary, secure MQTT, and post-commit ingress receipts behind inactive assembly wiring.
3. Run the simulator-backed #1904 pilot as a draft integration exercise. Its artifacts and receipts remain production-ineligible by type.
4. Add bounded operations and the minimum fault evidence at the unique T1/T2 owners recorded in [traceability.md](./traceability.md).
5. Extend existing repository verification and impact selection in #1909 without creating an L4-specific parallel closure path.
6. Stop at the draft, compile-only candidate boundary. Future candidate integration, real-consumer evidence, and any later hardening/T3 activation require the independent owners and transition defined by ADR-028; they are not work authorized by this plan.

Each invariant must have one canonical primary proof with a minimum sufficient Hard or Medium carrier assigned by [ADR-022](../../architecture/202607291724-022-l4-device-latent-production-loop.md). A Hard carrier is sufficient when construction, generated shape, or a database constraint makes the invalid state unrepresentable. An independent behavioral Medium proof is required for runtime hazards such as transaction joins, real network/broker behavior, restart or takeover, concurrency, and drain. If the assigned carrier cannot prove the claim, the owner narrows or defers it rather than relying on prose.

## Rollback

- Unactivated Rust, schema, and code-generated changes are reverted as a coherent unit. No alias, shim, dual reader, or dual writer remains.
- Database migrations are forward-only. On failure, pause writers and workers, preserve durable facts, and roll forward with a corrective migration.
- MQTT and assembly rollback means disable, pause, and deterministically drain. It never downgrades to plaintext, software-CA, simulator, or in-memory providers.
- The current rollback boundary remains draft and compile-only: disable or remove candidate wiring coherently while retaining durable facts and evidence. If a later ADR-028 activation is authorized, that independent change must define its own fail-closed disable/drain rollback; an active contract must never regress to draft.

Rollback does not reinterpret an ACK as convergence, discard committed ingress evidence, or manufacture an external PKI authorization receipt.
