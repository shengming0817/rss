# DeviceLatent L4 specification source baseline

This document is the provenance and current-code evidence owner for issue #1892 and its #2109 candidate-scope rebaseline. It records what was received, what was observed at each decision baseline, and how stale source assumptions were absorbed. It does not define target behavior; see [spec.md](./spec.md) and [contract-set.md](./contracts/contract-set.md).

## Implementation baseline

- Baseline fetched at implementation: `origin/develop@c5670bb38736115c892bad75c319184a016d24c2` (2026-07-29T17:18:10Z).
- Highest repository migration: `0079_align_auth_grant_sweeper_lock_order.sql`.
- No migration number is reserved by this specification. Each implementation PBI must allocate from the then-current head.
- The current L4 HTTP declaration is the empty draft `identity.reconcile-loop` at `contracts/http/identity/v2/contract.toml`. It is not a compatibility surface; #1894 replaces it directly.
- `PgRevocationStore` is already implemented, wired and persistent. Its migration landed as `0072`; the implementation ancestry includes `dca543c21267d395d9738f2b228e5c4b041203f7`.
- The current device-loop command lifecycle is in-memory and treats acknowledgement as a terminal command outcome. It has no durable desired/reported generations.
- Certificate reconciliation still exposes unfinished raw signer seams. Current MQTT assembly uses a plaintext development path, a non-stable client identity and automatic acknowledgement behavior that cannot prove durable application receipt.
- None of the six proposal identities in [contract-set.md](./contracts/contract-set.md) is a live contract at this baseline.

### Existing durable reconcile capability

The repository already has the durable reconcile substrate; the DeviceLatent PBIs extend it instead of scheduling a second implementation:

- `adapters/postgres/migrations/0041_create_reconcile_schema.sql`, `0044_create_reconcile_attempt_results.sql`, and `0045_reconcile_actions_recorded_label.sql` establish five persistent evidence classes: the target directory (`reconcile_targets`), target-local lease state (`reconcile_leases`), the append-only attempt ledger (`reconcile_attempts`), the append-only terminal-result ledger (`reconcile_attempt_results`), and the append-only converge-action ledger (`reconcile_actions`).
- `crates/eventexec/src/reconcile.rs` owns `ReconcileScheduleStore`, `ReconcileSchedulerBuilder`, and `ReconcileWorker`; `adapters/postgres/src/reconcile.rs` supplies the existing `PgReconcileStore` implementation, and `adapters/postgres/src/integration_tests.rs` exercises it against PostgreSQL.
- The current worker and store already claim due targets, support worker/target pause and resume, drain or release claimed work on pause/cancellation, and retain target-local leases with monotonically increasing epochs.
- Attempt append, terminal-result recording, action-plus-outbox recording, lease extension, and lease release are guarded by `target_id + lease_token + epoch` CAS. A zero-row update is treated as a lost lease rather than permission for a stale holder to write.
- `docs/rules/reconcile.md` is the current behavior guide for this substrate. It records the same five-table boundary and the existing claim/pause/drain/release and lease/epoch semantics.

Consequently, #1898 is limited to durable wake-version and failure-streak extensions plus the atomic join between a DeviceLatent desired update and the existing target-due state. #1899 is limited to the missing bounded concurrent execution and fairness increment. Neither PBI re-creates next-run scheduling, due claiming, lease/epoch fencing, pause, drain, or release.

## 2026-08-12 candidate-scope rebaseline

- Decision baseline: `origin/develop@7fabf4e36c526c4187c0d7a2bb8f8f96873456b4`.
- Received `rss-main-user-device-abac-speckit-20260811.zip`: SHA-256 `a714c58a4846ee9e38d5e955fa7e8a19933c8dee2e5718bbb99919d03564a6b8`.
- Received `rss-incubator-secure-device-rotation-speckit-20260811.zip`: SHA-256 `47a603d91c1117d2b341a02e29ff40132dcfad554cdb26d2620d2c3baa5b8051`.
- ADR-028 accepts `device-security` only as candidate scope. The current `deviceidentity` target remains a draft, compile-only library pilot with no binary, image, mounted contracts, production provider closure, or formal non-test production mint.
- #1910 closed without implementing activation; ADR-028 supersedes its direct activation/T3 route. Future candidate integration and any later hardening/T3 activation require independent owners.
- The exact RSS public waist remains the existing six draft contracts. Resource Security Fact is an External/incubator bootstrap or product fact, not a seventh RSS ingress or a compatibility path.

## Accepted contract amendment

PR #629 closes an ambiguity in the original draft proposal before activation: ACK and ingress-receipt outcome/reason pairs are closed sums, not independent enum products. The amended current specification hashes are:

- `contracts/device-command-acked.event.schema.json`: `1fa592ff1de51fe342ff346f6ccc33adf616cad21d40c9c8fa2fb002d6cf1d14`;
- `contracts/application-receipt.schema.json`: `e3ab656570b4f46bcb2bb734693dd705b6677f9f9269cb45c93dd4fb6320f63c`;
- `contracts/contract-set.md`: `4d041270278059f588bedd1bace5e93003370234515714673a5066e3f59c0148`.

The received-archive hashes below remain immutable provenance and intentionally continue to describe the original input.

## Received archive

- Source: `/Users/shengming/Downloads/rss-l4-speckit-overlay.zip`
- Archive SHA-256: `c19818c82a04571c5139803fbeead022bd2772452259faa7ac4e575fbd424c4d`
- Canonical original-document manifest SHA-256: `ec817327617f90a50d25dcf54a11f13eb3e0542949568d720f780c06dc88c648`
- Included source documents: 16. `.DS_Store`, the archive itself, and any issue/import package are excluded.

| Source path under `docs/` | SHA-256 |
|---|---|
| `architecture/202607151101-018-l4-device-latent-production-loop.md` | `981f90565f887d8e2b21a70a1b40fc19ab9f1652dfdb9a4f4285e50cfcee4907` |
| `spec/007-l4-device-latent-production-loop/checklists/requirements.md` | `475ade0bb38f4ec120f63bac6ec3e7377a659a068f050326db389795dad55dbf` |
| `spec/007-l4-device-latent-production-loop/contracts/application-receipt.schema.json` | `39e4c9942bb7378c85425f2fd363b62ecdce9d867167e59e890239a947ace7d5` |
| `spec/007-l4-device-latent-production-loop/contracts/apply-device-certificate.command.schema.json` | `b41891ccc2e40ec0c6b5dacce3ae1428caeb9932762f3fd614bcd96cf141821b` |
| `spec/007-l4-device-latent-production-loop/contracts/contract-set.md` | `1e889581bac0b6467b8437be6c9304b3987ec15b01ac3c2c5d4fed2eb1c33f93` |
| `spec/007-l4-device-latent-production-loop/contracts/device-certificate-policy-put.request.schema.json` | `c61743220b89994b977dd894ba1556d3c3e47ae5166b4eaa873b57b6d3e3944c` |
| `spec/007-l4-device-latent-production-loop/contracts/device-certificate-policy-put.response.schema.json` | `526c76d4cb938cbd901b5c42abf275665cac764ce5ee215806feb7897ba309c0` |
| `spec/007-l4-device-latent-production-loop/contracts/device-certificate-reported.event.schema.json` | `4b62067205b5b228954d1a00193c3416a811f9921d6489846d90d006c08b760e` |
| `spec/007-l4-device-latent-production-loop/contracts/device-certificate-status-get.response.schema.json` | `a8dffe1b9172bdfefde7d4bcdbe21ac6bf0f9baa655b7fe815ebd51f609038e3` |
| `spec/007-l4-device-latent-production-loop/contracts/device-command-acked.event.schema.json` | `86cd982db500351ea7e95b99683557872c1877056898caf778a70bd149ab0153` |
| `spec/007-l4-device-latent-production-loop/data-model.md` | `25803b5b9b6eabba734132a8bd1579a7a5931d40d86cc572d531130b30c5b2a8` |
| `spec/007-l4-device-latent-production-loop/plan.md` | `ffb0fe087e60ad36321da12d017a75b1dc8604e0f4b145c8a2a8939b05bcf28c` |
| `spec/007-l4-device-latent-production-loop/quickstart.md` | `93a03518b03c960cf8baa8880887b4032290fba9e77e002fbdf6dfa5cb67df5e` |
| `spec/007-l4-device-latent-production-loop/research.md` | `4658e3bf2de3eacbfb64823e1baa6e4be4e7519aa7a6a473d0683f6236539610` |
| `spec/007-l4-device-latent-production-loop/spec.md` | `9b51900780e784674d5e144ad93cfcb4c81d00d7e7d7f0cca3c5c3cce2361939` |
| `spec/007-l4-device-latent-production-loop/tasks.md` | `7b8a0ec9af525cf2b3018a1e7534fade057e58d0095d520f101e64d06e6fae42` |

## Absorption decisions

| Received assumption | Repository decision |
|---|---|
| The source implementation commit `08de5ceb…` and fixed migration range `0067`–`0070` are current | Rejected. The implementation baseline and migration head above are authoritative; later PBIs allocate numbers when they execute. |
| A new persistent revocation work package is required (`PR-10`, `T060`–`T065`) | Removed. Persistence already exists; all certificate work reuses the current store and security rules. |
| A generic `TargetWakeStore` is the selected abstraction | Rejected. #1898 owns a purpose-specific durable scheduling transaction and repair behavior. |
| A production Compose pilot proves closure | Rejected. #1904 is a draft simulator pilot only. ADR-028 owns a future candidate-integration handoff; #1910 is no longer an activation or T3 owner. |
| L4 needs its own `l4-closure` gate and required CI job | Rejected. #1909 extends the existing typed registry/code-generation verification path and CI-impact behavior. |
| PR count, task count, case count, random-sequence count, or changed-line count is a pass condition | Rejected. Changed-line ranges remain planning budgets only; proof comes from the carriers mapped by the ADR and traceability table. |
| The received ADR can be imported with number 018 | Rejected because ADR-018 already exists. Its content was re-adjudicated into ADR-022; this source filename and hash are retained only here. |
| Acknowledgement proves certificate convergence | Rejected. Acknowledgement advances command receipt/state; matching reported generation and state establishes readiness. |
| RSS owns certificate-authority and lifecycle behavior | Rejected. Those responsibilities are external PKI scope; RSS separately consumes an assembly-level sealed provider closure and per-command sealed authorized artifacts. |

Overlapping backlog items such as #1716 and #1717 are recorded as superseded candidates. This documentation PR does not mutate their issue state.
