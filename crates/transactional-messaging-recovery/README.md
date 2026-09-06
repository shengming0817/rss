# rss-transactional-messaging-recovery

Explicit, tenant-bound transactional message recovery. Products authorize operations; providers
atomically persist message changes and operation receipts. Commit uncertainty is never rollback.

The library owns recovery-only identities, immutable action requests, bounded tenant-scoped queries,
authorization binding, protected authored-message capsules and operation observations. It reuses
messaging `LocalTxAttempt` and deadlines rather than defining another transaction result. Providers
must atomically change durable state and persist the operation receipt, with tenant/target/revision
CAS and complete request-digest comparison for retries.

Authorize a `Mutation` or `Query` through the trusted product `Authorizer`. The library-created
`Challenge` contains the exact request; `authorized()` binds a decision but does not authenticate it.
Products supply identity, permission and approval policy. `AuthorizedMutation` / `AuthorizedQuery`
have no public constructors. A malicious provider or authorizer is outside this semantic trust
boundary, just as a false commit acknowledgement is outside the message transaction contract.

`RecoveryStore::mutate` performs one operation. `execute` accepts core `ExecutionDeadlines`, bounds mutation by the operation cutoff, and reserves
the settlement interval for exact receipt readback on unknown commit. Both cutoffs come from one
clock observation; no budget is reset. It never reruns
mutation. Missing/readback-unavailable receipts preserve unknown status. `Observer` receives only the closed action, attempt-status and error categories and is caller-owned;
no exporter, worker, scheduler or operational process is installed.

Replay uses a new caller-provided MessageId and the original authored metadata/payload, including
route and partition. A new Outbox row joins the partition tail; existing subscribers may all see it.
Transport context is not captured or replayed. Same-ID redrive cannot extend the original delivery
window. Expired resolution is distinct from publication; compensation evidence is a published
same-tenant message whose authored causation binds the resolved target. Products decide whether the
business compensation is sufficient.

Protection uses a caller-provided randomized AEAD through `rss-data-protection`, with recovery-owned
versioned capsule bytes and AAD derived from independently trusted record/tenant/group/contract and
fingerprint coordinates. Decrypted payloads remain in zeroizing `Plaintext`; list/inspect return no
payload or key data. Current limits are 4 MiB encoded plaintext and 16 MiB serialized ciphertext.

`python3 hack/recovery-package-proof.py` validates isolated core-only, PostgreSQL and managed-host
consumers from actual packaged archives. `--artifacts DIR --revision REV` validates supplied
candidate checksums and revision without repackaging. Package proof does not publish a release.

Exact retries reuse the same OperationId and request digest. A new operation cannot reuse a replay
MessageId, including a previous replay from the same source. `StoreFailureKind` retains closed backend
classification alongside `LocalTxAttempt`; transient classification alone never authorizes retry
after unknown commit or failed rollback.

## Consumer archive lifecycle

`archive` owns canonical archive format v1, exact-request product authorization, independently
keyed AEAD assembly, and verified/missing proofs. `HotKey` and `ArchiveKey` cannot be interchanged;
the archive cipher also rejects reuse of the actual HOT key identity. The canonical record includes
the authenticated authored message, source identity, fingerprint, reason and capture time. Archive
AAD binds tenant, source and generation under a separate protection domain. Before issuing a HOT
cleanup proof, the core reads and authenticates the versioned archive format and checks the authored
fingerprint against the trusted source; the format reader is private and grants no cold replay.

The product explicitly supplies HOT retention, cold retention after purge, and `Hold`. HOT retention
must cover the database's same-ID window plus safety margin. At purge the actual Compliance lock
must extend strictly past database time plus the greater of cold retention and receipt retention.
There is no fixed 30-day policy. `execute` is bounded, preserves `LocalTxAttempt` settlement states,
and reserves settlement time for exact receipt readback. Products own scheduling and authorization.

The PG repository persists randomized bytes before S3 writes. Unknown writes retry identical bytes;
verified receipt commit removes temporary bytes. Cleanup removes only HOT capsule content, retaining
source identity and operation receipts. `ConsumerDetails::hot_available` becomes false and a new
Replay returns `Archived`; exact existing Replay operation retries still return their original receipt.
No cold restoration/replay API is supplied in this version.

Expired generations retain coordinates for bounded reconciliation. The PG scan rotates a persisted
64-object batch so unresolved writes cannot starve later generations. A purged object remains
`Purged` until expiry; `Retained` means it still exists after expiry.

Missing/Evidence faults are persisted and block the same operation. A prior success cannot settle an
attempt that observed an integrity failure, even if the fault write itself is interrupted. A new
explicitly authorized operation is required to resume work; the old fault receipt stays intact.
Natural retention expiry renews the generation and is not an integrity fault.
Expired generations retain their evidence. A staged write with no known
version and no currently visible object remains unresolved: a key-level absence does not prove that
an unknown immutable version disappeared. Provider failures never mean missing. Closed observations
carry no tenant, object path, payload or key data. Providers and product authorizers are trusted
implementations; private proof construction does not establish the truth of a malicious provider.
