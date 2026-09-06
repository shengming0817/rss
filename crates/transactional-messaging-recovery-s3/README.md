# rss-transactional-messaging-recovery-s3

A dedicated, verified S3 Object Lock provider for consumer dead-letter archives.
Products supply the AWS SDK client (including TLS, endpoint, credentials and KMS configuration),
bucket and clock. `Unverified::verify` checks versioning, Object Lock and a real conditional-write
canary before yielding `S3ArchiveStore`. The canary is retained briefly and is left to product
lifecycle policy. The port exposes no deletion, listing or administration operations.

Every object uses Compliance retention, create-only PUT, SHA-256 and exact-version HEAD/GET.
An SDK timeout never establishes that a write failed. Recovery persists ciphertext before upload
and retries identical bytes. HEAD permission failures are not missing-object evidence.

This package owns no scheduler or product compliance policy. The recovery core and PostgreSQL
repository determine whether an actual retention horizon permits HOT cleanup.

Archive `put` also requires `s3:PutObjectRetention` because retention is explicit per object.
HEAD/checksum and GET need object/version read and retention permissions; SSE-KMS configurations
must additionally supply the permissions required by S3. No credentials are discovered by the library.
`tests/archive-integration` runs real TLS MinIO and PostgreSQL: locked-version deletion refusal,
short-lived exact-version disappearance, safe purge, response loss after real PUT, commit uncertainty,
wrong evidence, tenant isolation, holds and fencing. These are S3-compatible provider proofs, not an
AWS production deployment or IAM/KMS compliance claim.

Structured SDK failures retain a closed product-facing distinction: effective IAM/configuration and
4xx contract errors return `StorageContract`; transport, throttling and server failures return
`Unavailable`; mismatching object facts return `Evidence`. Exact HEAD 404 alone may mean absence.
An error category does not settle a PUT: the core preserves CommitUnknown independently and never
infers safe retry from `Unavailable` alone. Provider diagnostics are not exposed.
