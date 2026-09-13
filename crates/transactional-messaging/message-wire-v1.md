# Authored message byte contract v1

Owner: `rss-transactional-messaging`. `MessageEnvelope::canonical_bytes()` implements this public
contract. SQL and other language writers can encode it without knowing any adapter's private
storage format. The fingerprint is SHA-256 of the **entire encoded byte string**, without any
additional prefix or JSON serialization. `MessageFingerprint::of()` uses the same streaming
encoder. This publishes the existing fingerprint preimage; existing fingerprints do not change.
It detects authored drift, not authenticity or payload-schema validity.

Each frame is `tag:u8 || length:u64-big-endian || value:length-bytes`. Frames have exactly the
following order. All integers have the specified fixed width, big endian. Text is exact UTF-8,
without normalization. Unknown versions, missing/extra/reordered frames, noncanonical presence
flags, invalid lengths and trailing bytes must be rejected before persistence.

| Tag | Value | Cardinality |
| --- | --- | --- |
| 0 | UTF-8 `rss-transactional-message-v1` | one |
| 1 | message ID | one |
| 2 | tenant UUID, 16 raw octets in network order | one |
| 3 | occurred-at Unix seconds, nonnegative i64 (8 bytes) | one |
| 4 | presence byte 0 or 1; if 1, another tag-4 frame containing correlation ID | one or two |
| 5 | messaging domain | one |
| 6 | route | one |
| 7 | contract ID | one |
| 8 | nonzero contract major version, u32 (4 bytes) | one |
| 9 | schema digest text | one |
| 10 | partition presence, single byte 0 or 1 | one |
| 11 | partition tenant UUID (must equal tag 2) | only when tag 10 is 1 |
| 12 | partition domain (must equal tag 5) | only when tag 10 is 1 |
| 13 | partition key | only when tag 10 is 1 |
| 14 | presence byte 0 or 1; if 1, another tag-14 frame containing causation ID | one or two |
| 15 | attribute entry count, u64 (8 bytes) | one |
| 16, 17 | attribute key then value | count pairs, keys unique and strictly UTF-8-byte sorted |
| 18 | payload bytes, including empty or arbitrary binary values | one |

Primitive validation follows the owning core types: IDs/domain/route/causation are 1–255 ASCII
bytes `[A-Za-z0-9_.:-]`; correlation is 1–128 ASCII bytes `[A-Za-z0-9_.-]`; partition key is
1–255 UTF-8 bytes with no ASCII control bytes (0–31 or 127). Contract IDs have at least two
dot-separated segments, each beginning with a lowercase ASCII letter followed by lowercase
letters/digits or single hyphens between letters/digits, at most 255 bytes total. Schema digest
is exactly `sha256:` followed by 64 lowercase hex digits. Attribute keys and values are UTF-8
strings, including empty strings. No implicit trimming, case folding or Unicode normalization.

Transport trace and tenant authority are **not encoded or hashed**. The receiving adapter owns
how to accept/store per-delivery transport separately; callers cannot inject authored fields
through it. PostgreSQL accepts a separate JSON object with exactly `trace` and `tenant_authority`,
each string or null. PostgreSQL text cannot contain U+0000; that adapter rejects such text before
persistence, while payload bytes may contain zero. This is a storage restriction, not another
core encoding. Resource/transaction deadlines remain host-owned; the parser must bound every
length/count by the supplied input before allocating or iterating.

A SQL caller sends the complete bytes, never a purported digest. The database decodes and validates
all authored fields, binds the tenant to the transaction, derives row identity and computes SHA-256
itself. Different valid authored bytes under the same ID produce `conflict`; malformed bytes reject
before the existing-ID path, even when an earlier row exists. Clients must roll back on conflict.

Protocol changes require a new explicit version and a coordinated replacement; v1 parsers do not
accept unknown fields, auto-upgrade, dual-read or guess a legacy format. The real PostgreSQL test
`partition::wire_contract` includes an independent encoder, all optional fields, maximum numeric
values, Unicode attributes, binary payload, malformed frames and digest parity with the core.

`message-wire-v1-vector.json` publishes the exact ordered frames, canonical hex bytes and SHA-256
for the all-fields SQL test vector. It is checked against both independent encoding and the database.
