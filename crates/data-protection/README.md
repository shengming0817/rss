# rss-data-protection

`rss-data-protection` is the public owner of provider-neutral encrypted-data protection primitives
for RSS. It contains AEAD and plaintext capsules, ciphertext envelopes, derived AAD and protection
contexts and blind indexes.

The package defines data formats and invariants but does not select key providers, cryptographic
backends, storage adapters, workflows, or authorization policy. Diagnostic-output redaction is owned
separately by `rss-redact`.

`ProtectionContext::new(tenant, config_key, field, schema_version)` validates coordinate shape;
`derive()` produces domain-separated, length-prefixed canonical AAD. This replaces the former request
and maintenance constructors without changing encoded bytes. Neither constructor nor `DerivedAad`
authenticates a principal, verifies authorization, or proves the provenance of supplied coordinates.
Callers must establish these facts at their own trust boundary, including tenant/device access and
maintenance permission where applicable.

A conforming AEAD implementation rejects mismatched tenant, config key, field or schema version with
`AeadError::Open`. Possession of the correct key and coordinates is sufficient for cryptographic
verification; AAD does not deny an unauthorized caller who already possesses both. The recovery
component's existing ring fixture tests real AES-GCM tags across all four dimensions; this package's
identity fixture only tests the port and encoding contract.

Stored `ProtectionAad` cannot be passed directly to `Aead::open`, and `DerivedAad` has no raw-byte
constructor. These are encoding/type boundaries, not authentication capabilities. Decrypted plaintext
remains inside a zeroizing capsule. Public compile-fail tests cover the actual type boundaries.

Blind-index keys take zeroizing ownership before validating their length, so rejected keys are
cleared too. Transform input copies and every intermediate/final result use `Zeroizing<String>`;
outputs are sized before writing to prevent reallocation from leaving plaintext copies behind.
Lowercase preserves Unicode default casing (including Final Sigma), with ICU4X casing properties.
Borrowed caller inputs remain the caller’s responsibility; the library cannot erase copies made
before ownership transfer or guarantee register/stack-spill erasure.

`cargo test -p rss-data-protection --test zeroize` runs the independent allocator probe fixture
against the real public key/index APIs. It inspects initialized tracked buffers before release,
including spare capacity and reallocation, and calibrates against an ordinary nonzero Vec.
The fixture alone contains scoped unsafe allocator code; production crates remain unsafe-free.
Its committed source/lock live under this package’s tests; build artifacts and logs are regenerable
under `rss-external-check/zeroize-probe`. This T1 evidence is not an artifact/publishing claim.
