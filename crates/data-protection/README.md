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
