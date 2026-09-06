# rss-data-protection

`rss-data-protection` is the public owner of provider-neutral encrypted-data protection primitives
for RSS. It contains AEAD and plaintext capsules, ciphertext envelopes, derived AAD and protection
contexts and blind indexes.

The package defines data formats and invariants but does not select key providers, cryptographic
backends, storage adapters, workflows, or authorization policy. Diagnostic-output redaction is owned
separately by `rss-redact`.

Stored AAD cannot be passed back into an encryption operation, derived AAD cannot be reconstructed
from split fields, and decrypted plaintext remains inside a zeroizing capsule. Compile-fail tests
keep these boundaries part of the public contract.
