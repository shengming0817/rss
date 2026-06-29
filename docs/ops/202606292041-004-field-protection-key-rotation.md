# Field Protection Key Rotation Runbook

Issue: #1474

## Model

RSS field protection uses the provider keyset model already exposed by `diport::KeyProvider`:

- `KeyName`: provider keyset name, such as a Vault Transit key name.
- `KeyVersion`: cryptographic key version inside that keyset.
- `KeyRef`: stable envelope reference stored atomically with each ciphertext.
- `encrypt`: writes with the provider current-primary key.
- `decrypt`: reads the version encoded in the stored ciphertext and `KeyRef` while the provider still allows that previous-read version.
- `rewrap`: rewrites old ciphertext to the current-primary key without returning plaintext to the adapter.

For Vault Transit, `vault:vN:` identifies the key version used for a ciphertext; Vault key rotation makes future encryptions use the new version while old data remains decryptable through the keyring; `/rewrap` upgrades ciphertext to the latest version without revealing plaintext; `min_decryption_version` controls which old versions remain decryptable. References:

- `ref: hashicorp/vault builtin/logical/transit/path_encrypt.go@042e17bf44393d22158e45b6b25764d415edea58`
- `ref: hashicorp/vault builtin/logical/transit/path_decrypt.go@042e17bf44393d22158e45b6b25764d415edea58`
- `ref: hashicorp/vault builtin/logical/transit/path_rewrap.go@042e17bf44393d22158e45b6b25764d415edea58`

## Preconditions

- The application stores ciphertext and `KeyRef` in the same transaction.
- The application can derive AAD through `ProtectionContext::authorized_maintenance` from trusted record coordinates.
- Operators have Vault policy for `transit/keys/<key>/rotate`, `transit/rewrap/<key>`, and key config updates.
- The service token used by RSS runtime does not need key-management permissions.

## Current Production Boundary

This runbook currently covers the provider and Vault Transit rotation contract delivered by #1474. It does not yet deliver an RSS production rewrap tool for persisted application records. Until that tool exists, operators may rotate the Vault Transit key and verify new writes, but must keep the previous-read window open. Do not raise `min_decryption_version` to the current primary for an RSS field-protection key unless a production rewrap job has already proven zero old-version records remain.

The missing production job must provide these RSS-side controls before old versions can be disabled:

- A concrete inventory of protected tables and columns that store ciphertext and `KeyRef`.
- A dry-run mode that counts records where `KeyRef.version() < current_primary`.
- A resumable batch mode that derives AAD from persisted tenant/config-key/field/schema-version coordinates with `ProtectionContext::authorized_maintenance`.
- One storage transaction per record or batch that replaces ciphertext and `KeyRef` with the `KeyProvider::rewrap` output.
- Coverage SQL or an equivalent machine-readable report proving zero old-version `KeyRef` values remain.
- Canary encrypt/decrypt and sampled post-rewrite decrypt checks.
- Audit output for operator identity, key name, old/new versions, batch counts, failures, and resume cursor.

## Rotation

1. Snapshot current state:

   ```bash
   vault read transit/keys/<key>
   ```

   Record the current latest version and current `min_decryption_version`.

2. Rotate the key:

   ```bash
   vault write -f transit/keys/<key>/rotate
   vault read transit/keys/<key>
   ```

   Verify the latest version increased by one.

3. Verify new writes:

   - Write a canary value through `KeyProvider::encrypt`.
   - Confirm the returned `KeyRef.version()` equals the new Vault version.
   - Confirm the ciphertext starts with `vault:v<new-version>:` for Vault Transit.

4. Keep the previous-read window open:

   Because #1474 does not ship the RSS production rewrap job, stop the production procedure here after canary verification. Existing records continue to decrypt because Vault still allows their older versions. Do not run Future Production Rewrap step 3, or otherwise raise `min_decryption_version` to disable old versions, for RSS field-protection keys in this state.

## Future Production Rewrap

After a production rewrap job exists, use this sequence before disabling old versions:

1. Rewrap existing records:

   - Scan records whose stored `KeyRef.version()` is older than the current primary.
   - Re-derive AAD with `ProtectionContext::authorized_maintenance` from the persisted tenant/config-key/field/schema-version coordinates.
   - Call `KeyProvider::rewrap(ciphertext, old_key_ref, aad)`.
   - In one storage transaction, replace ciphertext and `KeyRef` with the returned values.
   - Do not decrypt plaintext in the migration path.

2. Validate coverage before disabling old versions:

   - Count remaining records where `KeyRef.version() < current_primary`.
   - The count must be zero before closing the previous-read window.
   - Sample decrypt rewritten records with `KeyProvider::decrypt` and the new `KeyRef`.

3. Disable old versions:

   ```bash
   vault write transit/keys/<key>/config min_decryption_version=<current-primary-version>
   vault read transit/keys/<key>
   ```

   After this point, old ciphertext should fail closed. RSS must surface the failure as `KeyProviderErrorKind::Rejected`, without leaking Vault response details.

## Rollback

If validation fails before disabling old versions, stop the batch and keep the previous-read window open. Existing records remain decryptable because old versions are still allowed.

If `min_decryption_version` was already raised and a missed record is discovered, temporarily lower `min_decryption_version` only under incident approval, rewrap the missed records, then restore `min_decryption_version` to the current primary.

## Compromise Mode

`rewrap` is not sufficient for master/wrapping-key compromise if the old key material is considered exposed. In that case, run an incident-specific full decrypt and encrypt migration under a newly provisioned keyset, with separate approval and audit, because normal rewrap intentionally does not return plaintext to RSS.
