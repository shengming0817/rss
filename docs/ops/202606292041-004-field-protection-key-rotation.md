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

This runbook covers the provider, Vault Transit rotation contract, and RSS production maintenance command for persisted settings `ConfigValue` records. `rss settings-config-values maintenance` proves legacy plaintext backfill status and performs rewrap, but it does not query Vault for the current-primary version. Operators must not raise `min_decryption_version` from `failed=0` and `remaining_plaintext=0` alone.

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

4. Keep the previous-read window open while RSS records are migrated.

5. Inspect pending RSS work:

   ```bash
   rss settings-config-values maintenance --operator-service-token-stdin --operator-tenant <uuid> --operation both --dry-run --batch-size 500 < /run/secrets/rss-operator-service-token
   ```

6. Backfill legacy plaintext rows:

   ```bash
   rss settings-config-values maintenance --operator-service-token-stdin --operator-tenant <uuid> --operation backfill --batch-size 500 < /run/secrets/rss-operator-service-token
   ```

   For throttled rollout, add `--tenant <uuid>` and/or `--max-rows <n>`. `--max-rows` limits the whole command; in `both` mode backfill and rewrap share that budget. `--operator-service-token-stdin` reads the operator service principal token only from standard input; `--operator-tenant` supplies the service-token MAC binding, and the verified subject is written to durable audit with job start/finish. Repeat until an unscoped run reports `failed=0` and `remaining_plaintext=0`. After that, remove `RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES`; serving reads no longer accept `protection_scheme=0`.

7. Rewrap encrypted rows:

   ```bash
   rss settings-config-values maintenance --operator-service-token-stdin --operator-tenant <uuid> --operation rewrap --batch-size 500 < /run/secrets/rss-operator-service-token
   ```

   The command uses `KeyProvider::rewrap` and does not decrypt plaintext in RSS. Run full, unthrottled rewrap passes until there are no failures; do not use a `--max-rows` batch result as evidence for disabling old versions.

## Production Rewrap

Use this sequence before disabling old versions:

1. Rewrap existing records with the RSS command:

   - Scan encrypted settings records for the configured settings key.
   - Re-derive AAD with `ProtectionContext::authorized_maintenance` from the persisted tenant/config-key/field/schema-version coordinates.
   - Call `KeyProvider::rewrap(ciphertext, old_key_ref, aad)`.
   - In one storage transaction, replace ciphertext and `KeyRef` with the returned values.
   - Do not decrypt plaintext in the migration path.

2. Validate coverage before disabling old versions:

   - Confirm an unscoped backfill/both command returned `failed=0` and `remaining_plaintext=0`; otherwise keep the previous-read window open and finish backfill.
   - Confirm full, unthrottled rewrap passes for the settings key return no failures. Because RSS deliberately does not query Vault current-primary version, this report is necessary but not sufficient for disabling old versions.
   - Verify coverage against the Vault version recorded in the rotation step by sampling persisted `key_id` values for the settings key and decrypting representative rewritten records with `KeyProvider::decrypt` and the expected new `KeyRef`.
   - If any sampled or audited record still references an old `KeyRef.version()`, keep old versions enabled and rerun rewrap before proceeding.

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
