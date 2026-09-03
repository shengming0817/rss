# Consistency Crash Matrix Fixtures

This directory contains committed data consumed directly by consistency and eventexec tests.

## Adding A Scenario

1. Place one `fixture-*.toml` file under `fixtures/consistency/<mechanism>/`.
2. Use a globally unique lowercase kebab-case `id`.
3. Set `contractId` to the existing `contracts/**/contract.toml` entry whose
   consistency capability is verified by the case. `domain` and `level` must
   match that contract's owner and `consistencyLevel`; do not use placeholder or
   future contract IDs.
4. Use `status = "ready"` only after adding a matching owner-crate test.
5. Include a non-empty `pendingReason` only for `status = "pending"`.
6. Run `cargo test --locked -p consistency` and
   `cargo test --locked -p eventexec --test outbox_crash_matrix`.

## Required Fields

```toml
schemaVersion = 1
id = "outbox-after-publish-before-settle"
title = "publish succeeds before settle crash"
level = "L2"
mechanism = "outbox"
status = "ready"
domain = "identity"
contractId = "identity.session-created"
tenantAlias = "tenant-a"
messageAlias = "message-a"
partitionKeyAlias = "aggregate-a"
tenantAuthority = "valid"
crashPoint = "after-publish-before-settle"
expectedInvariant = "outbox-publish-settled-once"
runner = "provider-neutral"
```

## Safety Rules

Fixtures must use aliases, not secrets or real user data. Do not store raw
message bodies, plaintext dead-letter contents, credentials, URLs with userinfo,
lease tokens, Vault key names, HMAC material, email addresses, names, or handler
error text. Tenant is an explicit fixture field and must not be hidden inside a
body-like field.

## Running The Fixtures

The JSON vectors are compiled into `consistency`; the TOML crash case is compiled into the
`eventexec` test target. There is no central catalog, runner mapping, or SelectionPlan. Real
provider tests are selected through the reverse dependency graph of the dedicated integration
packages under `tests/`.
