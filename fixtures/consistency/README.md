# Consistency Crash Matrix Fixtures

This directory contains data-only crash recovery fixtures for RSS consistency
mechanisms. A fixture describes one crash point and the expected recovery
observation. It does not execute a provider, start Docker, kill a process, or
prove runtime correctness.

## Adding A Scenario

1. Place one `fixture-*.toml` file under `fixtures/consistency/<mechanism>/`.
2. Use a globally unique lowercase kebab-case `id`.
3. Set `domain` to the owner of an existing `contracts/**/contract.toml` entry
   referenced by `contractId`; do not use placeholder or future contract IDs.
4. Keep new scenarios `status = "pending"` until a later PR wires an executable
   crash runner and provider-specific assertions.
5. Include a non-empty `pendingReason` for every pending case.
6. Run `cargo test -p testkit` and `cargo xtask consistency-fixtures`.

## Required Fields

```toml
schemaVersion = 1
id = "outbox-after-publish-before-settle"
title = "publish succeeds before settle crash"
level = "L2"
mechanism = "outbox"
status = "pending"
pendingReason = "N-003 only creates the DSL skeleton"
domain = "identity"
contractId = "identity.session-created"
tenantAlias = "tenant-a"
messageAlias = "message-a"
partitionKeyAlias = "aggregate-a"
tenantAuthority = "valid"
crashPoint = "after-publish-before-settle"
expectedRecovery = "redeliver-or-settle-idempotently"
```

## Safety Rules

Fixtures must use aliases, not secrets or real user data. Do not store raw
message bodies, plaintext dead-letter contents, credentials, URLs with userinfo,
lease tokens, Vault key names, HMAC material, email addresses, names, or handler
error text. Tenant is an explicit fixture field and must not be hidden inside a
body-like field.

The first N-003 fixtures are pending only. Passing these fixtures means the DSL
is parseable and indexed; it does not mean outbox, inbox, saga, projection, or
reconcile crash recovery has been behaviorally verified.
