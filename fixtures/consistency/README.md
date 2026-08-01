# Consistency Crash Matrix Fixtures

This directory contains the N-028 consistency fault crash matrix for RSS
consistency mechanisms. A fixture describes one crash point, the invariant that
must survive it, and the real backend runner used by the opt-in journey.

## Adding A Scenario

1. Place one `fixture-*.toml` file under `fixtures/consistency/<mechanism>/`.
2. Use a globally unique lowercase kebab-case `id`.
3. Set `contractId` to the existing `contracts/**/contract.toml` entry whose
   consistency capability is verified by the case. `domain` and `level` must
   match that contract's owner and `consistencyLevel`; do not use placeholder or
   future contract IDs.
4. Use `status = "ready"` only after adding a matching runner in
   `journeys-fault-matrix/tests/consistency_fault_matrix_journey.rs`.
5. Include a non-empty `pendingReason` only for `status = "pending"`.
6. Run `cargo test -p testkit` and `cargo xtask consistency-fixtures`.
7. Run the real backend matrix through the fixed `integration-critical` job with its canonical selection.

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
runner = "postgres-rabbitmq"
```

## Safety Rules

Fixtures must use aliases, not secrets or real user data. Do not store raw
message bodies, plaintext dead-letter contents, credentials, URLs with userinfo,
lease tokens, Vault key names, HMAC material, email addresses, names, or handler
error text. Tenant is an explicit fixture field and must not be hidden inside a
body-like field.

## Running The Matrix

`cargo xtask consistency-fixtures` is the no-Docker structural gate used by
`verify`. It checks schema, ownership, contract consistency level, ready-case
coverage, and runner mappings.

`cargo xtask ci run --job integration-critical --selection '<canonical SelectionPlan JSON>'` runs the selected real backend journeys. It uses
`cargo-nextest`, Postgres, Redis, and RabbitMQ. With Docker available, `testkit`
self-provisions containers. To use long-lived services instead, set
`RSS_TEST_ALLOW_EXTERNAL_POSTGRES` plus `PGHOST`, `PGPORT`, `PGDATABASE`,
`PGUSER`, `PGPASSWORD`, `REDIS_TEST_URL`, and set `RSS_AMQP_TEST_URL` to a base broker URL.
For the RabbitMQ env path, pre-create vhost `rss_fault_matrix` and grant the
URL user configure/write/read permissions on that vhost; the testkit env path
only appends the vhost name and does not create it.

Local cost is integration-test cost: expect container startup plus one targeted
`journeys-fault-matrix` test binary. It is intentionally not part of default `verify`.
