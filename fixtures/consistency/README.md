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
runner = "provider-neutral"
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

Run `cargo xtask ci run --job integration-critical --integration-group <postgres|transport|runtime|artifact> --selection '<canonical SelectionPlan JSON>'`
once for each required closed group to execute the selected real backend journeys. They use
`cargo-nextest`, Postgres, Redis, and RabbitMQ. With Docker available, `testkit`
self-provisions containers. To use long-lived services instead, set
`RSS_TEST_ALLOW_EXTERNAL_POSTGRES` plus `PGHOST`, `PGPORT`, `PGDATABASE`,
application-role credentials through the fixture API, `REDIS_TEST_URL`, and set
`RSS_AMQP_TEST_URL` to a base broker URL. External PostgreSQL owner credentials are not consumed.
External application roles must be isolated LOGIN roles with NOSUPERUSER, NOCREATEDB,
NOCREATEROLE, NOREPLICATION, NOBYPASSRLS, NOINHERIT, no memberships, and a non-expired password;
password-ignoring authentication is rejected. Migration-bearing targets remain owned/Docker-only.
For the RabbitMQ env path, pre-create vhost `rss_fault_matrix` and grant the
URL user configure/write/read permissions on that vhost; the testkit env path
only appends the vhost name and does not create it.

Local cost is integration-test cost: expect container startup plus one targeted
`journeys-fault-matrix` test binary. It is intentionally not part of default `verify`.
