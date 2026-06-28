# Quickstart: Tenancy / ABAC / Data Permission Closeout

## Local Verification

```bash
cargo fmt --all -- --check
cargo xtask verify
cargo test --workspace
```

## Focused Checks

```bash
cargo xtask schema-rls
cargo xtask setlocal-funnel
cargo test -p postgres --features integration
cargo test -p identity
cargo test -p authn
```

## Security Scenarios To Re-run Per PR

- Missing tenant context denies instead of defaulting.
- `rss_app` with tenant A cannot see tenant B rows.
- Superuser/BYPASSRLS durable setup fails.
- Unscoped outbox partition keys cannot be used for tenant-scoped ordered delivery.
- Tenant-aware `PartitionKey` and `OutboxEnvelopeParts` Debug/log output redacts credential-like identifiers.
- `RowScope::All` cannot be issued without durable audit success.
- Active routes without AuthZ mode are rejected.
- Sensitive read fields remain masked by default.
