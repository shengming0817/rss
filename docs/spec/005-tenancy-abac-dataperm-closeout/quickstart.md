# Quickstart: Tenancy / ABAC / Data Permission Closeout

## Local Verification

```bash
cargo fmt --all -- --check
cargo xtask verify --fast
cargo xtask verify
cargo test --workspace
```

## Focused Checks

```bash
cargo test -p xtask tenancy_closeout
cargo check -p tenancyconsumer
cargo run -p tenancyconsumer
cargo xtask tenancy-closeout
cargo xtask archrules verify
cargo xtask defer-gate
cargo xtask schema-rls
cargo xtask setlocal-funnel
cargo xtask pg-tenant-tx-guard
cargo test -p postgres --features integration
cargo test -p identity
cargo test -p authn
```

## Docs / Governance Only PBIs

For documentation boundary PBIs such as #1587, use the no-compile governance lane unless Rust behavior changes:

```bash
cargo test -p xtask tenancy_closeout
cargo check -p tenancyconsumer
cargo run -p tenancyconsumer
cargo xtask tenancy-closeout
cargo xtask archrules verify
cargo xtask defer-gate
cargo xtask verify --fast
```

## Security Scenarios To Re-run Per PR

- Missing tenant context denies instead of defaulting.
- `rss_app` with tenant A cannot see tenant B rows.
- Superuser/BYPASSRLS durable setup fails.
- Outbox ordered delivery gates by `(tenant_id, domain, partition_key)`; tenant A DLX cannot block tenant B with the same business key.
- `rss_app` cannot directly UPDATE/DELETE outbox and must use fixed outbox maintenance functions for relay settlement/retention.
- `RowScope::All` cannot be issued without durable audit success.
- Active routes without AuthZ mode are rejected.
- Sensitive read fields remain masked by default.
- Open-source AuthZ parity remains documented as RSS typed/in-process safety-objective equivalence in
  `docs/architecture/202607021958-014-authz-open-source-parity-boundary.md`.
