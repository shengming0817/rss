# tenancyconsumer

Compile-only consumer example for `docs/guides/202607090202-1596-tenancy-consumer-migration.md`.

It constructs the public `httpserve` route/projection types that downstream code should use. It does not start an HTTP
server, connect to Postgres, install a PDP, or depend directly on `generated`.

Run:

```bash
cargo check -p tenancyconsumer
cargo run -p tenancyconsumer
```
