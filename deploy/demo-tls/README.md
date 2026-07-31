# Demo TLS material (#1710)

`generate-demo-cas.sh` is the source of truth. It emits trust-anchor PEMs and leaf certs
under `out/` (gitignored) for postgres / redis / rabbitmq / minio. CA private keys are
removed after leaf issuance so compose directory mounts cannot expose them.

```bash
bash deploy/demo-tls/generate-demo-cas.sh
# force rewrite:
RSS_DEMO_TLS_FORCE=1 bash deploy/demo-tls/generate-demo-cas.sh
```

`deploy/smoke.sh` runs the generator before `compose up`. Manual compose users must
run it first so bind mounts under `deploy/demo-tls/out/` exist.

Leaf SANs include compose DNS names (`postgres`, `redis`, `rabbitmq`, `minio`) plus
`localhost` / `127.0.0.1` for host-side tooling. Keys are **demo-only**.

## Host-side TLS connect examples

After `docker compose up` (or smoke), verify each provider from the host with the
matching trust-anchor PEM:

```bash
# PostgreSQL (VerifyFull)
PGSSLMODE=verify-full \
PGSSLROOTCERT=deploy/demo-tls/out/postgres/ca.pem \
psql "host=127.0.0.1 port=5432 dbname=rss user=rss_app sslmode=verify-full"

# Redis (rediss)
redis-cli --tls \
  --cacert deploy/demo-tls/out/redis/ca.pem \
  -h 127.0.0.1 -p 6379 PING

# RabbitMQ (amqps; compose publishes 127.0.0.1:5671)
openssl s_client -connect 127.0.0.1:5671 \
  -CAfile deploy/demo-tls/out/rabbitmq/ca.pem </dev/null

# MinIO / S3 HTTPS
curl -v --cacert deploy/demo-tls/out/minio/CAs/rss-demo-s3-ca.pem \
  https://127.0.0.1:9000/minio/health/live
```
