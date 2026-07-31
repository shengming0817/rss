#!/usr/bin/env bash
# Docker-gated upgrade smoke: a real SQLx 0066 ledger and durable data exist before the release
# operator applies every migration through HEAD and the provisioning script sets the reader credential.
# Postgres serves TLS (VerifyFull + private CA); RSS_PG_SSL_MODE is banned (#1710).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
container="rss-pg-reader-upgrade-${$}"
volume="${container}-data"
port="${RSS_UPGRADE_SMOKE_PORT:-55467}"
database="rss_upgrade_test"
tls_dir="$(mktemp -d "${TMPDIR:-/tmp}/rss-pg-upgrade-tls.XXXXXX")"
migration_password_file="$(mktemp)"
reader_password_file="$(mktemp)"
printf '%s\n' owner_pw >"${migration_password_file}"
printf '%s\n' reader_pw >"${reader_password_file}"

owner_psql() {
  docker exec -i \
    -e PGPASSWORD=owner_pw \
    -e PGSSLMODE=verify-full \
    -e PGSSLROOTCERT=/rss-tls/ca.pem \
    "${container}" \
    psql -X --no-password -h 127.0.0.1 -U postgres -d "${database}" "$@"
}

cleanup() {
  rm -f "${migration_password_file}"
  rm -f "${reader_password_file}"
  rm -rf "${tls_dir}"
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker volume rm "${volume}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

RSS_DEMO_TLS_OUT="${tls_dir}" RSS_DEMO_TLS_FORCE=1 \
  bash "${repo_root}/deploy/demo-tls/generate-demo-cas.sh" >/dev/null

docker volume create "${volume}" >/dev/null
docker run -d --name "${container}" \
  -e POSTGRES_DB="${database}" \
  -e POSTGRES_PASSWORD=owner_pw \
  -p "127.0.0.1:${port}:5432" \
  -v "${volume}:/var/lib/postgresql/data" \
  -v "${tls_dir}/postgres:/rss-tls:ro" \
  -v "${tls_dir}/postgres/00-require-tls.sh:/docker-entrypoint-initdb.d/00-require-tls.sh:ro" \
  --entrypoint /rss-tls/start-postgres.sh \
  postgres:16.4-alpine >/dev/null

deadline=$((SECONDS + 90))
while ! owner_psql -c 'SELECT 1' >/dev/null 2>&1; do
  if [[ "$(docker inspect -f '{{.State.Running}}' "${container}" 2>/dev/null || true)" != "true" ]]; then
    echo "postgres upgrade-smoke container exited before readiness" >&2
    docker logs --tail 80 "${container}" >&2 || true
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    echo "postgres upgrade-smoke readiness timed out after 90 seconds" >&2
    docker logs --tail 80 "${container}" >&2 || true
    exit 1
  fi
  sleep 1
done

# The ignored integration harness is predecessor-only: SQLx creates the authentic 0001..0066
# ledger/checksums under its normal migration lock, then writes retained data and ACL drift.
RSS_TEST_ALLOW_EXTERNAL_POSTGRES=1 \
PGHOST=127.0.0.1 \
PGPORT="${port}" \
PGDATABASE="${database}" \
PGUSER=postgres \
PGPASSWORD=owner_pw \
PGSSLMODE=verify-full \
PGSSLROOTCERT="${tls_dir}/postgres/ca.pem" \
  "${repo_root}/hack/cargo.sh" test -p postgres --features integration \
    integration_tests::bootstrap_reader_upgrade_smoke_predecessor -- \
    --ignored --exact --nocapture

# Exercise the release binary entrypoint. Direct SQL replay here would bypass the exact-edge guard
# and SQLx ledger/checksum/advisory-lock semantics that this smoke exists to prove.
RSS_PG_HOST=127.0.0.1 \
RSS_PG_PORT="${port}" \
RSS_PG_DATABASE="${database}" \
RSS_PG_MIGRATOR_USERNAME=postgres \
RSS_PG_MIGRATOR_PASSWORD_FILE="${migration_password_file}" \
RSS_PG_SSL_ROOT_CERT_PATH="${tls_dir}/postgres/ca.pem" \
  "${repo_root}/hack/cargo.sh" run --quiet -p rss --bin rss -- \
    postgres migrate-all

RSS_PG_HOST=127.0.0.1 \
RSS_PG_PORT=5432 \
RSS_PG_DATABASE="${database}" \
RSS_PG_MIGRATOR_USERNAME=postgres \
RSS_PG_MIGRATOR_PASSWORD_FILE="${migration_password_file}" \
RSS_PG_READ_USERNAME=rss_app_read \
RSS_PG_READ_PASSWORD_FILE="${reader_password_file}" \
PSQL_CONTAINER="${container}" \
PGSSLMODE=verify-full \
PGSSLROOTCERT=/rss-tls/ca.pem \
  "${repo_root}/deploy/postgres-upgrade/provision-reader-role.sh"

marker="$(owner_psql -Atqc 'SELECT value FROM upgrade_reader_smoke_marker')"
[[ "${marker}" == "retained" ]]
column_update="$(owner_psql -Atqc "SELECT has_column_privilege('rss_app_read', 'sessions', 'subject', 'UPDATE')")"
[[ "${column_update}" == "f" ]]
ledger="$(owner_psql -Atqc "SELECT version || ':' || success || ':' || octet_length(checksum) FROM _sqlx_migrations WHERE version = 67")"
[[ "${ledger}" == "67:true:48" || "${ledger}" == "67:t:48" ]]
echo "retained-volume reader upgrade smoke passed"
