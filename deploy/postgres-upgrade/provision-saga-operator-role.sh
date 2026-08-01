#!/usr/bin/env bash
# Post-0088 credential provisioning/rotation for retained PostgreSQL clusters.
# The password enters psql through \getenv and never appears in argv or generated SQL files.
set +x
set -euo pipefail

: "${RSS_PG_HOST:?missing RSS_PG_HOST}"
: "${RSS_PG_PORT:?missing RSS_PG_PORT}"
: "${RSS_PG_DATABASE:?missing RSS_PG_DATABASE}"
: "${RSS_PG_MIGRATOR_USERNAME:?missing RSS_PG_MIGRATOR_USERNAME}"
: "${RSS_PG_MIGRATOR_PASSWORD_FILE:?missing RSS_PG_MIGRATOR_PASSWORD_FILE}"
: "${RSS_PG_SAGA_OPERATOR_USERNAME:?missing RSS_PG_SAGA_OPERATOR_USERNAME}"
: "${RSS_PG_SAGA_OPERATOR_PASSWORD_FILE:?missing RSS_PG_SAGA_OPERATOR_PASSWORD_FILE}"

read_secret_file() {
  local path="$1"
  [[ "${path}" == /* && "${path}" != *"/../"* && -r "${path}" ]] || {
    echo "invalid PostgreSQL password file reference" >&2
    exit 1
  }
  local value
  value="$(<"${path}")"
  [[ -n "${value}" ]] || {
    echo "empty PostgreSQL password file" >&2
    exit 1
  }
  printf '%s' "${value}"
}

[[ "${RSS_PG_SAGA_OPERATOR_USERNAME}" == "rss_saga_operator" ]] || {
  echo "RSS_PG_SAGA_OPERATOR_USERNAME must be exactly rss_saga_operator" >&2
  exit 1
}

migrator_password="$(read_secret_file "${RSS_PG_MIGRATOR_PASSWORD_FILE}")"
saga_operator_password="$(read_secret_file "${RSS_PG_SAGA_OPERATOR_PASSWORD_FILE}")"

PSQL_BIN="${PSQL_BIN:-psql}"
run_psql() {
  if [[ -n "${PSQL_CONTAINER:-}" ]]; then
    docker exec -i -e PGPASSWORD -e RSS_PROVISION_SAGA_OPERATOR_PASSWORD \
      -e PGSSLMODE -e PGSSLROOTCERT "${PSQL_CONTAINER}" psql "$@"
  else
    "${PSQL_BIN}" "$@"
  fi
}
if [[ -n "${PSQL_CONTAINER:-}" ]]; then
  export PGSSLMODE="${PGSSLMODE:-verify-full}"
  export PGSSLROOTCERT="${PGSSLROOTCERT:-/rss-tls/ca.pem}"
fi

export PGPASSWORD="${migrator_password}"
export RSS_PROVISION_SAGA_OPERATOR_PASSWORD="${saga_operator_password}"
run_psql -X --no-password --set ON_ERROR_STOP=1 \
  --host "${RSS_PG_HOST}" --port "${RSS_PG_PORT}" \
  --username "${RSS_PG_MIGRATOR_USERNAME}" --dbname "${RSS_PG_DATABASE}" <<'EOSQL'
\getenv saga_operator_password RSS_PROVISION_SAGA_OPERATOR_PASSWORD
BEGIN;
DO $$
DECLARE role_oid oid;
BEGIN
    SELECT oid INTO role_oid FROM pg_catalog.pg_roles WHERE rolname = 'rss_saga_operator';
    IF role_oid IS NULL THEN
        RAISE EXCEPTION 'rss_saga_operator is absent; apply migration 0088 first';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members
        WHERE roleid = role_oid OR member = role_oid
    ) THEN
        RAISE EXCEPTION 'rss_saga_operator has role membership';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_shdepend
        WHERE refclassid = 'pg_authid'::regclass AND refobjid = role_oid AND deptype = 'o'
    ) THEN
        RAISE EXCEPTION 'rss_saga_operator owns database objects';
    END IF;
END
$$;
SELECT pg_catalog.format(
    'ALTER ROLE rss_saga_operator LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
    :'saga_operator_password'
) \gexec
ALTER ROLE rss_saga_operator RESET ALL;
ALTER ROLE rss_saga_operator SET search_path = pg_catalog, public;
SELECT pg_catalog.format(
    'GRANT CONNECT ON DATABASE %I TO rss_saga_operator',
    current_database()
) \gexec
COMMIT;
EOSQL

unset PGPASSWORD RSS_PROVISION_SAGA_OPERATOR_PASSWORD
export PGPASSWORD="${saga_operator_password}"
actual="$(run_psql -X --no-password --tuples-only --no-align \
  --host "${RSS_PG_HOST}" --port "${RSS_PG_PORT}" \
  --username rss_saga_operator --dbname "${RSS_PG_DATABASE}" \
  --command "SELECT current_user || ':' || current_setting('transaction_read_only') || ':' || current_setting('search_path') || ':' || current_setting('lo_compat_privileges')")"
unset PGPASSWORD
[[ "${actual}" == "rss_saga_operator:off:pg_catalog, public:off" ]] || {
  echo "rss_saga_operator credential postflight failed" >&2
  exit 1
}
echo "Saga operator credential provisioning verified"
