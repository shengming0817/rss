#!/usr/bin/env bash
# Post-0085 credential provisioning/rotation for retained PostgreSQL clusters.
# Secrets enter psql through \getenv and never appear in argv or generated SQL files.
set +x
set -euo pipefail

: "${RSS_PG_HOST:?missing RSS_PG_HOST}"
: "${RSS_PG_PORT:?missing RSS_PG_PORT}"
: "${RSS_PG_DATABASE:?missing RSS_PG_DATABASE}"
: "${RSS_PG_MIGRATOR_USERNAME:?missing RSS_PG_MIGRATOR_USERNAME}"
: "${RSS_PG_MIGRATOR_PASSWORD_FILE:?missing RSS_PG_MIGRATOR_PASSWORD_FILE}"
: "${RSS_PG_PROJECTION_READER_USERNAME:?missing RSS_PG_PROJECTION_READER_USERNAME}"
: "${RSS_PG_PROJECTION_READER_PASSWORD_FILE:?missing RSS_PG_PROJECTION_READER_PASSWORD_FILE}"
: "${RSS_PG_PROJECTION_OPERATOR_USERNAME:?missing RSS_PG_PROJECTION_OPERATOR_USERNAME}"
: "${RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE:?missing RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE}"

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

[[ "${RSS_PG_PROJECTION_READER_USERNAME}" == "rss_projection_reader" ]] || {
  echo "RSS_PG_PROJECTION_READER_USERNAME must be exactly rss_projection_reader" >&2
  exit 1
}
[[ "${RSS_PG_PROJECTION_OPERATOR_USERNAME}" == "rss_projection_operator" ]] || {
  echo "RSS_PG_PROJECTION_OPERATOR_USERNAME must be exactly rss_projection_operator" >&2
  exit 1
}

migrator_password="$(read_secret_file "${RSS_PG_MIGRATOR_PASSWORD_FILE}")"
reader_password="$(read_secret_file "${RSS_PG_PROJECTION_READER_PASSWORD_FILE}")"
operator_password="$(read_secret_file "${RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE}")"

PSQL_BIN="${PSQL_BIN:-psql}"
run_psql() {
  if [[ -n "${PSQL_CONTAINER:-}" ]]; then
    docker exec -i \
      -e PGPASSWORD \
      -e RSS_PROVISION_PROJECTION_READER_PASSWORD \
      -e RSS_PROVISION_PROJECTION_OPERATOR_PASSWORD \
      -e PGSSLMODE \
      -e PGSSLROOTCERT \
      "${PSQL_CONTAINER}" psql "$@"
  else
    "${PSQL_BIN}" "$@"
  fi
}
if [[ -n "${PSQL_CONTAINER:-}" ]]; then
  export PGSSLMODE="${PGSSLMODE:-verify-full}"
  export PGSSLROOTCERT="${PGSSLROOTCERT:-/rss-tls/ca.pem}"
fi

export PGPASSWORD="${migrator_password}"
export RSS_PROVISION_PROJECTION_READER_PASSWORD="${reader_password}"
export RSS_PROVISION_PROJECTION_OPERATOR_PASSWORD="${operator_password}"

run_psql -X --no-password --set ON_ERROR_STOP=1 \
  --host "${RSS_PG_HOST}" \
  --port "${RSS_PG_PORT}" \
  --username "${RSS_PG_MIGRATOR_USERNAME}" \
  --dbname "${RSS_PG_DATABASE}" <<'EOSQL'
\getenv projection_reader_password RSS_PROVISION_PROJECTION_READER_PASSWORD
\getenv projection_operator_password RSS_PROVISION_PROJECTION_OPERATOR_PASSWORD

BEGIN;
DO $$
DECLARE
    role_name text;
    role_oid oid;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['rss_projection_reader', 'rss_projection_operator']
    LOOP
        SELECT oid INTO role_oid FROM pg_catalog.pg_roles WHERE rolname = role_name;
        IF role_oid IS NULL THEN
            RAISE EXCEPTION '% is absent; apply migration 0085 before provisioning credentials',
                role_name;
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_auth_members
            WHERE roleid = role_oid OR member = role_oid
        ) THEN
            RAISE EXCEPTION '% has role membership; refuse credential provisioning', role_name;
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_shdepend
            WHERE refclassid = 'pg_authid'::regclass
              AND refobjid = role_oid
              AND deptype = 'o'
        ) THEN
            RAISE EXCEPTION '% owns database objects; refuse credential provisioning', role_name;
        END IF;
    END LOOP;
END
$$;

SELECT pg_catalog.format(
    'ALTER ROLE rss_projection_reader LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
    :'projection_reader_password'
) \gexec
ALTER ROLE rss_projection_reader RESET ALL;
ALTER ROLE rss_projection_reader SET default_transaction_read_only = 'on';
ALTER ROLE rss_projection_reader SET search_path = pg_catalog, public;

SELECT pg_catalog.format(
    'ALTER ROLE rss_projection_operator LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
    :'projection_operator_password'
) \gexec
ALTER ROLE rss_projection_operator RESET ALL;
ALTER ROLE rss_projection_operator SET search_path = pg_catalog, public;
COMMIT;
EOSQL

unset PGPASSWORD
unset RSS_PROVISION_PROJECTION_READER_PASSWORD
unset RSS_PROVISION_PROJECTION_OPERATOR_PASSWORD

verify_role() {
  local role="$1"
  local password="$2"
  local expected="$3"
  export PGPASSWORD="${password}"
  local actual
  actual="$(run_psql -X --no-password --tuples-only --no-align \
    --host "${RSS_PG_HOST}" \
    --port "${RSS_PG_PORT}" \
    --username "${role}" \
    --dbname "${RSS_PG_DATABASE}" \
    --command "SELECT current_user || ':' || current_setting('transaction_read_only') || ':' || current_setting('search_path') || ':' || current_setting('lo_compat_privileges')")"
  unset PGPASSWORD
  [[ "${actual}" == "${expected}" ]] || {
    echo "${role} credential preflight failed" >&2
    exit 1
  }
}

verify_role rss_projection_reader "${reader_password}" \
  "rss_projection_reader:on:pg_catalog, public:off"
verify_role rss_projection_operator "${operator_password}" \
  "rss_projection_operator:off:pg_catalog, public:off"

echo "Projection reader/operator credential provisioning verified"
