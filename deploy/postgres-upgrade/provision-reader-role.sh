#!/usr/bin/env bash
# Post-migration credential provisioning for an existing PostgreSQL cluster.
# Secrets are imported inside psql with \getenv, so they never appear in argv or SQL files.
set +x
set -euo pipefail

: "${RSS_PG_HOST:?missing RSS_PG_HOST}"
: "${RSS_PG_PORT:?missing RSS_PG_PORT}"
: "${RSS_PG_DATABASE:?missing RSS_PG_DATABASE}"
: "${RSS_PG_MIGRATOR_USERNAME:?missing RSS_PG_MIGRATOR_USERNAME}"
: "${RSS_PG_MIGRATOR_PASSWORD_FILE:?missing RSS_PG_MIGRATOR_PASSWORD_FILE}"
: "${RSS_PG_READ_USERNAME:?missing RSS_PG_READ_USERNAME}"
: "${RSS_PG_READ_PASSWORD_FILE:?missing RSS_PG_READ_PASSWORD_FILE}"

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

migrator_password="$(read_secret_file "${RSS_PG_MIGRATOR_PASSWORD_FILE}")"
reader_password="$(read_secret_file "${RSS_PG_READ_PASSWORD_FILE}")"

if [[ "${RSS_PG_READ_USERNAME}" != "rss_app_read" ]]; then
  echo "RSS_PG_READ_USERNAME must be exactly rss_app_read" >&2
  exit 1
fi

PSQL_BIN="${PSQL_BIN:-psql}"
run_psql() {
  if [[ -n "${PSQL_CONTAINER:-}" ]]; then
    docker exec -i \
      -e PGPASSWORD \
      -e RSS_PROVISION_READER_PASSWORD \
      "${PSQL_CONTAINER}" psql "$@"
  else
    "${PSQL_BIN}" "$@"
  fi
}
export PGPASSWORD="${migrator_password}"
export RSS_PROVISION_READER_PASSWORD="${reader_password}"

run_psql -X --no-password --set ON_ERROR_STOP=1 \
  --host "${RSS_PG_HOST}" \
  --port "${RSS_PG_PORT}" \
  --username "${RSS_PG_MIGRATOR_USERNAME}" \
  --dbname "${RSS_PG_DATABASE}" <<'EOSQL'
\getenv reader_password RSS_PROVISION_READER_PASSWORD

DO $$
DECLARE
    reader_oid oid;
BEGIN
    SELECT oid INTO reader_oid FROM pg_roles WHERE rolname = 'rss_app_read';
    IF reader_oid IS NULL THEN
        RAISE EXCEPTION 'rss_app_read is absent; apply migration 0067 before provisioning credentials';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
        WHERE roleid = reader_oid OR member = reader_oid
    ) THEN
        RAISE EXCEPTION 'rss_app_read has role membership; refuse credential provisioning';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_shdepend
        WHERE refclassid = 'pg_authid'::regclass
          AND refobjid = reader_oid
          AND deptype = 'o'
    ) THEN
        RAISE EXCEPTION 'rss_app_read owns database objects; refuse credential provisioning';
    END IF;
END
$$;

SELECT format(
    'ALTER ROLE rss_app_read LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
    :'reader_password'
) \gexec
ALTER ROLE rss_app_read RESET ALL;
ALTER ROLE rss_app_read SET default_transaction_read_only = 'on';
ALTER ROLE rss_app_read SET search_path = pg_catalog, public;
EOSQL

unset PGPASSWORD
unset RSS_PROVISION_READER_PASSWORD
export PGPASSWORD="${reader_password}"
readonly_state="$(run_psql -X --no-password --tuples-only --no-align \
  --host "${RSS_PG_HOST}" \
  --port "${RSS_PG_PORT}" \
  --username rss_app_read \
  --dbname "${RSS_PG_DATABASE}" \
  --command "SELECT current_user || ':' || current_setting('transaction_read_only') || ':' || current_setting('search_path') || ':' || current_setting('lo_compat_privileges')")"
unset PGPASSWORD

if [[ "${readonly_state}" != "rss_app_read:on:pg_catalog, public:off" ]]; then
  echo "rss_app_read credential preflight failed" >&2
  exit 1
fi
echo "rss_app_read credential provisioning verified"
