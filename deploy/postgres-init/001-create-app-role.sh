#!/usr/bin/env bash
# Create the demo serving role used by server. The role is intentionally not a
# superuser and does not have BYPASSRLS; runtime startup must fail if that stops
# being true.
set +x
set -euo pipefail

: "${POSTGRES_DB:?missing POSTGRES_DB}"
: "${POSTGRES_USER:?missing POSTGRES_USER}"
: "${POSTGRES_APP_USER:?missing POSTGRES_APP_USER}"
: "${RSS_PG_READ_USERNAME:?missing RSS_PG_READ_USERNAME}"
: "${RSS_PG_PASSWORD_FILE:?missing RSS_PG_PASSWORD_FILE}"
: "${RSS_PG_READ_PASSWORD_FILE:?missing RSS_PG_READ_PASSWORD_FILE}"
: "${RSS_PG_PROJECTION_READER_USERNAME:?missing RSS_PG_PROJECTION_READER_USERNAME}"
: "${RSS_PG_PROJECTION_READER_PASSWORD_FILE:?missing RSS_PG_PROJECTION_READER_PASSWORD_FILE}"
: "${RSS_PG_PROJECTION_OPERATOR_USERNAME:?missing RSS_PG_PROJECTION_OPERATOR_USERNAME}"
: "${RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE:?missing RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE}"
: "${RSS_PG_SAGA_OPERATOR_USERNAME:?missing RSS_PG_SAGA_OPERATOR_USERNAME}"
: "${RSS_PG_SAGA_OPERATOR_PASSWORD_FILE:?missing RSS_PG_SAGA_OPERATOR_PASSWORD_FILE}"
: "${RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME:?missing RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME}"
: "${RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE:?missing RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE}"
: "${RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME:?missing RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME}"
: "${RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE:?missing RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE}"
: "${RSS_PG_DLX_ARCHIVER_USERNAME:?missing RSS_PG_DLX_ARCHIVER_USERNAME}"
: "${RSS_PG_DLX_ARCHIVER_PASSWORD_FILE:?missing RSS_PG_DLX_ARCHIVER_PASSWORD_FILE}"
: "${RSS_PG_DLX_VERIFIER_USERNAME:?missing RSS_PG_DLX_VERIFIER_USERNAME}"
: "${RSS_PG_DLX_VERIFIER_PASSWORD_FILE:?missing RSS_PG_DLX_VERIFIER_PASSWORD_FILE}"
: "${RSS_PG_DLX_PURGER_USERNAME:?missing RSS_PG_DLX_PURGER_USERNAME}"
: "${RSS_PG_DLX_PURGER_PASSWORD_FILE:?missing RSS_PG_DLX_PURGER_PASSWORD_FILE}"

if [[ "${RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE}" == "${RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE}" ]]; then
  echo "L2 DR auditor and executor password files must be distinct" >&2
  exit 1
fi

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

RSS_INIT_APP_PASSWORD="$(read_secret_file "${RSS_PG_PASSWORD_FILE}")"
RSS_INIT_READ_PASSWORD="$(read_secret_file "${RSS_PG_READ_PASSWORD_FILE}")"
RSS_INIT_PROJECTION_READER_PASSWORD="$(read_secret_file "${RSS_PG_PROJECTION_READER_PASSWORD_FILE}")"
RSS_INIT_PROJECTION_OPERATOR_PASSWORD="$(read_secret_file "${RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE}")"
RSS_INIT_SAGA_OPERATOR_PASSWORD="$(read_secret_file "${RSS_PG_SAGA_OPERATOR_PASSWORD_FILE}")"
RSS_INIT_L2_DR_RECOVERY_AUDITOR_PASSWORD="$(read_secret_file "${RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE}")"
RSS_INIT_L2_DR_RECOVERY_EXECUTOR_PASSWORD="$(read_secret_file "${RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE}")"
if [[ "${RSS_INIT_L2_DR_RECOVERY_AUDITOR_PASSWORD}" == "${RSS_INIT_L2_DR_RECOVERY_EXECUTOR_PASSWORD}" ]]; then
  echo "L2 DR auditor and executor passwords must be distinct" >&2
  exit 1
fi
RSS_INIT_DLX_ARCHIVER_PASSWORD="$(read_secret_file "${RSS_PG_DLX_ARCHIVER_PASSWORD_FILE}")"
RSS_INIT_DLX_VERIFIER_PASSWORD="$(read_secret_file "${RSS_PG_DLX_VERIFIER_PASSWORD_FILE}")"
RSS_INIT_DLX_PURGER_PASSWORD="$(read_secret_file "${RSS_PG_DLX_PURGER_PASSWORD_FILE}")"
export RSS_INIT_APP_PASSWORD RSS_INIT_READ_PASSWORD RSS_INIT_DLX_ARCHIVER_PASSWORD
export RSS_INIT_DLX_VERIFIER_PASSWORD RSS_INIT_DLX_PURGER_PASSWORD
export RSS_INIT_PROJECTION_READER_PASSWORD RSS_INIT_PROJECTION_OPERATOR_PASSWORD
export RSS_INIT_SAGA_OPERATOR_PASSWORD
export RSS_INIT_L2_DR_RECOVERY_AUDITOR_PASSWORD RSS_INIT_L2_DR_RECOVERY_EXECUTOR_PASSWORD
clear_init_passwords() {
  unset RSS_INIT_APP_PASSWORD RSS_INIT_READ_PASSWORD RSS_INIT_DLX_ARCHIVER_PASSWORD
  unset RSS_INIT_DLX_VERIFIER_PASSWORD RSS_INIT_DLX_PURGER_PASSWORD
  unset RSS_INIT_PROJECTION_READER_PASSWORD RSS_INIT_PROJECTION_OPERATOR_PASSWORD
  unset RSS_INIT_SAGA_OPERATOR_PASSWORD
  unset RSS_INIT_L2_DR_RECOVERY_AUDITOR_PASSWORD RSS_INIT_L2_DR_RECOVERY_EXECUTOR_PASSWORD
}
trap clear_init_passwords EXIT

if [[ "$RSS_PG_DLX_ARCHIVER_USERNAME" != "rss_dlx_archiver" ]]; then
  echo "RSS_PG_DLX_ARCHIVER_USERNAME must be exactly rss_dlx_archiver" >&2
  exit 1
fi
if [[ "$POSTGRES_APP_USER" != "rss_app" ]]; then
  echo "POSTGRES_APP_USER must be exactly rss_app" >&2
  exit 1
fi
if [[ "$RSS_PG_READ_USERNAME" != "rss_app_read" ]]; then
  echo "RSS_PG_READ_USERNAME must be exactly rss_app_read" >&2
  exit 1
fi
if [[ "$RSS_PG_PROJECTION_READER_USERNAME" != "rss_projection_reader" ]]; then
  echo "RSS_PG_PROJECTION_READER_USERNAME must be exactly rss_projection_reader" >&2
  exit 1
fi
if [[ "$RSS_PG_PROJECTION_OPERATOR_USERNAME" != "rss_projection_operator" ]]; then
  echo "RSS_PG_PROJECTION_OPERATOR_USERNAME must be exactly rss_projection_operator" >&2
  exit 1
fi
if [[ "$RSS_PG_SAGA_OPERATOR_USERNAME" != "rss_saga_operator" ]]; then
  echo "RSS_PG_SAGA_OPERATOR_USERNAME must be exactly rss_saga_operator" >&2
  exit 1
fi
if [[ "$RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME" != "rss_l2_dr_recovery_auditor" ]]; then
  echo "RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME must be exactly rss_l2_dr_recovery_auditor" >&2
  exit 1
fi
if [[ "$RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME" != "rss_l2_dr_recovery_executor" ]]; then
  echo "RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME must be exactly rss_l2_dr_recovery_executor" >&2
  exit 1
fi
if [[ "$RSS_PG_DLX_VERIFIER_USERNAME" != "rss_dlx_verifier" ]]; then
  echo "RSS_PG_DLX_VERIFIER_USERNAME must be exactly rss_dlx_verifier" >&2
  exit 1
fi
if [[ "$RSS_PG_DLX_PURGER_USERNAME" != "rss_dlx_purger" ]]; then
  echo "RSS_PG_DLX_PURGER_USERNAME must be exactly rss_dlx_purger" >&2
  exit 1
fi

psql \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set app_user="$POSTGRES_APP_USER" \
  --set db_name="$POSTGRES_DB" <<'EOSQL'

\getenv app_password RSS_INIT_APP_PASSWORD
\getenv read_password RSS_INIT_READ_PASSWORD
\getenv projection_reader_password RSS_INIT_PROJECTION_READER_PASSWORD
\getenv projection_operator_password RSS_INIT_PROJECTION_OPERATOR_PASSWORD
\getenv saga_operator_password RSS_INIT_SAGA_OPERATOR_PASSWORD
\getenv l2_dr_recovery_auditor_password RSS_INIT_L2_DR_RECOVERY_AUDITOR_PASSWORD
\getenv l2_dr_recovery_executor_password RSS_INIT_L2_DR_RECOVERY_EXECUTOR_PASSWORD
\getenv dlx_archiver_password RSS_INIT_DLX_ARCHIVER_PASSWORD
\getenv dlx_verifier_password RSS_INIT_DLX_VERIFIER_PASSWORD
\getenv dlx_purger_password RSS_INIT_DLX_PURGER_PASSWORD

SELECT format(
  'CREATE ROLE rss_app NOLOGIN NOBYPASSRLS'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app')\gexec

SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L NOBYPASSRLS',
  :'app_user',
  :'app_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'app_user')\gexec

SELECT format(
  'ALTER ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'app_user',
  :'app_password'
)\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'db_name', :'app_user')\gexec
SELECT format('GRANT rss_app TO %I', :'app_user')
WHERE :'app_user' <> 'rss_app'\gexec

SELECT format(
  'CREATE ROLE rss_app_read LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'read_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app_read')\gexec

SELECT format(
  'ALTER ROLE rss_app_read LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'read_password'
)\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO rss_app_read', :'db_name')\gexec

SELECT format(
  'CREATE ROLE rss_projection_reader LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'projection_reader_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_projection_reader')\gexec
SELECT format(
  'ALTER ROLE rss_projection_reader LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'projection_reader_password'
)\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO rss_projection_reader', :'db_name')\gexec

SELECT format(
  'CREATE ROLE rss_projection_operator LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'projection_operator_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_projection_operator')\gexec
SELECT format(
  'ALTER ROLE rss_projection_operator LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'projection_operator_password'
)\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO rss_projection_operator', :'db_name')\gexec

SELECT format(
  'CREATE ROLE rss_saga_operator LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'saga_operator_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_saga_operator')\gexec
SELECT format(
  'ALTER ROLE rss_saga_operator LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'saga_operator_password'
)\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO rss_saga_operator', :'db_name')\gexec

SELECT format(
  'CREATE ROLE rss_l2_dr_recovery_auditor LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'l2_dr_recovery_auditor_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_l2_dr_recovery_auditor')\gexec
SELECT format(
  'ALTER ROLE rss_l2_dr_recovery_auditor LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'l2_dr_recovery_auditor_password'
)\gexec
ALTER ROLE rss_l2_dr_recovery_auditor RESET ALL;
ALTER ROLE rss_l2_dr_recovery_auditor SET search_path = pg_catalog, public;
SELECT format('GRANT CONNECT ON DATABASE %I TO rss_l2_dr_recovery_auditor', :'db_name')\gexec

SELECT format(
  'CREATE ROLE rss_l2_dr_recovery_executor LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'l2_dr_recovery_executor_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_l2_dr_recovery_executor')\gexec
SELECT format(
  'ALTER ROLE rss_l2_dr_recovery_executor LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
  :'l2_dr_recovery_executor_password'
)\gexec
ALTER ROLE rss_l2_dr_recovery_executor RESET ALL;
ALTER ROLE rss_l2_dr_recovery_executor SET search_path = pg_catalog, public;
SELECT format('GRANT CONNECT ON DATABASE %I TO rss_l2_dr_recovery_executor', :'db_name')\gexec

SELECT format(
  'CREATE ROLE rss_dlx_archiver LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'dlx_archiver_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_dlx_archiver')\gexec

SELECT format(
  'ALTER ROLE rss_dlx_archiver LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'dlx_archiver_password'
)\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO rss_dlx_archiver', :'db_name')\gexec

SELECT format(
  'CREATE ROLE rss_dlx_verifier LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'dlx_verifier_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_dlx_verifier')\gexec
SELECT format(
  'ALTER ROLE rss_dlx_verifier LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'dlx_verifier_password'
)\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO rss_dlx_verifier', :'db_name')\gexec

SELECT format(
  'CREATE ROLE rss_dlx_purger LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'dlx_purger_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_dlx_purger')\gexec
SELECT format(
  'ALTER ROLE rss_dlx_purger LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'dlx_purger_password'
)\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO rss_dlx_purger', :'db_name')\gexec
EOSQL

clear_init_passwords
trap - EXIT
