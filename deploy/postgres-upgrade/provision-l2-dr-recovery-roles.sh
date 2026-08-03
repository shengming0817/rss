#!/bin/sh
# Post-0098 credential provisioning/rotation for the two fixed L2 DR lanes.
# Passwords enter psql only through environment-backed \getenv and never through argv or SQL files.
set +x
set -eu

: "${RSS_PG_HOST:?missing RSS_PG_HOST}"
: "${RSS_PG_PORT:?missing RSS_PG_PORT}"
: "${RSS_PG_DATABASE:?missing RSS_PG_DATABASE}"
: "${RSS_PG_MIGRATOR_USERNAME:?missing RSS_PG_MIGRATOR_USERNAME}"
: "${RSS_PG_MIGRATOR_PASSWORD_FILE:?missing RSS_PG_MIGRATOR_PASSWORD_FILE}"
: "${RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME:?missing RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME}"
: "${RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE:?missing RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE}"
: "${RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME:?missing RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME}"
: "${RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE:?missing RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE}"

forbidden_credential_env=""
[ "${RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD+x}" = x ] && forbidden_credential_env="plaintext auditor password"
[ "${RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD+x}" = x ] && forbidden_credential_env="plaintext executor password"
[ "${RSS_PG_L2_DR_RECOVERY_OPERATOR_USERNAME+x}" = x ] && forbidden_credential_env="legacy operator username"
[ "${RSS_PG_L2_DR_RECOVERY_OPERATOR_PASSWORD+x}" = x ] && forbidden_credential_env="legacy operator password"
[ "${RSS_PG_L2_DR_RECOVERY_OPERATOR_PASSWORD_FILE+x}" = x ] && forbidden_credential_env="legacy operator password file"
if [ -n "${forbidden_credential_env}" ]; then
  echo "plaintext and legacy L2 DR credential environment is forbidden" >&2
  exit 1
fi

if [ "${RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME}" != "rss_l2_dr_recovery_auditor" ]; then
  echo "RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME must be exactly rss_l2_dr_recovery_auditor" >&2
  exit 1
fi
if [ "${RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME}" != "rss_l2_dr_recovery_executor" ]; then
  echo "RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME must be exactly rss_l2_dr_recovery_executor" >&2
  exit 1
fi
if [ "${RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE}" = "${RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE}" ]; then
  echo "L2 DR auditor and executor password files must be distinct" >&2
  exit 1
fi

read_secret_file() {
  secret_path="$1"
  case "${secret_path}" in
    /*/../*|/*/..|/*) ;;
    *)
      echo "invalid PostgreSQL password file reference" >&2
      exit 1
      ;;
  esac
  case "${secret_path}" in
    /*/../*|/*/..)
      echo "invalid PostgreSQL password file reference" >&2
      exit 1
      ;;
  esac
  if [ ! -r "${secret_path}" ]; then
    echo "invalid PostgreSQL password file reference" >&2
    exit 1
  fi
  secret_value="$(cat "${secret_path}")"
  if [ -z "${secret_value}" ]; then
    echo "empty PostgreSQL password file" >&2
    exit 1
  fi
  printf '%s' "${secret_value}"
}

migrator_password="$(read_secret_file "${RSS_PG_MIGRATOR_PASSWORD_FILE}")"
auditor_password="$(read_secret_file "${RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE}")"
executor_password="$(read_secret_file "${RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE}")"
if [ "${auditor_password}" = "${executor_password}" ]; then
  echo "L2 DR auditor and executor passwords must be distinct" >&2
  exit 1
fi

clear_passwords() {
  unset PGPASSWORD RSS_PROVISION_L2_DR_RECOVERY_AUDITOR_PASSWORD
  unset RSS_PROVISION_L2_DR_RECOVERY_EXECUTOR_PASSWORD
  unset migrator_password auditor_password executor_password secret_value verify_password
}
trap clear_passwords EXIT HUP INT TERM

PSQL_BIN="${PSQL_BIN:-psql}"
run_psql() {
  if [ -n "${PSQL_CONTAINER:-}" ]; then
    docker exec -i \
      -e PGPASSWORD \
      -e RSS_PROVISION_L2_DR_RECOVERY_AUDITOR_PASSWORD \
      -e RSS_PROVISION_L2_DR_RECOVERY_EXECUTOR_PASSWORD \
      -e PGSSLMODE \
      -e PGSSLROOTCERT \
      "${PSQL_CONTAINER}" psql "$@"
  else
    "${PSQL_BIN}" "$@"
  fi
}
if [ -n "${PSQL_CONTAINER:-}" ]; then
  export PGSSLMODE="${PGSSLMODE:-verify-full}"
  export PGSSLROOTCERT="${PGSSLROOTCERT:-/rss-tls/ca.pem}"
fi

export PGPASSWORD="${migrator_password}"
export RSS_PROVISION_L2_DR_RECOVERY_AUDITOR_PASSWORD="${auditor_password}"
export RSS_PROVISION_L2_DR_RECOVERY_EXECUTOR_PASSWORD="${executor_password}"
run_psql -X --no-password --set ON_ERROR_STOP=1 \
  --host "${RSS_PG_HOST}" \
  --port "${RSS_PG_PORT}" \
  --username "${RSS_PG_MIGRATOR_USERNAME}" \
  --dbname "${RSS_PG_DATABASE}" <<'EOSQL'
\getenv l2_dr_recovery_auditor_password RSS_PROVISION_L2_DR_RECOVERY_AUDITOR_PASSWORD
\getenv l2_dr_recovery_executor_password RSS_PROVISION_L2_DR_RECOVERY_EXECUTOR_PASSWORD

BEGIN;
DO $$
DECLARE
    role_name text;
    role_oid oid;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'rss_l2_dr_recovery_auditor',
        'rss_l2_dr_recovery_executor'
    ] LOOP
        SELECT oid INTO role_oid
        FROM pg_catalog.pg_roles
        WHERE rolname = role_name;
        IF role_oid IS NULL THEN
            RAISE EXCEPTION '% is absent; apply migration 0100 before provisioning credentials',
                role_name;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members
            WHERE roleid = role_oid OR member = role_oid
        ) THEN
            RAISE EXCEPTION '% has role membership; refuse credential provisioning', role_name;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.pg_shdepend
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
    'ALTER ROLE rss_l2_dr_recovery_auditor LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
    :'l2_dr_recovery_auditor_password'
) \gexec
ALTER ROLE rss_l2_dr_recovery_auditor RESET ALL;
ALTER ROLE rss_l2_dr_recovery_auditor SET search_path = pg_catalog, public;
SELECT pg_catalog.format(
    'GRANT CONNECT ON DATABASE %I TO rss_l2_dr_recovery_auditor',
    current_database()
) \gexec

SELECT pg_catalog.format(
    'ALTER ROLE rss_l2_dr_recovery_executor LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
    :'l2_dr_recovery_executor_password'
) \gexec
ALTER ROLE rss_l2_dr_recovery_executor RESET ALL;
ALTER ROLE rss_l2_dr_recovery_executor SET search_path = pg_catalog, public;
SELECT pg_catalog.format(
    'GRANT CONNECT ON DATABASE %I TO rss_l2_dr_recovery_executor',
    current_database()
) \gexec
COMMIT;
EOSQL

unset PGPASSWORD RSS_PROVISION_L2_DR_RECOVERY_AUDITOR_PASSWORD
unset RSS_PROVISION_L2_DR_RECOVERY_EXECUTOR_PASSWORD

verify_role() {
  verify_role_name="$1"
  verify_password="$2"
  export PGPASSWORD="${verify_password}"
  actual="$(run_psql -X --no-password --tuples-only --no-align \
    --host "${RSS_PG_HOST}" \
    --port "${RSS_PG_PORT}" \
    --username "${verify_role_name}" \
    --dbname "${RSS_PG_DATABASE}" \
    --command "SELECT current_user || ':' || session_user || ':' || rolcanlogin || ':' || rolsuper || ':' || rolbypassrls || ':' || rolcreatedb || ':' || rolcreaterole || ':' || rolreplication || ':' || rolinherit || ':' || current_setting('transaction_read_only') || ':' || current_setting('search_path') || ':' || current_setting('lo_compat_privileges') FROM pg_catalog.pg_roles WHERE rolname = current_user")"
  unset PGPASSWORD
  expected="${verify_role_name}:${verify_role_name}:true:false:false:false:false:false:false:off:pg_catalog, public:off"
  if [ "${actual}" != "${expected}" ]; then
    echo "${verify_role_name} credential postflight failed" >&2
    exit 1
  fi
}

verify_role rss_l2_dr_recovery_auditor "${auditor_password}"
verify_role rss_l2_dr_recovery_executor "${executor_password}"

clear_passwords
trap - EXIT HUP INT TERM
echo "L2 DR auditor/executor credential provisioning verified"
