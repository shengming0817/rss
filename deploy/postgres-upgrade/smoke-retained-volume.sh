#!/usr/bin/env bash
# Docker-gated upgrade smoke: the nearest ancestor artifact containing 0084 but not 0085 runs its
# real `postgres migrate-all` completion path, including the predecessor generated Projection
# registry. The current release then applies 0085 through HEAD and provisions the serving-reader
# plus Projection, Saga, and split L2 DR credentials through HEAD (0098).
# Postgres serves TLS (VerifyFull + private CA); RSS_PG_SSL_MODE is banned (#1710).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
container="rss-pg-reader-upgrade-${$}"
volume="${container}-data"
port="${RSS_UPGRADE_SMOKE_PORT:-55467}"
database="rss_upgrade_test"
tls_dir="$(mktemp -d "${TMPDIR:-/tmp}/rss-pg-upgrade-tls.XXXXXX")"
migration_password_file="$(mktemp)"
migration_database_url_file="$(mktemp)"
reader_password_file="$(mktemp)"
projection_reader_password_file="$(mktemp)"
projection_operator_password_file="$(mktemp)"
saga_operator_password_file="$(mktemp)"
l2_dr_recovery_auditor_password_file="$(mktemp)"
l2_dr_recovery_executor_password_file="$(mktemp)"
predecessor_source="$(mktemp -d "${TMPDIR:-/tmp}/rss-pg-predecessor.XXXXXX")"
printf '%s\n' owner_pw >"${migration_password_file}"
printf '%s\n' reader_pw >"${reader_password_file}"
printf '%s\n' projection_reader_pw >"${projection_reader_password_file}"
printf '%s\n' projection_operator_pw >"${projection_operator_password_file}"
printf '%s\n' saga_operator_pw >"${saga_operator_password_file}"
printf '%s\n' l2_dr_recovery_auditor_pw >"${l2_dr_recovery_auditor_password_file}"
printf '%s\n' l2_dr_recovery_executor_pw >"${l2_dr_recovery_executor_password_file}"

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
  rm -f "${migration_database_url_file}"
  rm -f "${reader_password_file}"
  rm -f "${projection_reader_password_file}"
  rm -f "${projection_operator_password_file}"
  rm -f "${saga_operator_password_file}"
  rm -f "${l2_dr_recovery_auditor_password_file}"
  rm -f "${l2_dr_recovery_executor_password_file}"
  rm -rf "${predecessor_source}"
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

printf '%s\n' \
  "postgresql://postgres:owner_pw@127.0.0.1:${port}/${database}?sslmode=verify-full&sslrootcert=${tls_dir}/postgres/ca.pem" \
  >"${migration_database_url_file}"

# Select an actual historical artifact, not hand-replayed migration SQL. In this PR's merge-shaped
# history the nearest qualifying ancestor is the current base branch; after landing it is the
# parent commit that first introduced 0085. The 0084 path requirement prevents selecting an older,
# weaker ledger fixture.
predecessor_ref="$(
  while IFS= read -r candidate; do
    if /usr/bin/git -C "${repo_root}" cat-file -e \
         "${candidate}:adapters/postgres/migrations/0084_persist_reconcile_wake_and_device_policy_operations.sql" 2>/dev/null \
       && ! /usr/bin/git -C "${repo_root}" cat-file -e \
         "${candidate}:adapters/postgres/migrations/0085_projection_privilege_boundaries.sql" 2>/dev/null; then
      printf '%s\n' "${candidate}"
      break
    fi
  done < <(/usr/bin/git -C "${repo_root}" rev-list --topo-order HEAD)
)"
[[ -n "${predecessor_ref}" ]] || {
  echo "unable to locate the 0084 predecessor artifact" >&2
  exit 1
}
/usr/bin/git clone --quiet --shared --no-checkout "${repo_root}" "${predecessor_source}"
/usr/bin/git -C "${predecessor_source}" checkout --quiet --detach "${predecessor_ref}"

RSS_PG_DATABASE_URL_FILE="${migration_database_url_file}" \
  "${predecessor_source}/hack/cargo.sh" run --quiet -p rss --bin rss -- \
    postgres migrate-all

predecessor_ledger="$(owner_psql -Atqc "SELECT max(version) || ':' || bool_and(success) || ':' || min(octet_length(checksum)) || ':' || count(*) FROM _sqlx_migrations")"
[[ "${predecessor_ledger}" == "84:true:48:84" || "${predecessor_ledger}" == "84:t:48:84" ]]
predecessor_registry="$(owner_psql -Atqc "SELECT count(*) || ':' || min(generation) || ':' || max(generation) FROM projection_input_bindings")"
[[ "${predecessor_registry}" == "2:sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895:sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895" ]]

owner_psql <<'EOSQL' >/dev/null
CREATE TABLE upgrade_reader_smoke_marker(value text PRIMARY KEY);
INSERT INTO upgrade_reader_smoke_marker VALUES ('retained');
GRANT UPDATE (subject) ON sessions TO rss_app_read;
EOSQL

# Exercise the release binary entrypoint. Direct SQL replay here would bypass the exact-edge guard
# and SQLx ledger/checksum/advisory-lock semantics that this smoke exists to prove.
RSS_PG_DATABASE_URL_FILE="${migration_database_url_file}" \
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

RSS_PG_HOST=127.0.0.1 \
RSS_PG_PORT=5432 \
RSS_PG_DATABASE="${database}" \
RSS_PG_MIGRATOR_USERNAME=postgres \
RSS_PG_MIGRATOR_PASSWORD_FILE="${migration_password_file}" \
RSS_PG_PROJECTION_READER_USERNAME=rss_projection_reader \
RSS_PG_PROJECTION_READER_PASSWORD_FILE="${projection_reader_password_file}" \
RSS_PG_PROJECTION_OPERATOR_USERNAME=rss_projection_operator \
RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE="${projection_operator_password_file}" \
PSQL_CONTAINER="${container}" \
PGSSLMODE=verify-full \
PGSSLROOTCERT=/rss-tls/ca.pem \
  "${repo_root}/deploy/postgres-upgrade/provision-projection-roles.sh"

RSS_PG_HOST=127.0.0.1 \
RSS_PG_PORT=5432 \
RSS_PG_DATABASE="${database}" \
RSS_PG_MIGRATOR_USERNAME=postgres \
RSS_PG_MIGRATOR_PASSWORD_FILE="${migration_password_file}" \
RSS_PG_SAGA_OPERATOR_USERNAME=rss_saga_operator \
RSS_PG_SAGA_OPERATOR_PASSWORD_FILE="${saga_operator_password_file}" \
PSQL_CONTAINER="${container}" \
PGSSLMODE=verify-full \
PGSSLROOTCERT=/rss-tls/ca.pem \
  "${repo_root}/deploy/postgres-upgrade/provision-saga-operator-role.sh"

run_l2_dr_provision() {
  RSS_PG_HOST=127.0.0.1 \
  RSS_PG_PORT=5432 \
  RSS_PG_DATABASE="${database}" \
  RSS_PG_MIGRATOR_USERNAME=postgres \
  RSS_PG_MIGRATOR_PASSWORD_FILE="${migration_password_file}" \
  RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME=rss_l2_dr_recovery_auditor \
  RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE="${l2_dr_recovery_auditor_password_file}" \
  RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME=rss_l2_dr_recovery_executor \
  RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE="${l2_dr_recovery_executor_password_file}" \
  PSQL_CONTAINER="${container}" \
  PGSSLMODE=verify-full \
  PGSSLROOTCERT=/rss-tls/ca.pem \
    "${repo_root}/deploy/postgres-upgrade/provision-l2-dr-recovery-roles.sh"
}

# Fail-closed: renamed-away roles simulate a database that never applied 0098.
owner_psql <<'EOSQL' >/dev/null
ALTER ROLE rss_l2_dr_recovery_auditor RENAME TO rss_l2_dr_recovery_auditor_absent;
ALTER ROLE rss_l2_dr_recovery_executor RENAME TO rss_l2_dr_recovery_executor_absent;
EOSQL
if run_l2_dr_provision; then
  echo "provision must fail when 0098 L2 DR roles are absent" >&2
  exit 1
fi
l2_dr_absent_login="$(owner_psql -Atqc "
SELECT string_agg(rolname || ':' || rolcanlogin, ',' ORDER BY rolname)
FROM pg_catalog.pg_roles
WHERE rolname IN (
    'rss_l2_dr_recovery_auditor_absent',
    'rss_l2_dr_recovery_executor_absent'
)")"
[[ "${l2_dr_absent_login}" == "rss_l2_dr_recovery_auditor_absent:false,rss_l2_dr_recovery_executor_absent:false" ]]
owner_psql <<'EOSQL' >/dev/null
ALTER ROLE rss_l2_dr_recovery_auditor_absent RENAME TO rss_l2_dr_recovery_auditor;
ALTER ROLE rss_l2_dr_recovery_executor_absent RENAME TO rss_l2_dr_recovery_executor;
EOSQL

# Fail-closed: membership drift must refuse LOGIN rotation.
owner_psql -c "GRANT rss_app TO rss_l2_dr_recovery_auditor" >/dev/null
if run_l2_dr_provision; then
  echo "provision must fail when L2 DR role membership has drifted" >&2
  exit 1
fi
l2_dr_drift_login="$(owner_psql -Atqc "
SELECT string_agg(rolname || ':' || rolcanlogin, ',' ORDER BY rolname)
FROM pg_catalog.pg_roles
WHERE rolname IN ('rss_l2_dr_recovery_auditor', 'rss_l2_dr_recovery_executor')")"
[[ "${l2_dr_drift_login}" == "rss_l2_dr_recovery_auditor:false,rss_l2_dr_recovery_executor:false" ]]
owner_psql -c "REVOKE rss_app FROM rss_l2_dr_recovery_auditor" >/dev/null

run_l2_dr_provision

marker="$(owner_psql -Atqc 'SELECT value FROM upgrade_reader_smoke_marker')"
[[ "${marker}" == "retained" ]]
ledger="$(owner_psql -Atqc "SELECT max(version) || ':' || bool_and(success) || ':' || min(octet_length(checksum)) || ':' || count(*) FROM _sqlx_migrations")"
[[ "${ledger}" == "98:true:48:98" || "${ledger}" == "98:t:48:98" ]]
projection_roles="$(owner_psql -Atqc "SELECT string_agg(rolname || ':' || rolcanlogin || ':' || rolinherit, ',' ORDER BY rolname) FROM pg_roles WHERE rolname IN ('rss_projection_reader', 'rss_projection_operator')")"
[[ "${projection_roles}" == "rss_projection_operator:true:false,rss_projection_reader:true:false" || "${projection_roles}" == "rss_projection_operator:t:f,rss_projection_reader:t:f" ]]
saga_operator_role="$(owner_psql -Atqc "SELECT rolname || ':' || rolcanlogin || ':' || rolinherit FROM pg_roles WHERE rolname = 'rss_saga_operator'")"
[[ "${saga_operator_role}" == "rss_saga_operator:true:false" || "${saga_operator_role}" == "rss_saga_operator:t:f" ]]
l2_dr_recovery_owner="$(owner_psql -Atqc "
SELECT rolname || ':' || rolcanlogin || ':' || rolbypassrls || ':' || rolsuper || ':' ||
       rolcreatedb || ':' || rolcreaterole || ':' || rolreplication || ':' || rolinherit
FROM pg_catalog.pg_roles
WHERE rolname = 'rss_l2_dr_recovery_owner'")"
[[ "${l2_dr_recovery_owner}" == "rss_l2_dr_recovery_owner:false:true:false:false:false:false:false" ]]
l2_dr_recovery_roles="$(owner_psql -Atqc "
SELECT string_agg(
    rolname || ':' || rolcanlogin || ':' || rolinherit || ':' || rolbypassrls || ':' ||
    rolsuper || ':' || rolcreatedb || ':' || rolcreaterole || ':' || rolreplication,
    ',' ORDER BY rolname
)
FROM pg_catalog.pg_roles
WHERE rolname IN ('rss_l2_dr_recovery_auditor', 'rss_l2_dr_recovery_executor')")"
[[ "${l2_dr_recovery_roles}" == "rss_l2_dr_recovery_auditor:true:false:false:false:false:false:false,rss_l2_dr_recovery_executor:true:false:false:false:false:false:false" ]]
l2_dr_recovery_legacy_role="$(owner_psql -Atqc "
SELECT count(*)
FROM pg_catalog.pg_roles
WHERE rolname = 'rss_l2_dr_recovery_operator'")"
[[ "${l2_dr_recovery_legacy_role}" == "0" ]]
l2_dr_recovery_memberships="$(owner_psql -Atqc "
SELECT count(*)
FROM pg_catalog.pg_auth_members AS membership
JOIN pg_catalog.pg_roles AS role
  ON role.oid IN (membership.roleid, membership.member)
WHERE role.rolname IN ('rss_l2_dr_recovery_auditor', 'rss_l2_dr_recovery_executor')")"
[[ "${l2_dr_recovery_memberships}" == "0" ]]
l2_dr_recovery_ownership="$(owner_psql -Atqc "
SELECT count(*)
FROM pg_catalog.pg_shdepend AS dependency
JOIN pg_catalog.pg_roles AS role ON role.oid = dependency.refobjid
WHERE dependency.refclassid = 'pg_authid'::regclass
  AND dependency.deptype = 'o'
  AND role.rolname IN ('rss_l2_dr_recovery_auditor', 'rss_l2_dr_recovery_executor')")"
[[ "${l2_dr_recovery_ownership}" == "0" ]]
l2_dr_recovery_separation="$(owner_psql -Atqc "
SELECT
    pg_catalog.has_function_privilege(
        'rss_l2_dr_recovery_auditor',
        'public.rss_service_token_replay_check_and_record(bytea,timestamp with time zone)',
        'EXECUTE'
    )
    AND pg_catalog.has_function_privilege(
        'rss_l2_dr_recovery_auditor',
        'public.rss_l2_dr_recovery_record_start_audit(bigint,integer,text,uuid,uuid,bytea,uuid)',
        'EXECUTE'
    )
    AND pg_catalog.has_function_privilege(
        'rss_l2_dr_recovery_auditor',
        'public.rss_l2_dr_recovery_record_finish_audit(bigint,integer,text,uuid,uuid,text,text,uuid)',
        'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
        'rss_l2_dr_recovery_auditor',
        'public.rss_l2_dr_recovery_apply(uuid,uuid,text,bigint,bigint,text,text[],bytea,text,uuid)',
        'EXECUTE'
    )
    AND pg_catalog.has_function_privilege(
        'rss_l2_dr_recovery_executor',
        'public.rss_l2_dr_recovery_apply(uuid,uuid,text,bigint,bigint,text,text[],bytea,text,uuid)',
        'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
        'rss_l2_dr_recovery_executor',
        'public.rss_l2_dr_recovery_record_start_audit(bigint,integer,text,uuid,uuid,bytea,uuid)',
        'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
        'rss_l2_dr_recovery_executor',
        'public.rss_l2_dr_recovery_record_finish_audit(bigint,integer,text,uuid,uuid,text,text,uuid)',
        'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
        'rss_l2_dr_recovery_executor',
        'public.rss_service_token_replay_check_and_record(bytea,timestamp with time zone)',
        'EXECUTE'
    )")"
[[ "${l2_dr_recovery_separation}" == "t" ]]
echo "retained-volume PostgreSQL privilege-boundary upgrade smoke passed through 0098"
