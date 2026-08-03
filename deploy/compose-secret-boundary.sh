#!/usr/bin/env bash
# Verify serving/Projection/L2 provisioning Secret boundaries + egress TLS (#1710/#1915).
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run_checks() {
  local compose_file="$1"
  local rendered
  rendered="$(docker compose --profile "*" -f "${compose_file}" config --format json)"
  python3 -c '
import json, os, sys

document = json.load(sys.stdin)
services = document["services"]
server = services["server"]
environment = server.get("environment", {})
forbidden = {
    "POSTGRES_PASSWORD", "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "RSS_AMQP_URL", "RSS_SETTINGS_AMQP_URL", "RSS_IDENTITY_AMQP_URL",
    "RSS_AUDIT_AMQP_URL", "RSS_AUDIT_CHAIN_KEY_B64URL",
    "RSS_COMMAND_IDEMPOTENCY_KEYS_JSON", "RSS_DLX_ARCHIVE_VAULT_TOKEN",
    "RSS_DLX_HOT_VAULT_TOKEN", "RSS_PG_MIGRATOR_PASSWORD_FILE",
    "RSS_PG_PASSWORD_FILE", "RSS_PG_READ_PASSWORD_FILE",
    "RSS_PG_PROJECTION_READER_PASSWORD_FILE",
    "RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE",
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE",
    "RSS_PG_AUDIT_ADMIN_PASSWORD_FILE",
    "RSS_PG_DLX_ARCHIVER_PASSWORD_FILE", "RSS_PG_DLX_VERIFIER_PASSWORD_FILE",
    "RSS_PG_DLX_PURGER_PASSWORD_FILE", "RSS_REDIS_URL",
    "RSS_S3_ACCESS_KEY_ID", "RSS_S3_SECRET_ACCESS_KEY", "RSS_S3_SESSION_TOKEN",
    "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL",
    "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL", "RSS_VAULT_TOKEN",
}
leaked = sorted(key for key in forbidden if environment.get(key) is not None)
if leaked:
    raise SystemExit("server has forbidden Secret environment keys: " + ",".join(leaked))
mounts = [volume for volume in server.get("volumes", [])
          if volume.get("target") == "/var/run/rss/secrets/serving-secret-bundle"]
if len(mounts) != 1 or mounts[0].get("read_only") is not True:
    raise SystemExit("server serving-secret-bundle mount is not exact/read-only")
server_targets = {str(volume.get("target")) for volume in server.get("volumes", [])}
server_forbidden_targets = {
    "/var/run/rss/secrets/projection-operator-secret-bundle",
    "/run/rss-demo-secrets/pg-projection-reader-password",
    "/run/rss-demo-secrets/pg-projection-operator-password",
    "/run/rss-demo-secrets/pg-l2-dr-recovery-auditor-password",
    "/run/rss-demo-secrets/pg-l2-dr-recovery-executor-password",
    "/run/rss-projection-operator/projection-operator-jwks.json",
}
server_projection_leaks = sorted(server_targets & server_forbidden_targets)
if server_projection_leaks:
    raise SystemExit(
        "server mounts Projection-only secret carriers: " + ",".join(server_projection_leaks)
    )

projection = services.get("projection-operator") or {}
projection_environment = projection.get("environment", {})
projection_forbidden_environment = forbidden | {
    "RSS_PG_PROJECTION_READER_PASSWORD",
    "RSS_PG_PROJECTION_OPERATOR_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_OPERATOR_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_OPERATOR_PASSWORD_FILE",
    "RSS_PG_L2_DR_RECOVERY_OPERATOR_USERNAME",
    "RSS_PG_PASSWORD", "RSS_PG_READ_PASSWORD", "RSS_PG_AUDIT_ADMIN_PASSWORD",
    "RSS_PG_DLX_ARCHIVER_PASSWORD", "RSS_PG_DLX_VERIFIER_PASSWORD",
    "RSS_PG_DLX_PURGER_PASSWORD",
}
projection_env_leaks = sorted(
    key for key in projection_forbidden_environment
    if projection_environment.get(key) is not None
)
if projection_env_leaks:
    raise SystemExit(
        "projection operator has forbidden Secret environment keys: "
        + ",".join(projection_env_leaks)
    )
projection_volumes = projection.get("volumes", [])
projection_targets = {str(volume.get("target")) for volume in projection_volumes}
required_projection_targets = {
    "/var/run/rss/secrets/projection-operator-secret-bundle",
    "/run/rss-demo-secrets/pg-projection-reader-password",
    "/run/rss-demo-secrets/pg-projection-operator-password",
    "/run/rss-projection-operator/projection-operator-jwks.json",
    "/run/rss-demo-tls/postgres/ca.pem",
    "/run/rss-demo-vault",
}
if projection_targets != required_projection_targets:
    raise SystemExit(
        "projection operator mount set is not exact: "
        + ",".join(sorted(projection_targets))
    )
if any(volume.get("read_only") is not True for volume in projection_volumes):
    raise SystemExit("projection operator mounts must all be read-only")
if "/var/run/rss/secrets/serving-secret-bundle" in projection_targets:
    raise SystemExit("projection operator must not mount serving-secret-bundle")

postgres = services.get("postgres") or {}
postgres_environment = postgres.get("environment", {})
expected_l2_init_environment = {
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME": "rss_l2_dr_recovery_auditor",
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE":
        "/run/rss-demo-secrets/pg-l2-dr-recovery-auditor-password",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME": "rss_l2_dr_recovery_executor",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE":
        "/run/rss-demo-secrets/pg-l2-dr-recovery-executor-password",
}
for key, expected in expected_l2_init_environment.items():
    if postgres_environment.get(key) != expected:
        raise SystemExit(f"postgres has invalid {key}")
postgres_volumes = postgres.get("volumes", [])
postgres_targets = {str(volume.get("target")): volume for volume in postgres_volumes}
for target in (
    "/run/rss-demo-secrets/pg-l2-dr-recovery-auditor-password",
    "/run/rss-demo-secrets/pg-l2-dr-recovery-executor-password",
):
    volume = postgres_targets.get(target)
    if volume is None or volume.get("read_only") is not True:
        raise SystemExit("postgres must mount L2 DR password files read-only")

l2_provision = services.get("l2-dr-recovery-provision") or {}
l2_environment = l2_provision.get("environment", {})
expected_l2_provision_environment = expected_l2_init_environment | {
    "RSS_PG_MIGRATOR_USERNAME": "postgres",
    "RSS_PG_MIGRATOR_PASSWORD_FILE": "/run/rss-demo-secrets/pg-migrator-password",
}
for key, expected in expected_l2_provision_environment.items():
    if l2_environment.get(key) != expected:
        raise SystemExit(f"L2 DR provisioner has invalid {key}")
l2_plaintext_or_legacy = {
    "POSTGRES_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_OPERATOR_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_OPERATOR_PASSWORD_FILE",
    "RSS_PG_L2_DR_RECOVERY_OPERATOR_USERNAME",
}
l2_leaks = sorted(key for key in l2_plaintext_or_legacy if l2_environment.get(key) is not None)
if l2_leaks:
    raise SystemExit("L2 DR provisioner has plaintext/legacy credential keys: " + ",".join(l2_leaks))
l2_volumes = l2_provision.get("volumes", [])
l2_targets = {str(volume.get("target")) for volume in l2_volumes}
required_l2_targets = {
    "/usr/local/bin/provision-l2-dr-recovery-roles.sh",
    "/run/rss-demo-secrets/pg-migrator-password",
    "/run/rss-demo-secrets/pg-l2-dr-recovery-auditor-password",
    "/run/rss-demo-secrets/pg-l2-dr-recovery-executor-password",
    "/run/rss-demo-tls/postgres/ca.pem",
}
if l2_targets != required_l2_targets:
    raise SystemExit(
        "L2 DR provisioner mount set is not exact: " + ",".join(sorted(l2_targets))
    )
if any(volume.get("read_only") is not True for volume in l2_volumes):
    raise SystemExit("L2 DR provisioner mounts must all be read-only")
l2_dependencies = l2_provision.get("depends_on", {})
if (l2_dependencies.get("migration") or {}).get("condition") != "service_completed_successfully":
    raise SystemExit("L2 DR provisioner must run only after migration completion")
server_dependencies = server.get("depends_on", {})
if (server_dependencies.get("l2-dr-recovery-provision") or {}).get("condition") != "service_completed_successfully":
    raise SystemExit("server must wait for L2 DR credential provisioning")

# Egress TLS static declarations (#1710).
redis = services.get("redis") or {}
redis_cmd = " ".join(str(part) for part in (redis.get("command") or []))
if "--tls-port" not in redis_cmd:
    raise SystemExit("redis service must declare --tls-port")

compose_dir = os.path.dirname(os.environ["RSS_COMPOSE_FILE"])
demo_tls_out = os.path.join(compose_dir, "demo-tls", "out")

rabbit = services.get("rabbitmq") or {}
rabbit_vols = rabbit.get("volumes") or []
has_conf_mount = any(
    "rabbitmq.conf" in str(vol.get("source", "")) or "rabbitmq.conf" in str(vol.get("target", ""))
    for vol in rabbit_vols
)
if not has_conf_mount:
    raise SystemExit("rabbitmq service must mount rabbitmq.conf (listeners.tcp=none + ssl)")

rabbit_conf = os.path.join(demo_tls_out, "rabbitmq", "rabbitmq.conf")
if not os.path.isfile(rabbit_conf):
    raise SystemExit("rabbitmq.conf host path must be an existing file: " + rabbit_conf)
conf_text = open(rabbit_conf, encoding="utf-8").read()
if "listeners.tcp = none" not in conf_text or "listeners.ssl" not in conf_text:
    raise SystemExit("rabbitmq.conf must set listeners.tcp=none and listeners.ssl")

required_host_files = [
    os.path.join(demo_tls_out, "rabbitmq", "ca.pem"),
    os.path.join(demo_tls_out, "rabbitmq", "server.pem"),
    os.path.join(demo_tls_out, "rabbitmq", "server-key.pem"),
    os.path.join(demo_tls_out, "redis", "ca.pem"),
    os.path.join(demo_tls_out, "postgres", "ca.pem"),
    os.path.join(demo_tls_out, "minio", "CAs", "rss-demo-s3-ca.pem"),
]
missing_host = [path for path in required_host_files if not os.path.isfile(path)]
if missing_host:
    raise SystemExit("demo-tls host CA/leaf paths must be files: " + ",".join(missing_host))

minio = services.get("minio") or {}
minio_cmd = " ".join(str(part) for part in (minio.get("command") or []))
if "--certs-dir" not in minio_cmd:
    raise SystemExit("minio service must declare --certs-dir")

required_ca_env = [
    "RSS_REDIS_CA_CERT_PEM_PATH",
    "RSS_AMQP_CA_CERT_PEM_PATH",
    "RSS_S3_CA_CERT_PEM_PATH",
    "RSS_PG_SSL_ROOT_CERT_PATH",
]
missing_ca = [key for key in required_ca_env if not environment.get(key)]
if missing_ca:
    raise SystemExit("server missing egress CA env paths: " + ",".join(missing_ca))

server_vols = server.get("volumes") or []
required_targets = [
    "/run/rss-demo-tls/redis/ca.pem",
    "/run/rss-demo-tls/rabbitmq/ca.pem",
    "/run/rss-demo-tls/minio/CAs/rss-demo-s3-ca.pem",
    "/run/rss-demo-tls/postgres/ca.pem",
]
mounted = {str(vol.get("target")) for vol in server_vols}
missing_mounts = [path for path in required_targets if path not in mounted]
if missing_mounts:
    raise SystemExit("server missing egress CA mounts: " + ",".join(missing_mounts))
' <<<"${rendered}"
}

if [[ "${1:-}" == "--selftest" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT
  mkdir -p "${tmp}/demo-tls/out/rabbitmq"

  mkdir -p "${tmp}/l2-init-bin"
  printf '%s\n' '#!/bin/sh' 'exit 0' >"${tmp}/l2-init-bin/psql"
  chmod +x "${tmp}/l2-init-bin/psql"
  printf '%s\n' 'other-secret' >"${tmp}/other-password"
  printf '%s\n' 'auditor-secret' >"${tmp}/auditor-password"
  printf '%s\n' 'executor-secret' >"${tmp}/executor-password"
  printf '%s\n' 'auditor-secret' >"${tmp}/same-secret-password"
  l2_init_common=(
    "PATH=${tmp}/l2-init-bin:${PATH}"
    POSTGRES_DB=rss POSTGRES_USER=postgres POSTGRES_APP_USER=rss_app
    RSS_PG_READ_USERNAME=rss_app_read
    "RSS_PG_PASSWORD_FILE=${tmp}/other-password"
    "RSS_PG_READ_PASSWORD_FILE=${tmp}/other-password"
    RSS_PG_PROJECTION_READER_USERNAME=rss_projection_reader
    "RSS_PG_PROJECTION_READER_PASSWORD_FILE=${tmp}/other-password"
    RSS_PG_PROJECTION_OPERATOR_USERNAME=rss_projection_operator
    "RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE=${tmp}/other-password"
    RSS_PG_SAGA_OPERATOR_USERNAME=rss_saga_operator
    "RSS_PG_SAGA_OPERATOR_PASSWORD_FILE=${tmp}/other-password"
    RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME=rss_l2_dr_recovery_auditor
    RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME=rss_l2_dr_recovery_executor
    RSS_PG_DLX_ARCHIVER_USERNAME=rss_dlx_archiver
    "RSS_PG_DLX_ARCHIVER_PASSWORD_FILE=${tmp}/other-password"
    RSS_PG_DLX_VERIFIER_USERNAME=rss_dlx_verifier
    "RSS_PG_DLX_VERIFIER_PASSWORD_FILE=${tmp}/other-password"
    RSS_PG_DLX_PURGER_USERNAME=rss_dlx_purger
    "RSS_PG_DLX_PURGER_PASSWORD_FILE=${tmp}/other-password"
  )
  if env "${l2_init_common[@]}" \
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE=${tmp}/auditor-password" \
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE=${tmp}/auditor-password" \
    bash "${script_dir}/postgres-init/001-create-app-role.sh" \
    >"${tmp}/same-path.out" 2>&1; then
    echo "selftest expected red for shared L2 DR fresh-init password file" >&2
    exit 1
  fi
  grep -q 'password files must be distinct' "${tmp}/same-path.out"
  if env "${l2_init_common[@]}" \
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE=${tmp}/auditor-password" \
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE=${tmp}/same-secret-password" \
    bash "${script_dir}/postgres-init/001-create-app-role.sh" \
    >"${tmp}/same-secret.out" 2>&1; then
    echo "selftest expected red for equal L2 DR fresh-init passwords" >&2
    exit 1
  fi
  grep -q 'passwords must be distinct' "${tmp}/same-secret.out"
  env "${l2_init_common[@]}" \
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE=${tmp}/auditor-password" \
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE=${tmp}/executor-password" \
    bash "${script_dir}/postgres-init/001-create-app-role.sh" \
    >"${tmp}/distinct-passwords.out" 2>&1

  cat >"${tmp}/docker-compose.yml" <<'YAML'
services:
  redis:
    image: redis:7-alpine
    command: ["redis-server", "--tls-port", "6379"]
  rabbitmq:
    image: rabbitmq:3
    volumes:
      - ./demo-tls/out/rabbitmq/rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf:ro
  minio:
    image: minio/minio
    command: ["server", "/data", "--certs-dir", "/certs"]
  migration:
    image: rss:dev
  postgres:
    image: postgres:16-alpine
    environment:
      RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME: rss_l2_dr_recovery_auditor
      RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE: /run/rss-demo-secrets/pg-l2-dr-recovery-auditor-password
      RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME: rss_l2_dr_recovery_executor
      RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE: /run/rss-demo-secrets/pg-l2-dr-recovery-executor-password
    volumes:
      - ./auditor:/run/rss-demo-secrets/pg-l2-dr-recovery-auditor-password:ro
      - ./executor:/run/rss-demo-secrets/pg-l2-dr-recovery-executor-password:ro
  l2-dr-recovery-provision:
    image: postgres:16-alpine
    environment:
      RSS_PG_MIGRATOR_USERNAME: postgres
      RSS_PG_MIGRATOR_PASSWORD_FILE: /run/rss-demo-secrets/pg-migrator-password
      RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME: rss_l2_dr_recovery_auditor
      RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE: /run/rss-demo-secrets/pg-l2-dr-recovery-auditor-password
      RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME: rss_l2_dr_recovery_executor
      RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE: /run/rss-demo-secrets/pg-l2-dr-recovery-executor-password
      RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD: synthetic-plaintext-must-fail
    depends_on:
      migration:
        condition: service_completed_successfully
    volumes:
      - ./provision.sh:/usr/local/bin/provision-l2-dr-recovery-roles.sh:ro
      - ./migrator:/run/rss-demo-secrets/pg-migrator-password:ro
      - ./auditor:/run/rss-demo-secrets/pg-l2-dr-recovery-auditor-password:ro
      - ./executor:/run/rss-demo-secrets/pg-l2-dr-recovery-executor-password:ro
      - ./postgres-ca.pem:/run/rss-demo-tls/postgres/ca.pem:ro
  server:
    image: rss:dev
    environment:
      RSS_REDIS_CA_CERT_PEM_PATH: /run/rss-demo-tls/redis/ca.pem
      RSS_AMQP_CA_CERT_PEM_PATH: /run/rss-demo-tls/rabbitmq/ca.pem
      RSS_S3_CA_CERT_PEM_PATH: /run/rss-demo-tls/minio/CAs/rss-demo-s3-ca.pem
      RSS_PG_SSL_ROOT_CERT_PATH: /run/rss-demo-tls/postgres/ca.pem
    depends_on:
      l2-dr-recovery-provision:
        condition: service_completed_successfully
    volumes:
      - ./bundle.json:/var/run/rss/secrets/serving-secret-bundle:ro
      - ./redis-ca.pem:/run/rss-demo-tls/redis/ca.pem:ro
      - ./rabbitmq-ca.pem:/run/rss-demo-tls/rabbitmq/ca.pem:ro
      - ./minio-ca.pem:/run/rss-demo-tls/minio/CAs/rss-demo-s3-ca.pem:ro
      - ./postgres-ca.pem:/run/rss-demo-tls/postgres/ca.pem:ro
  projection-operator:
    image: rss:dev
    volumes:
      - ./bundle.json:/var/run/rss/secrets/serving-secret-bundle:ro
      - ./reader:/run/rss-demo-secrets/pg-projection-reader-password:ro
      - ./operator:/run/rss-demo-secrets/pg-projection-operator-password:ro
      - ./projection-jwks.json:/run/rss-projection-operator/projection-operator-jwks.json:ro
      - ./postgres-ca.pem:/run/rss-demo-tls/postgres/ca.pem:ro
      - ./vault-ca:/run/rss-demo-vault:ro
YAML
  # A Projection process receiving the serving bundle must fail before unrelated TLS checks.
  export RSS_COMPOSE_FILE="${tmp}/docker-compose.yml"
  if run_checks "${tmp}/docker-compose.yml"; then
    echo "selftest expected red for Projection serving-bundle exposure" >&2
    exit 1
  fi
  python3 - "${tmp}/docker-compose.yml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "./bundle.json:/var/run/rss/secrets/serving-secret-bundle:ro\n"
    "      - ./reader:/run/rss-demo-secrets/pg-projection-reader-password:ro",
    "./projection-bundle.json:/var/run/rss/secrets/projection-operator-secret-bundle:ro\n"
    "      - ./reader:/run/rss-demo-secrets/pg-projection-reader-password:ro",
    1,
)
path.write_text(text, encoding="utf-8")
PY
  # With Projection fixed, an L2 provisioner receiving plaintext credentials must be the next red.
  if run_checks "${tmp}/docker-compose.yml"; then
    echo "selftest expected red for L2 DR plaintext credential exposure" >&2
    exit 1
  fi
  python3 - "${tmp}/docker-compose.yml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "      RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD: synthetic-plaintext-must-fail\n",
    "",
    1,
)
path.write_text(text, encoding="utf-8")
PY
  # Conf present but incomplete TLS knobs / missing CA materials → still red.
  printf '%s\n' 'listeners.tcp = none' 'listeners.ssl.default = 5671' \
    >"${tmp}/demo-tls/out/rabbitmq/rabbitmq.conf"
  if run_checks "${tmp}/docker-compose.yml"; then
    echo "selftest expected red for missing TLS knobs / host CA files" >&2
    exit 1
  fi
  printf '%s\n' 'compose-secret-boundary selftest red case passed'
  exit 0
fi

export RSS_COMPOSE_FILE="${script_dir}/docker-compose.yml"
run_checks "${script_dir}/docker-compose.yml"
printf '%s\n' 'compose serving, Projection, and L2 provisioning Secret boundaries verified'
