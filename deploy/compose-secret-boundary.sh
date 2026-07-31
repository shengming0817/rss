#!/usr/bin/env bash
# Verify compose serving/Projection Secret boundaries + egress TLS static declarations (#1710/#1915).
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
  cat >"${tmp}/docker-compose.yml" <<'YAML'
services:
  redis:
    image: redis:7-alpine
    command: ["redis-server"]
  rabbitmq:
    image: rabbitmq:3
    volumes:
      - ./demo-tls/out/rabbitmq/rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf:ro
  minio:
    image: minio/minio
    command: ["server", "/data"]
  server:
    image: rss:dev
    environment:
      RSS_REDIS_CA_CERT_PEM_PATH: /run/rss-demo-tls/redis/ca.pem
    volumes:
      - ./bundle.json:/var/run/rss/secrets/serving-secret-bundle:ro
  projection-operator:
    image: rss:dev
    volumes:
      - ./bundle.json:/var/run/rss/secrets/serving-secret-bundle:ro
      - ./reader:/run/rss-demo-secrets/pg-projection-reader-password:ro
      - ./operator:/run/rss-demo-secrets/pg-projection-operator-password:ro
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
printf '%s\n' 'compose serving and Projection Secret boundaries verified'
