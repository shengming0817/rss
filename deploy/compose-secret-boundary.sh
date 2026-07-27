#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rendered="$(docker compose -f "${script_dir}/docker-compose.yml" config --format json)"
python3 -c '
import json, sys
document = json.load(sys.stdin)
server = document["services"]["server"]
environment = server.get("environment", {})
forbidden = {
    "POSTGRES_PASSWORD", "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "RSS_AMQP_URL", "RSS_SETTINGS_AMQP_URL", "RSS_IDENTITY_AMQP_URL",
    "RSS_AUDIT_AMQP_URL", "RSS_AUDIT_CHAIN_KEY_B64URL",
    "RSS_COMMAND_IDEMPOTENCY_KEYS_JSON", "RSS_DLX_ARCHIVE_VAULT_TOKEN",
    "RSS_DLX_HOT_VAULT_TOKEN", "RSS_PG_MIGRATOR_PASSWORD_FILE",
    "RSS_PG_PASSWORD_FILE", "RSS_PG_READ_PASSWORD_FILE",
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
' <<<"${rendered}"

printf '%s\n' 'compose serving Secret boundary verified'
