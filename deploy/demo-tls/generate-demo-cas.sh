#!/usr/bin/env bash
# Demo private CA + service certs for compose egress TLS (#1710).
# Source of truth for regenerating material under deploy/demo-tls/out/ (gitignored).
#
# Usage:
#   bash deploy/demo-tls/generate-demo-cas.sh
#   RSS_DEMO_TLS_OUT=/tmp/rss-demo-tls bash deploy/demo-tls/generate-demo-cas.sh
#
# Emits per-service CA + leaf certs with SANs matching compose DNS names
# (postgres / redis / rabbitmq / minio) plus localhost/127.0.0.1 for host-side smoke.
# Demo-only keys — never reuse outside the local compose harness.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${RSS_DEMO_TLS_OUT:-$ROOT/out}"
FORCE="${RSS_DEMO_TLS_FORCE:-0}"

need_openssl() {
  command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required to generate demo TLS material" >&2
    exit 1
  }
}

wipe_if_forced() {
  if [[ "$FORCE" == "1" ]]; then
    rm -rf "$OUT"
  fi
}

ensure_layout() {
  mkdir -p \
    "$OUT/postgres" \
    "$OUT/redis" \
    "$OUT/rabbitmq" \
    "$OUT/minio/CAs"
}

# Keep existing tree unless FORCE=1 so repeated smoke runs stay idempotent.
already_complete() {
  [[ -f "$OUT/postgres/ca.pem" ]] &&
    [[ -f "$OUT/postgres/server.pem" ]] &&
    [[ -f "$OUT/postgres/server-key.pem" ]] &&
    [[ ! -f "$OUT/postgres/ca-key.pem" ]] &&
    [[ -f "$OUT/postgres/start-postgres.sh" ]] &&
    [[ -f "$OUT/postgres/00-require-tls.sh" ]] &&
    [[ -f "$OUT/redis/ca.pem" ]] &&
    [[ -f "$OUT/redis/server.pem" ]] &&
    [[ -f "$OUT/redis/server-key.pem" ]] &&
    [[ ! -f "$OUT/redis/ca-key.pem" ]] &&
    [[ -f "$OUT/rabbitmq/ca.pem" ]] &&
    [[ -f "$OUT/rabbitmq/server.pem" ]] &&
    [[ -f "$OUT/rabbitmq/server-key.pem" ]] &&
    [[ ! -f "$OUT/rabbitmq/ca-key.pem" ]] &&
    [[ -f "$OUT/rabbitmq/rabbitmq.conf" ]] &&
    [[ -f "$OUT/minio/ca.pem" ]] &&
    [[ -f "$OUT/minio/server.pem" ]] &&
    [[ -f "$OUT/minio/server-key.pem" ]] &&
    [[ ! -f "$OUT/minio/ca-key.pem" ]] &&
    [[ -f "$OUT/minio/CAs/rss-demo-s3-ca.pem" ]] &&
    [[ -f "$OUT/minio/public.crt" ]] &&
    [[ -f "$OUT/minio/private.key" ]]
}

gen_ca() {
  local dir="$1"
  local cn="$2"
  local key="$dir/ca-key.pem"
  local cert="$dir/ca.pem"
  openssl req -x509 -newkey rsa:2048 \
    -keyout "$key" \
    -out "$cert" \
    -days 3650 \
    -nodes \
    -subj "/CN=${cn}" \
    >/dev/null 2>&1
  chmod 644 "$cert"
  chmod 600 "$key"
}

gen_server() {
  local dir="$1"
  local cn="$2"
  shift 2
  local san_dns=("$@")
  local conf
  conf="$(mktemp)"
  {
    echo "[req]"
    echo "distinguished_name = req_distinguished_name"
    echo "req_extensions = v3_req"
    echo "prompt = no"
    echo "[req_distinguished_name]"
    echo "CN = ${cn}"
    echo "[v3_req]"
    echo "basicConstraints = CA:FALSE"
    echo "keyUsage = digitalSignature, keyEncipherment"
    echo "extendedKeyUsage = serverAuth"
    echo "subjectAltName = @alt_names"
    echo "[alt_names]"
    local i=1
    local name
    for name in "${san_dns[@]}"; do
      if [[ "$name" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "IP.${i} = ${name}"
      else
        echo "DNS.${i} = ${name}"
      fi
      i=$((i + 1))
    done
  } >"$conf"

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$dir/server-key.pem" \
    -out "$dir/server.csr" \
    -config "$conf" \
    >/dev/null 2>&1
  openssl x509 -req \
    -in "$dir/server.csr" \
    -CA "$dir/ca.pem" \
    -CAkey "$dir/ca-key.pem" \
    -CAcreateserial \
    -out "$dir/server.pem" \
    -days 825 \
    -extfile "$conf" \
    -extensions v3_req \
    >/dev/null 2>&1
  rm -f "$dir/server.csr" "$dir/ca.srl" "$conf"
  # Drop CA private key after leaf issuance so compose dir mounts cannot expose it.
  rm -f "$dir/ca-key.pem"
  # World-readable key: official redis/rabbitmq images drop privileges before reading TLS keys
  # (mirrors crates/testkit::copied_tls_image mode 0o644).
  chmod 644 "$dir/server.pem" "$dir/server-key.pem"
}

write_postgres_helpers() {
  # Copy leaf material off the read-only bind mount before chown (compose mounts :ro).
  cat >"$OUT/postgres/start-postgres.sh" <<'EOF'
#!/bin/sh
set -eu
cp /rss-tls/server.pem /tmp/server.pem
cp /rss-tls/server-key.pem /tmp/server-key.pem
chown postgres:postgres /tmp/server.pem /tmp/server-key.pem
chmod 600 /tmp/server-key.pem
chmod 644 /tmp/server.pem
exec /usr/local/bin/docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file=/tmp/server.pem \
  -c ssl_key_file=/tmp/server-key.pem \
  -c ssl_min_protocol_version=TLSv1.2
EOF
  cat >"$OUT/postgres/00-require-tls.sh" <<'EOF'
#!/bin/sh
set -eu
sed -i -E 's/^host([[:space:]])/hostssl\1/' "$PGDATA/pg_hba.conf"
EOF
  chmod 755 "$OUT/postgres/start-postgres.sh" "$OUT/postgres/00-require-tls.sh"
}

write_rabbitmq_conf() {
  cat >"$OUT/rabbitmq/rabbitmq.conf" <<'EOF'
listeners.tcp = none
listeners.ssl.default = 5671
ssl_options.cacertfile = /rss-tls/ca.pem
ssl_options.certfile = /rss-tls/server.pem
ssl_options.keyfile = /rss-tls/server-key.pem
ssl_options.verify = verify_none
ssl_options.fail_if_no_peer_cert = false
loopback_users.guest = false
EOF
}

stage_minio_layout() {
  # MinIO --certs-dir expects public.crt / private.key and optional CAs/*.pem.
  cp "$OUT/minio/ca.pem" "$OUT/minio/CAs/rss-demo-s3-ca.pem"
  cp "$OUT/minio/server.pem" "$OUT/minio/public.crt"
  cp "$OUT/minio/server-key.pem" "$OUT/minio/private.key"
  chmod 644 "$OUT/minio/CAs/rss-demo-s3-ca.pem" "$OUT/minio/public.crt"
  chmod 600 "$OUT/minio/private.key"
}

need_openssl
wipe_if_forced
ensure_layout

if already_complete; then
  echo "keep existing demo TLS material under $OUT (set RSS_DEMO_TLS_FORCE=1 to regenerate)"
else
  gen_ca "$OUT/postgres" "rss-demo-pg-ca"
  gen_server "$OUT/postgres" "postgres" postgres localhost 127.0.0.1
  write_postgres_helpers

  gen_ca "$OUT/redis" "rss-demo-redis-ca"
  gen_server "$OUT/redis" "redis" redis localhost 127.0.0.1

  gen_ca "$OUT/rabbitmq" "rss-demo-amqp-ca"
  gen_server "$OUT/rabbitmq" "rabbitmq" rabbitmq localhost 127.0.0.1
  write_rabbitmq_conf

  # MinIO leaf lives under out/minio; CA copied into CAs/ for --certs-dir layout.
  gen_ca "$OUT/minio" "rss-demo-s3-ca"
  gen_server "$OUT/minio" "minio" minio localhost 127.0.0.1
  stage_minio_layout

  echo "wrote demo TLS material under $OUT"
fi

cat <<EOF
Demo TLS ready under $OUT.

Compose / runtime CA mounts (Deny + VerifyFull):
  RSS_REDIS_CA_CERT_PEM_PATH=/run/rss-demo-tls/redis/ca.pem
  RSS_AMQP_CA_CERT_PEM_PATH=/run/rss-demo-tls/rabbitmq/ca.pem
  RSS_S3_CA_CERT_PEM_PATH=/run/rss-demo-tls/minio/CAs/rss-demo-s3-ca.pem
  RSS_PG_SSL_ROOT_CERT_PATH=/run/rss-demo-tls/postgres/ca.pem

Regenerate: RSS_DEMO_TLS_FORCE=1 bash deploy/demo-tls/generate-demo-cas.sh
EOF
