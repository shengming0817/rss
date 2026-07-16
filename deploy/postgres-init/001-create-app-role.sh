#!/usr/bin/env bash
# Create the demo serving role used by server. The role is intentionally not a
# superuser and does not have BYPASSRLS; runtime startup must fail if that stops
# being true.
set -euo pipefail

: "${POSTGRES_DB:?missing POSTGRES_DB}"
: "${POSTGRES_USER:?missing POSTGRES_USER}"
: "${POSTGRES_APP_USER:?missing POSTGRES_APP_USER}"
: "${POSTGRES_APP_PASSWORD:?missing POSTGRES_APP_PASSWORD}"
: "${RSS_PG_READ_USERNAME:?missing RSS_PG_READ_USERNAME}"
: "${RSS_PG_READ_PASSWORD:?missing RSS_PG_READ_PASSWORD}"
: "${RSS_PG_DLX_ARCHIVER_USERNAME:?missing RSS_PG_DLX_ARCHIVER_USERNAME}"
: "${RSS_PG_DLX_ARCHIVER_PASSWORD:?missing RSS_PG_DLX_ARCHIVER_PASSWORD}"
: "${RSS_PG_DLX_VERIFIER_USERNAME:?missing RSS_PG_DLX_VERIFIER_USERNAME}"
: "${RSS_PG_DLX_VERIFIER_PASSWORD:?missing RSS_PG_DLX_VERIFIER_PASSWORD}"
: "${RSS_PG_DLX_PURGER_USERNAME:?missing RSS_PG_DLX_PURGER_USERNAME}"
: "${RSS_PG_DLX_PURGER_PASSWORD:?missing RSS_PG_DLX_PURGER_PASSWORD}"

if [[ "$RSS_PG_DLX_ARCHIVER_USERNAME" != "rss_dlx_archiver" ]]; then
  echo "RSS_PG_DLX_ARCHIVER_USERNAME must be exactly rss_dlx_archiver" >&2
  exit 1
fi
if [[ "$RSS_PG_READ_USERNAME" != "rss_app_read" ]]; then
  echo "RSS_PG_READ_USERNAME must be exactly rss_app_read" >&2
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
  --set app_password="$POSTGRES_APP_PASSWORD" \
  --set dlx_archiver_password="$RSS_PG_DLX_ARCHIVER_PASSWORD" \
  --set dlx_verifier_password="$RSS_PG_DLX_VERIFIER_PASSWORD" \
  --set dlx_purger_password="$RSS_PG_DLX_PURGER_PASSWORD" \
  --set db_name="$POSTGRES_DB" <<'EOSQL'
\getenv read_password RSS_PG_READ_PASSWORD

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
  'ALTER ROLE %I LOGIN PASSWORD %L NOBYPASSRLS',
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
