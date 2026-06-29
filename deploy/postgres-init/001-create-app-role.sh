#!/usr/bin/env bash
# Create the demo serving role used by server. The role is intentionally not a
# superuser and does not have BYPASSRLS; runtime startup must fail if that stops
# being true.
set -euo pipefail

: "${POSTGRES_DB:?missing POSTGRES_DB}"
: "${POSTGRES_USER:?missing POSTGRES_USER}"
: "${POSTGRES_APP_USER:?missing POSTGRES_APP_USER}"
: "${POSTGRES_APP_PASSWORD:?missing POSTGRES_APP_PASSWORD}"

psql \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set app_user="$POSTGRES_APP_USER" \
  --set app_password="$POSTGRES_APP_PASSWORD" \
  --set db_name="$POSTGRES_DB" <<'EOSQL'
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
SELECT format('GRANT rss_app TO %I', :'app_user')\gexec
EOSQL
