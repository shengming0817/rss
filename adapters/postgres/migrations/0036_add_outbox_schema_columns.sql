-- 0036_add_outbox_schema_columns.sql
-- Persist outbox schema headers as physical columns. Relay treats these columns
-- as authoritative; metadata remains envelope carrier only.

ALTER TABLE outbox ADD COLUMN contract_version text;
ALTER TABLE outbox ADD COLUMN schema_hash text;
ALTER TABLE outbox ADD COLUMN causation_id text;

CREATE TEMP TABLE outbox_contract_schema_map ON COMMIT DROP AS
SELECT domain, contract_id, topic, 'v1'::text AS schema_version, schema_hash
FROM (
    VALUES
        ('_seed', 'seed.thing-happened', 'seed.thing-happened', 'sha256:016334bee5ce3a5205f0e31d2cb6f9ca20bbefc741f82111a08bb5506a50be23'),
        ('_seed', 'seed.do-thing', 'seed.commands.do-thing', 'sha256:a369f1548799cc66da6f3d539dfd3048f7e5d94e87e8b130c3d816b5da75a71b'),
        ('identity', 'identity.role-assigned', 'identity.role-assigned', 'sha256:7c7a931a40c99329cfd172d834191fdbc47c5d7f3307a4f09f4320693d7722e9'),
        ('identity', 'identity.role-revoked', 'identity.role-revoked', 'sha256:5907e4ae46c66b849cd4edca354d4e11abdd6209ad898f37196002fb65ed9a51'),
        ('identity', 'identity.session-created', 'identity.session-created', 'sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516'),
        ('settings', 'settings.config-version-changed', 'settings.config-version-changed', 'sha256:1e9ad2529beb3a274d37a734a5093847cb8418082f4d04f9cb180d3df181e864')
) AS v(domain, contract_id, topic, schema_hash);

CREATE TEMP TABLE outbox_schema_header_keys ON COMMIT DROP AS
SELECT 'schemaVersion'::text AS schema_version_key,
       'schemaHash'::text AS schema_hash_key;

DO $$
DECLARE
    bad_rows bigint;
    bad_sample text;
BEGIN
    WITH bad AS (
        SELECT o.event_id, o.domain, o.contract_id, o.topic
        FROM outbox AS o
        JOIN pg_temp.outbox_contract_schema_map AS cs
          ON o.domain = cs.domain
         AND o.contract_id = cs.contract_id
         AND o.topic = cs.topic
        CROSS JOIN pg_temp.outbox_schema_header_keys AS hk
        WHERE (o.metadata ? hk.schema_version_key AND o.metadata->>hk.schema_version_key <> cs.schema_version)
           OR (o.metadata ? hk.schema_hash_key AND o.metadata->>hk.schema_hash_key <> cs.schema_hash)
    )
    SELECT count(*),
           min(format('event_id=%s domain=%s contract_id=%s topic=%s', event_id, domain, contract_id, topic))
      INTO bad_rows, bad_sample
      FROM bad;

    IF bad_rows > 0 THEN
        RAISE EXCEPTION
            'outbox known contract schema headers mismatch generated map: bad_rows=%, sample=%',
            bad_rows,
            bad_sample;
    END IF;
END
$$;

UPDATE outbox AS o
SET contract_version = cs.schema_version,
    schema_hash = cs.schema_hash,
    metadata = o.metadata || jsonb_build_object(
        hk.schema_version_key, cs.schema_version,
        hk.schema_hash_key, cs.schema_hash
    )
FROM pg_temp.outbox_contract_schema_map AS cs
CROSS JOIN pg_temp.outbox_schema_header_keys AS hk
WHERE o.domain = cs.domain
  AND o.contract_id = cs.contract_id
  AND o.topic = cs.topic;

DO $$
DECLARE
    bad_rows bigint;
    bad_sample text;
BEGIN
    WITH bad AS (
        SELECT event_id, domain, contract_id, topic
        FROM outbox
        CROSS JOIN pg_temp.outbox_schema_header_keys AS hk
        WHERE contract_version IS NULL
           OR schema_hash IS NULL
           OR contract_version !~ '^v[0-9]+$'
           OR schema_hash !~ '^sha256:[0-9a-f]{64}$'
           OR (metadata ? hk.schema_version_key AND metadata->>hk.schema_version_key <> contract_version)
           OR (metadata ? hk.schema_hash_key AND metadata->>hk.schema_hash_key <> schema_hash)
    )
    SELECT count(*),
           min(format('event_id=%s domain=%s contract_id=%s topic=%s', event_id, domain, contract_id, topic))
      INTO bad_rows, bad_sample
      FROM bad;

    IF bad_rows > 0 THEN
        RAISE EXCEPTION
            'outbox schema column backfill requires generated known contract map: bad_rows=%, sample=%',
            bad_rows,
            bad_sample;
    END IF;
END
$$;

DROP TABLE pg_temp.outbox_contract_schema_map;
DROP TABLE pg_temp.outbox_schema_header_keys;

ALTER TABLE outbox ALTER COLUMN contract_version SET NOT NULL;
ALTER TABLE outbox ALTER COLUMN schema_hash SET NOT NULL;

ALTER TABLE outbox ADD CONSTRAINT outbox_contract_version_valid
    CHECK (contract_version ~ '^v[0-9]+$');
ALTER TABLE outbox ADD CONSTRAINT outbox_schema_hash_valid
    CHECK (schema_hash ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE outbox ADD CONSTRAINT outbox_causation_id_valid
    CHECK (causation_id IS NULL OR (length(causation_id) > 0 AND octet_length(causation_id) <= 256));
ALTER TABLE outbox ADD CONSTRAINT outbox_metadata_schema_matches_columns
    CHECK (
        COALESCE(metadata->>'schemaVersion' = contract_version, true)
        AND COALESCE(metadata->>'schemaHash' = schema_hash, true)
    );

CREATE INDEX idx_outbox_contract_schema
    ON outbox (domain, contract_id, contract_version, schema_hash);

DROP FUNCTION IF EXISTS rss_outbox_acquire_lease(text);
CREATE FUNCTION rss_outbox_acquire_lease(p_event_id text)
RETURNS TABLE(
    retry_count int,
    lease_token text,
    tenant_id text,
    metadata text,
    domain text,
    contract_id text,
    topic text,
    contract_version text,
    schema_hash text,
    now_epoch bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH outbox_status(name) AS (VALUES ('publishing'))
    UPDATE outbox
    SET status = outbox_status.name,
        lease_token = gen_random_uuid(),
        updated_at = now()
    FROM outbox_status
    WHERE event_id = p_event_id
      AND (
            status = 'pending'
         OR (status = outbox_status.name AND updated_at <= now() - make_interval(secs => 60))
      )
    RETURNING retry_count, lease_token::text, tenant_id::text, metadata::text, domain, contract_id, topic,
              contract_version, schema_hash, EXTRACT(EPOCH FROM now())::bigint
$$;

DROP FUNCTION IF EXISTS rss_outbox_mark_dlx(text, int, uuid);
CREATE FUNCTION rss_outbox_mark_dlx(
    p_event_id text,
    p_retry_count int,
    p_lease_token uuid
)
RETURNS TABLE(
    tenant_id text,
    domain text,
    contract_id text,
    topic text,
    payload bytea,
    metadata text,
    contract_version text,
    schema_hash text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH outbox_status(name) AS (VALUES ('publishing'))
    UPDATE outbox
    SET status = 'dlx',
        retry_count = p_retry_count,
        updated_at = now()
    FROM outbox_status
    WHERE event_id = p_event_id
      AND status = outbox_status.name
      AND lease_token = p_lease_token
    RETURNING tenant_id::text, domain, contract_id, topic, payload, metadata::text,
              contract_version, schema_hash
$$;

ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_mark_dlx(text, int, uuid) OWNER TO rss_outbox_maintenance;

REVOKE ALL ON FUNCTION rss_outbox_acquire_lease(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_mark_dlx(text, int, uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_outbox_acquire_lease(text) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_mark_dlx(text, int, uuid) TO rss_app;
