-- 0035_backfill_outbox_schema_headers.sql — backfill schema headers for legacy outbox rows.

WITH contract_schema(domain, contract_id, topic, schema_version, schema_hash) AS (
    VALUES
        ('_seed', 'seed.thing-happened', 'seed.thing-happened', 'v1', 'sha256:016334bee5ce3a5205f0e31d2cb6f9ca20bbefc741f82111a08bb5506a50be23'),
        ('_seed', 'seed.do-thing', 'seed.commands.do-thing', 'v1', 'sha256:a369f1548799cc66da6f3d539dfd3048f7e5d94e87e8b130c3d816b5da75a71b'),
        ('identity', 'identity.role-assigned', 'identity.role-assigned', 'v1', 'sha256:7c7a931a40c99329cfd172d834191fdbc47c5d7f3307a4f09f4320693d7722e9'),
        ('identity', 'identity.role-revoked', 'identity.role-revoked', 'v1', 'sha256:5907e4ae46c66b849cd4edca354d4e11abdd6209ad898f37196002fb65ed9a51'),
        ('identity', 'identity.session-created', 'identity.session-created', 'v1', 'sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516'),
        ('settings', 'settings.config-version-changed', 'settings.config-version-changed', 'v1', 'sha256:1e9ad2529beb3a274d37a734a5093847cb8418082f4d04f9cb180d3df181e864')
)
UPDATE outbox AS o
SET metadata = jsonb_set(
    jsonb_set(
        o.metadata,
        '{schemaVersion}',
        to_jsonb(COALESCE(o.metadata->>'schemaVersion', cs.schema_version)),
        true
    ),
    '{schemaHash}',
    to_jsonb(COALESCE(o.metadata->>'schemaHash', cs.schema_hash)),
    true
)
FROM contract_schema AS cs
WHERE o.domain = cs.domain
  AND o.contract_id = cs.contract_id
  AND o.topic = cs.topic
  AND (
      o.metadata->>'schemaVersion' IS NULL
      OR o.metadata->>'schemaHash' IS NULL
  );
