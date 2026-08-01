-- Tenant-safe, metadata-only durable model for `settings.config-projection` (#1918).
-- The projection remains dormant until #1919 supplies the typed target and shadow replay wiring.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE public.settings_projection_generations (
    tenant_id                  uuid        NOT NULL,
    projection_id              text        NOT NULL,
    generation                 text        NOT NULL,
    definition_version         text        NOT NULL,
    definition_schema_digest   text        NOT NULL,
    input_generation           text        NOT NULL,
    high_water_lsn             bigint,
    created_at                 timestamptz NOT NULL DEFAULT pg_catalog.now(),
    updated_at                 timestamptz NOT NULL DEFAULT pg_catalog.now(),
    PRIMARY KEY (tenant_id, projection_id, generation),
    CONSTRAINT settings_projection_generations_projection_fixed
        CHECK (projection_id = 'settings.config-projection'),
    CONSTRAINT settings_projection_generations_generation_canonical
        CHECK (generation ~ '^[a-z0-9][a-z0-9._-]*$'),
    CONSTRAINT settings_projection_generations_generation_bounded
        CHECK (pg_catalog.octet_length(generation) BETWEEN 1 AND 256),
    CONSTRAINT settings_projection_generations_definition_version_canonical
        CHECK (definition_version ~ '^[a-z0-9][a-z0-9._-]*$'),
    CONSTRAINT settings_projection_generations_definition_digest_sha256
        CHECK (definition_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT settings_projection_generations_input_generation_sha256
        CHECK (input_generation ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT settings_projection_generations_high_water_nonnegative
        CHECK (high_water_lsn IS NULL OR high_water_lsn >= 0),
    CONSTRAINT settings_projection_generations_timestamps_ordered
        CHECK (created_at <= updated_at)
);

CREATE TABLE public.settings_config_projection_rows (
    tenant_id                  uuid        NOT NULL,
    projection_id              text        NOT NULL,
    generation                 text        NOT NULL,
    config_key                 text        NOT NULL,
    config_version             bigint      NOT NULL,
    change_kind                text        NOT NULL,
    source_event_id            text        NOT NULL,
    source_lsn                 bigint      NOT NULL,
    source_occurred_at_secs    bigint      NOT NULL,
    created_at                 timestamptz NOT NULL DEFAULT pg_catalog.now(),
    updated_at                 timestamptz NOT NULL DEFAULT pg_catalog.now(),
    PRIMARY KEY (tenant_id, projection_id, generation, config_key),
    CONSTRAINT settings_config_projection_rows_generation_fk
        FOREIGN KEY (tenant_id, projection_id, generation)
        REFERENCES public.settings_projection_generations (tenant_id, projection_id, generation),
    CONSTRAINT settings_config_projection_rows_projection_fixed
        CHECK (projection_id = 'settings.config-projection'),
    CONSTRAINT settings_config_projection_rows_generation_canonical
        CHECK (generation ~ '^[a-z0-9][a-z0-9._-]*$'),
    CONSTRAINT settings_config_projection_rows_generation_bounded
        CHECK (pg_catalog.octet_length(generation) BETWEEN 1 AND 256),
    CONSTRAINT settings_config_projection_rows_key_bounded
        CHECK (pg_catalog.octet_length(config_key) BETWEEN 1 AND 256),
    CONSTRAINT settings_config_projection_rows_version_positive
        CHECK (config_version > 0),
    CONSTRAINT settings_config_projection_rows_change_kind_closed
        CHECK (change_kind IN ('published', 'rolledBack', 'deleted')),
    CONSTRAINT settings_config_projection_rows_event_id_bounded
        CHECK (pg_catalog.octet_length(source_event_id) BETWEEN 1 AND 512),
    CONSTRAINT settings_config_projection_rows_lsn_nonnegative
        CHECK (source_lsn >= 0),
    CONSTRAINT settings_config_projection_rows_occurred_nonnegative
        CHECK (source_occurred_at_secs >= 0),
    CONSTRAINT settings_config_projection_rows_timestamps_ordered
        CHECK (created_at <= updated_at)
);

CREATE TABLE public.settings_projection_dedupe_receipts (
    tenant_id          uuid        NOT NULL,
    projection_id      text        NOT NULL,
    generation         text        NOT NULL,
    source_event_id    text        NOT NULL,
    source_lsn         bigint      NOT NULL,
    fact_digest        bytea       NOT NULL,
    applied_at         timestamptz NOT NULL DEFAULT pg_catalog.now(),
    PRIMARY KEY (tenant_id, projection_id, generation, source_event_id),
    CONSTRAINT settings_projection_dedupe_receipts_generation_fk
        FOREIGN KEY (tenant_id, projection_id, generation)
        REFERENCES public.settings_projection_generations (tenant_id, projection_id, generation),
    CONSTRAINT settings_projection_dedupe_receipts_source_lsn_unique
        UNIQUE (tenant_id, projection_id, generation, source_lsn),
    CONSTRAINT settings_projection_dedupe_receipts_projection_fixed
        CHECK (projection_id = 'settings.config-projection'),
    CONSTRAINT settings_projection_dedupe_receipts_generation_canonical
        CHECK (generation ~ '^[a-z0-9][a-z0-9._-]*$'),
    CONSTRAINT settings_projection_dedupe_receipts_generation_bounded
        CHECK (pg_catalog.octet_length(generation) BETWEEN 1 AND 256),
    CONSTRAINT settings_projection_dedupe_receipts_event_id_bounded
        CHECK (pg_catalog.octet_length(source_event_id) BETWEEN 1 AND 512),
    CONSTRAINT settings_projection_dedupe_receipts_lsn_nonnegative
        CHECK (source_lsn >= 0),
    CONSTRAINT settings_projection_dedupe_receipts_digest_sha256
        CHECK (pg_catalog.octet_length(fact_digest) = 32)
);

ALTER TABLE public.settings_projection_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.settings_projection_generations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.settings_projection_generations
    USING (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    );

ALTER TABLE public.settings_config_projection_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.settings_config_projection_rows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.settings_config_projection_rows
    USING (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    );

ALTER TABLE public.settings_projection_dedupe_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.settings_projection_dedupe_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.settings_projection_dedupe_receipts
    USING (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    );

REVOKE ALL ON TABLE public.settings_projection_generations, public.settings_config_projection_rows, public.settings_projection_dedupe_receipts FROM PUBLIC;
REVOKE ALL ON TABLE public.settings_projection_generations, public.settings_config_projection_rows, public.settings_projection_dedupe_receipts FROM rss_app, rss_app_read;

GRANT SELECT ON TABLE public.settings_projection_generations, public.settings_config_projection_rows, public.settings_projection_dedupe_receipts TO rss_app_read;
GRANT SELECT ON TABLE public.settings_projection_generations, public.settings_config_projection_rows, public.settings_projection_dedupe_receipts TO rss_app;

GRANT INSERT (
    tenant_id, projection_id, generation, definition_version,
    definition_schema_digest, input_generation, high_water_lsn
) ON public.settings_projection_generations TO rss_app;
GRANT UPDATE (high_water_lsn, updated_at)
    ON public.settings_projection_generations TO rss_app;

GRANT INSERT (
    tenant_id, projection_id, generation, config_key, config_version, change_kind,
    source_event_id, source_lsn, source_occurred_at_secs
) ON public.settings_config_projection_rows TO rss_app;
GRANT UPDATE (
    config_version, change_kind, source_event_id, source_lsn,
    source_occurred_at_secs, updated_at
) ON public.settings_config_projection_rows TO rss_app;

GRANT INSERT (
    tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest
) ON public.settings_projection_dedupe_receipts TO rss_app;

REVOKE UPDATE ON TABLE public.settings_projection_dedupe_receipts FROM rss_app, rss_app_read;
REVOKE DELETE, TRUNCATE ON TABLE public.settings_projection_generations, public.settings_config_projection_rows, public.settings_projection_dedupe_receipts FROM rss_app, rss_app_read;
