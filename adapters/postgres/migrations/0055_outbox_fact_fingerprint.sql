-- 0055_outbox_fact_fingerprint.sql
-- Canonical same-fact/conflict identity for mutable and CDC outbox writes (#1739).
--
-- The Rust typed funnel is the producer-side source.  These immutable SQL functions reproduce
-- the same versioned encoding so stored generated columns cannot be omitted or forged, and so
-- existing mutable rows receive a deterministic backfill.  outbox_log predates partition_key;
-- because that information is unrecoverable, a non-empty CDC ledger fails closed.  The explicit
-- lock closes the check/DDL race with an old CDC writer and is held until the migration commits.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE outbox_log IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM outbox_log LIMIT 1) THEN
        RAISE EXCEPTION 'outbox_log must be empty before canonical fact fingerprint migration';
    END IF;
END
$$;

-- A stored generated column rewrites the mutable heap.  Fail before taking its cutover lock when
-- the bounded online migration envelope is exceeded; larger ledgers require an explicitly sized
-- maintenance window, not an unbounded application-start migration.
DO $$
BEGIN
    IF pg_total_relation_size('outbox'::regclass) > 10737418240 THEN
        RAISE EXCEPTION 'outbox exceeds 10 GiB canonical fingerprint migration capacity limit';
    END IF;
END
$$;

LOCK TABLE outbox IN ACCESS EXCLUSIVE MODE;

ALTER TABLE outbox_log ADD COLUMN partition_key text NULL;

CREATE FUNCTION rss_outbox_fact_frame(
    p_type_tag integer,
    p_option_tag integer,
    p_value bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT set_byte('\x00'::bytea, 0, p_type_tag)
        || set_byte('\x00'::bytea, 0, p_option_tag)
        || int8send(octet_length(p_value)::bigint)
        || p_value
$$;

CREATE FUNCTION rss_outbox_canonical_number(p_value jsonb)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    rendered text := p_value::text;
    negative boolean := false;
    dot_at integer;
    fractional_digits integer := 0;
    trailing_zeroes integer;
    digits text;
BEGIN
    IF jsonb_typeof(p_value) <> 'number' THEN
        RAISE EXCEPTION 'outbox canonical number requires JSON number';
    END IF;
    IF left(rendered, 1) = '-' THEN
        negative := true;
        rendered := substring(rendered FROM 2);
    END IF;

    -- jsonb stores numbers as exact PostgreSQL numeric and renders without an exponent. Convert
    -- that rendering to the frozen `<integer-coefficient>e<base10-exponent>` spelling.
    dot_at := strpos(rendered, '.');
    IF dot_at > 0 THEN
        fractional_digits := length(rendered) - dot_at;
        digits := replace(rendered, '.', '');
    ELSE
        digits := rendered;
    END IF;
    digits := regexp_replace(digits, '^0+', '');
    IF digits = '' THEN
        RETURN convert_to('0e0', 'UTF8');
    END IF;
    trailing_zeroes := length(digits) - length(rtrim(digits, '0'));
    digits := rtrim(digits, '0');
    RETURN convert_to(
        CASE WHEN negative THEN '-' ELSE '' END
            || digits || 'e' || (trailing_zeroes - fractional_digits)::text,
        'UTF8'
    );
END
$$;

CREATE FUNCTION rss_outbox_canonical_json(
    p_value jsonb,
    p_strip_volatile_root boolean
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    value_kind text;
    encoded bytea;
    item record;
    first_item boolean := true;
BEGIN
    value_kind := jsonb_typeof(p_value);
    IF value_kind = 'number' THEN
        RETURN public.rss_outbox_canonical_number(p_value);
    END IF;
    IF value_kind IN ('null', 'boolean', 'string') THEN
        RETURN convert_to(p_value::text, 'UTF8');
    END IF;

    IF value_kind = 'array' THEN
        encoded := convert_to('[', 'UTF8');
        FOR item IN
            SELECT value
            FROM jsonb_array_elements(p_value) WITH ORDINALITY AS elements(value, ordinal)
            ORDER BY ordinal
        LOOP
            IF NOT first_item THEN
                encoded := encoded || convert_to(',', 'UTF8');
            END IF;
            encoded := encoded || public.rss_outbox_canonical_json(item.value, false);
            first_item := false;
        END LOOP;
        RETURN encoded || convert_to(']', 'UTF8');
    END IF;

    IF value_kind = 'object' THEN
        encoded := convert_to('{', 'UTF8');
        FOR item IN
            SELECT key, value
            FROM jsonb_each(p_value)
            WHERE NOT (
                p_strip_volatile_root
                AND key IN ('occurredAt', 'trace', 'correlation')
            )
            ORDER BY key COLLATE "C"
        LOOP
            IF NOT first_item THEN
                encoded := encoded || convert_to(',', 'UTF8');
            END IF;
            encoded := encoded
                || convert_to(to_json(item.key)::text, 'UTF8')
                || convert_to(':', 'UTF8')
                || public.rss_outbox_canonical_json(item.value, false);
            first_item := false;
        END LOOP;
        RETURN encoded || convert_to('}', 'UTF8');
    END IF;

    RAISE EXCEPTION 'unsupported outbox metadata JSON kind';
END
$$;

CREATE FUNCTION rss_outbox_fact_fingerprint(
    p_event_id text,
    p_tenant_id text,
    p_domain text,
    p_topic text,
    p_contract_id text,
    p_contract_version text,
    p_schema_hash text,
    p_payload bytea,
    p_partition_key text,
    p_causation_id text,
    p_metadata jsonb
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
    SELECT sha256(
        rss_outbox_fact_frame(1, 1, convert_to('rss-outbox-fact-v1', 'UTF8'))
        || rss_outbox_fact_frame(1, 1, convert_to(p_event_id, 'UTF8'))
        || rss_outbox_fact_frame(1, 1, convert_to(p_tenant_id, 'UTF8'))
        || rss_outbox_fact_frame(1, 1, convert_to(p_domain, 'UTF8'))
        || rss_outbox_fact_frame(1, 1, convert_to(p_topic, 'UTF8'))
        || rss_outbox_fact_frame(1, 1, convert_to(p_contract_id, 'UTF8'))
        || rss_outbox_fact_frame(1, 1, convert_to(p_contract_version, 'UTF8'))
        || rss_outbox_fact_frame(1, 1, convert_to(p_schema_hash, 'UTF8'))
        || rss_outbox_fact_frame(2, 1, p_payload)
        || CASE
            WHEN p_partition_key IS NULL THEN rss_outbox_fact_frame(1, 0, '\x'::bytea)
            ELSE rss_outbox_fact_frame(1, 1, convert_to(p_partition_key, 'UTF8'))
           END
        || CASE
            WHEN p_causation_id IS NULL THEN rss_outbox_fact_frame(1, 0, '\x'::bytea)
            ELSE rss_outbox_fact_frame(1, 1, convert_to(p_causation_id, 'UTF8'))
           END
        || rss_outbox_fact_frame(3, 1, rss_outbox_canonical_json(p_metadata, true))
    )
$$;

-- Ownership stays with the short-lived migrator role.  rss_app is the long-lived serving role and
-- must not own schema objects: function ownership would let it ALTER/DROP these generated-column
-- dependencies and dismantle the database-side fingerprint invariant.

REVOKE ALL ON FUNCTION rss_outbox_fact_frame(integer, integer, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_canonical_number(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_canonical_json(jsonb, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_fact_fingerprint(text, text, text, text, text, text, text, bytea, text, text, jsonb)
    FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_outbox_fact_frame(integer, integer, bytea) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_canonical_number(jsonb) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_canonical_json(jsonb, boolean) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_fact_fingerprint(text, text, text, text, text, text, text, bytea, text, text, jsonb)
    TO rss_app;

-- Relay state functions are SECURITY DEFINER-owned by this narrowly scoped role. PostgreSQL
-- reevaluates stored generated expressions on their UPDATEs, so it needs only EXECUTE on the
-- canonical helpers; it receives no ownership and no broader schema capability.
GRANT EXECUTE ON FUNCTION rss_outbox_fact_frame(integer, integer, bytea) TO rss_outbox_maintenance;
GRANT EXECUTE ON FUNCTION rss_outbox_canonical_number(jsonb) TO rss_outbox_maintenance;
GRANT EXECUTE ON FUNCTION rss_outbox_canonical_json(jsonb, boolean) TO rss_outbox_maintenance;
GRANT EXECUTE ON FUNCTION rss_outbox_fact_fingerprint(text, text, text, text, text, text, text, bytea, text, text, jsonb)
    TO rss_outbox_maintenance;

ALTER TABLE outbox
    ADD COLUMN fact_fingerprint bytea GENERATED ALWAYS AS (
        rss_outbox_fact_fingerprint(
            event_id,
            tenant_id::text,
            domain,
            topic,
            contract_id,
            contract_version,
            schema_hash,
            payload,
            partition_key,
            causation_id,
            metadata
        )
    ) STORED;

ALTER TABLE outbox_log
    ADD COLUMN fact_fingerprint bytea GENERATED ALWAYS AS (
        rss_outbox_fact_fingerprint(
            event_id,
            tenant_id::text,
            aggregate_type,
            topic,
            contract_id,
            contract_version,
            schema_hash,
            payload,
            partition_key,
            causation_id,
            metadata
        )
    ) STORED;

ALTER TABLE outbox
    ALTER COLUMN fact_fingerprint SET NOT NULL,
    ADD CONSTRAINT outbox_fact_fingerprint_valid
        CHECK (octet_length(fact_fingerprint) = 32);

ALTER TABLE outbox_log
    ALTER COLUMN fact_fingerprint SET NOT NULL,
    ADD CONSTRAINT outbox_log_fact_fingerprint_valid
        CHECK (octet_length(fact_fingerprint) = 32),
    ADD CONSTRAINT outbox_log_partition_key_valid
        CHECK (
            partition_key IS NULL
            OR (length(partition_key) > 0 AND octet_length(partition_key) <= 256)
        );

-- A fact-conflict quarantine is durable operator-visible state. It is intentionally a closed
-- nullable enum: NULL is active/no quarantine, and no compatibility/free-form reason exists.
ALTER TABLE reconcile_targets
    ADD COLUMN disabled_reason text NULL,
    ADD CONSTRAINT reconcile_targets_disabled_reason_valid
        CHECK (
            disabled_reason IS NULL
            OR (status = 'disabled' AND disabled_reason = 'fact_conflict')
        );

-- INVARIANT: OUTBOX-FACT-FUNNEL-01
-- Hard: fingerprint is a stored generated column; producer SQL cannot omit or supply it.
-- Medium: Rust/SQL golden parity and pg-tenant-tx-guard prevent algorithm/callsite drift.
