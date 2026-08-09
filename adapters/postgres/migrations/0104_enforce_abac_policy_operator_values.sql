-- #1947/#1948: durable Common ABAC operator/value boundary for policy JSONB.
-- Pre-GA, one-way, non-rolling hard cut: no coercion, truncation, deletion, or legacy fallback.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

-- PostgreSQL database encoding is immutable after CREATE DATABASE. Prove that every existing 0102
-- octet_length(text) CHECK is already measuring UTF-8 bytes; do not silently reinterpret it.
DO $$
BEGIN
    IF pg_catalog.current_setting('server_encoding') IS DISTINCT FROM 'UTF8' THEN
        RAISE EXCEPTION '0104: server_encoding must be UTF8 for Common ABAC byte invariants';
    END IF;
END $$;

CREATE FUNCTION public.rss_abac_policy_operator_values_valid_v1(document jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    rule jsonb;
    operator_doc jsonb;
    operand jsonb;
    scalar jsonb;
    previous_scalar jsonb;
    values_doc jsonb;
    scalar_text text;
    value_type text;
BEGIN
    -- Only the traversal container is required here. Effect, obligations and effective windows remain
    -- owned by the Rust RulesDoc decoder; this function closes the operator/value subtree exclusively.
    IF jsonb_typeof(document) IS DISTINCT FROM 'object'
       OR jsonb_typeof(document -> 'rules') IS DISTINCT FROM 'array'
       OR jsonb_array_length(document -> 'rules') < 1 THEN
        RETURN false;
    END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(document -> 'rules') AS entry(value)
    LOOP
        IF jsonb_typeof(rule) IS DISTINCT FROM 'object'
           OR jsonb_typeof(rule -> 'condition') IS DISTINCT FROM 'object'
           OR jsonb_typeof(rule #> '{condition,operator}') IS DISTINCT FROM 'object' THEN
            RETURN false;
        END IF;
        operator_doc := rule #> '{condition,operator}';
        IF (SELECT count(*) FROM jsonb_object_keys(operator_doc)) <> 3
           OR NOT (operator_doc ?& ARRAY['family', 'predicate', 'operand'])
           OR jsonb_typeof(operator_doc -> 'family') IS DISTINCT FROM 'string'
           OR jsonb_typeof(operator_doc -> 'predicate') IS DISTINCT FROM 'string'
           OR jsonb_typeof(operator_doc -> 'operand') IS DISTINCT FROM 'object' THEN
            RETURN false;
        END IF;
        operand := operator_doc -> 'operand';

        CASE operator_doc ->> 'family'
        WHEN 'equality' THEN
            IF operator_doc ->> 'predicate' NOT IN ('eq', 'ne') THEN
                RETURN false;
            END IF;
            CASE operand ->> 'kind'
            WHEN 'attribute' THEN
                IF (SELECT count(*) FROM jsonb_object_keys(operand)) <> 3
                   OR NOT (operand ?& ARRAY['kind', 'valueType', 'attribute'])
                   OR operand ->> 'valueType' IS DISTINCT FROM 'string'
                   OR jsonb_typeof(operand -> 'attribute') IS DISTINCT FROM 'string'
                   OR operand ->> 'attribute' NOT IN
                      ('principal.kind', 'principal.id', 'tenant.id', 'contract.id', 'permission', 'resource.id') THEN
                    RETURN false;
                END IF;
            WHEN 'literal' THEN
                IF (SELECT count(*) FROM jsonb_object_keys(operand)) <> 3
                   OR NOT (operand ?& ARRAY['kind', 'valueType', 'value'])
                   OR jsonb_typeof(operand -> 'valueType') IS DISTINCT FROM 'string' THEN
                    RETURN false;
                END IF;
                value_type := operand ->> 'valueType';
                scalar := operand -> 'value';
                scalar_text := scalar #>> '{}';
                CASE value_type
                WHEN 'string' THEN
                    IF jsonb_typeof(scalar) IS DISTINCT FROM 'string'
                       OR octet_length(pg_catalog.convert_to(scalar_text, 'UTF8')) > 256 THEN RETURN false; END IF;
                WHEN 'boolean' THEN
                    IF jsonb_typeof(scalar) IS DISTINCT FROM 'boolean' THEN RETURN false; END IF;
                WHEN 'integer' THEN
                    IF jsonb_typeof(scalar) IS DISTINCT FROM 'number'
                       OR scalar_text !~ '^-?(0|[1-9][0-9]*)$' THEN RETURN false; END IF;
                    IF scalar_text::numeric NOT BETWEEN -9223372036854775808 AND 9223372036854775807
                    THEN RETURN false; END IF;
                WHEN 'decimal' THEN
                    IF jsonb_typeof(scalar) IS DISTINCT FROM 'string'
                       OR octet_length(scalar_text) NOT BETWEEN 1 AND 64
                       OR scalar_text !~ '^(0|-?[1-9][0-9]*|(-?0|-?[1-9][0-9]*)\.[0-9]*[1-9])$'
                    THEN RETURN false; END IF;
                ELSE RETURN false;
                END CASE;
            ELSE RETURN false;
            END CASE;

        WHEN 'ordering' THEN
            IF operator_doc ->> 'predicate' NOT IN ('gt', 'ge', 'lt', 'le')
               OR (SELECT count(*) FROM jsonb_object_keys(operand)) <> 3
               OR NOT (operand ?& ARRAY['kind', 'valueType', 'value'])
               OR operand ->> 'kind' IS DISTINCT FROM 'literal'
               OR jsonb_typeof(operand -> 'valueType') IS DISTINCT FROM 'string' THEN
                RETURN false;
            END IF;
            value_type := operand ->> 'valueType';
            scalar := operand -> 'value';
            scalar_text := scalar #>> '{}';
            CASE value_type
            WHEN 'integer' THEN
                IF jsonb_typeof(scalar) IS DISTINCT FROM 'number'
                   OR scalar_text !~ '^-?(0|[1-9][0-9]*)$' THEN RETURN false; END IF;
                IF scalar_text::numeric NOT BETWEEN -9223372036854775808 AND 9223372036854775807
                THEN RETURN false; END IF;
            WHEN 'decimal' THEN
                IF jsonb_typeof(scalar) IS DISTINCT FROM 'string'
                   OR octet_length(scalar_text) NOT BETWEEN 1 AND 64
                   OR scalar_text !~ '^(0|-?[1-9][0-9]*|(-?0|-?[1-9][0-9]*)\.[0-9]*[1-9])$'
                THEN RETURN false; END IF;
            ELSE RETURN false;
            END CASE;

        WHEN 'membership' THEN
            IF operator_doc ->> 'predicate' NOT IN ('in', 'notIn')
               OR (SELECT count(*) FROM jsonb_object_keys(operand)) <> 3
               OR NOT (operand ?& ARRAY['kind', 'valueType', 'values'])
               OR operand ->> 'kind' IS DISTINCT FROM 'set'
               OR jsonb_typeof(operand -> 'valueType') IS DISTINCT FROM 'string'
               OR jsonb_typeof(operand -> 'values') IS DISTINCT FROM 'array' THEN
                RETURN false;
            END IF;
            values_doc := operand -> 'values';
            IF jsonb_array_length(values_doc) NOT BETWEEN 1 AND 32
               OR (SELECT count(*) FROM jsonb_array_elements(values_doc))
                  <> (SELECT count(DISTINCT value) FROM jsonb_array_elements(values_doc) AS item(value)) THEN
                RETURN false;
            END IF;
            value_type := operand ->> 'valueType';
            previous_scalar := NULL;
            FOR scalar IN SELECT value FROM jsonb_array_elements(values_doc) AS item(value)
            LOOP
                scalar_text := scalar #>> '{}';
                CASE value_type
                WHEN 'string' THEN
                    IF jsonb_typeof(scalar) IS DISTINCT FROM 'string'
                       OR octet_length(pg_catalog.convert_to(scalar_text, 'UTF8')) > 256 THEN RETURN false; END IF;
                WHEN 'boolean' THEN
                    IF jsonb_typeof(scalar) IS DISTINCT FROM 'boolean' THEN RETURN false; END IF;
                WHEN 'integer' THEN
                    IF jsonb_typeof(scalar) IS DISTINCT FROM 'number'
                       OR scalar_text !~ '^-?(0|[1-9][0-9]*)$' THEN RETURN false; END IF;
                    IF scalar_text::numeric NOT BETWEEN -9223372036854775808 AND 9223372036854775807
                    THEN RETURN false; END IF;
                WHEN 'decimal' THEN
                    IF jsonb_typeof(scalar) IS DISTINCT FROM 'string'
                       OR octet_length(scalar_text) NOT BETWEEN 1 AND 64
                       OR scalar_text !~ '^(0|-?[1-9][0-9]*|(-?0|-?[1-9][0-9]*)\.[0-9]*[1-9])$'
                    THEN RETURN false; END IF;
                ELSE RETURN false;
                END CASE;

                -- Mirror PolicyValueSet::new's homogeneous strict ordering without depending on
                -- database collation. Canonical strings use UTF-8 byte order; numeric kinds use
                -- their typed value order.
                IF previous_scalar IS NOT NULL THEN
                    CASE value_type
                    WHEN 'string' THEN
                        IF pg_catalog.convert_to(previous_scalar #>> '{}', 'UTF8') >=
                           pg_catalog.convert_to(scalar_text, 'UTF8') THEN RETURN false; END IF;
                    WHEN 'boolean' THEN
                        IF (previous_scalar #>> '{}')::boolean >= scalar_text::boolean THEN RETURN false; END IF;
                    WHEN 'integer', 'decimal' THEN
                        IF (previous_scalar #>> '{}')::numeric >= scalar_text::numeric THEN RETURN false; END IF;
                    ELSE RETURN false;
                    END CASE;
                END IF;
                previous_scalar := scalar;
            END LOOP;

        WHEN 'string' THEN
            IF operator_doc ->> 'predicate' NOT IN ('startsWith', 'endsWith', 'contains', 'glob', 'regex')
               OR (SELECT count(*) FROM jsonb_object_keys(operand)) <> 3
               OR NOT (operand ?& ARRAY['kind', 'valueType', 'value'])
               OR operand ->> 'kind' IS DISTINCT FROM 'pattern'
               OR operand ->> 'valueType' IS DISTINCT FROM 'string'
               OR jsonb_typeof(operand -> 'value') IS DISTINCT FROM 'string'
               OR octet_length(pg_catalog.convert_to(operand ->> 'value', 'UTF8')) NOT BETWEEN 1 AND 256
               OR operand ->> 'value' ~ '[[:cntrl:]]' THEN
                RETURN false;
            END IF;
        ELSE
            RETURN false;
        END CASE;
    END LOOP;
    RETURN true;
EXCEPTION
    WHEN data_exception OR numeric_value_out_of_range OR invalid_text_representation THEN
        RETURN false;
END;
$$;

REVOKE ALL ON FUNCTION public.rss_abac_policy_operator_values_valid_v1(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_abac_policy_operator_values_valid_v1(jsonb) TO rss_app;

LOCK TABLE public.abac_policies IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    invalid_count bigint;
    invalid_coordinates text;
BEGIN
    SELECT count(*)
      INTO invalid_count
      FROM public.abac_policies
     WHERE NOT public.rss_abac_policy_operator_values_valid_v1(rules);
    IF invalid_count > 0 THEN
        SELECT string_agg(tenant_id::text || '/' || id, ', ' ORDER BY tenant_id, id)
          INTO invalid_coordinates
          FROM (
              SELECT tenant_id, id
                FROM public.abac_policies
               WHERE NOT public.rss_abac_policy_operator_values_valid_v1(rules)
               ORDER BY tenant_id, id
               LIMIT 20
          ) AS invalid_sample;
        RAISE EXCEPTION
            '0104: invalid ABAC policy operator values: count=%, sample coordinates=%, truncated=%',
            invalid_count,
            invalid_coordinates,
            CASE WHEN invalid_count > 20 THEN 'true' ELSE 'false' END;
    END IF;
END $$;

ALTER TABLE public.abac_policies
    ADD CONSTRAINT abac_policies_operator_values_v1
    CHECK (public.rss_abac_policy_operator_values_valid_v1(rules));

COMMENT ON CONSTRAINT abac_policies_operator_values_v1 ON public.abac_policies IS
    'Closed RSS Common ABAC v1 operator/value subtree; malformed or out-of-bound values are rejected.';
