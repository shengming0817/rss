-- #1238: one-way, non-rolling RSS Common ABAC Profile cutover.
-- Old gt/lt rules were untyped f64 comparisons. Their LHS type cannot be inferred without changing
-- semantics, so the migration fails instead of guessing, coercing, or deleting policy data.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

-- Freeze every legacy writer before preflight so no old-shape row can race the validation/rewrite.
LOCK TABLE abac_policies, resource_attributes IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    ambiguous text;
    malformed text;
BEGIN
    SELECT string_agg(DISTINCT id, ', ' ORDER BY id)
      INTO malformed
      FROM abac_policies
     WHERE jsonb_typeof(rules) IS DISTINCT FROM 'object'
        OR (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(rules) = 'object' THEN rules ELSE '{}'::jsonb END)) <> 1
        OR jsonb_typeof(rules -> 'rules') IS DISTINCT FROM 'array';
    IF malformed IS NOT NULL THEN
        RAISE EXCEPTION '0102: malformed abac_policies.rules documents: %', malformed;
    END IF;

    SELECT string_agg(DISTINCT policy.id, ', ' ORDER BY policy.id)
      INTO ambiguous
      FROM abac_policies AS policy,
           LATERAL jsonb_array_elements(policy.rules -> 'rules') AS rule
     WHERE rule #>> '{condition,operator,kind}' IN ('gt', 'lt');
    IF ambiguous IS NOT NULL THEN
        RAISE EXCEPTION '0102: ambiguous legacy numeric policies must be rewritten before migration: %', ambiguous;
    END IF;

    SELECT string_agg(DISTINCT policy.id, ', ' ORDER BY policy.id)
      INTO malformed
      FROM abac_policies AS policy,
           LATERAL jsonb_array_elements(policy.rules -> 'rules') AS rule
     WHERE jsonb_typeof(rule) IS DISTINCT FROM 'object'
        OR (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(rule) = 'object' THEN rule ELSE '{}'::jsonb END)) <> 3
        OR NOT (rule ?& ARRAY['condition', 'effect', 'obligations'])
        OR jsonb_typeof(rule -> 'condition') IS DISTINCT FROM 'object'
        OR (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(rule -> 'condition') = 'object' THEN rule -> 'condition' ELSE '{}'::jsonb END)) <> 2
        OR NOT ((rule -> 'condition') ?& ARRAY['attribute', 'operator'])
        OR jsonb_typeof(rule #> '{condition,attribute}') IS DISTINCT FROM 'string'
        OR coalesce(octet_length(rule #>> '{condition,attribute}'), 0) NOT BETWEEN 1 AND 128
        OR coalesce(rule #>> '{condition,attribute}', '') !~ '^[A-Za-z0-9_.-]+$'
        OR jsonb_typeof(rule -> 'effect') IS DISTINCT FROM 'string'
        OR rule ->> 'effect' NOT IN ('allow', 'deny')
        OR jsonb_typeof(rule -> 'obligations') IS DISTINCT FROM 'object'
        OR (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(rule -> 'obligations') = 'object' THEN rule -> 'obligations' ELSE '{}'::jsonb END)) <> 2
        OR NOT ((rule -> 'obligations') ?& ARRAY['rowScope', 'fieldMask'])
        OR (
            rule #> '{obligations,rowScope}' <> 'null'::jsonb
            AND (
                jsonb_typeof(rule #> '{obligations,rowScope}') IS DISTINCT FROM 'string'
                OR rule #>> '{obligations,rowScope}' NOT IN ('selfOnly', 'device', 'tenant')
            )
        )
        OR jsonb_typeof(rule #> '{obligations,fieldMask}') IS DISTINCT FROM 'array'
        OR EXISTS (
            SELECT 1
              FROM jsonb_array_elements(
                  CASE WHEN jsonb_typeof(rule #> '{obligations,fieldMask}') = 'array'
                       THEN rule #> '{obligations,fieldMask}' ELSE '[]'::jsonb END
              ) AS field(value)
             WHERE jsonb_typeof(field.value) IS DISTINCT FROM 'string'
                OR coalesce(octet_length(field.value #>> '{}'), 0) NOT BETWEEN 1 AND 128
                OR coalesce(field.value #>> '{}', '') !~ '^[A-Za-z0-9_.-]+$'
        )
        OR jsonb_typeof(rule #> '{condition,operator}') IS DISTINCT FROM 'object'
        OR rule #>> '{condition,operator,kind}' IS NULL
        OR rule #>> '{condition,operator,kind}' NOT IN ('eq', 'ne', 'like', 'eqAttr')
        OR (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(rule #> '{condition,operator}') = 'object' THEN rule #> '{condition,operator}' ELSE '{}'::jsonb END)) <> 2
        OR CASE rule #>> '{condition,operator,kind}'
             WHEN 'eq' THEN jsonb_typeof(rule #> '{condition,operator,value}') IS DISTINCT FROM 'string'
                            OR coalesce(octet_length(rule #>> '{condition,operator,value}'), 257) > 256
             WHEN 'ne' THEN jsonb_typeof(rule #> '{condition,operator,value}') IS DISTINCT FROM 'string'
                            OR coalesce(octet_length(rule #>> '{condition,operator,value}'), 257) > 256
             WHEN 'like' THEN jsonb_typeof(rule #> '{condition,operator,pattern}') IS DISTINCT FROM 'string'
                              OR coalesce(octet_length(rule #>> '{condition,operator,pattern}'), 0) NOT BETWEEN 1 AND 256
                              OR coalesce(rule #>> '{condition,operator,pattern}', '') ~ '[[:cntrl:]]'
             WHEN 'eqAttr' THEN rule #>> '{condition,operator,attribute}' IS NULL
                                OR rule #>> '{condition,operator,attribute}' NOT IN
                                   ('principal.kind', 'principal.id', 'tenant.id', 'contract.id', 'permission', 'resource.id')
             ELSE true
           END;
    IF malformed IS NOT NULL THEN
        RAISE EXCEPTION '0102: malformed or out-of-bounds legacy ABAC policies: %', malformed;
    END IF;

    SELECT string_agg(
               tenant_id::text || '/' || resource_id::text || '/' || attribute_key,
               ', ' ORDER BY tenant_id, resource_id, attribute_key
           )
      INTO malformed
      FROM resource_attributes
     WHERE octet_length(attribute_value) > 256;
    IF malformed IS NOT NULL THEN
        RAISE EXCEPTION '0102: resource attributes exceed 256 UTF-8 bytes: %', malformed;
    END IF;
END $$;

UPDATE abac_policies AS policy
SET rules = jsonb_build_object(
    'rules',
    (
        SELECT coalesce(jsonb_agg(
            jsonb_set(
                rule,
                '{condition,operator}',
                CASE rule #>> '{condition,operator,kind}'
                    WHEN 'eq' THEN jsonb_build_object(
                        'family', 'equality', 'predicate', 'eq',
                        'operand', jsonb_build_object('kind', 'literal', 'valueType', 'string', 'value', rule #> '{condition,operator,value}')
                    )
                    WHEN 'ne' THEN jsonb_build_object(
                        'family', 'equality', 'predicate', 'ne',
                        'operand', jsonb_build_object('kind', 'literal', 'valueType', 'string', 'value', rule #> '{condition,operator,value}')
                    )
                    WHEN 'like' THEN jsonb_build_object(
                        'family', 'string', 'predicate', 'glob',
                        'operand', jsonb_build_object('kind', 'pattern', 'valueType', 'string', 'value', rule #> '{condition,operator,pattern}')
                    )
                    WHEN 'eqAttr' THEN jsonb_build_object(
                        'family', 'equality', 'predicate', 'eq',
                        'operand', jsonb_build_object('kind', 'attribute', 'valueType', 'string', 'attribute', rule #> '{condition,operator,attribute}')
                    )
                END,
                false
            )
            ORDER BY ordinal
        ), '[]'::jsonb)
        FROM jsonb_array_elements(policy.rules -> 'rules') WITH ORDINALITY AS entry(rule, ordinal)
    )
);

ALTER TABLE resource_attributes
    ALTER COLUMN attribute_value TYPE jsonb
    USING jsonb_build_object('valueType', 'string', 'value', attribute_value);

ALTER TABLE resource_attributes
    ADD CONSTRAINT resource_attributes_typed_value CHECK (
        jsonb_typeof(attribute_value) = 'object'
        AND attribute_value ? 'valueType'
        AND attribute_value ? 'value'
        AND (attribute_value - 'valueType' - 'value') = '{}'::jsonb
        AND CASE attribute_value ->> 'valueType'
            WHEN 'string' THEN jsonb_typeof(attribute_value -> 'value') = 'string'
                               AND octet_length(attribute_value ->> 'value') <= 256
            WHEN 'boolean' THEN jsonb_typeof(attribute_value -> 'value') = 'boolean'
            WHEN 'integer' THEN jsonb_typeof(attribute_value -> 'value') = 'number'
                                AND attribute_value ->> 'value' ~ '^-?(0|[1-9][0-9]*)$'
                                AND (attribute_value ->> 'value')::numeric BETWEEN
                                    -9223372036854775808 AND 9223372036854775807
            WHEN 'decimal' THEN jsonb_typeof(attribute_value -> 'value') = 'string'
                                AND length(attribute_value ->> 'value') BETWEEN 1 AND 64
                                AND attribute_value ->> 'value' ~ '^(0|-?[1-9][0-9]*|(-?0|-?[1-9][0-9]*)\.[0-9]*[1-9])$'
            ELSE false
        END
    );

COMMENT ON COLUMN resource_attributes.attribute_value IS
    'Closed RSS Common ABAC typed value; no legacy text/implicit numeric coercion.';
