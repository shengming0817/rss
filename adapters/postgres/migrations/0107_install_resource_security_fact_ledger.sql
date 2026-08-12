-- #2111: External Resource Security Fact append-only projection.
-- Pre-GA hard cut: legacy rows cannot be assigned trustworthy source/freshness metadata.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.resource_attributes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.abac_policies IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    legacy_count bigint;
    legacy_sample text;
    invalid_policy_count bigint;
    invalid_policy_sample text;
BEGIN
    SELECT count(*) INTO legacy_count FROM public.resource_attributes;
    IF legacy_count > 0 THEN
        SELECT string_agg(coordinate, ', ' ORDER BY coordinate)
          INTO legacy_sample
          FROM (
              SELECT tenant_id::text || '/' || resource_id::text || '/' || attribute_key AS coordinate
                FROM public.resource_attributes
               ORDER BY tenant_id, resource_id, attribute_key
               LIMIT 20
          ) AS sample;
        RAISE EXCEPTION
            '0107: legacy resource_attributes require external re-authoring: count=%, sample coordinates=%, truncated=%',
            legacy_count, legacy_sample, CASE WHEN legacy_count > 20 THEN 'true' ELSE 'false' END;
    END IF;

    SELECT count(*) INTO invalid_policy_count
      FROM public.abac_policies AS policy
     WHERE EXISTS (
        SELECT 1
          FROM jsonb_array_elements(policy.rules -> 'rules') AS entry(rule)
         WHERE entry.rule #>> '{condition,attribute}' LIKE 'resource.%'
           AND entry.rule #>> '{condition,attribute}' NOT IN
               ('resource.id')
     );
    IF invalid_policy_count > 0 THEN
        SELECT string_agg(coordinate, ', ' ORDER BY coordinate)
          INTO invalid_policy_sample
          FROM (
              SELECT tenant_id::text || '/' || id AS coordinate
                FROM public.abac_policies AS policy
               WHERE EXISTS (
                    SELECT 1 FROM jsonb_array_elements(policy.rules -> 'rules') AS entry(rule)
                     WHERE entry.rule #>> '{condition,attribute}' LIKE 'resource.%'
                       AND entry.rule #>> '{condition,attribute}' NOT IN
                           ('resource.id')
               )
               ORDER BY tenant_id, id
               LIMIT 20
          ) AS sample;
        RAISE EXCEPTION
            '0107: ABAC policies contain unsupported resource facts: count=%, sample coordinates=%, truncated=%',
            invalid_policy_count, invalid_policy_sample,
            CASE WHEN invalid_policy_count > 20 THEN 'true' ELSE 'false' END;
    END IF;
END $$;

DROP TABLE public.resource_attributes;

CREATE TABLE public.resource_security_fact_revisions (
    tenant_id uuid NOT NULL CHECK (tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    device_id uuid NOT NULL CHECK (device_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    fact_key text NOT NULL CHECK (fact_key IN ('resource.owner', 'resource.riskClass')),
    revision bigint NOT NULL CHECK (revision > 0),
    source_id text NOT NULL CHECK (
        octet_length(pg_catalog.convert_to(source_id, 'UTF8')) BETWEEN 1 AND 256
        AND source_id !~ '[[:cntrl:]]'
    ),
    owner_principal_id text,
    risk_class text,
    observed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, device_id, fact_key, revision),
    CHECK (observed_at < expires_at),
    CHECK (
        (fact_key = 'resource.owner'
         AND owner_principal_id IS NOT NULL
         AND octet_length(pg_catalog.convert_to(owner_principal_id, 'UTF8')) BETWEEN 1 AND 256
         AND owner_principal_id !~ '[[:cntrl:]]'
         AND risk_class IS NULL)
        OR
        (fact_key = 'resource.riskClass'
         AND owner_principal_id IS NULL
         AND risk_class IN ('normal', 'restricted', 'quarantined'))
    )
);

CREATE INDEX resource_security_fact_revisions_latest_idx
    ON public.resource_security_fact_revisions
       (tenant_id, device_id, fact_key, revision DESC);

ALTER TABLE public.resource_security_fact_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.resource_security_fact_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.resource_security_fact_revisions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

REVOKE ALL ON TABLE public.resource_security_fact_revisions FROM PUBLIC, rss_app, rss_app_read, rss_audit_admin;
GRANT SELECT ON TABLE public.resource_security_fact_revisions TO rss_app, rss_app_read;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_resource_fact_bootstrap') THEN
        CREATE ROLE rss_resource_fact_bootstrap NOLOGIN NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_resource_fact_funnel_owner') THEN
        CREATE ROLE rss_resource_fact_funnel_owner NOLOGIN NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_abac_policy_validator_owner') THEN
        CREATE ROLE rss_abac_policy_validator_owner NOLOGIN NOINHERIT NOBYPASSRLS;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles
         WHERE rolname IN (
             'rss_resource_fact_bootstrap',
             'rss_resource_fact_funnel_owner',
             'rss_abac_policy_validator_owner'
         )
           AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole
                OR rolreplication OR rolinherit)
    ) THEN
        RAISE EXCEPTION '0107: resource fact security role attributes are unsafe';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_auth_members AS membership
          JOIN pg_roles AS member_role ON member_role.oid = membership.member
          JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
         WHERE member_role.rolname IN (
                   'rss_resource_fact_bootstrap',
                   'rss_resource_fact_funnel_owner',
                   'rss_abac_policy_validator_owner'
               )
            OR granted_role.rolname IN (
                   'rss_resource_fact_bootstrap',
                   'rss_resource_fact_funnel_owner',
                   'rss_abac_policy_validator_owner'
               )
    ) THEN
        RAISE EXCEPTION '0107: resource fact security roles must not have memberships';
    END IF;
END $$;

REVOKE ALL ON TABLE public.resource_security_fact_revisions
    FROM rss_resource_fact_bootstrap, rss_resource_fact_funnel_owner;
GRANT INSERT, SELECT ON TABLE public.resource_security_fact_revisions
    TO rss_resource_fact_funnel_owner;

CREATE TYPE public.rss_resource_security_fact_apply_outcome AS ENUM ('Applied', 'Replay');

CREATE FUNCTION public.rss_apply_resource_security_fact_revision(
    p_tenant_id uuid,
    p_device_id uuid,
    p_fact_key text,
    p_revision bigint,
    p_source_id text,
    p_owner_principal_id text,
    p_risk_class text,
    p_observed_at timestamptz,
    p_expires_at timestamptz
) RETURNS public.rss_resource_security_fact_apply_outcome
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    session_tenant uuid;
    latest public.resource_security_fact_revisions%ROWTYPE;
    acceptance_time timestamptz;
BEGIN
    session_tenant := NULLIF(current_setting('rss.tenant_id', true), '')::uuid;
    IF session_tenant IS NULL
       OR session_tenant = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR session_tenant <> p_tenant_id THEN
        RAISE EXCEPTION 'resource security fact tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(p_tenant_id::text || '/' || p_device_id::text || '/' || p_fact_key, 0)
    );
    SELECT * INTO latest
      FROM public.resource_security_fact_revisions
     WHERE tenant_id = p_tenant_id AND device_id = p_device_id AND fact_key = p_fact_key
     ORDER BY revision DESC
     LIMIT 1;

    IF FOUND AND latest.revision = p_revision THEN
        IF latest.source_id = p_source_id
           AND latest.owner_principal_id IS NOT DISTINCT FROM p_owner_principal_id
           AND latest.risk_class IS NOT DISTINCT FROM p_risk_class
           AND latest.observed_at = p_observed_at
           AND latest.expires_at = p_expires_at THEN
            RETURN 'Replay';
        END IF;
        RAISE EXCEPTION 'resource security fact revision conflict' USING ERRCODE = 'P2111';
    END IF;
    IF (NOT FOUND AND p_revision <> 1)
       OR (FOUND AND p_revision <> latest.revision + 1) THEN
        RAISE EXCEPTION 'resource security fact revision conflict' USING ERRCODE = 'P2111';
    END IF;

    acceptance_time := clock_timestamp();
    IF p_observed_at > acceptance_time OR p_expires_at <= acceptance_time THEN
        RAISE EXCEPTION 'resource security fact is not fresh' USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.resource_security_fact_revisions (
        tenant_id, device_id, fact_key, revision, source_id, owner_principal_id,
        risk_class, observed_at, expires_at, accepted_at
    ) VALUES (
        p_tenant_id, p_device_id, p_fact_key, p_revision, p_source_id,
        p_owner_principal_id, p_risk_class, p_observed_at, p_expires_at, acceptance_time
    );
    RETURN 'Applied';
END $$;

ALTER FUNCTION public.rss_apply_resource_security_fact_revision(
    uuid, uuid, text, bigint, text, text, text, timestamptz, timestamptz
) OWNER TO rss_resource_fact_funnel_owner;
REVOKE ALL ON FUNCTION public.rss_apply_resource_security_fact_revision(
    uuid, uuid, text, bigint, text, text, text, timestamptz, timestamptz
) FROM PUBLIC, rss_app, rss_app_read, rss_audit_admin;
GRANT EXECUTE ON FUNCTION public.rss_apply_resource_security_fact_revision(
    uuid, uuid, text, bigint, text, text, text, timestamptz, timestamptz
) TO rss_resource_fact_bootstrap;
GRANT USAGE ON SCHEMA public TO rss_resource_fact_bootstrap;
GRANT USAGE ON TYPE public.rss_resource_security_fact_apply_outcome
    TO rss_resource_fact_bootstrap;

-- Close policy LHS resource keys without retaining the v1 function as a second authority.
ALTER FUNCTION public.rss_abac_policy_operator_values_valid_v1(jsonb)
    RENAME TO rss_abac_policy_operator_values_structurally_valid;
REVOKE ALL ON FUNCTION public.rss_abac_policy_operator_values_structurally_valid(jsonb)
    FROM PUBLIC, rss_app;

ALTER FUNCTION public.rss_abac_policy_operator_values_structurally_valid(jsonb)
    OWNER TO rss_abac_policy_validator_owner;

CREATE FUNCTION public.rss_abac_policy_operator_values_valid_v2(document jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT public.rss_abac_policy_operator_values_structurally_valid(document)
       AND NOT EXISTS (
            SELECT 1
              FROM jsonb_array_elements(document -> 'rules') AS entry(rule)
             WHERE entry.rule #>> '{condition,attribute}' LIKE 'resource.%'
               AND entry.rule #>> '{condition,attribute}' NOT IN
                   ('resource.id')
       )
$$;

ALTER FUNCTION public.rss_abac_policy_operator_values_valid_v2(jsonb)
    OWNER TO rss_abac_policy_validator_owner;

REVOKE ALL ON FUNCTION public.rss_abac_policy_operator_values_valid_v2(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_abac_policy_operator_values_valid_v2(jsonb) TO rss_app;
ALTER TABLE public.abac_policies
    ADD CONSTRAINT abac_policies_operator_values_v2
    CHECK (public.rss_abac_policy_operator_values_valid_v2(rules));
ALTER TABLE public.abac_policies DROP CONSTRAINT abac_policies_operator_values_v1;

COMMENT ON TABLE public.resource_security_fact_revisions IS
    'Append-only External Resource Security Fact projection and acceptance audit ledger (#2111).';
