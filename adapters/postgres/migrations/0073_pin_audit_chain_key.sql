-- Pin the only supported audit-chain HMAC key generation to one durable keyed sentinel.
--
-- There is deliberately no transparent rotation or legacy adoption. If audit_entries already
-- exist when the singleton is absent, initialization returns false: an operator must run an
-- explicit verified migration rather than blessing an arbitrary startup secret over an old chain.

ALTER TABLE audit_entries ALTER COLUMN key_id DROP DEFAULT;
ALTER TABLE audit_entries
    ADD CONSTRAINT audit_entries_key_id_v1 CHECK (key_id = 1);

CREATE TABLE audit_chain_key_guard (
    singleton        boolean  PRIMARY KEY DEFAULT true CHECK (singleton),
    key_id           smallint NOT NULL CHECK (key_id = 1),
    verification_tag bytea    NOT NULL CHECK (octet_length(verification_tag) = 32)
);

REVOKE ALL ON audit_chain_key_guard FROM PUBLIC, rss_app, rss_app_read, rss_audit_admin;

CREATE OR REPLACE FUNCTION rss_verify_audit_chain_key_v1(
    p_key_id smallint,
    p_verification_tag bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    current_key_id smallint;
    current_tag bytea;
BEGIN
    IF p_key_id <> 1 OR octet_length(p_verification_tag) <> 32 THEN
        RETURN false;
    END IF;

    LOCK TABLE public.audit_chain_key_guard IN EXCLUSIVE MODE;
    SELECT key_id, verification_tag
      INTO current_key_id, current_tag
      FROM public.audit_chain_key_guard
     WHERE singleton = true;

    IF FOUND THEN
        RETURN current_key_id = p_key_id AND current_tag = p_verification_tag;
    END IF;

    IF EXISTS (SELECT 1 FROM public.audit_entries LIMIT 1) THEN
        RETURN false;
    END IF;

    INSERT INTO public.audit_chain_key_guard(singleton, key_id, verification_tag)
    VALUES (true, p_key_id, p_verification_tag);
    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION rss_verify_audit_chain_key_v1(smallint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_verify_audit_chain_key_v1(smallint, bytea) TO rss_app;
