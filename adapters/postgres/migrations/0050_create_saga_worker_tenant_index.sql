-- 0050_create_saga_worker_tenant_index.sql
--
-- Narrow saga worker tenant discovery index (#1247).
-- The app role does not read this table directly; it can only call the fixed
-- SECURITY DEFINER candidate function, which returns tenant ids and no saga
-- ids, payload, or journal data.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_saga_maintenance') THEN
        CREATE ROLE rss_saga_maintenance NOLOGIN BYPASSRLS;
    ELSE
        ALTER ROLE rss_saga_maintenance NOLOGIN BYPASSRLS;
    END IF;
END
$$;

CREATE TABLE saga_worker_tenant_index (
    tenant_id   uuid        NOT NULL,
    owner       text        NOT NULL,
    contract_id text        NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, owner, contract_id),
    CONSTRAINT saga_worker_tenant_index_owner_valid
        CHECK (length(owner) > 0 AND octet_length(owner) <= 128),
    CONSTRAINT saga_worker_tenant_index_contract_id_valid
        CHECK (length(contract_id) > 0 AND octet_length(contract_id) <= 256)
);

CREATE INDEX idx_saga_worker_tenant_index_owner_contract_updated
    ON saga_worker_tenant_index (owner, contract_id, updated_at, tenant_id);

INSERT INTO saga_worker_tenant_index (tenant_id, owner, contract_id, updated_at)
SELECT tenant_id, owner, contract_id, max(updated_at)
FROM saga_instances
WHERE status IN ('ready', 'running', 'compensating')
GROUP BY tenant_id, owner, contract_id
ON CONFLICT (tenant_id, owner, contract_id) DO UPDATE
SET updated_at = EXCLUDED.updated_at;

ALTER TABLE saga_worker_tenant_index ENABLE ROW LEVEL SECURITY;
ALTER TABLE saga_worker_tenant_index FORCE ROW LEVEL SECURITY;

CREATE POLICY saga_worker_tenant_index_no_direct_app_access
ON saga_worker_tenant_index
FOR ALL
TO rss_app
USING (
    tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    AND false
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    AND false
);

REVOKE ALL ON saga_worker_tenant_index FROM PUBLIC;
REVOKE ALL ON saga_worker_tenant_index FROM rss_app;

GRANT SELECT ON saga_instances TO rss_saga_maintenance;
GRANT SELECT, INSERT, UPDATE, DELETE ON saga_worker_tenant_index TO rss_saga_maintenance;

CREATE OR REPLACE FUNCTION rss_saga_worker_tenant_index_refresh()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NEW.status IN ('ready', 'running', 'compensating') THEN
        INSERT INTO saga_worker_tenant_index (tenant_id, owner, contract_id, updated_at)
        VALUES (NEW.tenant_id, NEW.owner, NEW.contract_id, now())
        ON CONFLICT (tenant_id, owner, contract_id) DO UPDATE
        SET updated_at = EXCLUDED.updated_at;
        RETURN NEW;
    END IF;

    DELETE FROM saga_worker_tenant_index idx
    WHERE idx.tenant_id = NEW.tenant_id
      AND idx.owner = NEW.owner
      AND idx.contract_id = NEW.contract_id
      AND NOT EXISTS (
          SELECT 1
          FROM saga_instances si
          WHERE si.tenant_id = NEW.tenant_id
            AND si.owner = NEW.owner
            AND si.contract_id = NEW.contract_id
            AND si.status IN ('ready', 'running', 'compensating')
      );
    RETURN NEW;
END;
$$;

CREATE TRIGGER saga_worker_tenant_index_refresh
AFTER INSERT OR UPDATE OF status ON saga_instances
FOR EACH ROW
EXECUTE FUNCTION rss_saga_worker_tenant_index_refresh();

CREATE OR REPLACE FUNCTION rss_saga_candidate_tenants(
    p_owner text,
    p_contract_id text,
    p_limit bigint
)
RETURNS TABLE (tenant_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF p_owner IS NULL OR length(p_owner) = 0 THEN
        RAISE EXCEPTION 'rss_saga_candidate_tenants owner must be non-empty';
    END IF;
    IF p_contract_id IS NULL OR length(p_contract_id) = 0 THEN
        RAISE EXCEPTION 'rss_saga_candidate_tenants contract id must be non-empty';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10000 THEN
        RAISE EXCEPTION 'rss_saga_candidate_tenants limit must be in range [1, 10000]';
    END IF;

    RETURN QUERY
    SELECT idx.tenant_id
    FROM saga_worker_tenant_index idx
    WHERE idx.owner = p_owner
      AND idx.contract_id = p_contract_id
      AND EXISTS (
          SELECT 1
          FROM saga_instances si
          WHERE si.tenant_id = idx.tenant_id
            AND si.owner = idx.owner
            AND si.contract_id = idx.contract_id
            AND si.status IN ('ready', 'running', 'compensating')
            AND (
                  si.lease_token IS NULL
               OR si.expires_at <= now()
            )
      )
    ORDER BY idx.updated_at, idx.tenant_id
    LIMIT p_limit;
END;
$$;

ALTER FUNCTION rss_saga_worker_tenant_index_refresh() OWNER TO rss_saga_maintenance;
ALTER FUNCTION rss_saga_candidate_tenants(text, text, bigint) OWNER TO rss_saga_maintenance;

REVOKE ALL ON FUNCTION rss_saga_worker_tenant_index_refresh() FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_saga_candidate_tenants(text, text, bigint) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_saga_candidate_tenants(text, text, bigint) TO rss_app;
