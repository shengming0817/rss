-- Fresh installation by a dedicated NOSUPERUSER NOBYPASSRLS owner.
-- ref: baseline 5b63e10 adapters/postgres/migrations/0041*,0044*,0084*: claim/wake semantics only.
CREATE SCHEMA rss_reconcile;
COMMENT ON SCHEMA rss_reconcile IS 'rss-reconcile-postgres:1';
CREATE TABLE rss_reconcile.targets (
    tenant_id uuid NOT NULL,
    reconciler text NOT NULL CHECK (reconciler ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    entity text NOT NULL CHECK (entity ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    wake_version bigint NOT NULL DEFAULT 1 CHECK (wake_version > 0),
    epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    token uuid,
    lease_until timestamptz,
    next_run timestamptz DEFAULT clock_timestamp(),
    failures bigint NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 4294967295),
    result text NOT NULL DEFAULT 'pending' CHECK (result IN ('pending','running','applied','converged','retry','suspended')),
    PRIMARY KEY (tenant_id,reconciler,entity),
    CHECK ((token IS NULL) = (lease_until IS NULL)),
    CHECK (token IS NULL OR next_run IS NOT NULL)
);
CREATE INDEX targets_due ON rss_reconcile.targets(tenant_id,reconciler,next_run,entity) WHERE next_run IS NOT NULL;
ALTER TABLE rss_reconcile.targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_reconcile.targets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_reconcile.targets
USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE FUNCTION rss_reconcile.assert_tenant(t uuid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
    IF t IS NULL OR t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
        RAISE EXCEPTION 'reconcile scope mismatch' USING ERRCODE='P1001';
    END IF;
END $$;
CREATE FUNCTION rss_reconcile.wake(t uuid,r text,e text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
    PERFORM rss_reconcile.assert_tenant(t);
    INSERT INTO rss_reconcile.targets(tenant_id,reconciler,entity) VALUES(t,r,e)
    ON CONFLICT(tenant_id,reconciler,entity) DO UPDATE SET
        wake_version=targets.wake_version+1,next_run=clock_timestamp(),failures=0,result='pending';
END $$;
CREATE FUNCTION rss_reconcile.claim_due(t uuid,r text,n integer,ttl bigint)
RETURNS SETOF rss_reconcile.targets LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE at_time timestamptz := clock_timestamp();
BEGIN
    PERFORM rss_reconcile.assert_tenant(t);
    IF n IS NULL OR n NOT BETWEEN 1 AND 64 OR ttl IS NULL OR ttl NOT BETWEEN 1 AND 86400000 THEN
        RAISE EXCEPTION 'invalid claim limits' USING ERRCODE='P1003';
    END IF;
    RETURN QUERY WITH due AS (
        SELECT tenant_id,reconciler,entity FROM rss_reconcile.targets
        WHERE tenant_id=t AND reconciler=r AND next_run<=at_time AND (lease_until IS NULL OR lease_until<=at_time)
        ORDER BY next_run,entity LIMIT n FOR UPDATE SKIP LOCKED
    ) UPDATE rss_reconcile.targets AS x SET token=gen_random_uuid(),epoch=x.epoch+1,
        lease_until=at_time+ttl*interval '1 millisecond',result='running'
    FROM due WHERE (x.tenant_id,x.reconciler,x.entity)=(due.tenant_id,due.reconciler,due.entity) RETURNING x.*;
END $$;
CREATE FUNCTION rss_reconcile.lock_claim(t uuid,r text,e text,k uuid,g bigint) RETURNS rss_reconcile.targets
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE row rss_reconcile.targets;
BEGIN
    PERFORM rss_reconcile.assert_tenant(t);
    SELECT * INTO row FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND entity=e FOR UPDATE;
    IF NOT FOUND OR k IS NULL OR row.token IS DISTINCT FROM k OR row.epoch IS DISTINCT FROM g OR row.lease_until IS NULL OR row.lease_until<=clock_timestamp() THEN
        RAISE EXCEPTION 'reconcile claim lost' USING ERRCODE='P1002';
    END IF;
    RETURN row;
END $$;
CREATE FUNCTION rss_reconcile.renew(t uuid,r text,e text,k uuid,g bigint,ttl bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
    PERFORM rss_reconcile.lock_claim(t,r,e,k,g);
    IF ttl IS NULL OR ttl NOT BETWEEN 1 AND 86400000 THEN RAISE EXCEPTION 'invalid lease' USING ERRCODE='P1003'; END IF;
    UPDATE rss_reconcile.targets SET lease_until=clock_timestamp()+ttl*interval '1 millisecond' WHERE tenant_id=t AND reconciler=r AND entity=e;
END $$;
CREATE FUNCTION rss_reconcile.finish(t uuid,r text,e text,k uuid,g bigint,w bigint,outcome text,delay bigint,f bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE row rss_reconcile.targets; at_time timestamptz;
BEGIN
    row:=rss_reconcile.lock_claim(t,r,e,k,g); at_time:=clock_timestamp();
    IF outcome IS NULL OR outcome NOT IN ('converged','pending','retry','suspended') OR f IS NULL OR f NOT BETWEEN 0 AND 4294967295 OR
       (outcome IN ('pending','retry') AND (delay IS NULL OR delay NOT BETWEEN 1 AND 86400000)) THEN
        RAISE EXCEPTION 'invalid completion' USING ERRCODE='P1003';
    END IF;
    IF w IS NULL OR w>row.wake_version THEN RAISE EXCEPTION 'invalid wake version' USING ERRCODE='P1003'; END IF;
    UPDATE rss_reconcile.targets SET token=NULL,lease_until=NULL,
        next_run=CASE WHEN row.wake_version<>w THEN least(row.next_run,at_time) WHEN outcome IN ('converged','suspended') THEN NULL ELSE at_time+delay*interval '1 millisecond' END,
        failures=CASE WHEN row.wake_version<>w THEN row.failures ELSE f END,
        result=CASE WHEN row.wake_version<>w THEN 'pending' ELSE outcome END
    WHERE tenant_id=t AND reconciler=r AND entity=e;
END $$;
CREATE FUNCTION rss_reconcile.release(t uuid,r text,e text,k uuid,g bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
    PERFORM rss_reconcile.lock_claim(t,r,e,k,g);
    UPDATE rss_reconcile.targets SET token=NULL,lease_until=NULL WHERE tenant_id=t AND reconciler=r AND entity=e;
END $$;
CREATE FUNCTION rss_reconcile.mark_applied(t uuid,r text,e text,k uuid,g bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
    PERFORM rss_reconcile.lock_claim(t,r,e,k,g);
    UPDATE rss_reconcile.targets SET next_run=least(next_run,clock_timestamp()),result='applied' WHERE tenant_id=t AND reconciler=r AND entity=e;
END $$;
REVOKE ALL ON SCHEMA rss_reconcile FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_reconcile FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_reconcile FROM PUBLIC;
