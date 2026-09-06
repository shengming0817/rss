-- Additive correction before first release: a nonzero baseline requires its receipt set.
-- Existing migration files remain immutable; this removes the unsafe initializer signature.
ALTER TABLE rss_projection.receipts ADD COLUMN baseline boolean NOT NULL DEFAULT false;
DROP FUNCTION rss_projection.initialize(uuid,text,text,text,bigint,boolean,bigint);
CREATE FUNCTION rss_projection.initialize(t uuid, s text, p text, g text, start_at bigint, is_replay boolean, end_at bigint, ids text[], digests bytea[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_projection AS $$
DECLARE c rss_projection.checkpoints; created boolean;
BEGIN
    PERFORM rss_projection.assert_tenant(t);
    IF ids IS NULL OR digests IS NULL OR cardinality(ids) <> cardinality(digests)
       OR (start_at IS NULL AND cardinality(ids) <> 0)
       OR (start_at IS NOT NULL AND cardinality(ids) = 0) THEN
        RAISE EXCEPTION 'projection baseline required' USING ERRCODE='23514';
    END IF;
    INSERT INTO rss_projection.checkpoints(tenant_id,source_id,projection_id,generation,start_position,position,replay,end_position)
        VALUES(t,s,p,g,start_at,start_at,is_replay,end_at) ON CONFLICT DO NOTHING RETURNING true INTO created;
    SELECT * INTO STRICT c FROM rss_projection.checkpoints WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g FOR UPDATE;
    IF c.start_position IS DISTINCT FROM start_at OR c.replay IS DISTINCT FROM is_replay OR c.end_position IS DISTINCT FROM end_at THEN
        RAISE EXCEPTION 'projection generation conflict' USING ERRCODE='P1003';
    END IF;
    IF coalesce(created,false) THEN
        INSERT INTO rss_projection.receipts(tenant_id,source_id,projection_id,generation,event_id,fingerprint,baseline)
            SELECT t,s,p,g,id,digest,true FROM unnest(ids,digests) AS supplied(id,digest);
    ELSIF EXISTS (
        (SELECT id,digest FROM unnest(ids,digests) AS supplied(id,digest)
         EXCEPT SELECT event_id,fingerprint FROM rss_projection.receipts
            WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g AND baseline)
        UNION ALL
        (SELECT event_id,fingerprint FROM rss_projection.receipts
            WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g AND baseline
         EXCEPT SELECT id,digest FROM unnest(ids,digests) AS supplied(id,digest))
    ) THEN
        RAISE EXCEPTION 'projection baseline conflict' USING ERRCODE='P1003';
    END IF;
END $$;
CREATE OR REPLACE FUNCTION rss_projection.finish_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_projection AS $$
BEGIN
    PERFORM rss_projection.lock_event(t,s,p,g,worker_epoch,token,expected,at_position,e,digest);
    INSERT INTO rss_projection.receipts(tenant_id,source_id,projection_id,generation,event_id,fingerprint) VALUES(t,s,p,g,e,digest) ON CONFLICT DO NOTHING;
    UPDATE rss_projection.checkpoints SET position=at_position WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_projection FROM PUBLIC;
COMMENT ON SCHEMA rss_projection IS 'rss-projection-postgres:2';
