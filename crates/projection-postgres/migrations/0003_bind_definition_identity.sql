-- One-way v2 -> v3. Execute outside another transaction as the dedicated migration owner.
-- No legacy generation adoption: any physical checkpoint row aborts the entire upgrade.
-- ref: serverlesstechnology/cqrs persistence/postgres-es/src/view_repository.rs (version CAS).
BEGIN;
LOCK TABLE rss_projection.checkpoints IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF (SELECT obj_description('rss_projection'::regnamespace,'pg_namespace')) IS DISTINCT FROM 'rss-projection-postgres:2' THEN
        RAISE EXCEPTION 'expected projection storage revision 2';
    END IF;
END $$;
ALTER TABLE rss_projection.checkpoints ADD COLUMN definition_identity bytea;
-- DDL validates every physical row, including rows hidden by FORCE RLS.
ALTER TABLE rss_projection.checkpoints ALTER COLUMN definition_identity SET NOT NULL;
ALTER TABLE rss_projection.checkpoints ADD CONSTRAINT definition_identity_length CHECK (octet_length(definition_identity) = 32);
DROP FUNCTION rss_projection.finish_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea);
DROP FUNCTION rss_projection.lock_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea);
DROP FUNCTION rss_projection.takeover(uuid,text,text,text,uuid);
DROP FUNCTION rss_projection.initialize(uuid,text,text,text,bigint,boolean,bigint,text[],bytea[]);
CREATE FUNCTION rss_projection.initialize(t uuid, s text, p text, g text, start_at bigint, is_replay boolean, end_at bigint, ids text[], digests bytea[], definition bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_projection AS $$
DECLARE c rss_projection.checkpoints; created boolean;
BEGIN
    PERFORM rss_projection.assert_tenant(t);
    IF definition IS NULL OR octet_length(definition) <> 32 THEN
        RAISE EXCEPTION 'projection definition required' USING ERRCODE='P1003';
    END IF;
    IF ids IS NULL OR digests IS NULL OR cardinality(ids) <> cardinality(digests)
       OR (start_at IS NULL AND cardinality(ids) <> 0)
       OR (start_at IS NOT NULL AND cardinality(ids) = 0) THEN
        RAISE EXCEPTION 'projection baseline required' USING ERRCODE='23514';
    END IF;
    INSERT INTO rss_projection.checkpoints(tenant_id,source_id,projection_id,generation,start_position,position,replay,end_position,definition_identity)
        VALUES(t,s,p,g,start_at,start_at,is_replay,end_at,definition) ON CONFLICT DO NOTHING RETURNING true INTO created;
    SELECT * INTO STRICT c FROM rss_projection.checkpoints WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g FOR UPDATE;
    IF c.definition_identity IS DISTINCT FROM definition OR c.start_position IS DISTINCT FROM start_at OR c.replay IS DISTINCT FROM is_replay OR c.end_position IS DISTINCT FROM end_at THEN
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

CREATE FUNCTION rss_projection.takeover(t uuid, s text, p text, g text, token uuid, definition bytea) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_projection AS $$
DECLARE c rss_projection.checkpoints; n bigint;
BEGIN
    PERFORM rss_projection.assert_tenant(t);
    IF token IS NULL THEN RAISE EXCEPTION 'projection token required' USING ERRCODE='P1002'; END IF;
    SELECT * INTO c FROM rss_projection.checkpoints WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'projection generation missing' USING ERRCODE='P1002'; END IF;
    IF c.definition_identity IS DISTINCT FROM definition THEN
        RAISE EXCEPTION 'projection definition conflict' USING ERRCODE='P1003';
    END IF;
    UPDATE rss_projection.checkpoints SET epoch=epoch+1,worker_token=token
        WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g RETURNING epoch INTO n;
    RETURN n;
END $$;

CREATE FUNCTION rss_projection.lock_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea, definition bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_projection AS $$
DECLARE c rss_projection.checkpoints; previous bytea;
BEGIN
    PERFORM rss_projection.assert_tenant(t);
    SELECT * INTO c FROM rss_projection.checkpoints WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g FOR UPDATE;
    IF NOT FOUND OR c.epoch IS DISTINCT FROM worker_epoch OR c.worker_token IS DISTINCT FROM token OR token IS NULL OR c.position IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'projection worker fenced' USING ERRCODE='P1002';
    END IF;
    IF c.definition_identity IS DISTINCT FROM definition THEN
        RAISE EXCEPTION 'projection definition conflict' USING ERRCODE='P1003';
    END IF;
    IF at_position IS NULL OR at_position < 0 OR (c.position IS NOT NULL AND at_position <= c.position)
        OR (c.replay AND (c.end_position IS NULL OR at_position > c.end_position)) THEN
        RAISE EXCEPTION 'projection out of order' USING ERRCODE='P1004';
    END IF;
    IF digest IS NULL OR octet_length(digest) <> 32 THEN RAISE EXCEPTION 'projection fact invalid' USING ERRCODE='P1003'; END IF;
    SELECT fingerprint INTO previous FROM rss_projection.receipts WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g AND event_id=e;
    IF FOUND THEN
        IF previous IS DISTINCT FROM digest THEN RAISE EXCEPTION 'projection fact conflict' USING ERRCODE='P1003'; END IF;
        RETURN true;
    END IF;
    RETURN false;
END $$;

CREATE FUNCTION rss_projection.finish_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea, definition bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_projection AS $$
BEGIN
    PERFORM rss_projection.lock_event(t,s,p,g,worker_epoch,token,expected,at_position,e,digest,definition);
    INSERT INTO rss_projection.receipts(tenant_id,source_id,projection_id,generation,event_id,fingerprint) VALUES(t,s,p,g,e,digest) ON CONFLICT DO NOTHING;
    UPDATE rss_projection.checkpoints SET position=at_position WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_projection FROM PUBLIC;
COMMENT ON SCHEMA rss_projection IS 'rss-projection-postgres:3';
COMMIT;
