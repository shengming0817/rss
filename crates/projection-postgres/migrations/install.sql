-- Fresh schema. Execute as a dedicated NOSUPERUSER NOBYPASSRLS owner.
-- ref: baseline 5b63e10 adapters/postgres/migrations/0040_projection_events_funnel_and_projection_dlx.sql: commit-ordered append.
-- Production migration execution and runtime grants belong to the application.
BEGIN;
CREATE SCHEMA rss_projection;
CREATE TABLE rss_projection.sources (
    tenant_id uuid NOT NULL,
    source_id text NOT NULL CHECK (octet_length(source_id) BETWEEN 1 AND 255 AND (source_id COLLATE "C") !~ '[^A-Za-z0-9_.:-]'),
    next_position bigint NOT NULL DEFAULT 0 CHECK (next_position >= 0),
    PRIMARY KEY (tenant_id, source_id)
);
CREATE TABLE rss_projection.events (
    tenant_id uuid NOT NULL,
    source_id text NOT NULL,
    position bigint NOT NULL CHECK (position >= 0),
    event_id text NOT NULL CHECK (event_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    payload bytea NOT NULL CHECK (octet_length(payload) <= 1048576),
    PRIMARY KEY (tenant_id, source_id, position),
    UNIQUE (tenant_id, source_id, event_id),
    FOREIGN KEY (tenant_id, source_id) REFERENCES rss_projection.sources
);
CREATE TABLE rss_projection.checkpoints (
    tenant_id uuid NOT NULL,
    source_id text NOT NULL CHECK (octet_length(source_id) BETWEEN 1 AND 255 AND (source_id COLLATE "C") !~ '[^A-Za-z0-9_.:-]'),
    projection_id text NOT NULL CHECK (octet_length(projection_id) BETWEEN 1 AND 255 AND (projection_id COLLATE "C") !~ '[^A-Za-z0-9_.:-]'),
    generation text NOT NULL CHECK (generation ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    start_position bigint CHECK (start_position >= 0),
    position bigint CHECK (position >= 0),
    replay boolean NOT NULL,
    end_position bigint CHECK (end_position >= 0),
    epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    worker_token uuid,
    definition_identity bytea NOT NULL CONSTRAINT definition_identity_length CHECK (octet_length(definition_identity) = 32),
    PRIMARY KEY (tenant_id, source_id, projection_id, generation),
    CHECK (NOT replay OR start_position IS NULL OR (end_position IS NOT NULL AND start_position <= end_position)),
    CHECK (replay OR end_position IS NULL)
);
CREATE TABLE rss_projection.receipts (
    tenant_id uuid NOT NULL,
    source_id text NOT NULL,
    projection_id text NOT NULL,
    generation text NOT NULL,
    event_id text NOT NULL CHECK (event_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    baseline boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, source_id, projection_id, generation, event_id),
    FOREIGN KEY (tenant_id, source_id, projection_id, generation) REFERENCES rss_projection.checkpoints
);
ALTER TABLE rss_projection.sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_projection.sources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_projection.sources
    USING (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid);
ALTER TABLE rss_projection.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_projection.events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_projection.events
    USING (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid);
ALTER TABLE rss_projection.checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_projection.checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_projection.checkpoints
    USING (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid);
ALTER TABLE rss_projection.receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_projection.receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_projection.receipts
    USING (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid);

CREATE FUNCTION rss_projection.assert_tenant(t uuid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, rss_projection AS $$
BEGIN
    IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id', true), '')::uuid THEN
        RAISE EXCEPTION 'projection scope mismatch' USING ERRCODE = 'P1001';
    END IF;
END $$;

CREATE FUNCTION rss_projection.append_event(t uuid, s text, e text, bytes bytea) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_projection AS $$
DECLARE n bigint; old rss_projection.events;
BEGIN
    PERFORM rss_projection.assert_tenant(t);
    INSERT INTO rss_projection.sources(tenant_id, source_id) VALUES(t,s) ON CONFLICT DO NOTHING;
    SELECT next_position INTO STRICT n FROM rss_projection.sources WHERE tenant_id=t AND source_id=s FOR UPDATE;
    SELECT * INTO old FROM rss_projection.events WHERE tenant_id=t AND source_id=s AND event_id=e;
    IF FOUND THEN
        IF old.payload IS DISTINCT FROM bytes THEN RAISE EXCEPTION 'projection fact conflict' USING ERRCODE='P1003'; END IF;
        RETURN old.position;
    END IF;
    INSERT INTO rss_projection.events VALUES(t,s,n,e,bytes);
    UPDATE rss_projection.sources SET next_position=n+1 WHERE tenant_id=t AND source_id=s;
    RETURN n;
END $$;

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
-- The two runtime entry points share one validation path. This invoker helper
-- has no authority of its own to update or lock component rows.
CREATE FUNCTION rss_projection.process_batch(t uuid, s text, p text, g text, worker_epoch bigint,
    token uuid, expected bigint, positions bigint[], ids text[], digests bytea[], definition bytea,
    settle boolean) RETURNS boolean[]
LANGUAGE plpgsql SET search_path = pg_catalog, rss_projection AS $$
DECLARE n integer := cardinality(positions); c rss_projection.checkpoints;
        duplicates boolean[]; invalid_fact boolean;
BEGIN
    PERFORM rss_projection.assert_tenant(t);
    IF n IS NULL OR n NOT BETWEEN 1 AND 1024
       OR cardinality(ids) IS DISTINCT FROM n OR cardinality(digests) IS DISTINCT FROM n
       OR array_ndims(positions) <> 1 OR array_ndims(ids) <> 1 OR array_ndims(digests) <> 1
       OR array_lower(positions,1) <> 1 OR array_lower(ids,1) <> 1 OR array_lower(digests,1) <> 1 THEN
        RAISE EXCEPTION 'invalid projection batch' USING ERRCODE='23514';
    END IF;
    IF EXISTS (SELECT FROM unnest(positions) WITH ORDINALITY AS e(pos,i)
               WHERE pos IS NULL OR pos < 0 OR pos <= expected OR pos <= positions[i::int-1]) THEN
        RAISE EXCEPTION 'projection out of order' USING ERRCODE='P1004';
    END IF;
    IF settle THEN
        -- Standalone settlement acquires authority by CAS. Later validation
        -- errors roll back this update along with any staged effects.
        UPDATE rss_projection.checkpoints SET position=positions[n]
          WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g
            AND epoch=worker_epoch AND worker_token=token AND position IS NOT DISTINCT FROM expected
          RETURNING * INTO c;
    ELSE
        SELECT * INTO c FROM rss_projection.checkpoints
          WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g
            AND epoch=worker_epoch AND worker_token=token AND position IS NOT DISTINCT FROM expected
          FOR UPDATE;
    END IF;
    IF NOT FOUND THEN RAISE EXCEPTION 'projection worker fenced' USING ERRCODE='P1002'; END IF;
    IF c.definition_identity IS DISTINCT FROM definition THEN
        RAISE EXCEPTION 'projection definition conflict' USING ERRCODE='P1003';
    END IF;
    IF c.replay AND (c.end_position IS NULL OR positions[n] > c.end_position) THEN
        RAISE EXCEPTION 'projection out of order' USING ERRCODE='P1004';
    END IF;

    -- Start this statement after acquiring the checkpoint, so a waiter can
    -- see receipts published by the transaction it waited for.
    WITH input AS MATERIALIZED (
        SELECT * FROM unnest(ids,digests) WITH ORDINALITY AS e(id,digest,i)
    ), firsts AS (
        SELECT DISTINCT ON (id) * FROM input ORDER BY id,i
    ), known AS MATERIALIZED (
        SELECT f.*, r.fingerprint FROM firsts f LEFT JOIN LATERAL (
            SELECT fingerprint FROM rss_projection.receipts
              WHERE tenant_id=t AND source_id=s AND projection_id=p AND generation=g AND event_id=f.id
              LIMIT 1
        ) r ON true
    )
    SELECT bool_or(e.id IS NULL OR (e.id COLLATE "C") !~ '^[A-Za-z0-9_.:-]{1,128}$'
                   OR octet_length(e.digest) IS DISTINCT FROM 32
                   OR k.digest IS DISTINCT FROM e.digest
                   OR (k.fingerprint IS NOT NULL AND k.fingerprint IS DISTINCT FROM e.digest)),
           array_agg(k.fingerprint IS NOT NULL OR k.i <> e.i ORDER BY e.i)
      INTO invalid_fact, duplicates FROM input e LEFT JOIN known k ON k.id=e.id;
    IF invalid_fact THEN RAISE EXCEPTION 'projection fact conflict' USING ERRCODE='P1003'; END IF;
    IF settle THEN
        INSERT INTO rss_projection.receipts(tenant_id,source_id,projection_id,generation,event_id,fingerprint)
            SELECT t,s,p,g,id,digest FROM unnest(ids,digests,duplicates) AS e(id,digest,seen)
            WHERE NOT seen;
    END IF;
    RETURN duplicates;
END $$;

CREATE FUNCTION rss_projection.lock_batch(uuid,text,text,text,bigint,uuid,bigint,bigint[],text[],bytea[],bytea)
RETURNS boolean[] LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, rss_projection
BEGIN ATOMIC
    SELECT rss_projection.process_batch($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,false);
END;
CREATE FUNCTION rss_projection.finish_batch(uuid,text,text,text,bigint,uuid,bigint,bigint[],text[],bytea[],bytea)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, rss_projection
BEGIN ATOMIC
    SELECT rss_projection.process_batch($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true) IS NOT NULL;
END;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_projection FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_projection FROM PUBLIC;
COMMENT ON SCHEMA rss_projection IS 'rss-projection-postgres:1';
COMMIT;
