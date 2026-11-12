-- One-way V2 -> V3. External schema owner stops writers before executing this transaction.
-- ref: PostgreSQL REL_16_11 src/backend/utils/adt/datetime.c (checked integer microseconds).
BEGIN;
LOCK TABLE rss_saga.instances, rss_saga.journal IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT obj_description(oid,'pg_namespace') FROM pg_namespace WHERE nspname='rss_saga') IS DISTINCT FROM 'rss-saga-postgres:2' THEN RAISE EXCEPTION 'expected saga schema 2'; END IF;
END $$;

CREATE OR REPLACE FUNCTION rss_saga.claim(p_id uuid,p_token uuid,p_ttl bigint) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE row rss_saga.instances; t uuid := current_setting('rss.tenant_id')::uuid; now_ timestamptz;
BEGIN
    IF p_ttl IS NULL OR p_token IS NULL OR p_ttl<=0 OR p_ttl>9223372036854775 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga lease ttl'; END IF;
    SELECT * INTO row FROM rss_saga.instances WHERE tenant_id=t AND saga_id=p_id FOR UPDATE;
    now_ := clock_timestamp();
    IF NOT FOUND OR (row.expires_at IS NOT NULL AND row.expires_at>now_) THEN RAISE EXCEPTION USING ERRCODE='RS001',MESSAGE='saga lease unavailable'; END IF;
    UPDATE rss_saga.instances SET lease_token=p_token,epoch=epoch+1,expires_at=now_+(p_ttl::text || ' milliseconds')::interval WHERE tenant_id=t AND saga_id=p_id RETURNING epoch INTO row.epoch;
    RETURN row.epoch;
END $$;

CREATE OR REPLACE FUNCTION rss_saga.lease(p_id uuid,p_token uuid,p_epoch bigint,p_ttl bigint) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE ignored jsonb; t uuid := current_setting('rss.tenant_id')::uuid;
BEGIN
    ignored := rss_saga.lock_instance(p_id,p_token,p_epoch);
    IF p_ttl=0 THEN UPDATE rss_saga.instances SET lease_token=NULL,expires_at=NULL WHERE tenant_id=t AND saga_id=p_id;
    ELSIF p_ttl>0 AND p_ttl<=9223372036854775 THEN UPDATE rss_saga.instances SET expires_at=clock_timestamp()+(p_ttl::text || ' milliseconds')::interval WHERE tenant_id=t AND saga_id=p_id;
    ELSE RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga lease ttl'; END IF;
END $$;

COMMENT ON SCHEMA rss_saga IS 'rss-saga-postgres:3';
COMMIT;
