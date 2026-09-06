-- One-way V1 -> V2 upgrade. Execute as the dedicated owner with writers stopped.
-- The explicit transaction keeps temporary owner visibility and backfill atomic.
-- ref: postgres/postgres doc/src/sgml/mvcc.sgml@c13dd7d50f21268dc64b4b3edbce31993985ab12
BEGIN;
LOCK TABLE rss_observation.objects, rss_observation.streams, rss_observation.batches IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT obj_description(oid,'pg_namespace') FROM pg_namespace WHERE nspname='rss_observation') IS DISTINCT FROM 'rss-observation-postgres:1' THEN
  RAISE EXCEPTION 'expected observation storage revision 1';
 END IF;
END $$;
ALTER TABLE rss_observation.batches ADD COLUMN log_position bigint;
ALTER TABLE rss_observation.batches NO FORCE ROW LEVEL SECURITY;
CREATE TABLE rss_observation.journals (
 tenant_id uuid PRIMARY KEY,
 last_position bigint NOT NULL CHECK(last_position>=0)
);
-- No prior journal/checkpoint exists. Only per-stream order has historical meaning.
WITH numbered AS (
 SELECT tenant_id,scope,batch_id,row_number() OVER(PARTITION BY tenant_id ORDER BY scope COLLATE "C",sequence,batch_id COLLATE "C") AS position
 FROM rss_observation.batches WHERE applicable
)
UPDATE rss_observation.batches b SET log_position=n.position FROM numbered n
WHERE b.tenant_id=n.tenant_id AND b.scope=n.scope AND b.batch_id=n.batch_id;
INSERT INTO rss_observation.journals SELECT tenant_id,max(log_position) FROM rss_observation.batches WHERE applicable GROUP BY tenant_id;
ALTER TABLE rss_observation.batches FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_observation.batches ADD CONSTRAINT observation_position CHECK (
 applicable=(log_position IS NOT NULL) AND (log_position IS NULL OR log_position>0)
);
DROP INDEX rss_observation.observation_ready;
CREATE UNIQUE INDEX observation_log ON rss_observation.batches(tenant_id,log_position) WHERE applicable;
ALTER TABLE rss_observation.journals ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_observation.journals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_observation.journals USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON rss_observation.journals FROM PUBLIC;
-- Lock order remains object -> stream -> tenant journal, held until settlement.
CREATE OR REPLACE FUNCTION rss_observation.commit_batch(p_scope text,p_id text,p_sequence numeric,p_raw bytea,p_fingerprint bytea,p_received bigint,p_policy text,p_decision text,p_expected numeric,p_applicable boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_observation AS $$
DECLARE current_stream rss_observation.streams; t uuid := (p_scope::jsonb->>'tenant')::uuid; position bigint; last bigint;
BEGIN
 SELECT * INTO STRICT current_stream FROM rss_observation.lock_stream(p_scope);
 IF current_stream.revision<>p_expected OR current_stream.state::jsonb<>p_decision::jsonb->'before'
 OR (p_decision::jsonb->'after'->>'revision')::numeric<>p_expected+1 OR current_stream.policy::jsonb<>p_policy::jsonb THEN
  RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='transition contract';
 END IF;
 INSERT INTO rss_observation.journals(tenant_id,last_position) VALUES(t,0) ON CONFLICT DO NOTHING;
 SELECT last_position INTO STRICT last FROM rss_observation.journals WHERE tenant_id=t FOR UPDATE;
 IF last=9223372036854775807 THEN
  RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='journal exhausted';
 END IF;
 IF p_applicable THEN
  position:=last+1;
  UPDATE rss_observation.journals SET last_position=position WHERE tenant_id=t;
 END IF;
 INSERT INTO rss_observation.batches(tenant_id,scope,batch_id,sequence,raw,fingerprint,received_at,policy,decision,applicable,log_position)
 VALUES(t,p_scope,p_id,p_sequence,p_raw,p_fingerprint,p_received,p_policy,p_decision,p_applicable,position);
 UPDATE rss_observation.streams SET state=(p_decision::jsonb->'after')::text WHERE tenant_id=t AND scope=p_scope;
END $$;
COMMENT ON SCHEMA rss_observation IS 'rss-observation-postgres:2';
COMMIT;
