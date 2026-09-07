-- Single execution protocol. External migrator installs verified identities while traffic is isolated.
-- ref: postgres REL_17_STABLE src/backend/access/heap/heapam.c (shared/exclusive tuple locks).
CREATE TABLE rss_transactional_messaging.storage_lineage (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 target bytea NOT NULL CHECK(octet_length(target)=16),
 lineage bytea NOT NULL CHECK(octet_length(lineage)=16)
);
CREATE TABLE rss_transactional_messaging.tenant_epoch (
 tenant_id uuid PRIMARY KEY, epoch bigint NOT NULL CHECK(epoch>0)
);
CREATE TABLE rss_transactional_messaging.dr_plans (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 lineage bytea NOT NULL CHECK(octet_length(lineage)=16), epoch bigint NOT NULL CHECK(epoch>0),
 kind text NOT NULL CHECK(kind IN ('database','broker','terminate')), evidence jsonb,
 target_operation uuid, target_digest bytea,
 CONSTRAINT dr_plan_action CHECK((kind<>'terminate' AND evidence IS NOT NULL AND target_operation IS NULL AND target_digest IS NULL) OR (kind='terminate' AND evidence IS NULL AND target_operation IS NOT NULL AND target_digest IS NOT NULL AND octet_length(target_digest)=32)),
 FOREIGN KEY(tenant_id,target_operation) REFERENCES rss_transactional_messaging.dr_plans(tenant_id,operation_id),
 UNIQUE(tenant_id,target_operation),
 PRIMARY KEY(tenant_id,operation_id), UNIQUE(tenant_id,lineage,epoch)
);
CREATE TABLE rss_transactional_messaging.dr_members (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 499),
 message_id text NOT NULL, consumer_group text NOT NULL, contract text,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32), outbox_seq bigint REFERENCES rss_transactional_messaging.outbox(seq),
 status text NOT NULL CHECK(status IN ('pending','publishing','completed','blocked')),
 block_reason text CONSTRAINT dr_member_reason CHECK(block_reason IN ('deadline_expired','permanent_publish_failure')),
 CONSTRAINT dr_member_block_shape CHECK((status='blocked')=(block_reason IS NOT NULL)),
 lease_token uuid, lease_until timestamptz, retry_after timestamptz NOT NULL DEFAULT clock_timestamp(),
 retry_count integer NOT NULL DEFAULT 0 CHECK(retry_count>=0),
 PRIMARY KEY(tenant_id,operation_id,ordinal), UNIQUE(tenant_id,operation_id,message_id,consumer_group),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES rss_transactional_messaging.dr_plans(tenant_id,operation_id),
 CHECK((status='publishing')=(lease_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK((outbox_seq IS NOT NULL AND consumer_group='' AND contract IS NULL) OR (outbox_seq IS NULL AND consumer_group<>'' AND contract IS NOT NULL))
);
CREATE INDEX dr_member_outbox ON rss_transactional_messaging.dr_members(outbox_seq);
ALTER TABLE rss_transactional_messaging.inbox ADD COLUMN claim_epoch bigint NOT NULL DEFAULT 0;
ALTER TABLE rss_transactional_messaging.inbox ADD COLUMN claim_lineage bytea;
ALTER TABLE rss_transactional_messaging.outbox ADD COLUMN claim_epoch bigint NOT NULL DEFAULT 0;
ALTER TABLE rss_transactional_messaging.outbox ADD COLUMN claim_lineage bytea;
ALTER TABLE rss_transactional_messaging.archive_jobs ADD COLUMN claim_epoch bigint NOT NULL DEFAULT 0;
ALTER TABLE rss_transactional_messaging.archive_jobs ADD COLUMN claim_lineage bytea;
ALTER TABLE rss_transactional_messaging.archive_objects ADD COLUMN verified_epoch bigint NOT NULL DEFAULT 0;
ALTER TABLE rss_transactional_messaging.archive_objects ADD COLUMN verified_lineage bytea;

ALTER TABLE rss_transactional_messaging.tenant_epoch ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.tenant_epoch FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.dr_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.dr_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.dr_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.dr_members FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_fence ON rss_transactional_messaging.tenant_epoch USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY dr_tenant ON rss_transactional_messaging.dr_plans USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY dr_tenant ON rss_transactional_messaging.dr_members USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT USAGE,CREATE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;
-- FOR SHARE needs UPDATE on at least one column. The checked singleton key permits only a no-op.
-- The definer can lock this external witness, but cannot replace its target or lineage.
GRANT SELECT,UPDATE(singleton) ON rss_transactional_messaging.storage_lineage TO rss_tmsg_relay;
GRANT SELECT,UPDATE ON rss_transactional_messaging.tenant_epoch TO rss_tmsg_relay;
GRANT SELECT,INSERT,UPDATE ON rss_transactional_messaging.dr_plans,rss_transactional_messaging.dr_members TO rss_tmsg_relay;
REVOKE ALL ON rss_transactional_messaging.storage_lineage,rss_transactional_messaging.tenant_epoch,rss_transactional_messaging.dr_plans,rss_transactional_messaging.dr_members FROM PUBLIC;

-- Session values are set only by the trusted transaction owner, not application handlers.
CREATE FUNCTION rss_transactional_messaging.check_execution() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE s storage_lineage; e bigint;
BEGIN
 SELECT * INTO s FROM storage_lineage WHERE singleton FOR SHARE;
 IF NOT FOUND OR s.target IS DISTINCT FROM decode(current_setting('rss.storage_target',true),'hex') OR s.lineage IS DISTINCT FROM decode(current_setting('rss.storage_lineage',true),'hex') THEN
  RAISE EXCEPTION 'storage lineage fenced' USING ERRCODE='PZ001'; END IF;
 SELECT epoch INTO e FROM tenant_epoch WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid FOR SHARE;
 IF NOT FOUND OR e IS DISTINCT FROM nullif(current_setting('rss.execution_epoch',true),'')::bigint THEN RAISE EXCEPTION 'tenant epoch fenced' USING ERRCODE='PZ001'; END IF;
END $f$;
ALTER FUNCTION rss_transactional_messaging.check_execution() OWNER TO rss_tmsg_relay;
REVOKE ALL ON FUNCTION rss_transactional_messaging.check_execution() FROM PUBLIC;

-- Row guard also protects direct writes through trusted companion infrastructure. Old SQL with
-- no bound authority fails. This is not a SQL sandbox for holders of trusted connection access.
CREATE FUNCTION rss_transactional_messaging.guard_execution() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
BEGIN
 PERFORM check_execution();
 IF TG_OP='DELETE' THEN
  IF OLD.tenant_id IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION 'tenant scope denied' USING ERRCODE='42501'; END IF;
  RETURN OLD;
 END IF;
 IF NEW.tenant_id IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION 'tenant scope denied' USING ERRCODE='42501'; END IF;
 IF TG_TABLE_NAME IN ('inbox','outbox','archive_jobs') THEN
 IF TG_OP='INSERT' OR NEW.lease_token IS DISTINCT FROM OLD.lease_token THEN
  NEW.claim_epoch:=current_setting('rss.execution_epoch')::bigint;
  NEW.claim_lineage:=decode(current_setting('rss.storage_lineage'),'hex');
 END IF;
 END IF;
 RETURN NEW;
END $f$;
ALTER FUNCTION rss_transactional_messaging.guard_execution() OWNER TO rss_tmsg_relay;
REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_execution() FROM PUBLIC;
DO $f$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['inbox','outbox','consumer_dead_letter','recovery_operations','archive_jobs','archive_objects','dr_members'] LOOP
 EXECUTE format('CREATE TRIGGER execution_fence BEFORE INSERT OR UPDATE OR DELETE ON rss_transactional_messaging.%I FOR EACH ROW EXECUTE FUNCTION rss_transactional_messaging.guard_execution()',tab);
 END LOOP;
END $f$;

-- Archive entrypoints lock the common fence BEFORE their existing source -> job/object locks.
-- Replace the seven canonical entrypoints explicitly; retain their existing source/job lock order.
CREATE OR REPLACE FUNCTION rss_transactional_messaging.archive_claim(p_op uuid,p_id uuid,p_version bigint,p_digest bytea,p_hot bigint,p_cold bigint,p_hold boolean,p_ttl bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; d consumer_dead_letter; j archive_jobs; p policy; a archive_objects; n timestamptz; retired jsonb;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 SELECT * INTO d FROM consumer_dead_letter WHERE tenant_id=t AND id=p_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'archive not found' USING ERRCODE='P0002'; END IF;
 SELECT * INTO p FROM policy WHERE revision=1;
 IF p_hot<p.automatic_window_seconds+p.safety_seconds OR p_cold<=0 OR p_ttl NOT BETWEEN 1 AND 300000 THEN RAISE EXCEPTION 'archive retention' USING ERRCODE='22023'; END IF;
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op FOR UPDATE;
 n:=clock_timestamp();
 IF FOUND THEN
  IF j.request_digest<>p_digest OR j.dead_letter_id<>p_id THEN RAISE EXCEPTION 'archive conflict' USING ERRCODE='40001'; END IF;
  IF j.source_version<>d.recovery_version THEN RAISE EXCEPTION 'archive fenced' USING ERRCODE='PZ001'; END IF;
  IF j.fault='missing' THEN RAISE EXCEPTION 'archive fault' USING ERRCODE='PZ002'; END IF;
  IF j.fault='evidence' THEN RAISE EXCEPTION 'archive fault' USING ERRCODE='PZ003'; END IF;
  IF j.lease_until>n AND j.claim_epoch=current_setting('rss.execution_epoch')::bigint AND j.claim_lineage=decode(current_setting('rss.storage_lineage'),'hex') THEN RAISE EXCEPTION 'archive leased' USING ERRCODE='55P03'; END IF;
 ELSE
  IF d.recovery_version<>p_version THEN RAISE EXCEPTION 'archive revision' USING ERRCODE='40001'; END IF;
  UPDATE consumer_dead_letter SET recovery_version=recovery_version+1 WHERE tenant_id=t AND id=p_id RETURNING * INTO d;
  UPDATE archive_jobs SET lease_until=NULL,lease_token=NULL WHERE tenant_id=t AND dead_letter_id=p_id;
  INSERT INTO archive_jobs(tenant_id,operation_id,dead_letter_id,request_digest,source_version,hot_seconds,cold_seconds,held,generation,purged)
  VALUES(t,p_op,p_id,p_digest,d.recovery_version,p_hot,p_cold,p_hold,gen_random_uuid(),d.capsule IS NULL) RETURNING * INTO j;
  -- A new operation after purge must reuse the existing durable object, never fabricate a HOT source.
  IF d.capsule IS NULL THEN
   SELECT o.* INTO a FROM archive_objects o JOIN archive_jobs old ON old.tenant_id=o.tenant_id AND old.operation_id=o.operation_id WHERE old.tenant_id=t AND old.dead_letter_id=p_id AND o.verified ORDER BY old.source_version DESC LIMIT 1;
   IF NOT FOUND THEN RAISE EXCEPTION 'archive receipt absent' USING ERRCODE='23514'; END IF;
   UPDATE archive_jobs SET generation=a.generation WHERE tenant_id=t AND operation_id=p_op RETURNING * INTO j;
  END IF;
 END IF;
 SELECT * INTO a FROM archive_objects WHERE tenant_id=t AND generation=j.generation;
 IF d.capsule IS NOT NULL AND FOUND AND (a.object->>'retainUntil')::bigint <= extract(epoch FROM n)::bigint+greatest(p_cold,p.receipt_retention_seconds) THEN
  -- Retain coordinates but discard redundant ciphertext of expired generations.
  UPDATE archive_objects SET prepared=NULL WHERE tenant_id=t AND generation=j.generation;
  UPDATE archive_jobs SET generation=gen_random_uuid() WHERE tenant_id=t AND operation_id=p_op RETURNING * INTO j;
 END IF;
 UPDATE archive_jobs SET lease_token=gen_random_uuid(),lease_until=n+p_ttl*interval '1 millisecond' WHERE tenant_id=t AND operation_id=p_op RETURNING * INTO j;
 -- Persist rotation even when an unknown PUT remains unresolved. Every eligible row gets a turn.
 WITH batch AS (
  SELECT o.generation FROM archive_objects o JOIN archive_jobs old ON old.tenant_id=o.tenant_id AND old.operation_id=o.operation_id
  WHERE old.tenant_id=t AND old.dead_letter_id=p_id AND o.generation<>j.generation AND NOT o.reconciled
   AND (o.object->>'retainUntil')::bigint <= floor(extract(epoch FROM n))
  ORDER BY o.last_checked NULLS FIRST,o.generation LIMIT 64
 ), scanned AS (
  UPDATE archive_objects o SET last_checked=n FROM batch b WHERE o.tenant_id=t AND o.generation=b.generation RETURNING o.object
 ) SELECT coalesce(jsonb_agg(object),'[]'::jsonb) INTO retired FROM scanned;
 RETURN jsonb_build_object('retired',retired,'job',to_jsonb(j),'source',to_jsonb(d)-'capsule','capsule',encode(d.capsule,'hex'),'now',floor(extract(epoch FROM n))::bigint,'receipt',p.receipt_retention_seconds,'captured',floor(extract(epoch FROM d.created_at)*1000000)::bigint);
END $f$;

CREATE OR REPLACE FUNCTION rss_transactional_messaging.archive_fence(p_op uuid,p_token uuid,p_digest bytea)
RETURNS rss_transactional_messaging.archive_jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; j archive_jobs; v bigint;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op;
 SELECT recovery_version INTO v FROM consumer_dead_letter WHERE tenant_id=t AND id=j.dead_letter_id FOR UPDATE;
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op FOR UPDATE;
 IF NOT FOUND OR j.claim_epoch<>current_setting('rss.execution_epoch')::bigint OR j.claim_lineage IS DISTINCT FROM decode(current_setting('rss.storage_lineage'),'hex') OR j.source_version<>v OR j.lease_token IS DISTINCT FROM p_token OR j.lease_until<=clock_timestamp() OR j.request_digest<>p_digest THEN RAISE EXCEPTION 'archive fenced' USING ERRCODE='PZ001'; END IF;
 RETURN j;
END $f$;

CREATE OR REPLACE FUNCTION rss_transactional_messaging.archive_prepare(p_op uuid,p_token uuid,p_digest bytea,p_object jsonb,p_bytes bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE j archive_jobs; a archive_objects;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 j:=archive_fence(p_op,p_token,p_digest);
 IF j.held OR j.purged OR p_object->>'key'<>'consumer/'||j.tenant_id::text||'/'||j.dead_letter_id::text||'/'||j.generation::text||'.v1.enc' OR (p_object->>'length')::bigint<>octet_length(p_bytes) THEN RAISE EXCEPTION 'archive evidence' USING ERRCODE='23514'; END IF;
 INSERT INTO archive_objects(tenant_id,operation_id,generation,object,prepared) VALUES(j.tenant_id,p_op,j.generation,p_object,p_bytes) ON CONFLICT DO NOTHING;
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=j.generation;
 IF a.object<>p_object OR a.prepared IS DISTINCT FROM p_bytes THEN RAISE EXCEPTION 'archive conflict' USING ERRCODE='40001'; END IF;
END $f$;

CREATE OR REPLACE FUNCTION rss_transactional_messaging.archive_record(p_op uuid,p_token uuid,p_digest bytea,p_generation uuid,p_object jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE j archive_jobs; a archive_objects;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 j:=archive_fence(p_op,p_token,p_digest);
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=p_generation FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM archive_jobs old WHERE old.tenant_id=j.tenant_id AND old.operation_id=a.operation_id AND old.dead_letter_id=j.dead_letter_id) OR j.held OR a.object-'version'-'retainUntil'<>p_object-'version'-'retainUntil' OR nullif(p_object->>'version','') IS NULL OR p_object->>'version'='null' OR (p_object->>'retainUntil')::bigint<(a.object->>'retainUntil')::bigint OR (a.verified AND a.object->>'version'<>p_object->>'version') THEN RAISE EXCEPTION 'archive evidence' USING ERRCODE='23514'; END IF;
 UPDATE archive_objects SET object=p_object,verified=true,prepared=NULL WHERE tenant_id=j.tenant_id AND generation=p_generation;
END $f$;

CREATE OR REPLACE FUNCTION rss_transactional_messaging.archive_purge(p_op uuid,p_token uuid,p_digest bytea,p_object jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE j archive_jobs; a archive_objects; d consumer_dead_letter; p policy; n timestamptz;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 j:=archive_fence(p_op,p_token,p_digest);
 SELECT * INTO d FROM consumer_dead_letter WHERE tenant_id=j.tenant_id AND id=j.dead_letter_id;
 SELECT * INTO p FROM policy WHERE revision=1;
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=j.generation;
 n:=clock_timestamp();
 IF j.held OR j.fault IS NOT NULL OR NOT a.verified OR a.object IS DISTINCT FROM p_object OR j.hot_seconds<p.automatic_window_seconds+p.safety_seconds OR d.created_at+j.hot_seconds*interval '1 second'>n OR (p_object->>'retainUntil')::bigint<=extract(epoch FROM n)+greatest(j.cold_seconds,p.receipt_retention_seconds) THEN RAISE EXCEPTION 'archive unsafe purge' USING ERRCODE='23514'; END IF;
 UPDATE consumer_dead_letter SET capsule=NULL WHERE tenant_id=j.tenant_id AND id=j.dead_letter_id;
 UPDATE archive_jobs SET purged=true WHERE tenant_id=j.tenant_id AND operation_id=p_op;
END $f$;

CREATE OR REPLACE FUNCTION rss_transactional_messaging.archive_missing(p_op uuid,p_token uuid,p_digest bytea,p_generation uuid,p_object jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE j archive_jobs; a archive_objects;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 j:=archive_fence(p_op,p_token,p_digest);
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=p_generation FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM archive_jobs old WHERE old.tenant_id=j.tenant_id AND old.operation_id=a.operation_id AND old.dead_letter_id=j.dead_letter_id) OR a.object<>p_object OR (a.object->>'retainUntil')::bigint>extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION 'archive unsafe reconcile' USING ERRCODE='23514'; END IF;
 UPDATE archive_objects SET reconciled=true,prepared=NULL WHERE tenant_id=j.tenant_id AND generation=p_generation;
END $f$;

CREATE OR REPLACE FUNCTION rss_transactional_messaging.archive_fault(p_op uuid,p_token uuid,p_digest bytea,p_fault text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE j archive_jobs;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 j:=archive_fence(p_op,p_token,p_digest);
 IF p_fault IS NULL OR p_fault NOT IN ('missing','evidence') THEN RAISE EXCEPTION 'archive invalid fault' USING ERRCODE='23514'; END IF;
 UPDATE archive_jobs SET fault=coalesce(fault,p_fault) WHERE tenant_id=j.tenant_id AND operation_id=p_op;
END $f$;
-- HOT purge requires object verification in the current execution generation.
-- archive_fence above guards every claim-bound mutation; archive_claim may supersede old jobs.
CREATE FUNCTION rss_transactional_messaging.guard_archive_generation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
BEGIN
 IF TG_TABLE_NAME='archive_jobs' THEN
  IF NEW.purged AND NOT OLD.purged AND NOT EXISTS(SELECT 1 FROM archive_objects o WHERE o.tenant_id=NEW.tenant_id AND o.generation=NEW.generation AND o.verified_epoch=current_setting('rss.execution_epoch')::bigint AND o.verified_lineage=decode(current_setting('rss.storage_lineage'),'hex')) THEN RAISE EXCEPTION 'archive evidence' USING ERRCODE='PZ003'; END IF;
 ELSE
  NEW.verified_epoch:=current_setting('rss.execution_epoch')::bigint;
  NEW.verified_lineage:=decode(current_setting('rss.storage_lineage'),'hex');
 END IF;
 RETURN NEW;
END $f$;
-- Archive owner already has object visibility; retain migration owner for this trigger and deny EXECUTE.
REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_archive_generation() FROM PUBLIC;
CREATE TRIGGER archive_generation BEFORE UPDATE ON rss_transactional_messaging.archive_jobs FOR EACH ROW EXECUTE FUNCTION rss_transactional_messaging.guard_archive_generation();
CREATE TRIGGER archive_generation BEFORE UPDATE OF verified ON rss_transactional_messaging.archive_objects FOR EACH ROW EXECUTE FUNCTION rss_transactional_messaging.guard_archive_generation();

DROP FUNCTION rss_transactional_messaging.claim_outbox(text,integer,bigint);
DROP FUNCTION rss_transactional_messaging.outbox_lease(bigint,uuid,bigint,bigint);
DROP FUNCTION rss_transactional_messaging.settle_outbox(bigint,uuid,bigint,text);
CREATE FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid,p_domain text,p_limit integer,p_ttl_ms bigint)
RETURNS TABLE(seq bigint,tenant_id uuid,message_id text,domain text,partition_key text,lease_token uuid,lease_until timestamptz,envelope jsonb,fingerprint bytea,dr_operation uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE r record; o outbox; m dr_members; n timestamptz; e bigint:=nullif(current_setting('rss.execution_epoch',true),'')::bigint; l bytea:=decode(current_setting('rss.storage_lineage',true),'hex'); used integer:=0;
BEGIN
 PERFORM check_execution();
 IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid OR p_limit NOT BETWEEN 1 AND 64 OR p_ttl_ms NOT BETWEEN 1 AND 86400000 THEN RAISE EXCEPTION 'invalid claim' USING ERRCODE='22023'; END IF;
 FOR r IN
  SELECT src.seq AS source_seq, d.operation_id AS op FROM outbox src
  LEFT JOIN (dr_members d JOIN dr_plans p ON p.tenant_id=d.tenant_id AND p.operation_id=d.operation_id AND p.epoch=e AND p.lineage=l) ON d.outbox_seq=src.seq AND d.status<>'completed'
  WHERE src.tenant_id=p_tenant AND src.domain=p_domain
   AND ((d.operation_id IS NULL AND (src.status='pending' OR (src.status='publishing' AND (src.lease_until<=clock_timestamp() OR src.claim_epoch<>e OR src.claim_lineage IS DISTINCT FROM l))))
     OR (d.status='pending' OR (d.status='publishing' AND d.lease_until<=clock_timestamp())))
   AND COALESCE(d.retry_after,src.retry_after)<=clock_timestamp()
   AND (src.partition_key IS NULL OR NOT EXISTS(
    SELECT 1 FROM outbox predecessor WHERE predecessor.tenant_id=src.tenant_id AND predecessor.domain=src.domain AND predecessor.partition_key=src.partition_key AND predecessor.seq<src.seq
    AND (predecessor.status NOT IN ('published','resolved') OR EXISTS(SELECT 1 FROM dr_members x JOIN dr_plans p ON p.tenant_id=x.tenant_id AND p.operation_id=x.operation_id WHERE x.outbox_seq=predecessor.seq AND p.epoch=e AND p.lineage=l AND x.status<>'completed'))))
  ORDER BY src.seq
 LOOP
  EXIT WHEN used>=p_limit;
  SELECT * INTO o FROM outbox src WHERE src.seq=r.source_seq FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN CONTINUE; END IF;
  n:=clock_timestamp();
  IF r.op IS NULL THEN
   IF NOT (o.status='pending' OR (o.status='publishing' AND (o.lease_until<=n OR o.claim_epoch<>e OR o.claim_lineage IS DISTINCT FROM l))) OR o.retry_after>n THEN CONTINUE; END IF;
   UPDATE outbox src SET status='publishing',lease_token=gen_random_uuid(),lease_until=n+p_ttl_ms*interval '1 millisecond',automatic_retry_deadline=COALESCE(src.automatic_retry_deadline,n+interval '24 hours') WHERE src.seq=o.seq RETURNING * INTO o;
  ELSE
   SELECT * INTO m FROM dr_members x WHERE x.tenant_id=p_tenant AND x.operation_id=r.op AND x.outbox_seq=o.seq FOR UPDATE;
   IF NOT FOUND OR NOT (m.status='pending' OR (m.status='publishing' AND m.lease_until<=n)) OR m.retry_after>n THEN CONTINUE; END IF;
   IF o.automatic_retry_deadline IS NULL OR o.automatic_retry_deadline<=n THEN
    UPDATE dr_members x SET status='blocked',block_reason='deadline_expired',lease_token=NULL,lease_until=NULL WHERE x.tenant_id=p_tenant AND x.operation_id=r.op AND x.outbox_seq=o.seq; CONTINUE;
   END IF;
   UPDATE dr_members x SET status='publishing',lease_token=gen_random_uuid(),lease_until=n+p_ttl_ms*interval '1 millisecond' WHERE x.tenant_id=p_tenant AND x.operation_id=r.op AND x.outbox_seq=o.seq RETURNING * INTO m;
   o.lease_token:=m.lease_token; o.lease_until:=m.lease_until;
  END IF;
  used:=used+1;
  RETURN QUERY SELECT o.seq,o.tenant_id,o.message_id,o.domain,o.partition_key,o.lease_token,o.lease_until,o.envelope,o.fingerprint,r.op;
 END LOOP;
END $f$;

CREATE FUNCTION rss_transactional_messaging.outbox_lease(p_tenant uuid,p_seq bigint,p_token uuid,p_lease_us bigint,p_extend_ms bigint,p_dr uuid)
RETURNS TABLE(lease_us bigint,remaining_us bigint,delivery_us bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE o outbox; m dr_members; n timestamptz; deadline timestamptz; e bigint:=current_setting('rss.execution_epoch')::bigint; l bytea:=decode(current_setting('rss.storage_lineage'),'hex');
BEGIN
 PERFORM check_execution();
 IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid OR p_extend_ms NOT BETWEEN 0 AND 86400000 THEN RETURN; END IF;
 SELECT * INTO o FROM outbox src WHERE src.seq=p_seq AND src.tenant_id=p_tenant FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 IF p_dr IS NULL THEN
  IF o.status<>'publishing' OR o.lease_token IS DISTINCT FROM p_token OR o.claim_epoch<>e OR o.claim_lineage IS DISTINCT FROM l THEN RETURN; END IF;
  deadline:=o.lease_until;
 ELSE
  SELECT x.* INTO m FROM dr_members x JOIN dr_plans p ON p.tenant_id=x.tenant_id AND p.operation_id=x.operation_id WHERE x.tenant_id=p_tenant AND x.operation_id=p_dr AND x.outbox_seq=p_seq AND p.epoch=e AND p.lineage=l FOR UPDATE OF x;
  IF NOT FOUND OR m.status<>'publishing' OR m.lease_token IS DISTINCT FROM p_token THEN RETURN; END IF;
  deadline:=m.lease_until;
 END IF;
 n:=clock_timestamp();
 IF deadline<=n OR (extract(epoch FROM deadline)*1000000)::bigint<>p_lease_us THEN RETURN; END IF;
 IF p_extend_ms>0 THEN
  deadline:=n+p_extend_ms*interval '1 millisecond';
  IF p_dr IS NULL THEN UPDATE outbox SET lease_until=deadline WHERE outbox.seq=p_seq;
  ELSE UPDATE dr_members SET lease_until=deadline WHERE dr_members.tenant_id=p_tenant AND operation_id=p_dr AND outbox_seq=p_seq; END IF;
 END IF;
 RETURN QUERY SELECT (extract(epoch FROM deadline)*1000000)::bigint,GREATEST(0,(extract(epoch FROM deadline-n)*1000000)::bigint),GREATEST(0,(extract(epoch FROM o.automatic_retry_deadline-n)*1000000)::bigint);
END $f$;
CREATE FUNCTION rss_transactional_messaging.settle_outbox(p_tenant uuid,p_seq bigint,p_token uuid,p_lease_us bigint,p_disposition text,p_dr uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE n timestamptz; remaining bigint;
BEGIN
 SELECT delivery_us INTO remaining FROM outbox_lease(p_tenant,p_seq,p_token,p_lease_us,0,p_dr);
 IF NOT FOUND THEN RETURN 'lost_lease'; END IF;
 IF p_disposition NOT IN ('published','retry','dead_letter') THEN RAISE EXCEPTION 'invalid settlement' USING ERRCODE='22023'; END IF;
 n:=clock_timestamp();
 IF p_dr IS NULL THEN
  UPDATE outbox SET recovery_version=recovery_version+CASE WHEN p_disposition='dead_letter' THEN 1 ELSE 0 END,
   status=CASE WHEN p_disposition='retry' THEN 'pending' ELSE p_disposition END,
   retry_count=retry_count+CASE WHEN p_disposition='retry' THEN 1 ELSE 0 END,
   retry_after=CASE WHEN p_disposition='retry' THEN n+LEAST(3600,1::bigint<<LEAST(retry_count,12))*interval '1 second' ELSE retry_after END,
   lease_token=NULL,lease_until=NULL WHERE seq=p_seq AND tenant_id=p_tenant;
 ELSE
  UPDATE dr_members SET block_reason=CASE WHEN p_disposition='published' OR (p_disposition='retry' AND remaining>0) THEN NULL WHEN remaining<=0 THEN 'deadline_expired' ELSE 'permanent_publish_failure' END,
   status=CASE WHEN p_disposition='published' THEN 'completed' WHEN p_disposition='retry' AND remaining>0 THEN 'pending' ELSE 'blocked' END,
   retry_after=n+LEAST(3600,1::bigint<<LEAST(retry_count,12))*interval '1 second',retry_count=retry_count+1,
   lease_token=NULL,lease_until=NULL WHERE tenant_id=p_tenant AND operation_id=p_dr AND outbox_seq=p_seq;
 END IF;
 RETURN 'settled';
END $f$;
ALTER FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint) OWNER TO rss_tmsg_relay;
ALTER FUNCTION rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid) OWNER TO rss_tmsg_relay;
ALTER FUNCTION rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) OWNER TO rss_tmsg_relay;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_transactional_messaging FROM PUBLIC;
REVOKE CREATE ON SCHEMA rss_transactional_messaging FROM rss_tmsg_relay;
