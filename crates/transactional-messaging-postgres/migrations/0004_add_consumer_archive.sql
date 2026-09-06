-- Component upgrade; external migrator owns execution and grants. No legacy schema is imported.
ALTER TABLE rss_transactional_messaging.consumer_dead_letter ALTER COLUMN capsule DROP NOT NULL;
CREATE TABLE rss_transactional_messaging.archive_jobs (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, dead_letter_id uuid NOT NULL,
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32), source_version bigint NOT NULL,
 hot_seconds bigint NOT NULL CHECK(hot_seconds>0), cold_seconds bigint NOT NULL CHECK(cold_seconds>0),
 held boolean NOT NULL, generation uuid NOT NULL, lease_token uuid, lease_until timestamptz,
 purged boolean NOT NULL DEFAULT false, fault text CHECK(fault IN ('missing','evidence')),
 PRIMARY KEY(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,dead_letter_id) REFERENCES rss_transactional_messaging.consumer_dead_letter(tenant_id,id)
);
CREATE TABLE rss_transactional_messaging.archive_objects (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, generation uuid NOT NULL,
 object jsonb NOT NULL, prepared bytea, verified boolean NOT NULL DEFAULT false,
 reconciled boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,generation),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES rss_transactional_messaging.archive_jobs(tenant_id,operation_id),
 CHECK(prepared IS NULL OR octet_length(prepared) BETWEEN 1 AND 67108864)
);
CREATE INDEX archive_source ON rss_transactional_messaging.archive_jobs(tenant_id,dead_letter_id);
ALTER TABLE rss_transactional_messaging.archive_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.archive_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.archive_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.archive_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY archive_tenant ON rss_transactional_messaging.archive_jobs USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY archive_tenant ON rss_transactional_messaging.archive_objects USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON rss_transactional_messaging.archive_jobs,rss_transactional_messaging.archive_objects FROM PUBLIC;

CREATE FUNCTION rss_transactional_messaging.archive_claim(p_op uuid,p_id uuid,p_version bigint,p_digest bytea,p_hot bigint,p_cold bigint,p_hold boolean,p_ttl bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; d consumer_dead_letter; j archive_jobs; p policy; a archive_objects; n timestamptz;
BEGIN
 SELECT * INTO d FROM consumer_dead_letter WHERE tenant_id=t AND id=p_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'archive not found' USING ERRCODE='P0002'; END IF;
 SELECT * INTO p FROM policy WHERE revision=1;
 IF p_hot<p.automatic_window_seconds+p.safety_seconds OR p_cold<=0 OR p_ttl NOT BETWEEN 1 AND 300000 THEN RAISE EXCEPTION 'archive retention' USING ERRCODE='22023'; END IF;
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op FOR UPDATE;
 n:=clock_timestamp();
 IF FOUND THEN
  IF j.request_digest<>p_digest OR j.dead_letter_id<>p_id OR j.source_version<>d.recovery_version THEN RAISE EXCEPTION 'archive conflict' USING ERRCODE='40001'; END IF;
  IF j.lease_until>n THEN RAISE EXCEPTION 'archive leased' USING ERRCODE='40001'; END IF;
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
 RETURN jsonb_build_object('job',to_jsonb(j),'source',to_jsonb(d)-'capsule','capsule',encode(d.capsule,'hex'),'now',floor(extract(epoch FROM n))::bigint,'receipt',p.receipt_retention_seconds,'captured',floor(extract(epoch FROM d.created_at)*1000000)::bigint);
END $f$;

-- Locks are acquired in the same source -> job order as claim/replay/cleanup.
CREATE FUNCTION rss_transactional_messaging.archive_fence(p_op uuid,p_token uuid,p_digest bytea)
RETURNS rss_transactional_messaging.archive_jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; j archive_jobs; v bigint;
BEGIN
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op;
 SELECT recovery_version INTO v FROM consumer_dead_letter WHERE tenant_id=t AND id=j.dead_letter_id FOR UPDATE;
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op FOR UPDATE;
 IF NOT FOUND OR j.source_version<>v OR j.lease_token IS DISTINCT FROM p_token OR j.lease_until<=clock_timestamp() OR j.request_digest<>p_digest THEN RAISE EXCEPTION 'archive fenced' USING ERRCODE='40001'; END IF;
 RETURN j;
END $f$;
CREATE FUNCTION rss_transactional_messaging.archive_prepare(p_op uuid,p_token uuid,p_digest bytea,p_object jsonb,p_bytes bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging AS $f$
DECLARE j archive_jobs; a archive_objects;
BEGIN
 j:=archive_fence(p_op,p_token,p_digest);
 IF j.held OR j.purged OR p_object->>'key'<>'consumer/'||j.tenant_id::text||'/'||j.dead_letter_id::text||'/'||j.generation::text||'.v1.enc' OR (p_object->>'length')::bigint<>octet_length(p_bytes) THEN RAISE EXCEPTION 'archive evidence' USING ERRCODE='23514'; END IF;
 INSERT INTO archive_objects(tenant_id,operation_id,generation,object,prepared) VALUES(j.tenant_id,p_op,j.generation,p_object,p_bytes) ON CONFLICT DO NOTHING;
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=j.generation;
 IF a.object<>p_object OR a.prepared IS DISTINCT FROM p_bytes THEN RAISE EXCEPTION 'archive conflict' USING ERRCODE='40001'; END IF;
END $f$;
CREATE FUNCTION rss_transactional_messaging.archive_record(p_op uuid,p_token uuid,p_digest bytea,p_generation uuid,p_object jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging AS $f$
DECLARE j archive_jobs; a archive_objects;
BEGIN
 j:=archive_fence(p_op,p_token,p_digest);
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=p_generation FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM archive_jobs old WHERE old.tenant_id=j.tenant_id AND old.operation_id=a.operation_id AND old.dead_letter_id=j.dead_letter_id) OR j.held OR a.object-'version'-'retainUntil'<>p_object-'version'-'retainUntil' OR nullif(p_object->>'version','') IS NULL OR p_object->>'version'='null' OR (p_object->>'retainUntil')::bigint<(a.object->>'retainUntil')::bigint OR (a.verified AND a.object->>'version'<>p_object->>'version') THEN RAISE EXCEPTION 'archive evidence' USING ERRCODE='23514'; END IF;
 UPDATE archive_objects SET object=p_object,verified=true,prepared=NULL WHERE tenant_id=j.tenant_id AND generation=p_generation;
END $f$;
CREATE FUNCTION rss_transactional_messaging.archive_purge(p_op uuid,p_token uuid,p_digest bytea,p_object jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging AS $f$
DECLARE j archive_jobs; a archive_objects; d consumer_dead_letter; p policy; n timestamptz;
BEGIN
 j:=archive_fence(p_op,p_token,p_digest);
 SELECT * INTO d FROM consumer_dead_letter WHERE tenant_id=j.tenant_id AND id=j.dead_letter_id;
 SELECT * INTO p FROM policy WHERE revision=1;
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=j.generation;
 n:=clock_timestamp();
 IF j.held OR j.fault IS NOT NULL OR NOT a.verified OR a.object IS DISTINCT FROM p_object OR j.hot_seconds<p.automatic_window_seconds+p.safety_seconds OR d.created_at+j.hot_seconds*interval '1 second'>n OR (p_object->>'retainUntil')::bigint<=extract(epoch FROM n)+greatest(j.cold_seconds,p.receipt_retention_seconds) THEN RAISE EXCEPTION 'archive unsafe purge' USING ERRCODE='23514'; END IF;
 UPDATE consumer_dead_letter SET capsule=NULL WHERE tenant_id=j.tenant_id AND id=j.dead_letter_id;
 UPDATE archive_jobs SET purged=true WHERE tenant_id=j.tenant_id AND operation_id=p_op;
END $f$;
CREATE FUNCTION rss_transactional_messaging.archive_missing(p_op uuid,p_token uuid,p_digest bytea,p_generation uuid,p_object jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging AS $f$
DECLARE j archive_jobs; a archive_objects;
BEGIN
 j:=archive_fence(p_op,p_token,p_digest);
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=p_generation FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM archive_jobs old WHERE old.tenant_id=j.tenant_id AND old.operation_id=a.operation_id AND old.dead_letter_id=j.dead_letter_id) OR a.object<>p_object OR (a.object->>'retainUntil')::bigint>extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION 'archive unsafe reconcile' USING ERRCODE='23514'; END IF;
 UPDATE archive_objects SET reconciled=true,prepared=NULL WHERE tenant_id=j.tenant_id AND generation=p_generation;
END $f$;
CREATE FUNCTION rss_transactional_messaging.archive_fault(p_op uuid,p_token uuid,p_digest bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging AS $f$
DECLARE j archive_jobs;
BEGIN
 j:=archive_fence(p_op,p_token,p_digest);
 UPDATE archive_jobs SET fault='missing' WHERE tenant_id=j.tenant_id AND operation_id=p_op;
END $f$;
REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_claim(uuid,uuid,bigint,bytea,bigint,bigint,boolean,bigint),rss_transactional_messaging.archive_fence(uuid,uuid,bytea),rss_transactional_messaging.archive_prepare(uuid,uuid,bytea,jsonb,bytea),rss_transactional_messaging.archive_record(uuid,uuid,bytea,uuid,jsonb),rss_transactional_messaging.archive_purge(uuid,uuid,bytea,jsonb),rss_transactional_messaging.archive_missing(uuid,uuid,bytea,uuid,jsonb),rss_transactional_messaging.archive_fault(uuid,uuid,bytea) FROM PUBLIC;
