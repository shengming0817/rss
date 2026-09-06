ALTER TABLE rss_transactional_messaging.archive_objects ADD COLUMN last_checked timestamptz;

-- Preserve the stable archive error and transaction settlement contract.
CREATE OR REPLACE FUNCTION rss_transactional_messaging.archive_claim(p_op uuid,p_id uuid,p_version bigint,p_digest bytea,p_hot bigint,p_cold bigint,p_hold boolean,p_ttl bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; d consumer_dead_letter; j archive_jobs; p policy; a archive_objects; n timestamptz; retired jsonb;
BEGIN
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
  IF j.lease_until>n THEN RAISE EXCEPTION 'archive leased' USING ERRCODE='55P03'; END IF;
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

-- Locks are acquired in the same source -> job order as claim/replay/cleanup.
CREATE OR REPLACE FUNCTION rss_transactional_messaging.archive_fence(p_op uuid,p_token uuid,p_digest bytea)
RETURNS rss_transactional_messaging.archive_jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; j archive_jobs; v bigint;
BEGIN
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op;
 SELECT recovery_version INTO v FROM consumer_dead_letter WHERE tenant_id=t AND id=j.dead_letter_id FOR UPDATE;
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op FOR UPDATE;
 IF NOT FOUND OR j.source_version<>v OR j.lease_token IS DISTINCT FROM p_token OR j.lease_until<=clock_timestamp() OR j.request_digest<>p_digest THEN RAISE EXCEPTION 'archive fenced' USING ERRCODE='PZ001'; END IF;
 RETURN j;
END $f$;

-- Replace the incomplete fault entry point; no callable compatibility overload remains.
DROP FUNCTION rss_transactional_messaging.archive_fault(uuid,uuid,bytea);
CREATE FUNCTION rss_transactional_messaging.archive_fault(p_op uuid,p_token uuid,p_digest bytea,p_fault text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging AS $f$
DECLARE j archive_jobs;
BEGIN
 j:=archive_fence(p_op,p_token,p_digest);
 IF p_fault IS NULL OR p_fault NOT IN ('missing','evidence') THEN RAISE EXCEPTION 'archive invalid fault' USING ERRCODE='23514'; END IF;
 UPDATE archive_jobs SET fault=coalesce(fault,p_fault) WHERE tenant_id=j.tenant_id AND operation_id=p_op;
END $f$;
REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_fault(uuid,uuid,bytea,text) FROM PUBLIC;
