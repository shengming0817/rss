-- Batch-ready candidates without scanning terminal history or checking consumer scope per row.
-- ref: PostgreSQL REL_17_6 src/backend/executor/nodeLockRows.c; River river_job.sql JobGetAvailable.
GRANT CREATE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;
CREATE FUNCTION rss_transactional_messaging.consumer_scope_domain()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
 SELECT domain FROM consumer_scope WHERE login_role=session_user
$f$;
ALTER FUNCTION rss_transactional_messaging.consumer_scope_domain() OWNER TO rss_tmsg_relay;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.consumer_scope_domain() TO PUBLIC;
ALTER POLICY outbox_consumer_scope ON rss_transactional_messaging.outbox
 USING((domain=(SELECT rss_transactional_messaging.consumer_scope_domain())) IS NOT FALSE)
 WITH CHECK((domain=(SELECT rss_transactional_messaging.consumer_scope_domain())) IS NOT FALSE);
DROP FUNCTION rss_transactional_messaging.consumer_domain_allowed(text);

CREATE INDEX outbox_pending_candidates ON rss_transactional_messaging.outbox(tenant_id,domain,seq)
 WHERE status IN ('pending','publishing');
CREATE INDEX outbox_unfinished_partition ON rss_transactional_messaging.outbox(tenant_id,domain,partition_key,partition_seq)
 WHERE partition_key IS NOT NULL AND status NOT IN ('published','resolved');

CREATE OR REPLACE FUNCTION rss_transactional_messaging.outbox_candidates(p_tenant uuid,p_domain text)
RETURNS TABLE(source_seq bigint,dr_operation uuid,eligible_at timestamptz)
LANGUAGE sql SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
 WITH generation AS (
  SELECT nullif(current_setting('rss.execution_epoch',true),'')::bigint AS epoch,
   decode(current_setting('rss.storage_lineage',true),'hex') AS lineage
 ), current_dr AS MATERIALIZED (
  SELECT d.* FROM dr_members d JOIN dr_plans p USING(tenant_id,operation_id)
  CROSS JOIN generation g
  WHERE d.tenant_id=p_tenant AND p.epoch=g.epoch AND p.lineage=g.lineage
   AND d.outbox_seq IS NOT NULL AND d.status<>'completed'
 ), candidates AS (
  SELECT src.seq,src.tenant_id,src.domain,src.partition_key,src.partition_seq,
   NULL::uuid AS operation_id,
   greatest(src.retry_after,CASE WHEN src.status='publishing' AND src.claim_epoch=g.epoch
    AND src.claim_lineage IS NOT DISTINCT FROM g.lineage THEN src.lease_until
    ELSE '-infinity'::timestamptz END) AS eligible_at
  FROM outbox src CROSS JOIN generation g
  WHERE src.tenant_id=p_tenant AND src.domain=p_domain AND src.status IN ('pending','publishing')
   AND NOT EXISTS(SELECT FROM current_dr d WHERE d.outbox_seq=src.seq)
  UNION ALL
  SELECT src.seq,src.tenant_id,src.domain,src.partition_key,src.partition_seq,d.operation_id,
   greatest(d.retry_after,CASE WHEN d.status='publishing' THEN d.lease_until ELSE '-infinity'::timestamptz END)
  FROM current_dr d JOIN outbox src ON src.seq=d.outbox_seq
  WHERE src.tenant_id=p_tenant AND src.domain=p_domain AND d.status IN ('pending','publishing')
 )
 SELECT c.seq,c.operation_id,c.eligible_at FROM candidates c
 WHERE c.partition_key IS NULL OR (
  NOT EXISTS(SELECT FROM outbox predecessor
   WHERE predecessor.tenant_id=c.tenant_id AND predecessor.domain=c.domain
    AND predecessor.partition_key=c.partition_key AND predecessor.partition_seq<c.partition_seq
    AND predecessor.status NOT IN ('published','resolved'))
  AND NOT EXISTS(SELECT FROM current_dr d JOIN outbox predecessor ON predecessor.seq=d.outbox_seq
   WHERE predecessor.tenant_id=c.tenant_id AND predecessor.domain=c.domain
    AND predecessor.partition_key=c.partition_key AND predecessor.partition_seq<c.partition_seq)
 )
$f$;
CREATE OR REPLACE FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid,p_domain text,p_limit integer,p_ttl_ms bigint)
RETURNS TABLE(seq bigint,tenant_id uuid,message_id text,domain text,partition_key text,lease_token uuid,lease_until timestamptz,envelope jsonb,fingerprint bytea,dr_operation uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE r record; o outbox; m dr_members; n timestamptz; e bigint:=nullif(current_setting('rss.execution_epoch',true),'')::bigint; l bytea:=decode(current_setting('rss.storage_lineage',true),'hex'); used integer:=0;
BEGIN
 PERFORM check_execution();
 IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid OR p_limit IS NULL OR p_limit < 1 OR p_ttl_ms NOT BETWEEN 1 AND 86400000 THEN RAISE EXCEPTION 'invalid claim' USING ERRCODE='22023'; END IF;
 FOR r IN
  SELECT c.source_seq,c.dr_operation AS op FROM outbox_candidates(p_tenant,p_domain) c
  WHERE c.eligible_at<=clock_timestamp() ORDER BY c.source_seq
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


REVOKE CREATE ON SCHEMA rss_transactional_messaging FROM rss_tmsg_relay;
