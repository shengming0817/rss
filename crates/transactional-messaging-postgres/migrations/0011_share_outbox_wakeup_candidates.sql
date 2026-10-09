-- One candidate definition owns partition, generation, DR and durable scheduling eligibility.
-- ref: PostgreSQL REL_17_6 src/backend/executor/nodeLockRows.c (SKIP LOCKED and lock-time recheck).
GRANT CREATE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;
CREATE FUNCTION rss_transactional_messaging.outbox_candidates(p_tenant uuid,p_domain text)
RETURNS TABLE(source_seq bigint,dr_operation uuid,eligible_at timestamptz)
LANGUAGE sql SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
 WITH generation AS (
  SELECT nullif(current_setting('rss.execution_epoch',true),'')::bigint AS epoch,
   decode(current_setting('rss.storage_lineage',true),'hex') AS lineage
 )
 SELECT src.seq,d.operation_id,
  greatest(COALESCE(d.retry_after,src.retry_after),
   CASE WHEN d.operation_id IS NOT NULL AND d.status='publishing' THEN d.lease_until
    WHEN d.operation_id IS NULL AND src.status='publishing' AND src.claim_epoch=g.epoch
     AND src.claim_lineage IS NOT DISTINCT FROM g.lineage THEN src.lease_until
    ELSE '-infinity'::timestamptz END)
 FROM outbox src CROSS JOIN generation g
 LEFT JOIN (dr_members d JOIN dr_plans p ON p.tenant_id=d.tenant_id AND p.operation_id=d.operation_id)
  ON d.outbox_seq=src.seq AND d.status<>'completed' AND p.epoch=g.epoch AND p.lineage=g.lineage
 WHERE src.tenant_id=p_tenant AND src.domain=p_domain
  AND ((d.operation_id IS NULL AND src.status IN ('pending','publishing')) OR d.status IN ('pending','publishing'))
  AND (src.partition_key IS NULL OR NOT EXISTS(
   SELECT 1 FROM outbox predecessor WHERE predecessor.tenant_id=src.tenant_id AND predecessor.domain=src.domain
    AND predecessor.partition_key=src.partition_key AND predecessor.partition_seq<src.partition_seq
    AND (predecessor.status NOT IN ('published','resolved') OR EXISTS(
     SELECT 1 FROM dr_members x JOIN dr_plans p ON p.tenant_id=x.tenant_id AND p.operation_id=x.operation_id
     WHERE x.outbox_seq=predecessor.seq AND p.epoch=g.epoch AND p.lineage=g.lineage AND x.status<>'completed'))))
$f$;
ALTER FUNCTION rss_transactional_messaging.outbox_candidates(uuid,text) OWNER TO rss_tmsg_relay;
REVOKE ALL ON FUNCTION rss_transactional_messaging.outbox_candidates(uuid,text) FROM PUBLIC;

CREATE FUNCTION rss_transactional_messaging.next_outbox_wakeup(p_tenant uuid,p_domain text)
RETURNS TABLE(due_now boolean,next_us bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE observed timestamptz;
BEGIN
 PERFORM check_execution();
 IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid OR p_domain IS NULL THEN
  RAISE EXCEPTION 'invalid wakeup scope' USING ERRCODE='22023';
 END IF;
 observed:=clock_timestamp();
 RETURN QUERY SELECT coalesce(bool_or(c.eligible_at<=observed),false),
  floor(extract(epoch FROM (min(c.eligible_at) FILTER(WHERE c.eligible_at>observed)-observed))*1000000)::bigint
 FROM outbox_candidates(p_tenant,p_domain) c;
END $f$;
ALTER FUNCTION rss_transactional_messaging.next_outbox_wakeup(uuid,text) OWNER TO rss_tmsg_relay;
REVOKE ALL ON FUNCTION rss_transactional_messaging.next_outbox_wakeup(uuid,text) FROM PUBLIC;
REVOKE CREATE ON SCHEMA rss_transactional_messaging FROM rss_tmsg_relay;

CREATE OR REPLACE FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid,p_domain text,p_limit integer,p_ttl_ms bigint)
RETURNS TABLE(seq bigint,tenant_id uuid,message_id text,domain text,partition_key text,lease_token uuid,lease_until timestamptz,envelope jsonb,fingerprint bytea,dr_operation uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE r record; o outbox; m dr_members; n timestamptz; e bigint:=nullif(current_setting('rss.execution_epoch',true),'')::bigint; l bytea:=decode(current_setting('rss.storage_lineage',true),'hex'); used integer:=0;
BEGIN
 PERFORM check_execution();
 IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid OR p_limit NOT BETWEEN 1 AND 64 OR p_ttl_ms NOT BETWEEN 1 AND 86400000 THEN RAISE EXCEPTION 'invalid claim' USING ERRCODE='22023'; END IF;
 FOR r IN
  SELECT source_seq,dr_operation AS op FROM outbox_candidates(p_tenant,p_domain)
  WHERE eligible_at<=clock_timestamp() ORDER BY source_seq
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

