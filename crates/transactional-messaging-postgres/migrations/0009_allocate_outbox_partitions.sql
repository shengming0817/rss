-- INVARIANT: OUTBOX-PARTITION-ORDER-01
-- A partition ordinal is allocated under its transaction-owned allocator row lock.
-- Existing ordered rows are deliberately unsupported: installation requires an empty
-- ordered Outbox, not a fabricated backfill of historical commit order.
-- ref: postgres REL_17_6 src/backend/access/heap/heapam.c (transaction tuple locks).
CREATE TABLE rss_transactional_messaging.outbox_partitions (
 tenant_id uuid NOT NULL,
 domain text COLLATE "C" NOT NULL,
 partition_key text COLLATE "C" NOT NULL,
 last_sequence bigint NOT NULL DEFAULT 0 CHECK(last_sequence >= 0),
 prepared_by xid8 NOT NULL,
 PRIMARY KEY(tenant_id, domain, partition_key)
);
CREATE INDEX outbox_partition_preparation ON rss_transactional_messaging.outbox_partitions(tenant_id, prepared_by);
ALTER TABLE rss_transactional_messaging.outbox_partitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.outbox_partitions FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_partition_tenant ON rss_transactional_messaging.outbox_partitions
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON rss_transactional_messaging.outbox_partitions FROM PUBLIC;

ALTER TABLE rss_transactional_messaging.outbox ADD COLUMN partition_seq bigint;
ALTER TABLE rss_transactional_messaging.outbox ALTER COLUMN domain TYPE text COLLATE "C",
 ALTER COLUMN partition_key TYPE text COLLATE "C";
ALTER TABLE rss_transactional_messaging.outbox ADD CONSTRAINT outbox_partition_sequence_shape
 CHECK((partition_key IS NULL)=(partition_seq IS NULL) AND (partition_seq IS NULL OR partition_seq > 0));
DROP INDEX rss_transactional_messaging.outbox_partition;
CREATE UNIQUE INDEX outbox_partition ON rss_transactional_messaging.outbox(tenant_id,domain,partition_key,partition_seq)
 WHERE partition_key IS NOT NULL;

GRANT USAGE,CREATE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;
GRANT SELECT,INSERT,UPDATE ON rss_transactional_messaging.outbox_partitions TO rss_tmsg_relay;
GRANT INSERT ON rss_transactional_messaging.outbox TO rss_tmsg_relay;
GRANT USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq TO rss_tmsg_relay;

-- Input is the complete array of [domain, partition_key] pairs for the bound tenant.
-- prepared_by is DB-owned evidence: updating it also holds the row through settlement.
-- Sorting happens BEFORE any allocator row is inserted/locked, including missing rows.
CREATE FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 x xid8:=pg_current_xact_id(); item jsonb; r record;
BEGIN
 PERFORM check_execution();
 IF p_partitions IS NULL OR jsonb_typeof(p_partitions)<>'array' THEN
  RAISE EXCEPTION 'invalid partition declaration' USING ERRCODE='22023';
 END IF;
 -- An empty set acquires nothing and does not establish an ordered admission.
 IF jsonb_array_length(p_partitions)=0 THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM outbox_partitions WHERE tenant_id=t AND prepared_by=x) THEN
  RAISE EXCEPTION 'partition set already declared' USING ERRCODE='PZ002';
 END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(p_partitions) LOOP
  IF jsonb_typeof(item)<>'array' THEN
   RAISE EXCEPTION 'invalid partition declaration' USING ERRCODE='22023';
  END IF;
  IF jsonb_array_length(item)<>2 OR jsonb_typeof(item->0) IS DISTINCT FROM 'string' OR jsonb_typeof(item->1) IS DISTINCT FROM 'string'
   OR octet_length(item->>0) NOT BETWEEN 1 AND 255 OR octet_length(item->>1) NOT BETWEEN 1 AND 255
   OR ((item->>0) COLLATE "C") ~ '[^A-Za-z0-9_.:-]' OR ((item->>1) COLLATE "C") ~ '[[:cntrl:]]' THEN
   RAISE EXCEPTION 'invalid partition declaration' USING ERRCODE='22023';
  END IF;
 END LOOP;
 FOR r IN SELECT DISTINCT (value->>0) COLLATE "C" AS domain, (value->>1) COLLATE "C" AS partition_key
  FROM jsonb_array_elements(p_partitions) ORDER BY domain,partition_key LOOP
  INSERT INTO outbox_partitions(tenant_id,domain,partition_key,prepared_by)
   VALUES(t,r.domain,r.partition_key,x)
   ON CONFLICT(tenant_id,domain,partition_key) DO UPDATE SET prepared_by=EXCLUDED.prepared_by;
 END LOOP;
END $f$;

-- The only runtime INSERT authority. Same-ID readback remains a separate statement
-- after ON CONFLICT waits, so READ COMMITTED observes the winning transaction.
CREATE FUNCTION rss_transactional_messaging.append_outbox(
 p_message_id text,p_domain text,p_partition text,p_envelope jsonb,p_fingerprint bytea)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 ordinal bigint; persisted bytea;
BEGIN
 PERFORM check_execution();
 IF p_message_id IS NULL OR p_domain IS NULL OR p_fingerprint IS NULL
  OR octet_length(p_message_id) NOT BETWEEN 1 AND 255 OR octet_length(p_domain) NOT BETWEEN 1 AND 255
  OR (p_message_id COLLATE "C") ~ '[^A-Za-z0-9_.:-]' OR (p_domain COLLATE "C") ~ '[^A-Za-z0-9_.:-]'
  OR octet_length(p_fingerprint)<>32 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object'
  OR (p_partition IS NOT NULL AND (octet_length(p_partition) NOT BETWEEN 1 AND 255 OR (p_partition COLLATE "C") ~ '[[:cntrl:]]')) THEN
  RAISE EXCEPTION 'invalid outbox identity' USING ERRCODE='22023';
 END IF;
 IF jsonb_typeof(p_envelope->'tenant') IS DISTINCT FROM 'string'
  OR (p_envelope->>'tenant')::uuid IS DISTINCT FROM t
  OR p_envelope->'id' IS DISTINCT FROM to_jsonb(p_message_id)
  OR p_envelope->'domain' IS DISTINCT FROM to_jsonb(p_domain)
  OR p_envelope->'partition' IS DISTINCT FROM COALESCE(to_jsonb(p_partition),'null'::jsonb) THEN
  RAISE EXCEPTION 'outbox envelope identity mismatch' USING ERRCODE='22023';
 END IF;
 IF p_partition IS NOT NULL AND NOT EXISTS(SELECT 1 FROM outbox_partitions
  WHERE tenant_id=t AND domain=p_domain AND partition_key=p_partition AND prepared_by=pg_current_xact_id()) THEN
  RAISE EXCEPTION 'partition was not declared by this transaction' USING ERRCODE='PZ002';
 END IF;
 SELECT o.fingerprint INTO persisted FROM outbox o WHERE o.tenant_id=t AND o.message_id=p_message_id;
 IF FOUND THEN RETURN CASE WHEN persisted=p_fingerprint THEN 'already_present' ELSE 'conflict' END; END IF;
 IF p_partition IS NOT NULL THEN
  UPDATE outbox_partitions SET last_sequence=last_sequence+1
   WHERE tenant_id=t AND domain=p_domain AND partition_key=p_partition AND prepared_by=pg_current_xact_id()
   RETURNING last_sequence INTO ordinal;
 END IF;
 INSERT INTO outbox(tenant_id,message_id,domain,partition_key,partition_seq,envelope,fingerprint)
  VALUES(t,p_message_id,p_domain,p_partition,ordinal,p_envelope,p_fingerprint)
  ON CONFLICT(tenant_id,message_id) DO NOTHING RETURNING outbox.fingerprint INTO persisted;
 IF FOUND THEN RETURN 'inserted'; END IF;
 SELECT o.fingerprint INTO STRICT persisted FROM outbox o WHERE o.tenant_id=t AND o.message_id=p_message_id;
 RETURN CASE WHEN persisted=p_fingerprint THEN 'already_present' ELSE 'conflict' END;
END $f$;

ALTER FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb) OWNER TO rss_tmsg_relay;
ALTER FUNCTION rss_transactional_messaging.append_outbox(text,text,text,jsonb,bytea) OWNER TO rss_tmsg_relay;
REVOKE ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),
 rss_transactional_messaging.append_outbox(text,text,text,jsonb,bytea) FROM PUBLIC;
REVOKE CREATE ON SCHEMA rss_transactional_messaging FROM rss_tmsg_relay;
-- External provisioning grants only EXECUTE + Outbox SELECT to writers. Recovery
-- additionally receives UPDATE(status,recovery_version,lease_token,lease_until,retry_after).
-- Direct Outbox INSERT, ordering-field UPDATE and sequence USAGE are not runtime capabilities.

CREATE OR REPLACE FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid,p_domain text,p_limit integer,p_ttl_ms bigint)
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
    SELECT 1 FROM outbox predecessor WHERE predecessor.tenant_id=src.tenant_id AND predecessor.domain=src.domain AND predecessor.partition_key=src.partition_key AND predecessor.partition_seq<src.partition_seq
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

