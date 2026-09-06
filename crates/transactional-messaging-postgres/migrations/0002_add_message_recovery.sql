-- One-way component upgrade; execution and role grants belong to the external migrator.
ALTER TABLE rss_transactional_messaging.outbox ADD COLUMN recovery_version bigint NOT NULL DEFAULT 1 CHECK (recovery_version > 0);
ALTER TABLE rss_transactional_messaging.outbox DROP CONSTRAINT outbox_status_check;
ALTER TABLE rss_transactional_messaging.outbox ADD CONSTRAINT outbox_status_check CHECK (status IN ('pending','publishing','published','dead_letter','resolved'));
CREATE TABLE rss_transactional_messaging.consumer_dead_letter (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 message_id text NOT NULL,
 consumer_group text NOT NULL,
 contract text NOT NULL,
 contract_version text NOT NULL,
 schema_digest text NOT NULL,
 fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
 capsule bytea NOT NULL CHECK (octet_length(capsule) BETWEEN 1 AND 16777216),
 reason text NOT NULL CHECK (reason IN ('rejected_permanent','rejected_invariant')),
 recovery_version bigint NOT NULL DEFAULT 1 CHECK (recovery_version > 0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,id),
 UNIQUE (tenant_id,message_id,consumer_group)
);
CREATE TABLE rss_transactional_messaging.recovery_operations (
 tenant_id uuid NOT NULL,
 operation_id uuid NOT NULL,
 request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
 target_kind text NOT NULL CHECK (target_kind IN ('consumer','outbox')),
 target_key text NOT NULL,
 outcome text NOT NULL CHECK (outcome IN ('replayed','redriven','resolved')),
 result_version bigint NOT NULL CHECK (result_version > 0),
 replay_message_id text,
 resolution text CHECK (resolution IN ('accepted_gap','compensated')),
 evidence_message_id text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,operation_id),
 CONSTRAINT operation_shape CHECK (
   (outcome = 'replayed' AND target_kind = 'consumer' AND replay_message_id IS NOT NULL AND resolution IS NULL AND evidence_message_id IS NULL)
   OR (outcome = 'redriven' AND target_kind = 'outbox' AND replay_message_id IS NULL AND resolution IS NULL AND evidence_message_id IS NULL)
   OR (outcome = 'resolved' AND target_kind = 'outbox' AND replay_message_id IS NULL AND resolution IS NOT NULL AND
     ((resolution = 'accepted_gap' AND evidence_message_id IS NULL) OR (resolution = 'compensated' AND evidence_message_id IS NOT NULL))))
);
CREATE INDEX recovery_replay_source ON rss_transactional_messaging.recovery_operations (tenant_id,replay_message_id) WHERE replay_message_id IS NOT NULL;
ALTER TABLE rss_transactional_messaging.consumer_dead_letter ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.consumer_dead_letter FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.recovery_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.recovery_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_tenant ON rss_transactional_messaging.consumer_dead_letter USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY recovery_tenant ON rss_transactional_messaging.recovery_operations USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON rss_transactional_messaging.consumer_dead_letter, rss_transactional_messaging.recovery_operations FROM PUBLIC;
CREATE OR REPLACE FUNCTION rss_transactional_messaging.claim_outbox(p_domain text, p_limit integer, p_ttl_ms bigint)
RETURNS SETOF rss_transactional_messaging.outbox
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, rss_transactional_messaging
AS $function$
WITH claim_clock AS MATERIALIZED (SELECT clock_timestamp() AS claimed_at),
eligible AS MATERIALIZED (
  SELECT o.seq, c.claimed_at FROM rss_transactional_messaging.outbox o CROSS JOIN claim_clock c
  WHERE o.domain = p_domain AND p_limit BETWEEN 1 AND 64 AND p_ttl_ms BETWEEN 1 AND 86400000
    AND ((o.status = 'pending' AND o.retry_after <= c.claimed_at)
      OR (o.status = 'publishing' AND o.lease_until <= c.claimed_at))
    AND (o.partition_key IS NULL OR NOT EXISTS (
      SELECT 1 FROM rss_transactional_messaging.outbox predecessor
      WHERE predecessor.tenant_id = o.tenant_id AND predecessor.domain = o.domain
        AND predecessor.partition_key = o.partition_key AND predecessor.seq < o.seq
        AND predecessor.status NOT IN ('published', 'resolved')))
  ORDER BY o.seq LIMIT p_limit FOR UPDATE OF o SKIP LOCKED
)
UPDATE rss_transactional_messaging.outbox o SET
  status = 'publishing', lease_token = gen_random_uuid(),
  lease_until = e.claimed_at + p_ttl_ms * interval '1 millisecond',
  automatic_retry_deadline = COALESCE(o.automatic_retry_deadline, e.claimed_at + interval '24 hours')
FROM eligible e WHERE o.seq = e.seq RETURNING o.*
$function$;

-- Lock first, then sample time; a lock wait may invalidate an otherwise matching lease.
CREATE OR REPLACE FUNCTION rss_transactional_messaging.settle_outbox(
  p_seq bigint, p_token uuid, p_lease_us bigint, p_disposition text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_transactional_messaging
AS $function$
DECLARE row rss_transactional_messaging.outbox; observed timestamptz;
BEGIN
  SELECT * INTO row FROM rss_transactional_messaging.outbox o
    WHERE o.seq = p_seq AND o.lease_token = p_token AND o.status = 'publishing'
      AND (extract(epoch FROM o.lease_until) * 1000000)::bigint = p_lease_us FOR UPDATE;
  IF NOT FOUND THEN RETURN 'lost_lease'; END IF;
  observed := clock_timestamp();
  IF row.lease_until <= observed THEN RETURN 'expired'; END IF;
  IF p_disposition NOT IN ('published','retry','dead_letter') THEN
    RAISE EXCEPTION 'invalid settlement disposition';
  END IF;
  UPDATE rss_transactional_messaging.outbox SET
    recovery_version = row.recovery_version + CASE WHEN p_disposition = 'dead_letter' THEN 1 ELSE 0 END,
    status = CASE WHEN p_disposition = 'retry' THEN 'pending' ELSE p_disposition END,
    retry_count = row.retry_count + CASE WHEN p_disposition = 'retry' THEN 1 ELSE 0 END,
    retry_after = CASE WHEN p_disposition = 'retry'
      THEN observed + LEAST(3600, 1::bigint << LEAST(row.retry_count, 12)) * interval '1 second'
      ELSE retry_after END,
    lease_token = NULL, lease_until = NULL
    WHERE seq = row.seq;
  RETURN 'settled';
END
$function$;
