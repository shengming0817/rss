-- Fresh install only. External migrator provisions rss_tmsg_relay NOLOGIN NOBYPASSRLS,
-- owns schema/tables, can transfer function ownership, then grants runtime privileges.
CREATE SCHEMA rss_transactional_messaging;
CREATE TABLE rss_transactional_messaging.policy (
  revision integer PRIMARY KEY CHECK (revision = 1),
  automatic_window_seconds bigint NOT NULL CHECK (automatic_window_seconds = 86400),
  safety_seconds bigint NOT NULL CHECK (safety_seconds = 86400),
  receipt_retention_seconds bigint NOT NULL CHECK
    (receipt_retention_seconds > automatic_window_seconds + safety_seconds)
);
INSERT INTO rss_transactional_messaging.policy VALUES (1, 86400, 86400, 604800);

CREATE TABLE rss_transactional_messaging.inbox (
  tenant_id uuid NOT NULL,
  message_id text NOT NULL,
  consumer_group text NOT NULL,
  contract text NOT NULL,
  lease_token uuid NOT NULL,
  lease_until timestamptz NOT NULL,
  receive_count bigint NOT NULL DEFAULT 1 CHECK (receive_count > 0),
  fingerprint bytea,
  disposition text,
  PRIMARY KEY (tenant_id, message_id, consumer_group),
  CONSTRAINT inbox_receipt_shape CHECK (
    (fingerprint IS NULL AND disposition IS NULL) OR
    (fingerprint IS NOT NULL AND octet_length(fingerprint) = 32
      AND disposition IS NOT NULL AND disposition IN ('succeeded','rejected_permanent','rejected_invariant'))
  )
);
CREATE TABLE rss_transactional_messaging.outbox (
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL,
  message_id text NOT NULL,
  domain text NOT NULL,
  partition_key text,
  envelope jsonb NOT NULL,
  fingerprint bytea NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','publishing','published','dead_letter')),
  retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
  retry_after timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_token uuid,
  lease_until timestamptz,
  automatic_retry_deadline timestamptz,
  UNIQUE (tenant_id, message_id),
  CONSTRAINT outbox_fingerprint_length CHECK (octet_length(fingerprint) = 32),
  CONSTRAINT outbox_lease_shape CHECK ((status = 'publishing') = (lease_token IS NOT NULL AND lease_until IS NOT NULL))
);
CREATE INDEX outbox_partition ON rss_transactional_messaging.outbox (tenant_id, domain, partition_key, seq);
CREATE INDEX outbox_claimable ON rss_transactional_messaging.outbox (domain, retry_after, seq)
  WHERE status IN ('pending','publishing');

ALTER TABLE rss_transactional_messaging.inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_transactional_messaging.outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY inbox_tenant ON rss_transactional_messaging.inbox
  USING (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid);
CREATE POLICY outbox_tenant ON rss_transactional_messaging.outbox
  USING (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid);
CREATE POLICY outbox_relay ON rss_transactional_messaging.outbox TO rss_tmsg_relay
  USING (true) WITH CHECK (true);
-- Temporary CREATE permits a non-superuser migrator to transfer function ownership.
GRANT USAGE, CREATE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;
GRANT SELECT, UPDATE ON rss_transactional_messaging.outbox TO rss_tmsg_relay;

-- Adapted from baseline migration 0064: one authoritative clock and atomic SKIP LOCKED claim.
CREATE FUNCTION rss_transactional_messaging.claim_outbox(p_domain text, p_limit integer, p_ttl_ms bigint)
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
        AND predecessor.status <> 'published'))
  ORDER BY o.seq LIMIT p_limit FOR UPDATE OF o SKIP LOCKED
)
UPDATE rss_transactional_messaging.outbox o SET
  status = 'publishing', lease_token = gen_random_uuid(),
  lease_until = e.claimed_at + p_ttl_ms * interval '1 millisecond',
  automatic_retry_deadline = COALESCE(o.automatic_retry_deadline, e.claimed_at + interval '24 hours')
FROM eligible e WHERE o.seq = e.seq RETURNING o.*
$function$;

-- Lock first, then sample time; a lock wait may invalidate an otherwise matching lease.
CREATE FUNCTION rss_transactional_messaging.outbox_lease(
  p_seq bigint, p_token uuid, p_lease_us bigint, p_extend_ms bigint)
RETURNS TABLE (lease_us bigint, remaining_us bigint, delivery_us bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_transactional_messaging
AS $function$
DECLARE row rss_transactional_messaging.outbox; observed timestamptz;
BEGIN
  IF p_extend_ms IS NULL OR p_extend_ms NOT BETWEEN 0 AND 86400000 THEN RETURN; END IF;
  SELECT * INTO row FROM rss_transactional_messaging.outbox o
    WHERE o.seq = p_seq AND o.lease_token = p_token AND o.status = 'publishing'
      AND (extract(epoch FROM o.lease_until) * 1000000)::bigint = p_lease_us FOR UPDATE;
  observed := clock_timestamp();
  IF NOT FOUND OR row.lease_until <= observed THEN RETURN; END IF;
  IF p_extend_ms > 0 THEN
    row.lease_until := observed + p_extend_ms * interval '1 millisecond';
    UPDATE rss_transactional_messaging.outbox SET lease_until = row.lease_until WHERE seq = row.seq;
  END IF;
  RETURN QUERY SELECT (extract(epoch FROM row.lease_until) * 1000000)::bigint,
    GREATEST(0, (extract(epoch FROM row.lease_until - observed) * 1000000)::bigint),
    GREATEST(0, (extract(epoch FROM row.automatic_retry_deadline - observed) * 1000000)::bigint);
END
$function$;

-- Adapted from baseline migration 0066: closed settlement, token + persisted deadline CAS.
CREATE FUNCTION rss_transactional_messaging.settle_outbox(
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
ALTER FUNCTION rss_transactional_messaging.claim_outbox(text, integer, bigint) OWNER TO rss_tmsg_relay;
ALTER FUNCTION rss_transactional_messaging.outbox_lease(bigint, uuid, bigint, bigint) OWNER TO rss_tmsg_relay;
ALTER FUNCTION rss_transactional_messaging.settle_outbox(bigint, uuid, bigint, text) OWNER TO rss_tmsg_relay;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_transactional_messaging FROM PUBLIC;
REVOKE CREATE ON SCHEMA rss_transactional_messaging FROM rss_tmsg_relay;
-- External migrator explicitly grants runtime USAGE, table/sequence privileges and function EXECUTE.
