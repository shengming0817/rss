-- Check every row in the same snapshot. For an oversized conflict only the
-- bounded V1 header is needed; its payload is opaque. Rust consumes rows as a stream.
SELECT r.tenant_id::text, r.source_id, r.event_id, r.position, r.recorded_at,
       r.ledger_sequence, octet_length(r.canonical) AS stored_bytes,
       octet_length(r.canonical) > i.bytes AS oversized,
       CASE WHEN octet_length(r.canonical) > i.bytes
            THEN substring(r.canonical FROM 1 FOR $5)
            ELSE r.canonical END AS canonical
FROM rss_audit.records r
JOIN unnest($2::text[], $3::text[], $4::integer[]) AS i(source_id, event_id, bytes)
  ON r.source_id = i.source_id AND r.event_id = i.event_id
WHERE r.tenant_id = $1::uuid
