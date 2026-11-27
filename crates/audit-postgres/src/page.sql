WITH tail AS (
    SELECT COALESCE((SELECT max(position) FROM rss_audit.records WHERE tenant_id=$1::uuid),-1) AS position
), bounds AS MATERIALIZED (
    SELECT COALESCE($5::bigint, position) AS through, position AS current_head FROM tail
), selected AS MATERIALIZED (
    SELECT position, octet_length(canonical)::bigint AS bytes
    FROM rss_audit.records, bounds
    WHERE tenant_id=$1::uuid AND position>$2 AND position<=bounds.through
    ORDER BY position LIMIT $3
), summary AS (
    SELECT COALESCE(sum(bytes),0) AS bytes, max(position) AS last,
        COALESCE(bool_and(bytes BETWEEN 1 AND 131072),true) AS valid
    FROM selected
), admission AS MATERIALIZED (
    SELECT b.through, CASE
        WHEN $5::bigint IS NOT NULL AND (b.through>b.current_head OR $2>=b.through) THEN 3
        WHEN NOT s.valid THEN 2
        WHEN s.bytes>$4 THEN 1 ELSE 0 END AS status
    FROM summary s CROSS JOIN bounds b
)
SELECT a.status,a.through,EXISTS(SELECT FROM rss_audit.records remaining WHERE remaining.tenant_id=$1::uuid AND remaining.position>(SELECT last FROM summary) AND remaining.position<=a.through) AS has_more,r.tenant_id::text,r.source_id,r.event_id,r.position,r.recorded_at,r.canonical,r.ledger_sequence
FROM admission a LEFT JOIN rss_audit.records r ON a.status=0 AND r.tenant_id=$1::uuid
    AND r.position IN (SELECT position FROM selected)
ORDER BY r.position
