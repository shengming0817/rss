-- Compute the running size over bounded metadata before retrieving any event body.
WITH candidates AS (
    SELECT position, octet_length(payload) AS size
    FROM rss_projection.events
    WHERE tenant_id = $1::uuid AND source_id = $2 AND position > $3
    ORDER BY position LIMIT $4
), prefix AS (
    SELECT position, size, row_number() OVER ordered AS ordinal,
           sum(size) OVER ordered AS total
    FROM candidates
    WINDOW ordered AS (ORDER BY position ROWS UNBOUNDED PRECEDING)
)
SELECT prefix.position, prefix.size, body.event_id, body.payload
FROM prefix
-- Keep body retrieval a point lookup for each admitted key, including on generic plans.
LEFT JOIN LATERAL (
    SELECT event_id, payload
    FROM rss_projection.events
    WHERE prefix.total <= $5::bigint
      AND tenant_id = $1::uuid AND source_id = $2 AND position = prefix.position
    LIMIT 1
) body ON true
WHERE prefix.total <= $5::bigint OR prefix.ordinal = 1
ORDER BY prefix.position
