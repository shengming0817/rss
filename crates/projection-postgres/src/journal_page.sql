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
FROM prefix LEFT JOIN rss_projection.events body
  ON prefix.total <= $5::bigint AND body.tenant_id = $1::uuid
 AND body.source_id = $2 AND body.position = prefix.position
WHERE prefix.total <= $5::bigint OR prefix.ordinal = 1
ORDER BY prefix.position
