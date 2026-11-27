-- The caller supplies one candidate row and the byte budget for this write.
, measured AS MATERIALIZED (
    SELECT candidate.*, facts IS NULL OR octet_length(facts::text) <= budget AS fits
    FROM candidate
), chosen AS MATERIALIZED (
    SELECT measured.*,
           CASE WHEN fits THEN facts
                WHEN facts #>> '{department_snapshot,status}' = 'available'
                THEN jsonb_set(facts, '{department_snapshot}', '{"status":"unavailable","reason":"invalid_claim"}')
           END AS accepted_facts
    FROM measured
), admitted AS (
    SELECT * FROM chosen
    WHERE CASE WHEN fits THEN true ELSE octet_length(accepted_facts::text) <= budget END
)
