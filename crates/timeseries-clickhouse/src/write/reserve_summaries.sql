-- A pending stream owns its exact series. Maintenance cannot replace a clean
-- summary before the reserved revision joins the contiguous publication prefix.
WITH frontiers AS (
    SELECT * FROM jsonb_to_recordset($4::text::jsonb) f(series jsonb, at bigint)
), targets AS MATERIALIZED (
    SELECT f.series, s.spec_digest, s.lo FROM frontiers f
    CROSS JOIN LATERAL (
        SELECT spec_digest, lo FROM rss_ts_ch.summaries
        WHERE tenant_id=$1::text::uuid AND namespace=$2 AND NOT dirty AND hi>f.at
          AND convert_from(spec,'UTF8')::jsonb->'stream'=$3::text::jsonb
          AND convert_from(spec,'UTF8')::jsonb->'series'=f.series
        LIMIT ($5::bigint+1)
    ) s
), budget AS (
    SELECT NOT EXISTS(SELECT FROM targets GROUP BY series HAVING count(*)>$5) AS ok
), reserve AS (
    UPDATE rss_ts_ch.summaries s SET invalidate_revision=$6
    FROM targets t WHERE (SELECT ok FROM budget)
      AND s.tenant_id=$1::text::uuid AND s.namespace=$2
      AND s.spec_digest=t.spec_digest AND s.lo=t.lo
)
SELECT ok FROM budget
