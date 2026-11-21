-- A pending stream owns its exact series. Maintenance cannot replace a clean
-- summary before the reserved revision joins the contiguous publication prefix.
WITH frontiers AS (
    SELECT * FROM unnest($5::text[], $6::bigint[]) f(series, at)
), targets AS MATERIALIZED (
    SELECT f.series, s.spec_digest, s.lo FROM frontiers f
    CROSS JOIN LATERAL (
        SELECT spec_digest, lo FROM rss_ts_ch.summaries
        WHERE tenant_id=$1::text::uuid AND namespace=$2 AND NOT dirty AND hi>f.at
          AND source=$3 AND generation=$4 AND rss_ts_ch.summaries.series=f.series
        LIMIT ($7::bigint+1)
    ) s
), budget AS (
    SELECT NOT EXISTS(SELECT FROM targets GROUP BY series HAVING count(*)>$7) AS ok
), reserve AS (
    UPDATE rss_ts_ch.summaries s SET invalidate_revision=$8
    FROM targets t WHERE (SELECT ok FROM budget)
      AND s.tenant_id=$1::text::uuid AND s.namespace=$2
      AND s.spec_digest=t.spec_digest AND s.lo=t.lo
)
SELECT ok FROM budget
