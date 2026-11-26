-- Each input position refers to its full series snapshot. Keep time and identity
-- paired, including distinct observed times for the same series.
WITH series AS MATERIALIZED (
    SELECT serial, doc::jsonb AS s
    FROM unnest($4::text[]) WITH ORDINALITY AS docs(doc,serial)
), points AS (
    SELECT * FROM unnest($5::int[], $6::bigint[], $7::int[]) AS p(serial,at,pos)
)
SELECT p.pos, f.selection::text, f.lo, f.hi
FROM points p JOIN series ON series.serial=p.serial
JOIN rss_ts_ch.fences f ON f.tenant_id=$1::text::uuid AND f.namespace=$2
  AND f.lo<=p.at AND p.at<f.hi
  AND coalesce(f.selection#>>'{series,subject}',f.selection->>'subject')=s->>'subject'
  AND coalesce(f.selection#>>'{series,resource}',f.selection->>'resource')=s->>'resource'
  AND CASE f.selection->>'selection'
        WHEN 'exact' THEN f.selection->'stream'=$3::text::jsonb AND f.selection->'series'=s
        WHEN 'resource' THEN f.selection->'scope'=($3::text::jsonb)->'scope'
            AND (f.selection->'keys'='[]'::jsonb OR (f.selection->'keys') ? (s#>>'{definition,key}'))
      END
ORDER BY p.pos LIMIT 1
