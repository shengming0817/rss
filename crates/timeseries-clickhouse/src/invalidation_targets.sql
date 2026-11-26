SELECT spec,spec_digest,lo FROM rss_ts_ch.summaries
CROSS JOIN LATERAL (SELECT convert_from(spec,'UTF8')::jsonb AS doc) d
WHERE tenant_id=$1::text::uuid AND namespace=$2 AND hi>$3 AND dependency_start<$6 AND dirty_from IS DISTINCT FROM 0
  AND CASE WHEN $5::text::jsonb->>'selection'='exact'
      THEN doc->'stream'=$5::text::jsonb->'stream' AND doc->'series'=$5::text::jsonb->'series'
      ELSE doc->'stream'->'scope'=$5::text::jsonb->'scope' AND doc->'series'->'subject'=$5::text::jsonb->'subject' AND doc->'series'->'resource'=$5::text::jsonb->'resource' AND ($5::text::jsonb->'keys'='[]'::jsonb OR ($5::text::jsonb->'keys') ? (doc->'series'->'definition'->>'key'))
  END
LIMIT $4
