SELECT id,kind,selection::text,lo,hi,restore_until,restored
FROM rss_ts_ch.fences
CROSS JOIN (SELECT $7::text::jsonb AS q) request
WHERE tenant_id=$1::text::uuid AND namespace=$2
  AND coalesce(selection#>>'{series,subject}',selection->>'subject')=$3
  AND coalesce(selection#>>'{series,resource}',selection->>'resource')=$4
  AND hi>$5 AND lo<$6 AND (kind='pruned' OR (kind='delete' AND (NOT restored OR $9::boolean)))
  AND CASE
    WHEN selection->>'selection'='exact' AND q->>'selection'='exact' THEN selection=q
    WHEN q->>'selection'='exact' THEN selection->'keys'='[]'::jsonb OR (selection->'keys') ? (q#>>'{series,definition,key}')
    WHEN selection->>'selection'='exact' THEN q->'keys'='[]'::jsonb OR (q->'keys') ? (selection#>>'{series,definition,key}')
    ELSE selection->'keys'='[]'::jsonb OR q->'keys'='[]'::jsonb OR
         EXISTS(SELECT FROM jsonb_array_elements_text(q->'keys') k WHERE (selection->'keys') ? k)
  END
ORDER BY lo,id LIMIT $8
