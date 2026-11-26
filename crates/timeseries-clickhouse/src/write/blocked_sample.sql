-- Resolve interval sets once per selector. Membership is a binary search inside
-- an int8multirange. Only the earliest blocked input needs a durable witness.
WITH points AS MATERIALIZED (
    SELECT * FROM unnest($5::int[],$6::bigint[],$7::int[]) p(serial,at,pos)
), series AS MATERIALIZED (
    SELECT serial, doc::jsonb AS s, doc::jsonb->>'subject' AS subject,
        doc::jsonb->>'resource' AS resource, doc::jsonb#>>'{definition,key}' AS key
    FROM unnest($4::text[]) WITH ORDINALITY AS docs(doc,serial)
), fences AS MATERIALIZED (
    SELECT selection AS sel, lo, hi, int8range(lo,hi,'[)') AS span
    FROM rss_ts_ch.fences
    WHERE tenant_id=$1::text::uuid AND namespace=$2
      AND hi>(SELECT min(at) FROM points) AND lo<=(SELECT max(at) FROM points)
), exact AS MATERIALIZED (
    SELECT sel->'series' AS s, range_agg(span) AS spans FROM fences
    WHERE sel->>'selection'='exact' AND sel->'stream'=$3::text::jsonb
      AND sel->'series' IN (SELECT s FROM series)
    GROUP BY sel->'series'
), requested AS MATERIALIZED (
    SELECT subject,resource,jsonb_agg(key) AS keys,jsonb_object_agg(key,true) AS key_set
    FROM (SELECT DISTINCT subject,resource,key FROM series) unique_keys GROUP BY subject,resource
), resources AS MATERIALIZED (
    SELECT r.subject,r.resource,k.key,range_agg(f.span) AS spans
    FROM fences f JOIN requested r ON r.subject=f.sel->>'subject' AND r.resource=f.sel->>'resource'
    -- Expand the smaller key set. An empty fence key set yields one wildcard
    -- via the LEFT JOIN. A nonempty disjoint set must yield no binding.
    LEFT JOIN LATERAL jsonb_array_elements_text(
        CASE WHEN jsonb_array_length(f.sel->'keys')>jsonb_array_length(r.keys)
             THEN r.keys ELSE f.sel->'keys' END
    ) k(key) ON true
    WHERE f.sel->>'selection'='resource' AND f.sel->'scope'=($3::text::jsonb)->'scope'
      AND (f.sel->'keys'='[]'::jsonb OR (r.key_set ? k.key AND (f.sel->'keys') ? k.key))
    GROUP BY r.subject,r.resource,k.key
), bindings AS MATERIALIZED (
    SELECT s.*, e.spans AS exact_spans, all_keys.spans AS all_spans, keyed.spans AS key_spans
    FROM series s LEFT JOIN exact e ON s.s=e.s
    LEFT JOIN resources all_keys ON s.subject=all_keys.subject AND s.resource=all_keys.resource AND all_keys.key IS NULL
    LEFT JOIN resources keyed ON s.subject=keyed.subject AND s.resource=keyed.resource AND s.key=keyed.key
), first_hit AS MATERIALIZED (
    SELECT p.pos,p.at,b.s,b.subject,b.resource,b.key FROM points p
    JOIN bindings b USING(serial)
    WHERE p.at <@ b.exact_spans OR p.at <@ b.all_spans OR p.at <@ b.key_spans
    ORDER BY p.pos LIMIT 1
)
SELECT p.pos,w.sel::text,w.lo,w.hi FROM first_hit p LEFT JOIN LATERAL (
    SELECT sel,lo,hi FROM fences WHERE lo<=p.at AND p.at<hi AND CASE sel->>'selection'
        WHEN 'exact' THEN sel->'stream'=$3::text::jsonb AND sel->'series'=p.s
        WHEN 'resource' THEN sel->'scope'=($3::text::jsonb)->'scope' AND sel->>'subject'=p.subject
            AND sel->>'resource'=p.resource AND (sel->'keys'='[]'::jsonb OR (sel->'keys') ? p.key)
    END LIMIT 1
) w ON true
