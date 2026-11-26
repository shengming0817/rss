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
), resources AS MATERIALIZED (
    SELECT sel->>'subject' AS subject, sel->>'resource' AS resource,
        k.key, range_agg(span) AS spans
    FROM fences LEFT JOIN LATERAL jsonb_array_elements_text(sel->'keys') k(key) ON true
    WHERE sel->>'selection'='resource' AND sel->'scope'=($3::text::jsonb)->'scope'
      AND (sel->>'subject',sel->>'resource') IN (SELECT subject,resource FROM series)
    GROUP BY sel->>'subject',sel->>'resource',k.key
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
