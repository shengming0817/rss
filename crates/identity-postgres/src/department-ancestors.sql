-- The page filter has already checked availability. Fetch the chosen body once;
-- each recursive step sees the same snapshot and can reuse the hash of its nodes.
WITH RECURSIVE tree AS MATERIALIZED (SELECT r."departmentSnapshot" AS body), ancestors(id) AS (
 SELECT jsonb_array_elements_text(body->'memberships') FROM tree
 UNION
 SELECT n->>'parentId'
 FROM ancestors a CROSS JOIN LATERAL jsonb_array_elements((SELECT body->'nodes' FROM tree)) n
 WHERE n->>'id'=a.id AND n->>'parentId' IS NOT NULL
)
