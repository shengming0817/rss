WITH RECURSIVE ancestors(id) AS (
 SELECT jsonb_array_elements_text(r."departmentSnapshot"->'memberships')
 UNION
 SELECT n->>'parentId'
 FROM ancestors a CROSS JOIN LATERAL jsonb_array_elements(r."departmentSnapshot"->'nodes') n
 WHERE n->>'id'=a.id AND n->>'parentId' IS NOT NULL
)
