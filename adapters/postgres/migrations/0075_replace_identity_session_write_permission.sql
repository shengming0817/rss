-- Replace the removed broad session-write permission in every durable authorization carrier.
-- The only non-expanding successor is logout-current; logout-all always requires a fresh grant.

UPDATE roles AS role
SET permissions = (
    SELECT array_agg(permission ORDER BY first_ordinal) AS permissions
    FROM (
        SELECT mapped.permission, min(mapped.ordinality) AS first_ordinal
        FROM (
            SELECT CASE
                       WHEN permission = 'identity:session:write'
                           THEN 'identity:session:logout-current'
                       ELSE permission
                   END AS permission,
                   ordinality
            FROM unnest(role.permissions) WITH ORDINALITY AS raw(permission, ordinality)
        ) AS mapped
        GROUP BY mapped.permission
    ) AS deduplicated
)
WHERE 'identity:session:write' = ANY(role.permissions);

UPDATE abac_policies
SET permission = 'identity:session:logout-current'
WHERE permission = 'identity:session:write';

-- `permission` is part of the primary key. A pre-existing successor row is ambiguous and must
-- abort this migration transaction rather than silently merge or discard authorization data.
UPDATE resource_attributes
SET permission = 'identity:session:logout-current'
WHERE permission = 'identity:session:write';
