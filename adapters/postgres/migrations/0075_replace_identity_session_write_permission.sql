-- Replace the removed broad session-write permission in durable ABAC carriers. Role definitions
-- are append-only from their initial schema (#1291) and the project has no historical rows, so this
-- migration must not synthesize or rewrite a role revision for a compatibility state that never ran.

UPDATE abac_policies
SET permission = 'identity:session:logout-current'
WHERE permission = 'identity:session:write';

-- `permission` is part of the primary key. A pre-existing successor row is ambiguous and must
-- abort this migration transaction rather than silently merge or discard authorization data.
UPDATE resource_attributes
SET permission = 'identity:session:logout-current'
WHERE permission = 'identity:session:write';
