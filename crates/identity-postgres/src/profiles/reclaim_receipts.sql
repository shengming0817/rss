WITH reclaimed AS (
DELETE FROM identity_authority.profile_operations
WHERE ctid = ANY(ARRAY(
 SELECT tid FROM (
  SELECT ctid AS tid, accepted_at_ms FROM identity_authority.profile_operations
  WHERE tenant_id=$1::uuid AND principal_id=$2 AND revision>$4 ORDER BY revision LIMIT 64
 ) AS oldest WHERE accepted_at_ms<=$3
))
RETURNING revision
)
SELECT coalesce(max(revision), $4::bigint) FROM reclaimed
