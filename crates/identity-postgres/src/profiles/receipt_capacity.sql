SELECT EXISTS (
 SELECT FROM identity_authority.profile_operations
 WHERE tenant_id=$1::uuid AND principal_id=$2 AND revision=$3 AND accepted_at_ms>$4
)
