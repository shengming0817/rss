SELECT accepted_at_ms FROM identity_authority.profile_operations
WHERE tenant_id=$1::uuid AND principal_id=$2 AND revision>$3 ORDER BY revision LIMIT 1
