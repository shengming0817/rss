SELECT principal_id,actor,digest,revision FROM identity_authority.profile_operations
WHERE tenant_id=$1::uuid AND operation_id=$2 AND accepted_at_ms>$3
