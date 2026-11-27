SELECT coalesce(sum(value),0)::bigint, floor(extract(epoch FROM clock_timestamp())*1000000)::bigint
FROM identity_authority.directory_revisions
WHERE tenant_id=$1::uuid AND kind=ANY($2) AND (source='' OR $3::text IS NULL OR source=$3)
