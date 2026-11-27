SELECT o.*,
 a.enabled AND m.active AND (o.source='local' OR coalesce(
  p.enabled AND p.config_version=o.config_version AND p.revocation_epoch=o.source_epoch
  AND EXISTS (SELECT FROM identity_authority.external_identities e
   WHERE e.tenant_id=o.tenant_id AND e.principal_id=o.principal_id AND e.provider_id=o.provider_id),
  false)) AS eligible
FROM identity_authority.profile_observations o
JOIN identity_authority.accounts a USING(tenant_id,principal_id)
JOIN identity_authority.memberships m USING(tenant_id,principal_id)
LEFT JOIN identity_authority.providers p ON p.tenant_id=o.tenant_id AND p.provider_id=o.provider_id
