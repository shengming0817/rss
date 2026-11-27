-- $1 is the tenant and $2 the optional department source UUID. A subject may have
-- multiple external identities at one provider. Read its latest acceptance exactly once.
WITH department_facts AS (
 SELECT owners.tenant_id,owners.principal_id,latest.*,
  a.enabled AND m.active AND p.enabled AND p.config_version=latest.provider_config_version
   AND p.revocation_epoch=latest.provider_epoch AND a.auth_epoch=latest.auth_epoch AND m.epoch=latest.membership_epoch AS eligible
 FROM (
  SELECT DISTINCT e.tenant_id,e.principal_id FROM identity_authority.external_identities e
  WHERE e.tenant_id=$1::uuid AND e.provider_id=$2
 ) owners
 CROSS JOIN LATERAL (
  SELECT s.auth_facts->'department_snapshot' AS fact,s.provider_config_version,
   s.auth_epoch,s.membership_epoch,s.provider_epoch
  FROM identity_authority.sessions s
  WHERE s.tenant_id=owners.tenant_id AND s.principal_id=owners.principal_id AND s.source_provider_id=$2
  ORDER BY s.facts_sequence DESC,s.auth_epoch DESC,s.membership_epoch DESC,s.session_id LIMIT 1
 ) latest
 JOIN identity_authority.accounts a USING(tenant_id,principal_id)
 JOIN identity_authority.memberships m USING(tenant_id,principal_id)
 JOIN identity_authority.providers p ON p.tenant_id=owners.tenant_id AND p.provider_id=$2
)
