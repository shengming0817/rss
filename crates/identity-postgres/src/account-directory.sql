, account_base AS (
 SELECT a.principal_id AS "principalId",l.login_key AS login,a.enabled AS enabled,
 m.active AS "memberActive",l.principal_id IS NOT NULL AS "hasLocalPassword",
 CASE WHEN pv.status='available' AND o.value->'displayName'->>'status'='available' THEN o.value->'displayName'->>'value' END AS "displayName",
 CASE WHEN pv.status='available' AND o.value->'email'->>'status'='available' THEN o.value->'email'->>'value' END AS email,
 pv.status AS "profileStatus"
 FROM identity_authority.accounts a
 JOIN identity_authority.memberships m USING(tenant_id,principal_id)
 LEFT JOIN identity_authority.local_credentials l USING(tenant_id,principal_id)
 LEFT JOIN profile_facts o ON o.tenant_id=a.tenant_id AND o.principal_id=a.principal_id AND o.source=$4
 CROSS JOIN LATERAL (SELECT CASE
  WHEN $4::text IS NULL THEN 'unavailable'
  WHEN NOT (a.enabled AND m.active) THEN 'unavailable'
  WHEN o.snapshot_id IS NULL THEN 'missing'
  WHEN NOT o.eligible THEN 'unavailable'
  WHEN o.observed_at>$3 THEN 'unavailable'
  WHEN LEAST(o.expires_at,o.observed_at+$5)<=$3 THEN 'expired'
  ELSE 'available' END AS status) pv
 WHERE a.tenant_id=$1::uuid
)
