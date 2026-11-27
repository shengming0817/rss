, account_rows AS (
 SELECT a.principal_id AS "principalId",l.login_key AS login,a.enabled AS enabled,
 m.active AS "memberActive",l.principal_id IS NOT NULL AS "hasLocalPassword",
 CASE WHEN pv.status='available' AND o.value->'displayName'->>'status'='available' THEN o.value->'displayName'->>'value' END AS "displayName",
 CASE WHEN pv.status='available' AND o.value->'email'->>'status'='available' THEN o.value->'email'->>'value' END AS email,
 pv.status AS "profileStatus",dv.status AS "departmentStatus",
 CASE WHEN dv.status='available' THEN ds.fact->'snapshot' END AS "departmentSnapshot"
 FROM identity_authority.accounts a
 JOIN identity_authority.memberships m USING(tenant_id,principal_id)
 LEFT JOIN identity_authority.local_credentials l USING(tenant_id,principal_id)
 LEFT JOIN profile_facts o ON o.tenant_id=a.tenant_id AND o.principal_id=a.principal_id AND o.source=$4
 LEFT JOIN department_facts ds ON ds.tenant_id=a.tenant_id AND ds.principal_id=a.principal_id
 CROSS JOIN LATERAL (SELECT CASE
  WHEN $4::text IS NULL THEN 'unavailable'
  WHEN NOT (a.enabled AND m.active) THEN 'unavailable'
  WHEN o.snapshot_id IS NULL THEN 'missing'
  WHEN NOT o.eligible THEN 'unavailable'
  WHEN o.observed_at>$3 THEN 'unavailable'
  WHEN LEAST(o.expires_at,o.observed_at+$5)<=$3 THEN 'expired'
  ELSE 'available' END AS status) pv
 CROSS JOIN LATERAL (SELECT CASE
  WHEN $2::uuid IS NULL OR NOT (a.enabled AND m.active) THEN 'unavailable'
  WHEN ds.principal_id IS NULL THEN 'missing'
  WHEN NOT ds.eligible THEN 'unavailable'
  WHEN ds.fact->>'status'<>'available' THEN COALESCE(ds.fact->>'reason','unavailable')
  WHEN (ds.fact->>'observed_at')::bigint>$3 THEN 'not_yet_valid'
  WHEN (ds.fact->>'expires_at')::bigint<=$3 THEN 'expired'
  ELSE 'available' END AS status) dv
 WHERE a.tenant_id=$1::uuid
)
