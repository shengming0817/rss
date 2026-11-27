identity_personnel AS NOT MATERIALIZED (
 WITH profile_facts AS NOT MATERIALIZED ({profile_facts})
 SELECT a.tenant_id,a.principal_id,a.enabled AND m.active AS active,
 CASE WHEN {logins} AND a.enabled AND m.active THEN l.login_key END AS login,
 o.source,
 CASE WHEN NOT (a.enabled AND m.active) OR NOT ({profiles}) THEN 'unavailable'
  WHEN o.snapshot_id IS NULL THEN 'missing'
  WHEN NOT o.eligible OR o.observed_at>{now} THEN 'unavailable'
  WHEN least(o.expires_at,o.observed_at+{max_age})<={now} THEN 'expired'
  ELSE 'available' END AS status,
 CASE WHEN o.eligible AND o.observed_at<={now} AND least(o.expires_at,o.observed_at+{max_age})>{now}
  AND o.value->'displayName'->>'status'='available' THEN o.value->'displayName'->>'value' END AS display_name,
 CASE WHEN o.eligible AND o.observed_at<={now} AND least(o.expires_at,o.observed_at+{max_age})>{now}
  AND o.value->'username'->>'status'='available' THEN o.value->'username'->>'value' END AS username,
 least(o.expires_at,o.observed_at+{max_age}) AS expires_at
 FROM identity_authority.accounts a
 JOIN identity_authority.memberships m USING(tenant_id,principal_id)
 LEFT JOIN identity_authority.local_credentials l USING(tenant_id,principal_id)
 LEFT JOIN profile_facts o ON o.tenant_id=a.tenant_id AND o.principal_id=a.principal_id AND ({profiles})
 WHERE a.tenant_id='{tenant}'::uuid
)
