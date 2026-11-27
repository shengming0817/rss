-- Share the selected acceptance and its scalar metadata between the clock and page.
-- A linked session can copy a sequence. Qualify only after the complete tie-break.
department_facts AS MATERIALIZED (
 SELECT owners.principal_id, latest.session_id,
  CASE WHEN NOT eligible THEN 'unavailable'
       WHEN fact.status<>'available' THEN coalesce(fact.reason,'unavailable')
       WHEN fact.observed_at>$3 THEN 'not_yet_valid'
       WHEN fact.expires_at<=$3 THEN 'expired'
       ELSE 'available' END AS status,
  CASE WHEN eligible AND fact.status='available' THEN least(
    CASE WHEN fact.observed_at>$3 THEN fact.observed_at END,
    CASE WHEN fact.expires_at>$3 THEN fact.expires_at END) END AS next_change
 FROM (
  SELECT DISTINCT tenant_id,principal_id FROM identity_authority.external_identities
  WHERE tenant_id=$1::uuid AND provider_id=$2
 ) owners
 CROSS JOIN LATERAL (
  SELECT s.session_id,s.auth_facts,s.provider_config_version,s.auth_epoch,s.membership_epoch,s.provider_epoch
  FROM identity_authority.sessions s
  WHERE s.tenant_id=owners.tenant_id AND s.principal_id=owners.principal_id AND s.source_provider_id=$2
  ORDER BY s.facts_sequence DESC,s.auth_epoch DESC,s.membership_epoch DESC,s.session_id LIMIT 1
 ) latest
 JOIN identity_authority.accounts a USING(tenant_id,principal_id)
 JOIN identity_authority.memberships m USING(tenant_id,principal_id)
 JOIN identity_authority.providers p ON p.tenant_id=owners.tenant_id AND p.provider_id=$2
 CROSS JOIN LATERAL (SELECT a.enabled AND m.active AND p.enabled
  AND p.config_version=latest.provider_config_version AND p.revocation_epoch=latest.provider_epoch
  AND a.auth_epoch=latest.auth_epoch AND m.epoch=latest.membership_epoch AS eligible) eligibility
 CROSS JOIN LATERAL jsonb_to_record(latest.auth_facts->'department_snapshot')
  AS fact(status text,reason text,observed_at bigint,expires_at bigint)
),
