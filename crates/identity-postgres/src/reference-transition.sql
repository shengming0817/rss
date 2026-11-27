-- Bound the qualification work while the collection guard is held. If the budget fills,
-- every unseen reference expires at or after the last examined candidate.
WITH candidates AS MATERIALIZED (
 SELECT tenant_id,session_id,principal_id,credential_kind,authentication_source,platform_authentication,
        auth_epoch,membership_epoch,revoked_at,idle_expires_at,absolute_expires_at,
        external_identity_id,provider_config_version,provider_epoch
 FROM identity_authority.sessions
 WHERE tenant_id=$1::uuid AND revoked_at IS NULL AND idle_expires_at>$3 AND idle_expires_at<=$5
 ORDER BY idle_expires_at LIMIT $6
), {relation}
SELECT least(min(session_valid_until),
  (SELECT max(idle_expires_at) FROM candidates HAVING count(*)=$6))
FROM identity_session_references
