identity_session_references AS NOT MATERIALIZED (
 WITH ctx(tenant,instance,now_at,audience) AS (VALUES ({context}))
 SELECT ctx.instance AS instance_id,s.tenant_id,s.principal_id,s.session_id,s.credential_kind,
 -- session_lifetime constrains idle_expires_at <= absolute_expires_at.
 s.idle_expires_at AS session_valid_until,
 s.authentication_source,
 s.authentication_source='platform' AS requires_platform_check,
 CASE WHEN s.authentication_source='platform' THEN s.platform_authentication->'binding'->>'bindingId' END AS platform_binding_id,
 CASE WHEN s.authentication_source='platform' THEN s.platform_authentication->'binding'->>'bindingEpoch' END AS platform_binding_epoch,
 CASE WHEN s.authentication_source='platform' THEN s.platform_authentication->'binding'->>'sourceId' END AS platform_source_id,
 CASE WHEN s.authentication_source='platform' THEN s.platform_authentication->'binding'->>'sourceVersion' END AS platform_source_version
 FROM {sessions} s
 JOIN identity_authority.accounts a USING(tenant_id,principal_id)
 JOIN identity_authority.memberships m USING(tenant_id,principal_id)
 CROSS JOIN ctx
 WHERE s.tenant_id=ctx.tenant AND a.enabled AND m.active
 AND s.auth_epoch=a.auth_epoch AND s.membership_epoch=m.epoch AND s.revoked_at IS NULL
 AND s.idle_expires_at>ctx.now_at AND s.absolute_expires_at>ctx.now_at
 AND (s.authentication_source='local_password' OR
  (s.authentication_source='oidc' AND EXISTS (
   SELECT FROM identity_authority.external_identities e JOIN identity_authority.providers p USING(tenant_id,provider_id)
   WHERE e.tenant_id=s.tenant_id AND e.principal_id=s.principal_id AND e.identity_id=s.external_identity_id
   AND p.enabled AND p.revocation_epoch=s.provider_epoch AND p.config_version=s.provider_config_version
  )) OR (s.authentication_source='platform' AND ctx.audience IS NOT NULL
   AND s.platform_authentication->>'audience'=ctx.audience
   AND s.platform_authentication->'binding'->>'instance'=ctx.instance::text
   AND s.platform_authentication->'binding'->'account'->>'tenant'=s.tenant_id::text
   AND s.platform_authentication->'binding'->'account'->>'principal'=s.principal_id::text
   AND (
   s.platform_authentication->'binding'->'externalIdentity'='null'::jsonb OR EXISTS (
    SELECT FROM identity_authority.external_identities e JOIN identity_authority.providers p USING(tenant_id,provider_id)
    WHERE e.tenant_id=s.tenant_id AND e.principal_id=s.principal_id
    AND e.identity_id::text=s.platform_authentication->'binding'->'externalIdentity'->>'identityId'
    AND p.provider_id::text=s.platform_authentication->'binding'->'externalIdentity'->>'provider'
    AND p.enabled AND p.revocation_epoch::text=s.platform_authentication->'binding'->'externalIdentity'->>'revocationEpoch'
    AND p.config_version::text=s.platform_authentication->'binding'->'externalIdentity'->>'configVersion'
   )
  )))
)
