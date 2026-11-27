-- Bound the candidate scan even when every expired intent is still referenced.
WITH candidates AS MATERIALIZED (
 SELECT ctid AS tid,intent_id FROM identity_authority.link_intents
 WHERE tenant_id=$1::uuid AND expires_at<=$2 ORDER BY expires_at,intent_id LIMIT 128
)
DELETE FROM identity_authority.link_intents WHERE tenant_id=$1::uuid AND ctid=ANY(ARRAY(
 SELECT tid FROM candidates i WHERE (
  SELECT true FROM identity_authority.oidc_transactions t
  WHERE t.tenant_id=$1::uuid AND t.link_intent=i.intent_id LIMIT 1
 ) IS NULL
))
