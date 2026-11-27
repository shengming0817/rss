-- Both expiry ranges and their shared budget use the same database observation.
WITH ordinary AS (
 DELETE FROM identity_authority.attempts WHERE tenant_id=$1::uuid AND ctid=ANY(ARRAY(
  SELECT ctid FROM identity_authority.attempts
  WHERE tenant_id=$1::uuid AND expires_at<=statement_timestamp() ORDER BY expires_at LIMIT $2
 )) RETURNING 1
), passwords AS (
 DELETE FROM identity_authority.password_attempts WHERE tenant_id=$1::uuid AND ctid=ANY(ARRAY(
  SELECT ctid FROM identity_authority.password_attempts
  WHERE tenant_id=$1::uuid
    AND coalesce(greatest(window_until,claim_until),'-infinity'::timestamptz)<=statement_timestamp()
  ORDER BY coalesce(greatest(window_until,claim_until),'-infinity'::timestamptz)
  LIMIT ($2-(SELECT count(*) FROM ordinary))
 )) RETURNING 1
)
SELECT (SELECT count(*) FROM ordinary)+(SELECT count(*) FROM passwords)
