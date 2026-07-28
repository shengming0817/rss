-- Serving binaries must validate the frozen delivery policy without receiving table access.
CREATE FUNCTION rss_load_event_delivery_policy()
RETURNS TABLE (
    policy_revision text,
    automatic_retry_window_seconds bigint,
    same_id_redrive_horizon_seconds bigint,
    safety_margin_seconds bigint,
    inbox_receipt_retention_seconds bigint,
    relay_budget_revision text,
    relay_lease_ttl_ms bigint,
    relay_publish_timeout_ms bigint,
    relay_settle_timeout_ms bigint,
    relay_safety_margin_ms bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT policy.policy_revision,
           policy.automatic_retry_window_seconds,
           policy.same_id_redrive_horizon_seconds,
           policy.safety_margin_seconds,
           policy.inbox_receipt_retention_seconds,
           policy.relay_budget_revision,
           policy.relay_lease_ttl_ms,
           policy.relay_publish_timeout_ms,
           policy.relay_settle_timeout_ms,
           policy.relay_safety_margin_ms
    FROM public.event_delivery_policy AS policy
    WHERE policy.singleton
$$;

ALTER FUNCTION rss_load_event_delivery_policy() OWNER TO rss_outbox_maintenance;
REVOKE ALL ON FUNCTION rss_load_event_delivery_policy() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_load_event_delivery_policy() TO rss_app;
