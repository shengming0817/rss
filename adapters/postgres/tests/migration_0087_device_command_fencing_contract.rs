const MIGRATION_0087: &str = include_str!("../migrations/0087_fence_device_command_authority.sql");

#[test]
fn migration_0087_declares_the_closed_hard_cutover_contract() {
    let normalized = MIGRATION_0087
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    for required in [
        "SET LOCAL lock_timeout = '5s'",
        "SET LOCAL statement_timeout = '5min'",
        "LOCK TABLE public.reconcile_targets, public.reconcile_leases, public.reconcile_attempts",
        "public.device_certificate_desired_states, public.device_certificate_reported_states",
        "public.device_commands, public.device_ingress_receipts, public.outbox, public.command_journal IN ACCESS EXCLUSIVE MODE",
        "0087 requires every reconcile lease to be free",
        "0087 refuses multiple nonterminal device commands",
        "0087 refuses duplicate device command fence coordinates",
        "0087 refuses multiple intent digests for one device generation",
        "0087 refuses nonterminal command outside canonical authority",
        "0087 refuses reported state outside canonical authority",
        "CREATE UNIQUE INDEX device_commands_fence_coordinate_unique ON public.device_commands (tenant_id, device_id, generation, fence_epoch)",
        "CREATE UNIQUE INDEX device_commands_one_nonterminal_per_device ON public.device_commands (tenant_id, device_id) WHERE state IN ('queued', 'published', 'received')",
        "'stale_generation', 'stale_fence', 'stale_sequence'",
        "'rejected', 'device_rejected'",
        "target.reconciler_id = 'identity.device-certificate'",
        "target.resource_kind = 'device-certificate'",
        "target.resource_id = NEW.device_id::text",
        "NEW.generation <> authority_generation",
        "NEW.fence_epoch <> authority_epoch",
        "authority_generation >= OLD.generation AND authority_epoch > OLD.fence_epoch",
        "device command takeover must preserve generation intent digest",
        "pg_advisory_xact_lock",
        "NEW.observed_generation <> authority_generation",
        "REVOKE ALL ON FUNCTION public.rss_device_command_guard()",
        "REVOKE ALL ON FUNCTION public.rss_device_certificate_reported_guard()",
        "CREATE FUNCTION public.rss_install_fenced_device_command",
        "CREATE FUNCTION public.rss_apply_device_command_ack",
        "CREATE FUNCTION public.rss_upsert_device_certificate_report",
        "CREATE ROLE rss_device_command_funnel_owner NOLOGIN NOSUPERUSER NOBYPASSRLS",
        "REVOKE INSERT, UPDATE ON public.device_commands FROM rss_app",
        "REVOKE INSERT, UPDATE ON public.device_certificate_reported_states FROM rss_app",
    ] {
        assert!(
            normalized.contains(required),
            "0087 omits hard-cutover invariant `{required}`"
        );
    }

    let preflight = normalized
        .split_once("CREATE UNIQUE INDEX device_commands_fence_coordinate_unique")
        .map_or(normalized.as_str(), |(prefix, _)| prefix);
    for forbidden in [
        "UPDATE public.device_commands SET",
        "UPDATE public.device_certificate_reported_states SET",
        "DELETE FROM public.device_commands",
        "DROP TABLE public.device_commands",
        "DISABLE ROW LEVEL SECURITY",
        "NO FORCE ROW LEVEL SECURITY",
    ] {
        assert!(
            !preflight.contains(forbidden),
            "0087 contains a forbidden backfill, disposal, or tenant-boundary weakening: `{forbidden}`"
        );
    }

    let authority_sql = normalized
        .split_once("CREATE OR REPLACE FUNCTION public.rss_device_command_guard()")
        .map_or(normalized.as_str(), |(_, suffix)| suffix);
    for marker in [
        "FROM public.reconcile_targets AS target",
        "FROM public.reconcile_leases AS lease",
        "FROM public.device_certificate_desired_states AS desired",
    ] {
        assert_eq!(
            authority_sql.matches(marker).count(),
            5,
            "both triggers and all three fixed funnels must use each authority lock stage"
        );
    }
}
