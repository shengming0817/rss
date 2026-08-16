const MIGRATION: &str = include_str!("../migrations/0109_export_inbox_backlog_samples.sql");

fn normalized() -> String {
    MIGRATION.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn inbox_backlog_function_is_a_fixed_reader_only_capability() {
    let sql = normalized();
    for required in [
        "CREATE INDEX idx_inbox_receipts_group_stale_claims ON public.inbox_receipts (consumer_group, claimed_at, tenant_id) WHERE status = 'claimed'",
        "CREATE FUNCTION public.rss_inbox_sample_backlog(p_consumer_groups text[])",
        "REVOKE ALL ON TABLE public.inbox_receipts FROM rss_app_read",
        "STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp",
        "receipt.status = 'claimed'",
        "pg_catalog.make_interval(secs => 60)",
        "OWNER TO rss_inbox_receipt_maintenance",
        "REVOKE ALL ON FUNCTION public.rss_inbox_sample_backlog(text[]) FROM PUBLIC, rss_app, rss_app_read",
        "GRANT EXECUTE ON FUNCTION public.rss_inbox_sample_backlog(text[]) TO rss_app_read",
    ] {
        assert!(
            sql.contains(required),
            "missing fixed capability clause: {required}"
        );
    }
}

#[test]
fn inbox_backlog_function_fails_closed_on_unbounded_selections() {
    let sql = normalized();
    for required in [
        "p_consumer_groups IS NULL",
        "pg_catalog.cardinality(p_consumer_groups) = 0",
        "pg_catalog.array_position(p_consumer_groups, NULL) IS NOT NULL",
        "pg_catalog.count(DISTINCT requested)",
        "WHERE NOT requested = ANY (v_allowed)",
        "ERRCODE = '22023'",
    ] {
        assert!(
            sql.contains(required),
            "missing fail-closed guard: {required}"
        );
    }
}

#[test]
fn migration_allowlist_exactly_matches_generated_event_groups() {
    let mut generated = generated::event::EVENTS
        .iter()
        .flat_map(|event| event.subscriptions())
        .map(|subscription| subscription.group())
        .collect::<Vec<_>>();
    generated.sort_unstable();
    generated.dedup();
    assert!(
        !generated.is_empty(),
        "generated group inventory must be non-empty"
    );

    let start = MIGRATION
        .find("v_allowed constant text[] := ARRAY[")
        .expect("migration defines generated allowlist");
    let tail = &MIGRATION[start..];
    let body = tail
        .split_once("ARRAY[")
        .and_then(|(_, rest)| rest.split_once("]::text[]"))
        .map(|(body, _)| body)
        .expect("allowlist has fixed array body");
    let mut migrated = body
        .split(',')
        .map(str::trim)
        .map(|entry| entry.trim_matches('\''))
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    migrated.sort_unstable();
    assert_eq!(migrated, generated);
}
