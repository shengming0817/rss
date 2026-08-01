const MIGRATION: &str = include_str!("../migrations/0090_isolate_saga_operator_lane.sql");

#[test]
fn saga_operator_lane_is_closed_and_function_only() {
    for required in [
        "CREATE ROLE rss_saga_operator\n            NOLOGIN NOSUPERUSER NOBYPASSRLS",
        "ALTER ROLE rss_saga_operator_owner\n    NOLOGIN NOSUPERUSER NOBYPASSRLS",
        "CREATE FUNCTION public.rss_saga_operator_record_audit(",
        "p_target_tenant uuid",
        "SECURITY DEFINER\nSET search_path = pg_catalog, pg_temp",
        "'service', p_target_tenant,\n        'saga.operator', p_resource_id, p_action, p_outcome, p_failure_reason,",
        "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM rss_saga_operator",
        "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM rss_saga_operator",
        "GRANT SELECT ON TABLE public._sqlx_migrations TO rss_saga_operator",
        "GRANT EXECUTE ON FUNCTION public.rss_service_token_replay_check_and_record(bytea, timestamptz)\n    TO rss_saga_operator",
        "GRANT EXECUTE ON FUNCTION public.rss_saga_operator_record_audit(",
        "REVOKE EXECUTE ON FUNCTION public.rss_saga_retry_compensation(",
        "REVOKE EXECUTE ON FUNCTION public.rss_saga_terminate(",
        ") FROM rss_app, rss_app_read",
        ") TO rss_saga_operator",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing closed-lane clause: {required}"
        );
    }
    assert!(!MIGRATION.contains("GRANT SELECT ON TABLE public.saga_instances"));
    assert!(!MIGRATION.contains("GRANT EXECUTE ON FUNCTION public.rss_saga_observe_unresolved"));
    assert_eq!(
        MIGRATION.matches(") TO rss_saga_operator;").count(),
        3,
        "the multiline audit, retry and terminate grants must remain exact; replay is asserted separately",
    );
    assert!(
        !MIGRATION.contains("ALTER ROLE rss_saga_operator\n    NOLOGIN NOSUPERUSER NOBYPASSRLS")
    );
}
