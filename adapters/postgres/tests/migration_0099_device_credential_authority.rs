const MIGRATION: &str = include_str!("../migrations/0099_separate_device_credential_authority.sql");
const COMMAND_AUTHORITY_MIGRATION: &str =
    include_str!("../migrations/0087_fence_device_command_authority.sql");
const HISTORICAL_MIGRATION: &str = include_str!("../migrations/0094_close_device_ingress_uow.sql");

fn normalized(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn function_definition<'a>(migration: &'a str, function: &str) -> &'a str {
    let create = format!("CREATE FUNCTION public.{function}");
    let replace = format!("CREATE OR REPLACE FUNCTION public.{function}");
    let start = migration.find(&replace).or_else(|| migration.find(&create));
    assert!(start.is_some(), "missing historical function {function}");
    let start = start.unwrap_or_default();
    let body_end = migration[start..].find("$$;");
    assert!(
        body_end.is_some(),
        "unterminated historical function {function}"
    );
    let body_end = body_end.unwrap_or_default();
    &migration[start..start + body_end + 3]
}

fn replacement_shape(migration: &str, function: &str) -> String {
    normalized(function_definition(migration, function)).replacen(
        &format!("CREATE FUNCTION public.{function}"),
        &format!("CREATE OR REPLACE FUNCTION public.{function}"),
        1,
    )
}

fn replace_once(input: String, from: &str, to: &str, change: &str) -> String {
    assert_eq!(
        input.matches(from).count(),
        1,
        "whitelisted {change} source shape drifted"
    );
    input.replacen(from, to, 1)
}

#[test]
fn migration_preserves_only_exact_received_report_authority() {
    let normalized = MIGRATION.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(
        normalized
            .contains("CREATE OR REPLACE FUNCTION public.rss_device_certificate_reported_guard()")
    );
    assert!(normalized.contains("CREATE OR REPLACE FUNCTION public.rss_device_command_guard()"));
    assert!(normalized.contains(
        "retains_received_report_authority := OLD.state = 'received' AND NEW.state = 'applied'"
    ));
    assert!(
        normalized.contains(
            "NEW.fence_epoch <> authority_epoch AND NOT retains_received_report_authority"
        )
    );
    assert!(normalized.contains(
        "REVOKE ALL ON FUNCTION public.rss_device_command_guard() FROM PUBLIC,rss_app,rss_app_read"
    ));
    assert!(normalized.contains(
        "NEW.fence_epoch <> authority_epoch AND NOT EXISTS ( SELECT 1 FROM public.device_commands AS command WHERE command.tenant_id = NEW.tenant_id AND command.device_id = NEW.device_id AND command.generation = NEW.observed_generation AND command.fence_epoch = NEW.fence_epoch AND command.state = 'received' )"
    ));
    assert!(!normalized.contains(
        "NEW.observed_generation <> authority_generation OR NEW.fence_epoch <> authority_epoch"
    ));
    assert!(normalized.contains(
        "REVOKE ALL ON FUNCTION public.rss_device_certificate_reported_guard() FROM PUBLIC,rss_app,rss_app_read"
    ));
}

#[test]
fn migration_separates_transport_credential_from_certificate_authority() {
    let normalized = MIGRATION.split_whitespace().collect::<Vec<_>>().join(" ");

    assert_eq!(
        normalized
            .matches("CREATE OR REPLACE FUNCTION public.rss_commit_device_")
            .count(),
        2,
        "0099 must replace exactly the two authenticated ingress funnels"
    );
    assert_eq!(
        normalized
            .matches("p_credential_generation IS NULL OR p_credential_generation<=0")
            .count(),
        2,
        "both funnels must reject missing or non-positive authenticated credential evidence"
    );
    assert_eq!(normalized.matches("p_scope_matches IS NOT TRUE").count(), 2);
    assert_eq!(
        normalized
            .matches(
                "p_fence_epoch<authority_epoch AND command_state IS DISTINCT FROM 'received' THEN 'stale_fence'"
            )
            .count(),
        1,
        "only the exact received command retains report authority across a later reconcile lease"
    );
    assert_eq!(
        normalized
            .matches("p_fence_epoch<authority_epoch THEN 'stale_fence'")
            .count(),
        1,
        "ACK authority must still reject an old reconcile fence unconditionally"
    );
    assert_eq!(
        normalized
            .matches("p_credential_generation IS DISTINCT FROM authority_generation")
            .count(),
        0,
        "transport credential generation is not desired certificate generation"
    );
    assert_eq!(
        normalized
            .matches("OWNER TO rss_device_command_funnel_owner")
            .count(),
        2
    );
    assert_eq!(normalized.matches("REVOKE ALL ON FUNCTION").count(), 3);
    assert_eq!(normalized.matches("GRANT EXECUTE ON FUNCTION").count(), 1);
}

#[test]
fn correction_is_forward_only_and_preserves_historical_checksum_input() {
    let historical = normalized(HISTORICAL_MIGRATION);

    assert_eq!(
        historical
            .matches("p_credential_generation IS DISTINCT FROM authority_generation")
            .count(),
        2,
        "0094 remains immutable; the authority correction belongs exclusively to 0099"
    );
    assert!(!MIGRATION.contains("DROP FUNCTION"));
    assert!(!MIGRATION.contains("CREATE FUNCTION public.rss_commit_"));
}

#[test]
fn replacement_functions_equal_history_plus_the_explicit_authority_whitelist() {
    let command_guard = replace_once(
        replacement_shape(COMMAND_AUTHORITY_MIGRATION, "rss_device_command_guard"),
        "generation_intent_digest bytea; BEGIN",
        "generation_intent_digest bytea; retains_received_report_authority boolean := false; BEGIN IF TG_OP = 'UPDATE' THEN retains_received_report_authority := OLD.state = 'received' AND NEW.state = 'applied' AND ( NEW.tenant_id, NEW.command_id, NEW.device_id, NEW.generation, NEW.fence_epoch, NEW.intent_digest, NEW.deadline, NEW.queued_at ) IS NOT DISTINCT FROM ( OLD.tenant_id, OLD.command_id, OLD.device_id, OLD.generation, OLD.fence_epoch, OLD.intent_digest, OLD.deadline, OLD.queued_at ); END IF;",
        "received-command transition authority declaration",
    );
    let command_guard = replace_once(
        command_guard,
        "ELSIF NEW.generation <> authority_generation OR NEW.fence_epoch <> authority_epoch THEN",
        "ELSIF NEW.generation <> authority_generation OR ( NEW.fence_epoch <> authority_epoch AND NOT retains_received_report_authority ) THEN",
        "received-command old-fence transition",
    );
    assert_eq!(
        normalized(function_definition(MIGRATION, "rss_device_command_guard")),
        command_guard,
        "0099 command guard may only differ from 0087 by the received-to-applied authority exception"
    );

    let reported_guard = replace_once(
        replacement_shape(
            COMMAND_AUTHORITY_MIGRATION,
            "rss_device_certificate_reported_guard",
        ),
        "IF NEW.observed_generation <> authority_generation OR NEW.fence_epoch <> authority_epoch THEN RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'device certificate report coordinate does not match current authority'; END IF;",
        "IF NEW.observed_generation <> authority_generation THEN RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'device certificate report generation does not match current authority'; END IF; IF NEW.fence_epoch <> authority_epoch AND NOT EXISTS ( SELECT 1 FROM public.device_commands AS command WHERE command.tenant_id = NEW.tenant_id AND command.device_id = NEW.device_id AND command.generation = NEW.observed_generation AND command.fence_epoch = NEW.fence_epoch AND command.state = 'received' ) THEN RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'device certificate report fence does not match current command authority'; END IF;",
        "reported-state received-command old-fence authority",
    );
    assert_eq!(
        normalized(function_definition(
            MIGRATION,
            "rss_device_certificate_reported_guard",
        )),
        reported_guard,
        "0099 reported guard may only differ from 0087 by the exact received-command exception"
    );

    let ack_funnel = replace_once(
        replacement_shape(
            HISTORICAL_MIGRATION,
            "rss_commit_device_command_ack_ingress",
        ),
        "OR pg_catalog.octet_length(p_fingerprint)<>32 OR p_scope_matches IS NULL THEN",
        "OR pg_catalog.octet_length(p_fingerprint)<>32 OR p_scope_matches IS NULL OR p_credential_generation IS NULL OR p_credential_generation<=0 THEN",
        "ACK positive credential evidence",
    );
    let ack_funnel = replace_once(
        ack_funnel,
        "WHEN p_credential_generation IS DISTINCT FROM authority_generation THEN 'scope_mismatch' ",
        "",
        "ACK credential/certificate authority separation",
    );
    assert_eq!(
        normalized(function_definition(
            MIGRATION,
            "rss_commit_device_command_ack_ingress",
        )),
        ack_funnel,
        "0099 ACK funnel may only add positive credential validation and remove the invalid desired-generation comparison"
    );

    let report_funnel = replace_once(
        replacement_shape(
            HISTORICAL_MIGRATION,
            "rss_commit_device_certificate_report_ingress",
        ),
        "OR p_scope_matches IS NULL THEN",
        "OR p_scope_matches IS NULL OR p_credential_generation IS NULL OR p_credential_generation<=0 THEN",
        "report positive credential evidence",
    );
    let report_funnel = replace_once(
        report_funnel,
        "WHEN p_credential_generation IS DISTINCT FROM authority_generation THEN 'scope_mismatch' ",
        "",
        "report credential/certificate authority separation",
    );
    let report_funnel = replace_once(
        report_funnel,
        "WHEN p_fence_epoch<authority_epoch THEN 'stale_fence'",
        "WHEN p_fence_epoch<authority_epoch AND command_state IS DISTINCT FROM 'received' THEN 'stale_fence'",
        "report received-command old-fence authority",
    );
    assert_eq!(
        normalized(function_definition(
            MIGRATION,
            "rss_commit_device_certificate_report_ingress",
        )),
        report_funnel,
        "0099 report funnel may only contain the three explicit authority corrections"
    );

    let expected_migration = format!(
        "-- 0099_separate_device_credential_authority.sql
         -- Forward-only correction: the authenticated MQTT credential generation proves which
         -- transport credential entered the funnel; it is not the desired certificate generation
         -- that the device is being commanded to install.
         SET LOCAL lock_timeout = '5s';
         SET LOCAL statement_timeout = '5min';
         {command_guard}
         REVOKE ALL ON FUNCTION public.rss_device_command_guard()
         FROM PUBLIC,rss_app,rss_app_read;
         {reported_guard}
         REVOKE ALL ON FUNCTION public.rss_device_certificate_reported_guard()
         FROM PUBLIC,rss_app,rss_app_read;
         {ack_funnel}
         {report_funnel}
         ALTER FUNCTION public.rss_commit_device_command_ack_ingress(uuid,uuid,text,text,bigint,bigint,bigint,bytea,text,bigint,boolean)
         OWNER TO rss_device_command_funnel_owner;
         ALTER FUNCTION public.rss_commit_device_certificate_report_ingress(uuid,uuid,text,bigint,bigint,bigint,bytea,bytea,bytea,bigint,bigint,bigint,boolean)
         OWNER TO rss_device_command_funnel_owner;
         REVOKE ALL ON FUNCTION
          public.rss_commit_device_command_ack_ingress(uuid,uuid,text,text,bigint,bigint,bigint,bytea,text,bigint,boolean),
          public.rss_commit_device_certificate_report_ingress(uuid,uuid,text,bigint,bigint,bigint,bytea,bytea,bytea,bigint,bigint,bigint,boolean)
         FROM PUBLIC,rss_app_read;
         GRANT EXECUTE ON FUNCTION
          public.rss_commit_device_command_ack_ingress(uuid,uuid,text,text,bigint,bigint,bigint,bytea,text,bigint,boolean),
          public.rss_commit_device_certificate_report_ingress(uuid,uuid,text,bigint,bigint,bigint,bytea,bytea,bytea,bigint,bigint,bigint,boolean)
         TO rss_app;"
    );
    assert_eq!(
        normalized(MIGRATION),
        normalized(&expected_migration),
        "0099 must contain only the four reviewed replacements and their exact transactional/ACL shell"
    );
}
