mod postgres {
    #![allow(clippy::expect_used)]

    use std::borrow::Cow;
    use std::time::Duration;

    use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

    type TestError = Box<dyn std::error::Error + Send + Sync>;
    type TestResult = Result<(), TestError>;

    fn migrations_through(max_version: i64) -> sqlx::migrate::Migrator {
        let embedded = sqlx::migrate!("./migrations");
        sqlx::migrate::Migrator {
            migrations: Cow::Owned(
                embedded
                    .iter()
                    .filter(|migration| migration.version <= max_version)
                    .cloned()
                    .collect(),
            ),
            ignore_missing: false,
            locking: true,
            no_tx: embedded.no_tx,
        }
    }

    async fn pool_for(fixture: &testkit::PgFixture) -> Result<sqlx::PgPool, TestError> {
        let params = fixture.params();
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(
                PgConnectOptions::new()
                    .host(&params.host)
                    .port(params.port)
                    .database(&params.database)
                    .username(&params.username)
                    .password(&params.password)
                    .ssl_mode(PgSslMode::Prefer),
            )
            .await?;
        Ok(pool)
    }

    fn migration_database_error(
        failure: &sqlx::migrate::MigrateError,
    ) -> Result<&(dyn sqlx::error::DatabaseError + 'static), TestError> {
        match failure {
            sqlx::migrate::MigrateError::ExecuteMigration(
                sqlx::Error::Database(database_error),
                87,
            ) => Ok(database_error.as_ref()),
            _ => Err(std::io::Error::other(format!(
                "0087 failed through an unexpected path: {failure}"
            ))
            .into()),
        }
    }

    async fn authority(
        pool: &sqlx::PgPool,
        tenant_id: &str,
        device_id: &str,
        epoch: i64,
    ) -> Result<String, TestError> {
        sqlx::query(
            "INSERT INTO public.device_certificate_desired_states ( \
                 tenant_id, device_id, generation, validity_seconds, renew_before_seconds, \
                 client_auth, server_auth, sans \
             ) VALUES ($1::uuid, $2::uuid, 1, 3600, 600, true, false, ARRAY[]::text[])",
        )
        .bind(tenant_id)
        .bind(device_id)
        .execute(pool)
        .await?;
        let target_id: String = sqlx::query_scalar(
            "INSERT INTO public.reconcile_targets ( \
                 tenant_id, reconciler_id, resource_kind, resource_id \
             ) VALUES ( \
                 $1::uuid, 'identity.device-certificate', 'device-certificate', $2 \
             ) RETURNING target_id::text",
        )
        .bind(tenant_id)
        .bind(device_id)
        .fetch_one(pool)
        .await?;
        sqlx::query(
            "INSERT INTO public.reconcile_leases (tenant_id, target_id, state, epoch) \
             VALUES ($1::uuid, $2::uuid, 'free', $3)",
        )
        .bind(tenant_id)
        .bind(&target_id)
        .bind(epoch)
        .execute(pool)
        .await?;
        Ok(target_id)
    }

    async fn queue_command(
        pool: &sqlx::PgPool,
        tenant_id: &str,
        device_id: &str,
        command_id: &str,
        generation: i64,
        epoch: i64,
        digest_nibble: &str,
    ) -> Result<(), TestError> {
        sqlx::query(
            "INSERT INTO public.device_commands ( \
                 tenant_id, command_id, device_id, generation, fence_epoch, intent_digest, \
                 deadline, state, version, queued_at \
             ) VALUES ( \
                 $1::uuid, $2, $3::uuid, $4, $5, \
                 pg_catalog.decode(pg_catalog.repeat($6, 64), 'hex'), \
                 pg_catalog.transaction_timestamp() + interval '1 hour', \
                 'queued', 1, pg_catalog.transaction_timestamp() \
             )",
        )
        .bind(tenant_id)
        .bind(command_id)
        .bind(device_id)
        .bind(generation)
        .bind(epoch)
        .bind(digest_nibble)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn assert_migration_failure(pool: &sqlx::PgPool, message: &str) -> Result<(), TestError> {
        let failure = migrations_through(87).run(pool).await.expect_err(message);
        let database_error = migration_database_error(&failure)?;
        assert_eq!(database_error.code().as_deref(), Some("55000"));
        assert_eq!(database_error.message(), message);
        let ledger: (Option<i64>, i64) = sqlx::query_as(
            "SELECT max(version), count(*) FILTER (WHERE version = 87) \
             FROM public._sqlx_migrations",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(ledger, (Some(86), 0));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn held_lease_rejects_and_rolls_back_before_clean_retry() -> TestResult {
        let fixture = testkit::env_or_postgres().await?;
        let mut pool = pool_for(&fixture).await?;
        migrations_through(86).run(&pool).await?;

        let tenant_id = uuid::Uuid::new_v4().to_string();
        let device_id = uuid::Uuid::new_v4().to_string();
        let target_id = authority(&pool, &tenant_id, &device_id, 1).await?;
        sqlx::query(
            "UPDATE public.reconcile_leases SET \
                 state = 'held', lease_token = gen_random_uuid(), holder_id = 'legacy-worker', \
                 acquired_at = pg_catalog.transaction_timestamp(), \
                 expires_at = pg_catalog.transaction_timestamp() + interval '5 minutes', \
                 heartbeat_at = pg_catalog.transaction_timestamp(), \
                 updated_at = pg_catalog.transaction_timestamp() \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&target_id)
        .execute(&pool)
        .await?;

        assert_migration_failure(&pool, "0087 requires every reconcile lease to be free").await?;
        let partial_indexes: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_catalog.pg_class \
             WHERE relname IN ( \
                 'device_commands_fence_coordinate_unique', \
                 'device_commands_one_nonterminal_per_device' \
             )",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(partial_indexes, 0, "failed 0087 must roll back all indexes");

        sqlx::query(
            "UPDATE public.reconcile_leases SET \
                 state = 'free', lease_token = NULL, holder_id = NULL, acquired_at = NULL, \
                 expires_at = NULL, heartbeat_at = NULL, \
                 updated_at = pg_catalog.transaction_timestamp() \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&target_id)
        .execute(&pool)
        .await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;

        let orphan_device = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO public.device_certificate_desired_states ( \
                 tenant_id, device_id, generation, validity_seconds, renew_before_seconds, \
                 client_auth, server_auth, sans \
             ) VALUES ($1::uuid, $2::uuid, 1, 3600, 600, true, false, ARRAY[]::text[])",
        )
        .bind(&tenant_id)
        .bind(&orphan_device)
        .execute(&pool)
        .await?;
        queue_command(
            &pool,
            &tenant_id,
            &orphan_device,
            "orphan-command",
            1,
            1,
            "f",
        )
        .await?;
        assert_migration_failure(
            &pool,
            "0087 refuses nonterminal command outside canonical authority",
        )
        .await?;
        sqlx::query(
            "DELETE FROM public.device_commands \
             WHERE tenant_id = $1::uuid AND command_id = 'orphan-command'",
        )
        .bind(&tenant_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            "DELETE FROM public.device_certificate_desired_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&orphan_device)
        .execute(&pool)
        .await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;
        migrations_through(87).run(&pool).await?;

        let ledger: (Option<i64>, i64, bool) = sqlx::query_as(
            "SELECT max(version), count(*) FILTER (WHERE version = 87), bool_and(success) \
             FROM public._sqlx_migrations",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(ledger, (Some(87), 1, true));
        pool.close().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dirty_command_coordinates_fail_closed_without_backfill() -> TestResult {
        let fixture = testkit::env_or_postgres().await?;
        let mut pool = pool_for(&fixture).await?;
        migrations_through(86).run(&pool).await?;

        let tenant_id = uuid::Uuid::new_v4().to_string();
        let active_device = uuid::Uuid::new_v4().to_string();
        authority(&pool, &tenant_id, &active_device, 2).await?;
        queue_command(&pool, &tenant_id, &active_device, "active-1", 1, 1, "1").await?;
        queue_command(&pool, &tenant_id, &active_device, "active-2", 1, 2, "2").await?;

        let duplicate_device = uuid::Uuid::new_v4().to_string();
        authority(&pool, &tenant_id, &duplicate_device, 2).await?;
        for (command_id, digest) in [("duplicate-1", "3"), ("duplicate-2", "4")] {
            queue_command(
                &pool,
                &tenant_id,
                &duplicate_device,
                command_id,
                1,
                1,
                digest,
            )
            .await?;
            sqlx::query(
                "UPDATE public.device_commands SET \
                     state = 'cancelled', version = 2, \
                     terminal_at = pg_catalog.transaction_timestamp() \
                 WHERE tenant_id = $1::uuid AND command_id = $2",
            )
            .bind(&tenant_id)
            .bind(command_id)
            .execute(&pool)
            .await?;
        }

        assert_migration_failure(&pool, "0087 refuses multiple nonterminal device commands")
            .await?;
        sqlx::query(
            "DELETE FROM public.device_commands \
             WHERE tenant_id = $1::uuid AND command_id = 'active-2'",
        )
        .bind(&tenant_id)
        .execute(&pool)
        .await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;

        assert_migration_failure(
            &pool,
            "0087 refuses duplicate device command fence coordinates",
        )
        .await?;
        sqlx::query(
            "DELETE FROM public.device_commands \
             WHERE tenant_id = $1::uuid AND command_id = 'duplicate-2'",
        )
        .bind(&tenant_id)
        .execute(&pool)
        .await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;
        migrations_through(87).run(&pool).await?;
        pool.close().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ambiguous_generation_and_authority_fail_before_clean_retry() -> TestResult {
        let fixture = testkit::env_or_postgres().await?;
        let mut pool = pool_for(&fixture).await?;
        migrations_through(86).run(&pool).await?;

        let tenant_id = uuid::Uuid::new_v4().to_string();
        let digest_device = uuid::Uuid::new_v4().to_string();
        authority(&pool, &tenant_id, &digest_device, 3).await?;
        for (command_id, epoch, digest) in [("digest-a", 1_i64, "a"), ("digest-b", 2_i64, "b")] {
            queue_command(
                &pool,
                &tenant_id,
                &digest_device,
                command_id,
                1,
                epoch,
                digest,
            )
            .await?;
            sqlx::query(
                "UPDATE public.device_commands SET state = 'cancelled', version = 2, \
                 terminal_at = pg_catalog.transaction_timestamp() \
                 WHERE tenant_id = $1::uuid AND command_id = $2",
            )
            .bind(&tenant_id)
            .bind(command_id)
            .execute(&pool)
            .await?;
        }
        assert_migration_failure(
            &pool,
            "0087 refuses multiple intent digests for one device generation",
        )
        .await?;
        sqlx::query(
            "DELETE FROM public.device_commands \
             WHERE tenant_id = $1::uuid AND command_id = 'digest-b'",
        )
        .bind(&tenant_id)
        .execute(&pool)
        .await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;

        let command_device = uuid::Uuid::new_v4().to_string();
        authority(&pool, &tenant_id, &command_device, 1).await?;
        queue_command(
            &pool,
            &tenant_id,
            &command_device,
            "future-command",
            2,
            2,
            "c",
        )
        .await?;
        assert_migration_failure(
            &pool,
            "0087 refuses nonterminal command outside canonical authority",
        )
        .await?;
        sqlx::query(
            "DELETE FROM public.device_commands \
             WHERE tenant_id = $1::uuid AND command_id = 'future-command'",
        )
        .bind(&tenant_id)
        .execute(&pool)
        .await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;

        let reported_device = uuid::Uuid::new_v4().to_string();
        authority(&pool, &tenant_id, &reported_device, 1).await?;
        sqlx::query(
            "INSERT INTO public.device_certificate_reported_states ( \
                 tenant_id, device_id, observed_generation, fence_epoch, state_hash, \
                 artifact_digest, report_envelope_id, device_sequence, received_at \
             ) VALUES ( \
                 $1::uuid, $2::uuid, 1, 2, \
                 pg_catalog.decode(pg_catalog.repeat('d', 64), 'hex'), \
                 pg_catalog.decode(pg_catalog.repeat('e', 64), 'hex'), \
                 'future-report', 1, pg_catalog.transaction_timestamp() \
             )",
        )
        .bind(&tenant_id)
        .bind(&reported_device)
        .execute(&pool)
        .await?;
        assert_migration_failure(
            &pool,
            "0087 refuses reported state outside canonical authority",
        )
        .await?;
        sqlx::query(
            "DELETE FROM public.device_certificate_reported_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&reported_device)
        .execute(&pool)
        .await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;
        migrations_through(87).run(&pool).await?;
        pool.close().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn installed_guards_enforce_current_authority_and_preserve_tenant_boundaries()
    -> TestResult {
        let fixture = testkit::env_or_postgres().await?;
        let pool = pool_for(&fixture).await?;
        migrations_through(87).run(&pool).await?;

        let tenant_id = uuid::Uuid::new_v4().to_string();
        let device_id = uuid::Uuid::new_v4().to_string();
        let target_id = authority(&pool, &tenant_id, &device_id, 1).await?;
        queue_command(&pool, &tenant_id, &device_id, "command-epoch-1", 1, 1, "5").await?;

        let failure = sqlx::query(
            "UPDATE public.device_commands SET \
                 state = 'superseded', version = 2, \
                 terminal_at = pg_catalog.transaction_timestamp() \
             WHERE tenant_id = $1::uuid AND command_id = 'command-epoch-1'",
        )
        .bind(&tenant_id)
        .execute(&pool)
        .await
        .expect_err("equal authority must not supersede a command");
        assert_eq!(
            failure
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );

        sqlx::query(
            "UPDATE public.device_commands SET \
                 state = 'published', version = 2, \
                 published_at = pg_catalog.transaction_timestamp() \
             WHERE tenant_id = $1::uuid AND command_id = 'command-epoch-1'",
        )
        .bind(&tenant_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            "UPDATE public.reconcile_leases SET epoch = 2, \
                 updated_at = pg_catalog.transaction_timestamp() \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&target_id)
        .execute(&pool)
        .await?;

        let failure = sqlx::query(
            "UPDATE public.device_commands SET \
                 state = 'received', version = 3, \
                 received_at = pg_catalog.transaction_timestamp() \
             WHERE tenant_id = $1::uuid AND command_id = 'command-epoch-1'",
        )
        .bind(&tenant_id)
        .execute(&pool)
        .await
        .expect_err("stale epoch must reject a non-supersede transition");
        assert_eq!(
            failure
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );

        sqlx::query(
            "UPDATE public.device_commands SET \
                 state = 'superseded', version = 3, \
                 terminal_at = pg_catalog.transaction_timestamp() \
             WHERE tenant_id = $1::uuid AND command_id = 'command-epoch-1'",
        )
        .bind(&tenant_id)
        .execute(&pool)
        .await?;
        let failure = queue_command(
            &pool,
            &tenant_id,
            &device_id,
            "command-epoch-2-spoof",
            1,
            2,
            "6",
        )
        .await
        .expect_err("same-generation takeover must preserve the historical intent digest");
        assert_eq!(
            failure
                .downcast_ref::<sqlx::Error>()
                .and_then(sqlx::Error::as_database_error)
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        queue_command(&pool, &tenant_id, &device_id, "command-epoch-2", 1, 2, "5").await?;

        for (event_id, disposition) in [
            ("receipt-generation", "stale_generation"),
            ("receipt-fence", "stale_fence"),
            ("receipt-sequence", "stale_sequence"),
        ] {
            sqlx::query(
                "INSERT INTO public.device_ingress_receipts ( \
                     tenant_id, event_id, device_id, kind, command_id, generation, fence_epoch, \
                     device_sequence, fingerprint, disposition \
                 ) VALUES ( \
                     $1::uuid, $2, $3::uuid, 'report', NULL, 1, 2, 0, \
                     pg_catalog.decode(pg_catalog.repeat('7', 64), 'hex'), $4 \
                 )",
            )
            .bind(&tenant_id)
            .bind(event_id)
            .bind(&device_id)
            .bind(disposition)
            .execute(&pool)
            .await?;
        }
        let failure = sqlx::query(
            "INSERT INTO public.device_ingress_receipts ( \
                 tenant_id, event_id, device_id, kind, command_id, generation, fence_epoch, \
                 device_sequence, fingerprint, disposition \
             ) VALUES ( \
                 $1::uuid, 'receipt-open-vocabulary', $2::uuid, 'report', NULL, 1, 2, 0, \
                 pg_catalog.decode(pg_catalog.repeat('7', 64), 'hex'), 'invented' \
             )",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&pool)
        .await
        .expect_err("receipt disposition vocabulary must remain closed");
        assert_eq!(
            failure
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );

        sqlx::query(
            "INSERT INTO public.device_certificate_reported_states ( \
                 tenant_id, device_id, observed_generation, fence_epoch, state_hash, \
                 artifact_digest, report_envelope_id, device_sequence, received_at \
             ) VALUES ( \
                 $1::uuid, $2::uuid, 1, 2, \
                 pg_catalog.decode(pg_catalog.repeat('8', 64), 'hex'), \
                 pg_catalog.decode(pg_catalog.repeat('9', 64), 'hex'), \
                 'report-1', 0, pg_catalog.transaction_timestamp() \
             )",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            "UPDATE public.device_certificate_reported_states SET \
                 state_hash = pg_catalog.decode(pg_catalog.repeat('a', 64), 'hex'), \
                 report_envelope_id = 'report-2', device_sequence = 1 \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&pool)
        .await?;
        let failure = sqlx::query(
            "UPDATE public.device_certificate_reported_states SET \
                 state_hash = pg_catalog.decode(pg_catalog.repeat('b', 64), 'hex'), \
                 report_envelope_id = 'report-3' \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&pool)
        .await
        .expect_err("changed reported state must advance the sequence");
        assert_eq!(
            failure
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );

        sqlx::query(
            "UPDATE public.device_certificate_desired_states SET generation = 2 \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            "UPDATE public.reconcile_leases SET epoch = 3, \
                 updated_at = pg_catalog.transaction_timestamp() \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&target_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            "UPDATE public.device_certificate_reported_states SET \
                 observed_generation = 2, fence_epoch = 3, \
                 report_envelope_id = 'report-4', device_sequence = 2 \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&pool)
        .await?;
        let failure = sqlx::query(
            "UPDATE public.device_certificate_reported_states SET \
                 fence_epoch = 2, report_envelope_id = 'report-5', device_sequence = 3 \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&pool)
        .await
        .expect_err("reported fence must not regress");
        assert_eq!(
            failure
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );

        let boundaries_intact: bool = sqlx::query_scalar(
            "SELECT bool_and(class.relrowsecurity AND class.relforcerowsecurity) \
             FROM pg_catalog.pg_class AS class \
             WHERE class.oid IN ( \
                 'public.device_commands'::regclass, \
                 'public.device_ingress_receipts'::regclass, \
                 'public.device_certificate_reported_states'::regclass \
             )",
        )
        .fetch_one(&pool)
        .await?;
        assert!(boundaries_intact);
        let exact_unique_indexes: bool = sqlx::query_scalar(
            "SELECT count(*) = 2 AND bool_and(idx.indisunique) \
             FROM pg_catalog.pg_index AS idx \
             JOIN pg_catalog.pg_class AS class ON class.oid = idx.indexrelid \
             WHERE class.relname IN ( \
                 'device_commands_fence_coordinate_unique', \
                 'device_commands_one_nonterminal_per_device' \
             )",
        )
        .fetch_one(&pool)
        .await?;
        assert!(exact_unique_indexes);
        let retired_index_absent: bool = sqlx::query_scalar(
            "SELECT pg_catalog.to_regclass( \
                 'public.device_commands_one_active_intent' \
             ) IS NULL",
        )
        .fetch_one(&pool)
        .await?;
        assert!(retired_index_absent);
        let forbidden_mutations_absent: bool = sqlx::query_scalar(
            "SELECT NOT pg_catalog.has_table_privilege('rss_app', 'public.device_commands', 'DELETE') \
                 AND NOT pg_catalog.has_table_privilege('rss_app', 'public.device_commands', 'INSERT') \
                 AND NOT pg_catalog.has_table_privilege('rss_app', 'public.device_commands', 'UPDATE') \
                 AND NOT pg_catalog.has_table_privilege( \
                     'rss_app', 'public.device_certificate_reported_states', 'INSERT' \
                 ) \
                 AND NOT pg_catalog.has_table_privilege( \
                     'rss_app', 'public.device_certificate_reported_states', 'UPDATE' \
                 ) \
                 AND NOT pg_catalog.has_table_privilege( \
                     'rss_app', 'public.device_ingress_receipts', 'UPDATE' \
                 ) \
                 AND NOT pg_catalog.has_table_privilege( \
                     'rss_app_read', 'public.device_certificate_reported_states', 'UPDATE' \
                 )",
        )
        .fetch_one(&pool)
        .await?;
        assert!(forbidden_mutations_absent);
        let exact_funnel_acl: bool = sqlx::query_scalar(
            "SELECT pg_catalog.has_function_privilege( \
                     'rss_app', \
                     'public.rss_install_fenced_device_command(uuid,uuid,text,bigint,bigint,bytea,bigint)', \
                     'EXECUTE' \
                 ) \
                 AND pg_catalog.has_function_privilege( \
                     'rss_app', \
                     'public.rss_apply_device_command_ack(uuid,uuid,text,bigint,bigint,text)', \
                     'EXECUTE' \
                 ) \
                 AND pg_catalog.has_function_privilege( \
                     'rss_app', \
                     'public.rss_upsert_device_certificate_report(uuid,uuid,bigint,bigint,bytea,bytea,text,bigint,bigint,bigint)', \
                     'EXECUTE' \
                 ) \
                 AND NOT pg_catalog.has_function_privilege( \
                     'rss_app_read', \
                     'public.rss_install_fenced_device_command(uuid,uuid,text,bigint,bigint,bytea,bigint)', \
                     'EXECUTE' \
                 ) \
                 AND NOT pg_catalog.has_function_privilege( \
                     'rss_app_read', \
                     'public.rss_apply_device_command_ack(uuid,uuid,text,bigint,bigint,text)', \
                     'EXECUTE' \
                 ) \
                 AND NOT pg_catalog.has_function_privilege( \
                     'rss_app_read', \
                     'public.rss_upsert_device_certificate_report(uuid,uuid,bigint,bigint,bytea,bytea,text,bigint,bigint,bigint)', \
                     'EXECUTE' \
                 )",
        )
        .fetch_one(&pool)
        .await?;
        assert!(exact_funnel_acl);

        let funnel_tenant = uuid::Uuid::new_v4().to_string();
        let funnel_device = uuid::Uuid::new_v4().to_string();
        authority(&pool, &funnel_tenant, &funnel_device, 1).await?;
        let mut app_tx = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *app_tx)
            .await?;
        sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
            .bind(&funnel_tenant)
            .execute(&mut *app_tx)
            .await?;
        let inserted: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM public.rss_upsert_device_certificate_report( \
                 $1::uuid, $2::uuid, 1, 1, \
                 pg_catalog.decode(pg_catalog.repeat('a', 64), 'hex'), \
                 pg_catalog.decode(pg_catalog.repeat('b', 64), 'hex'), \
                 'funnel-report', 1, NULL, NULL \
             )",
        )
        .bind(&funnel_tenant)
        .bind(&funnel_device)
        .fetch_one(&mut *app_tx)
        .await?;
        assert_eq!(
            inserted, 1,
            "rss_app must write through the exact report funnel"
        );
        app_tx.commit().await?;

        let mut spoof_tx = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *spoof_tx)
            .await?;
        sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_id)
            .execute(&mut *spoof_tx)
            .await?;
        let spoof = sqlx::query(
            "SELECT * FROM public.rss_upsert_device_certificate_report( \
                 $1::uuid, $2::uuid, 1, 1, \
                 pg_catalog.decode(pg_catalog.repeat('a', 64), 'hex'), \
                 pg_catalog.decode(pg_catalog.repeat('b', 64), 'hex'), \
                 'spoof-report', 2, NULL, NULL \
             )",
        )
        .bind(&funnel_tenant)
        .bind(&funnel_device)
        .execute(&mut *spoof_tx)
        .await
        .expect_err("funnel tenant argument must match the transaction tenant GUC");
        assert_eq!(
            spoof
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("42501")
        );
        spoof_tx.rollback().await?;

        let persisted: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM public.device_certificate_reported_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
               AND report_envelope_id = 'funnel-report'",
        )
        .bind(&funnel_tenant)
        .bind(&funnel_device)
        .fetch_one(&pool)
        .await?;
        assert_eq!(
            persisted, 1,
            "the RLS-scoped funnel write must persist exactly once"
        );

        pool.close().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authority_funnel_waits_at_target_before_observing_lease_and_desired() -> TestResult {
        let fixture = testkit::env_or_postgres().await?;
        let pool = pool_for(&fixture).await?;
        migrations_through(87).run(&pool).await?;

        let tenant_id = uuid::Uuid::new_v4().to_string();
        let device_id = uuid::Uuid::new_v4().to_string();
        let target_id = authority(&pool, &tenant_id, &device_id, 1).await?;

        let mut authority_change = pool.begin().await?;
        sqlx::query(
            "SELECT target_id FROM public.reconcile_targets \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid FOR UPDATE",
        )
        .bind(&tenant_id)
        .bind(&target_id)
        .execute(&mut *authority_change)
        .await?;

        let blocked_pool = pool.clone();
        let blocked_tenant = tenant_id.clone();
        let blocked_device = device_id.clone();
        let mut install = tokio::spawn(async move {
            let mut tx = blocked_pool.begin().await?;
            sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
                .bind(&blocked_tenant)
                .execute(&mut *tx)
                .await?;
            let outcome: String = sqlx::query_scalar(
                "SELECT public.rss_install_fenced_device_command( \
                     $1::uuid, $2::uuid, 'interleaved-command', 1, 1, \
                     pg_catalog.decode(pg_catalog.repeat('1', 64), 'hex'), 4102444800 \
                 )",
            )
            .bind(&blocked_tenant)
            .bind(&blocked_device)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok::<_, sqlx::Error>(outcome)
        });
        if let Ok(unexpected) = tokio::time::timeout(Duration::from_millis(100), &mut install).await
        {
            panic!("funnel must block at the already-held target lock: {unexpected:?}");
        }

        sqlx::query(
            "UPDATE public.reconcile_leases SET epoch = 2, updated_at = transaction_timestamp() \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&target_id)
        .execute(&mut *authority_change)
        .await?;
        sqlx::query(
            "UPDATE public.device_certificate_desired_states SET generation = 2 \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&mut *authority_change)
        .await?;
        authority_change.commit().await?;

        let outcome = tokio::time::timeout(Duration::from_secs(5), &mut install)
            .await
            .map_err(|_| std::io::Error::other("authority funnel remained blocked"))???;
        assert_eq!(outcome, "lost");
        let command_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM public.device_commands \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(command_count, 0, "stale coordinates must remain zero-write");
        pool.close().await;
        Ok(())
    }
}
