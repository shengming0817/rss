//! Postgres integration tests — projection_events seam.

use super::support::*;

#[tokio::test(flavor = "multi_thread")]
async fn projection_writer_funnel_mirrors_only_registered_bound_insert_once() -> TestResult {
    use crate::projection_events::ProjectionWriteRegistry;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let registry = ProjectionWriteRegistry::from_selected(PROJECTION_CONFORMANCE_INPUTS);
    let bound_event_id = unique_event_id("projection-bound");
    let unbound_event_id = unique_event_id("projection-unbound");
    let schema_mismatch_event_id = unique_event_id("projection-schema-mismatch");
    let bound_entry = projection_conformance_entry(&bound_event_id)?;
    let unbound_entry = projection_conformance_entry(&unbound_event_id)?;
    let schema_mismatch_entry = projection_conformance_entry(&schema_mismatch_event_id)?;
    let bound_env = projection_conformance_env();
    let unbound_env = projection_conformance_env_with_unbound_routing_for_negative_test();
    let schema_mismatch_env = make_test_env_with_contract_metadata(
        ProjectionConformanceFixture::primary()
            .binding()
            .source_domain(),
        ProjectionConformanceFixture::primary()
            .binding()
            .contract_id(),
        vocab::ContractBinding::from_static(
            ProjectionConformanceFixture::primary()
                .binding()
                .source_domain(),
            ProjectionConformanceFixture::primary()
                .binding()
                .contract_id(),
            "v2",
            ProjectionConformanceFixture::primary()
                .binding()
                .schema_hash(),
        ),
    );

    eventing_test_db(&store)
        .test_write(
            integration_tenant_scope(test_tenant()),
            move |cap| {
                let bound_entry = bound_entry.clone();
                let unbound_entry = unbound_entry.clone();
                let bound_env = bound_env.clone();
                let unbound_env = unbound_env.clone();
                Box::pin(async move {
                    let _outcome =
                        append_outbox_with_projection(cap, &bound_entry, &bound_env, &registry)
                            .await
                            .map_err(test_append_error)?;
                    let _outcome =
                        append_outbox_with_projection(cap, &bound_entry, &bound_env, &registry)
                            .await
                            .map_err(test_append_error)?;
                    let _outcome =
                        append_outbox_with_projection(cap, &unbound_entry, &unbound_env, &registry)
                            .await
                            .map_err(test_append_error)?;
                    let _outcome = append_outbox_with_projection(
                        cap,
                        &schema_mismatch_entry,
                        &schema_mismatch_env,
                        &registry,
                    )
                    .await
                    .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            },
            std::convert::identity,
        )
        .await?;

    let projection_rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT event_id, contract_id, contract_version, schema_hash, metadata ->> 'tenantId'
        FROM projection_events
        WHERE event_id = ANY($1)
        ORDER BY event_id
        "#,
    )
    .bind(vec![
        bound_event_id.clone(),
        unbound_event_id.clone(),
        schema_mismatch_event_id.clone(),
    ])
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        projection_rows.len(),
        1,
        "only registered-bound outbox inserts should mirror to projection_events"
    );
    assert_eq!(projection_rows[0].0, bound_event_id);
    assert_eq!(
        projection_rows[0].1,
        ProjectionConformanceFixture::primary()
            .binding()
            .contract_id()
    );
    assert_eq!(projection_rows[0].2, "v1");
    assert_eq!(
        projection_rows[0].3,
        ProjectionConformanceFixture::primary()
            .binding()
            .schema_hash()
    );
    assert_eq!(projection_rows[0].4, COTX_TENANT_A);

    let outbox_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = ANY($1)")
            .bind(vec![
                bound_event_id,
                unbound_event_id,
                schema_mismatch_event_id,
            ])
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(outbox_count.0, 3, "all outbox rows should exist");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_writer_runtime_setup_mirrors_reviewed_generated_event() -> TestResult {
    use eventexec::event::ReviewedEventWriter as _;

    let (pg, deps) = setup_runtime_deps_with_projection_inputs(
        SESSION_PROJECTION_INPUT_GENERATION,
        SESSION_PROJECTION_INPUTS,
    )
    .await?;
    let emitter = deps.handle().infra().emitter(fixed_clock());
    let event_id = unique_event_id("projection-runtime-session");
    let tenant = test_tenant();
    let event = reviewed_session_event(
        &event_id,
        tenant,
        "projection-runtime-subject",
        actor_for(tenant),
        uuid::Uuid::from_u128(0x1001),
    )
    .await?;

    emitter.write(event).await?;

    let pool = runtime_assertion_pool(pg.owner_params()).await?;
    let binding_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM projection_input_bindings \
         WHERE contract_id = $1 AND contract_version = $2 AND schema_hash = $3 AND topic = $4",
    )
    .bind(generated::event::identity_v1::session_created::CONTRACT.contract_id())
    .bind(generated::event::identity_v1::session_created::CONTRACT.version())
    .bind(generated::event::identity_v1::session_created::CONTRACT.schema_hash())
    .bind(generated::event::identity_v1::session_created::TOPIC)
    .fetch_one(&pool)
    .await?;
    assert_eq!(binding_count.0, 1);

    let projection_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM projection_events WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(projection_count.0, 1);

    pool.close().await;
    let (resources, _sampler_factory) = deps.into_runtime_parts(std::time::Duration::from_secs(1));
    for resource in resources.into_iter().rev() {
        resource.shutdown().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_writer_funnel_serializes_lsn_with_commit_order() -> TestResult {
    use crate::projection_events::ProjectionWriteRegistry;

    let (pg, store) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    setup_outbox(&store).await?;

    let registry = ProjectionWriteRegistry::from_selected(PROJECTION_CONFORMANCE_INPUTS);
    let first_registry = registry.clone();
    let first_event_id = unique_event_id("projection-order-first");
    let second_event_id = unique_event_id("projection-order-second");
    let first_entry = projection_conformance_entry(&first_event_id)?;
    let second_entry = projection_conformance_entry(&second_event_id)?;
    let first_env = projection_conformance_env();
    let second_env = projection_conformance_env();

    let db_a = eventing_test_db(&store);
    let db_b = eventing_test_db(&store);
    let (first_appended_tx, first_appended_rx) = tokio::sync::oneshot::channel();
    let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel();
    let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();

    let first = tokio::spawn(async move {
        db_a.test_write(
            integration_tenant_scope(test_tenant()),
            move |tx| {
                Box::pin(async move {
                    let _outcome = append_outbox_with_projection(
                        tx,
                        &first_entry,
                        &first_env,
                        &first_registry,
                    )
                    .await
                    .map_err(test_append_error)?;
                    let _ = first_appended_tx.send(());
                    release_first_rx
                        .await
                        .map_err(|err| sqlx::Error::Protocol(err.to_string()))?;
                    Ok(())
                })
            },
            std::convert::identity,
        )
        .await
    });

    first_appended_rx.await?;

    let second = tokio::spawn(async move {
        db_b.test_write(
            integration_tenant_scope(test_tenant()),
            move |tx| {
                Box::pin(async move {
                    let _ = second_started_tx.send(());
                    let _outcome =
                        append_outbox_with_projection(tx, &second_entry, &second_env, &registry)
                            .await
                            .map_err(test_append_error)?;
                    Ok(())
                })
            },
            std::convert::identity,
        )
        .await
    });
    let mut second = second;

    second_started_rx.await?;
    let completed_before_first_commit =
        tokio::time::timeout(std::time::Duration::from_millis(150), &mut second).await;
    assert!(
        completed_before_first_commit.is_err(),
        "second projection-bound append must wait for first transaction's append advisory lock"
    );

    release_first_tx
        .send(())
        .map_err(|()| std::io::Error::other("first transaction task exited before release"))?;
    first.await??;
    second.await??;

    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT event_id, id
        FROM projection_events
        WHERE event_id = ANY($1)
        ORDER BY id
        "#,
    )
    .bind(vec![first_event_id.clone(), second_event_id.clone()])
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(rows.len(), 2, "both bound events should be projected");
    assert_eq!(rows[0].0, first_event_id);
    assert_eq!(rows[1].0, second_event_id);
    assert!(
        rows[0].1 < rows[1].1,
        "projection LSN order must match commit order for concurrent bound writes"
    );

    let operator_store = crate::PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let source_store = crate::PgStore::connect_verified_projection_source_read(
        &crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_READER_ROLE,
            TEST_PROJECTION_READER_PASSWORD,
        )),
    )
    .await?;
    let (high_water_capability_first, high_water_capability_second) =
        issue_projection_source_capability(
            &operator_store,
            uuid::Uuid::parse_str(COTX_TENANT_A)?,
            ProjectionConformanceFixture::primary().projection_id(),
            ProjectionConformanceFixture::primary().definition_version(),
            ProjectionConformanceFixture::primary().definition_schema_hash(),
            ProjectionConformanceFixture::primary().input_generation(),
        )
        .await?;
    let high_water: Option<i64> = sqlx::query_scalar(
        "SELECT public.rss_projection_source_high_water_scoped(\
         $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)",
    )
    .bind(high_water_capability_first)
    .bind(high_water_capability_second)
    .bind(COTX_TENANT_A)
    .bind(ProjectionConformanceFixture::primary().projection_id())
    .bind(ProjectionConformanceFixture::primary().definition_version())
    .bind(ProjectionConformanceFixture::primary().definition_schema_hash())
    .bind(ProjectionConformanceFixture::primary().input_generation())
    .fetch_one(source_store.pool())
    .await?;
    assert_eq!(
        high_water,
        Some(rows[1].1),
        "#1415 interleaved commits must publish the last committed LSN without skipping either event"
    );
    let (read_capability_first, read_capability_second) = issue_projection_source_capability(
        &operator_store,
        uuid::Uuid::parse_str(COTX_TENANT_A)?,
        ProjectionConformanceFixture::primary().projection_id(),
        ProjectionConformanceFixture::primary().definition_version(),
        ProjectionConformanceFixture::primary().definition_schema_hash(),
        ProjectionConformanceFixture::primary().input_generation(),
    )
    .await?;
    let replay_suffix: Vec<(String, i64)> = sqlx::query_as(
        "SELECT event_id, id FROM public.rss_read_projection_events_scoped(\
         $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, 10)",
    )
    .bind(read_capability_first)
    .bind(read_capability_second)
    .bind(COTX_TENANT_A)
    .bind(ProjectionConformanceFixture::primary().projection_id())
    .bind(ProjectionConformanceFixture::primary().definition_version())
    .bind(ProjectionConformanceFixture::primary().definition_schema_hash())
    .bind(ProjectionConformanceFixture::primary().input_generation())
    .bind(rows[0].1)
    .fetch_all(source_store.pool())
    .await?;
    assert_eq!(
        replay_suffix,
        vec![(second_event_id, rows[1].1)],
        "checkpointing the first committed LSN must leave the interleaved successor replayable"
    );

    source_store.store_arc().shutdown().await?;
    operator_store.store_arc().shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_events_runtime_uses_fixed_functions_not_direct_table_privileges() -> TestResult
{
    let (pg, store) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    setup_outbox(&store).await?;
    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let event_id = unique_event_id("projection-fn");

    for sql in [
        "SELECT count(*) FROM projection_events",
        "INSERT INTO projection_events \
             (event_id, domain, aggregate_id, event_type, payload, contract_id, contract_version, schema_hash, metadata) \
         VALUES ('forbidden', 'test', 'agg', 'test.event', '\\x00'::bytea, 'projection.bound', 'v1', \
                 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', \
                 '{\"tenantId\":\"f47ac10b-58cc-4372-a567-0e02b2c3d479\"}'::jsonb)",
        "UPDATE projection_events SET domain = domain",
        "DELETE FROM projection_events",
    ] {
        let result = sqlx::query(sql).execute(&app.pool).await;
        assert!(
            result.is_err(),
            "rss_app must not have direct projection_events table privilege for: {sql}"
        );
    }

    for sql in [
        "SELECT count(*) FROM projection_input_bindings",
        "INSERT INTO projection_input_bindings \
             (contract_id, contract_version, schema_hash, topic) \
         VALUES ('projection.bound', 'v1', \
                 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', \
                 'test.event')",
        "UPDATE projection_input_bindings SET topic = topic",
        "DELETE FROM projection_input_bindings",
    ] {
        let result = sqlx::query(sql).execute(&app.pool).await;
        assert!(
            result.is_err(),
            "rss_app must not have direct projection_input_bindings table privilege for: {sql}"
        );
    }

    let projection_probe_acl: (String, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT owner.rolname,
               owner.rolcanlogin,
               procedure.prosecdef,
               procedure.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[],
               has_function_privilege('rss_app', procedure.oid, 'EXECUTE'),
               NOT EXISTS (
                   SELECT 1
                   FROM aclexplode(
                       COALESCE(procedure.proacl, acldefault('f', procedure.proowner))
                   ) AS acl
                   WHERE acl.grantee = 0
                     AND acl.privilege_type = 'EXECUTE'
               ),
               has_schema_privilege('rss_app', 'public', 'USAGE'),
               has_schema_privilege('rss_app', 'public', 'CREATE')
        FROM pg_proc AS procedure
        JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        JOIN pg_roles AS owner ON owner.oid = procedure.proowner
        WHERE namespace.nspname = 'public'
          AND procedure.proname = 'rss_read_projection_input_generation'
          AND pg_get_function_identity_arguments(procedure.oid) = 'p_generation text'
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        projection_probe_acl,
        (
            "rss_projection_source_reader_owner".to_owned(),
            false,
            true,
            true,
            true,
            true,
            true,
            false,
        ),
        "projection generation probe must have a NOLOGIN owner, trusted search_path, exact EXECUTE grants and read-only schema access"
    );
    let registered: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT projection_id, projection_definition_version, \
                projection_definition_schema_digest, source_domain, contract_id, \
                contract_version, schema_hash, topic \
         FROM public.rss_read_projection_input_generation($1) \
         ORDER BY projection_id, contract_id",
    )
    .bind(ProjectionConformanceFixture::primary().input_generation())
    .fetch_all(&app.pool)
    .await?;
    let mut expected = [
        ProjectionConformanceFixture::foreign(),
        ProjectionConformanceFixture::primary(),
    ]
    .into_iter()
    .flat_map(|fixture| {
        projection_conformance_inputs(fixture)
            .into_iter()
            .map(move |binding| {
                (
                    fixture.projection_id().to_owned(),
                    fixture.definition_version().to_owned(),
                    fixture.definition_schema_hash().to_owned(),
                    binding.domain().to_owned(),
                    binding.contract_id().to_owned(),
                    binding.version().to_owned(),
                    binding.schema_hash().to_owned(),
                    binding.topic().to_owned(),
                )
            })
    })
    .collect::<Vec<_>>();
    expected.sort_unstable_by(|left, right| (&left.0, &left.4).cmp(&(&right.0, &right.4)));
    assert_eq!(registered, expected);

    assert!(
        generated::event::PROJECTION_INPUTS.len() >= 2,
        "cross-splice fixture requires two real generated source bindings"
    );
    register_generated_projection_input_catalog(&store).await?;
    let mut generated_sources = Vec::new();
    for binding in generated::event::PROJECTION_INPUTS.iter().take(2).copied() {
        let definition = generated::event::PROJECTION_DEFINITIONS
            .iter()
            .find(|definition| definition.contract_id() == binding.projection_id())
            .ok_or_else(|| std::io::Error::other("generated projection input lacks definition"))?;
        let source_event_id = unique_event_id(binding.projection_id());
        let source_lsn = append_projection_source_event(&app, binding, &source_event_id).await?;
        generated_sources.push((*definition, binding, source_event_id, source_lsn));
    }
    assert_ne!(generated_sources[0].0, generated_sources[1].0);
    assert_ne!(generated_sources[0].1, generated_sources[1].1);

    for (source_index, contract_index) in [(0_usize, 1_usize), (1, 0)] {
        let source = generated_sources[source_index].1;
        let contract = generated_sources[contract_index].1;
        let cross_event_id = unique_event_id("projection-cross-splice");
        let cross_entry = EventEntry::new(
            EventTopic::parse(contract.topic())?,
            IdemKey::parse(&cross_event_id)?,
            reviewed_payload(source.projection_id().as_bytes()),
        );
        let cross_env = make_test_env_with_contract_metadata(
            source.domain(),
            contract.contract_id(),
            vocab::ContractBinding::from_static(
                contract.domain(),
                contract.contract_id(),
                contract.version(),
                contract.schema_hash(),
            ),
        );
        let cross_metadata = cross_env.metadata_json();
        eventing_test_db(&store)
            .test_write(
                integration_tenant_scope(test_tenant()),
                move |cap| {
                    let entry = cross_entry.clone();
                    let env = cross_env.clone();
                    Box::pin(async move {
                        let _outcome = append_outbox(cap, &entry, &env)
                            .await
                            .map_err(test_append_error)?;
                        Ok(())
                    }) as BoxFuture<'_, Result<(), sqlx::Error>>
                },
                std::convert::identity,
            )
            .await?;
        let cross_append = sqlx::query(
            "SELECT public.rss_append_projection_event(\
             $1, $2, $1, $3, $4, NULL, $5, $6, $7, $8::jsonb, NULL, NULL)",
        )
        .bind(&cross_event_id)
        .bind(source.domain())
        .bind(contract.topic())
        .bind(source.projection_id().as_bytes())
        .bind(contract.contract_id())
        .bind(contract.version())
        .bind(contract.schema_hash())
        .bind(cross_metadata)
        .execute(&app.pool)
        .await;
        assert!(
            cross_append.is_err(),
            "source binding fields from different generated rows must not be cross-spliced"
        );
    }

    let entry = projection_conformance_entry(&event_id)?;
    let env = projection_conformance_env();
    let metadata = env.metadata_json();
    let unbound_event_id = unique_event_id("projection-fn-unbound");
    let unbound_entry = projection_conformance_entry(&unbound_event_id)?;
    let unbound_env = projection_conformance_env_with_unbound_routing_for_negative_test();
    let unbound_metadata = unbound_env.metadata_json();
    eventing_test_db(&store)
        .test_write(
            integration_tenant_scope(test_tenant()),
            move |cap| {
                let entry = entry.clone();
                let env = env.clone();
                let unbound_entry = unbound_entry.clone();
                let unbound_env = unbound_env.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    let _outcome = append_outbox(cap, &unbound_entry, &unbound_env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            },
            std::convert::identity,
        )
        .await?;

    let appended_outbox: (
        String,
        String,
        Vec<u8>,
        String,
        String,
        String,
        serde_json::Value,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT domain, topic, payload, contract_id, contract_version, schema_hash, metadata, \
                partition_key, causation_id FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        appended_outbox.0,
        ProjectionConformanceFixture::primary()
            .binding()
            .source_domain()
    );
    assert_eq!(
        appended_outbox.1,
        ProjectionConformanceFixture::primary().binding().topic()
    );
    assert_eq!(appended_outbox.2, b"payload");
    assert_eq!(
        appended_outbox.3,
        ProjectionConformanceFixture::primary()
            .binding()
            .contract_id()
    );
    assert_eq!(appended_outbox.4, "v1");
    assert_eq!(
        appended_outbox.5,
        ProjectionConformanceFixture::primary()
            .binding()
            .schema_hash()
    );
    let expected_metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(appended_outbox.6, expected_metadata);
    assert_eq!(appended_outbox.7, None);
    assert_eq!(appended_outbox.8, None);
    let append_precondition: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM public.outbox AS outbox_row
            JOIN public.projection_input_bindings AS binding
              ON binding.source_domain = outbox_row.domain
             AND binding.contract_id = outbox_row.contract_id
             AND binding.contract_version = outbox_row.contract_version
             AND binding.schema_hash = outbox_row.schema_hash
             AND binding.topic = outbox_row.topic
            WHERE outbox_row.event_id = $1
              AND outbox_row.domain = $3
              AND outbox_row.topic = $4
              AND outbox_row.payload = $2
              AND outbox_row.contract_id = $5
              AND outbox_row.contract_version = $6
              AND outbox_row.schema_hash = $7
              AND outbox_row.metadata = $8::jsonb
              AND outbox_row.partition_key IS NULL
              AND outbox_row.causation_id IS NULL
              AND COALESCE(outbox_row.partition_key, outbox_row.event_id) = $1
        )
        "#,
    )
    .bind(&event_id)
    .bind(b"payload".as_slice())
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .source_domain(),
    )
    .bind(ProjectionConformanceFixture::primary().binding().topic())
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .contract_id(),
    )
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .contract_version(),
    )
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .schema_hash(),
    )
    .bind(&metadata)
    .fetch_one(&store.pool)
    .await?;
    assert!(append_precondition.0);

    let mut app_tx = app.pool.begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(COTX_TENANT_A)
        .execute(&mut *app_tx)
        .await?;
    let (lsn,): (i64,) = sqlx::query_as(
        r#"
        SELECT rss_append_projection_event(
            $1, $3, $1, $4, $2, NULL,
            $5, $6, $7, $8::jsonb, NULL, NULL
        )
        "#,
    )
    .bind(&event_id)
    .bind(b"payload".as_slice())
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .source_domain(),
    )
    .bind(ProjectionConformanceFixture::primary().binding().topic())
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .contract_id(),
    )
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .contract_version(),
    )
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .schema_hash(),
    )
    .bind(&metadata)
    .fetch_one(&mut *app_tx)
    .await?;
    app_tx.commit().await?;
    assert!(lsn > 0, "fixed append function must return projection lsn");

    let operator_store = crate::PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let source_store = crate::PgStore::connect_verified_projection_source_read(
        &crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_READER_ROLE,
            TEST_PROJECTION_READER_PASSWORD,
        )),
    )
    .await?;
    for (definition, binding, source_event_id, source_lsn) in &generated_sources {
        let (capability_first, capability_second) = issue_projection_source_capability(
            &operator_store,
            uuid::Uuid::parse_str(COTX_TENANT_A)?,
            binding.projection_id(),
            definition.version(),
            definition.schema_hash(),
            generated::event::PROJECTION_INPUT_GENERATION,
        )
        .await
        .map_err(|error| {
            std::io::Error::other(format!(
                "issue generated source capability for {}: {error}",
                binding.projection_id()
            ))
        })?;
        let scoped: Vec<(i64, String)> = sqlx::query_as(
            "SELECT id, event_id FROM public.rss_read_projection_events_scoped(\
             $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 0, 10)",
        )
        .bind(capability_first)
        .bind(capability_second)
        .bind(COTX_TENANT_A)
        .bind(binding.projection_id())
        .bind(definition.version())
        .bind(definition.schema_hash())
        .bind(generated::event::PROJECTION_INPUT_GENERATION)
        .fetch_all(source_store.pool())
        .await?;
        assert_eq!(scoped, vec![(*source_lsn, source_event_id.clone())]);
    }
    #[cfg(feature = "test-support")]
    for (_definition, binding, source_event_id, source_lsn) in &generated_sources {
        let projection = eventexec::ProjectionId::parse(binding.projection_id())?;
        let scope = eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
            &projection,
            test_tenant(),
        )
        .ok_or_else(|| std::io::Error::other("generated registry did not mint source scope"))?;
        let reader = crate::projection_events::PgProjectionSourceReader::new(
            &operator_store,
            &source_store,
            scope,
        );
        let records = reader
            .read_from(None, consistency::ProjectionBatchLimit::new(10)?)
            .await?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn().get(), u64::try_from(*source_lsn)?);
        assert_eq!(records[0].metadata().event_id(), source_event_id);
        assert_eq!(records[0].topic().as_str(), binding.topic());
    }
    for (projection_index, identity_index) in [(0_usize, 1_usize), (1, 0)] {
        let projection_binding = generated_sources[projection_index].1;
        let projection_definition = generated_sources[projection_index].0;
        let foreign_definition = generated_sources[identity_index].0;
        let (capability_first, capability_second) = issue_projection_source_capability(
            &operator_store,
            uuid::Uuid::parse_str(COTX_TENANT_A)?,
            projection_binding.projection_id(),
            projection_definition.version(),
            projection_definition.schema_hash(),
            generated::event::PROJECTION_INPUT_GENERATION,
        )
        .await?;
        let result = sqlx::query_as::<_, (i64,)>(
            "SELECT count(*)::bigint FROM public.rss_read_projection_events_scoped(\
             $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 0, 10)",
        )
        .bind(capability_first)
        .bind(capability_second)
        .bind(COTX_TENANT_A)
        .bind(projection_binding.projection_id())
        .bind(foreign_definition.version())
        .bind(foreign_definition.schema_hash())
        .bind(generated::event::PROJECTION_INPUT_GENERATION)
        .fetch_one(source_store.pool())
        .await;
        let Err(error) = result else {
            return Err(std::io::Error::other(
                "cross-spliced Projection source identity was unexpectedly accepted",
            )
            .into());
        };
        assert_database_sqlstate(
            &error,
            "22023",
            "projection identity fields from different generated definitions",
        );
    }
    let (scoped_capability_first, scoped_capability_second) = {
        issue_projection_source_capability(
            &operator_store,
            uuid::Uuid::parse_str(COTX_TENANT_A)?,
            ProjectionConformanceFixture::primary().projection_id(),
            ProjectionConformanceFixture::primary().definition_version(),
            ProjectionConformanceFixture::primary().definition_schema_hash(),
            ProjectionConformanceFixture::primary().input_generation(),
        )
        .await?
    };
    let scoped_ids: Vec<(i64,)> = sqlx::query_as(
        r#"
        SELECT id
        FROM public.rss_read_projection_events_scoped(
            $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 0, 10
        )
        "#,
    )
    .bind(scoped_capability_first)
    .bind(scoped_capability_second)
    .bind(COTX_TENANT_A)
    .bind(ProjectionConformanceFixture::primary().projection_id())
    .bind(ProjectionConformanceFixture::primary().definition_version())
    .bind(ProjectionConformanceFixture::primary().definition_schema_hash())
    .bind(ProjectionConformanceFixture::primary().input_generation())
    .fetch_all(source_store.pool())
    .await?;
    assert_eq!(scoped_ids, vec![(lsn,)]);
    let (cross_tenant_capability_first, cross_tenant_capability_second) = {
        issue_projection_source_capability(
            &operator_store,
            uuid::Uuid::parse_str(COTX_TENANT_A)?,
            ProjectionConformanceFixture::primary().projection_id(),
            ProjectionConformanceFixture::primary().definition_version(),
            ProjectionConformanceFixture::primary().definition_schema_hash(),
            ProjectionConformanceFixture::primary().input_generation(),
        )
        .await?
    };
    let cross_tenant = sqlx::query_as::<_, (i64,)>(
        r#"
        SELECT count(*)::bigint
        FROM public.rss_read_projection_events_scoped(
            $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 0, 10
        )
        "#,
    )
    .bind(cross_tenant_capability_first)
    .bind(cross_tenant_capability_second)
    .bind(COTX_TENANT_B)
    .bind(ProjectionConformanceFixture::primary().projection_id())
    .bind(ProjectionConformanceFixture::primary().definition_version())
    .bind(ProjectionConformanceFixture::primary().definition_schema_hash())
    .bind(ProjectionConformanceFixture::primary().input_generation())
    .fetch_one(source_store.pool())
    .await;
    let Err(cross_tenant_error) = cross_tenant else {
        return Err(std::io::Error::other(
            "tenant-A capability unexpectedly authorized a tenant-B source read",
        )
        .into());
    };
    assert_database_sqlstate(&cross_tenant_error, "22023", "cross-tenant capability");
    for (label, projection, definition_version, definition_digest, generation) in [
        (
            "projection",
            "other-projection",
            "v1",
            ProjectionConformanceFixture::primary().definition_schema_hash(),
            ProjectionConformanceFixture::primary().input_generation(),
        ),
        (
            "definition-version",
            ProjectionConformanceFixture::primary().projection_id(),
            "v2",
            ProjectionConformanceFixture::primary().definition_schema_hash(),
            ProjectionConformanceFixture::primary().input_generation(),
        ),
        (
            "definition-digest",
            ProjectionConformanceFixture::primary().projection_id(),
            ProjectionConformanceFixture::primary().definition_version(),
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ProjectionConformanceFixture::primary().input_generation(),
        ),
        (
            "generation",
            ProjectionConformanceFixture::primary().projection_id(),
            ProjectionConformanceFixture::primary().definition_version(),
            ProjectionConformanceFixture::primary().definition_schema_hash(),
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
    ] {
        let (capability_first, capability_second) = issue_projection_source_capability(
            &operator_store,
            uuid::Uuid::parse_str(COTX_TENANT_A)?,
            ProjectionConformanceFixture::primary().projection_id(),
            ProjectionConformanceFixture::primary().definition_version(),
            ProjectionConformanceFixture::primary().definition_schema_hash(),
            ProjectionConformanceFixture::primary().input_generation(),
        )
        .await?;
        let result = sqlx::query_as::<_, (i64,)>(
            r#"
            SELECT count(*)::bigint
            FROM public.rss_read_projection_events_scoped(
                $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 0, 10
            )
            "#,
        )
        .bind(capability_first)
        .bind(capability_second)
        .bind(COTX_TENANT_A)
        .bind(projection)
        .bind(definition_version)
        .bind(definition_digest)
        .bind(generation)
        .fetch_one(source_store.pool())
        .await;
        let Err(error) = result else {
            return Err(std::io::Error::other(format!(
                "{label} scope mismatch was unexpectedly accepted"
            ))
            .into());
        };
        assert_database_sqlstate(&error, "22023", &format!("{label} scope mismatch"));
    }
    assert!(
        sqlx::query("SELECT count(*) FROM public.projection_events")
            .execute(source_store.pool())
            .await
            .is_err(),
        "scoped reader must never receive raw ledger SELECT"
    );
    assert!(
        sqlx::query("SELECT count(*) FROM public.projection_source_capabilities")
            .execute(source_store.pool())
            .await
            .is_err(),
        "scoped reader must never inspect the source capability catalog"
    );
    for (label, tenant_id, projection_id) in [
        (
            "missing-tenant",
            None,
            Some(ProjectionConformanceFixture::primary().projection_id()),
        ),
        ("missing-projection", Some(COTX_TENANT_A), None),
        (
            "nil-tenant",
            Some("00000000-0000-0000-0000-000000000000"),
            Some(ProjectionConformanceFixture::primary().projection_id()),
        ),
    ] {
        let (capability_first, capability_second) = issue_projection_source_capability(
            &operator_store,
            uuid::Uuid::parse_str(COTX_TENANT_A)?,
            ProjectionConformanceFixture::primary().projection_id(),
            ProjectionConformanceFixture::primary().definition_version(),
            ProjectionConformanceFixture::primary().definition_schema_hash(),
            ProjectionConformanceFixture::primary().input_generation(),
        )
        .await?;
        let result = sqlx::query(
            "SELECT * FROM public.rss_read_projection_events_scoped(\
             $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 0, 10)",
        )
        .bind(capability_first)
        .bind(capability_second)
        .bind(tenant_id)
        .bind(projection_id)
        .bind(ProjectionConformanceFixture::primary().definition_version())
        .bind(ProjectionConformanceFixture::primary().definition_schema_hash())
        .bind(ProjectionConformanceFixture::primary().input_generation())
        .execute(source_store.pool())
        .await;
        let Err(error) = result else {
            return Err(std::io::Error::other(format!(
                "{label} scope unexpectedly released a payload"
            ))
            .into());
        };
        assert_database_sqlstate(&error, "22023", label);
    }

    assert!(
        sqlx::query(
            "SELECT * FROM public.rss_read_projection_events_scoped(\
             '00000000-0000-4000-8000-000000000001'::uuid, \
             '00000000-0000-4000-8000-000000000002'::uuid, \
             $1::uuid, $2, $3, $4, $5, 0, 10)",
        )
        .bind(COTX_TENANT_A)
        .bind(ProjectionConformanceFixture::primary().projection_id())
        .bind(ProjectionConformanceFixture::primary().definition_version())
        .bind(ProjectionConformanceFixture::primary().definition_schema_hash())
        .bind(ProjectionConformanceFixture::primary().input_generation())
        .execute(&operator_store.store_arc().pool)
        .await
        .is_err(),
        "operator credential must not receive Projection payload capability"
    );
    let audit_resource = format!("projection-audit-{}", uuid::Uuid::new_v4().simple());
    let command_id = uuid::Uuid::new_v4();
    let command_id_text = command_id.to_string();
    sqlx::query(
        "SELECT public.rss_projection_operator_record_audit(\
         $1, 0, 'operator:test', $2, 'projection.status.start', 'success', NULL, $3, $3)",
    )
    .bind(1_700_000_000_i64)
    .bind(&audit_resource)
    .bind(&command_id_text)
    .execute(&operator_store.store_arc().pool)
    .await?;
    let audit_row: (i64, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT count(*)::bigint, min(request_id), min(correlation_id) \
         FROM public.auth_audit_events \
         WHERE resource_kind = 'projection.maintenance' AND resource_id = $1",
    )
    .bind(&audit_resource)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        audit_row.0, 1,
        "operator audit must use its fixed insert funnel"
    );
    assert_eq!(
        audit_row.1.as_deref(),
        Some(command_id_text.as_str()),
        "operator audit must persist non-null request_id"
    );
    assert_eq!(
        audit_row.2.as_deref(),
        Some(command_id_text.as_str()),
        "operator audit must persist equal correlation_id"
    );
    assert!(
        sqlx::query(
            "SELECT public.rss_projection_operator_record_audit(\
             $1, 0, 'operator:test', $2, 'projection.raw.start', 'failure', NULL, $3, $3)",
        )
        .bind(1_700_000_000_i64)
        .bind(&audit_resource)
        .bind(&command_id_text)
        .execute(&operator_store.store_arc().pool)
        .await
        .is_err(),
        "operator audit funnel must reject an inconsistent failure record"
    );
    for (label, request_id, correlation_id) in [
        (
            "nil",
            "00000000-0000-0000-0000-000000000000",
            command_id_text.as_str(),
        ),
        ("empty", "", command_id_text.as_str()),
        ("illegal", "not-a-uuid", command_id_text.as_str()),
        (
            "mismatched-nil-correlation",
            command_id_text.as_str(),
            "00000000-0000-0000-0000-000000000000",
        ),
    ] {
        let Err(error) = sqlx::query(
            "SELECT public.rss_projection_operator_record_audit(\
             $1, 0, 'operator:test', $2, 'projection.status.finish', 'success', NULL, $3, $4)",
        )
        .bind(1_700_000_000_i64)
        .bind(&audit_resource)
        .bind(request_id)
        .bind(correlation_id)
        .execute(&operator_store.store_arc().pool)
        .await
        else {
            return Err(std::io::Error::other(format!(
                "operator audit must fail-closed for {label} correlation id"
            ))
            .into());
        };
        assert_database_sqlstate(&error, "22023", label);
    }
    assert!(
        sqlx::query(
            "SELECT public.rss_projection_operator_record_audit(\
             $1, 0, 'operator:test', $2, 'projection.status.start', 'success', NULL)",
        )
        .bind(1_700_000_000_i64)
        .bind(&audit_resource)
        .execute(&operator_store.store_arc().pool)
        .await
        .is_err(),
        "old 7-arg audit overload must not exist after hard cut"
    );

    let no_outbox_event_id = unique_event_id("projection-fn-no-outbox");
    let no_outbox_result = sqlx::query(
        r#"
        SELECT rss_append_projection_event(
            $1, $3, $1, $4, $2, NULL,
            $5, $6, $7, $8::jsonb, NULL, NULL
        )
        "#,
    )
    .bind(&no_outbox_event_id)
    .bind(b"payload".as_slice())
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .source_domain(),
    )
    .bind(ProjectionConformanceFixture::primary().binding().topic())
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .contract_id(),
    )
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .contract_version(),
    )
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .schema_hash(),
    )
    .bind(&metadata)
    .execute(&app.pool)
    .await;
    assert!(
        no_outbox_result.is_err(),
        "fixed append function must reject raw writes without a matching outbox row"
    );

    let unbound_result = sqlx::query(
        r#"
        SELECT rss_append_projection_event(
            $1, $3, $1, $4, $2, NULL,
            'projection.unbound', $5, $6, $7::jsonb, NULL, NULL
        )
        "#,
    )
    .bind(&unbound_event_id)
    .bind(b"payload".as_slice())
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .source_domain(),
    )
    .bind(ProjectionConformanceFixture::primary().binding().topic())
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .contract_version(),
    )
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .schema_hash(),
    )
    .bind(&unbound_metadata)
    .execute(&app.pool)
    .await;
    assert!(
        unbound_result.is_err(),
        "fixed append function must reject outbox rows absent from generated projection bindings"
    );

    let raw_read = sqlx::query("SELECT * FROM rss_read_projection_events(0, 10)")
        .execute(&app.pool)
        .await;
    assert!(
        raw_read.is_err(),
        "rss_app must not retain the unscoped raw Projection source function"
    );

    for (label, sql) in [
        (
            "null-limit",
            "SELECT * FROM rss_read_projection_events(0, NULL::integer)",
        ),
        (
            "zero-limit",
            "SELECT * FROM rss_read_projection_events(0, 0)",
        ),
        (
            "too-large-limit",
            "SELECT * FROM rss_read_projection_events(0, 1001)",
        ),
        (
            "negative-after",
            "SELECT * FROM rss_read_projection_events(-1, 10)",
        ),
        (
            "null-after",
            "SELECT * FROM rss_read_projection_events(NULL::bigint, 10)",
        ),
    ] {
        let result = sqlx::query(sql).execute(&app.pool).await;
        assert!(
            result.is_err(),
            "rss_app must not reach any legacy Projection read shape, including {label}"
        );
    }

    for (label, tenant_id) in [
        ("invalid", "not-a-uuid"),
        ("nil", "00000000-0000-0000-0000-000000000000"),
        ("uppercase", "F47AC10B-58CC-4372-A567-0E02B2C3D479"),
    ] {
        let result = sqlx::query(
            r#"
            SELECT rss_append_projection_event(
                $1, $3, $1, $4, $2, NULL,
                $5, $6, $7, $8::jsonb, NULL, NULL
            )
            "#,
        )
        .bind(unique_event_id(&format!("projection-fn-{label}")))
        .bind(b"payload".as_slice())
        .bind(
            ProjectionConformanceFixture::primary()
                .binding()
                .source_domain(),
        )
        .bind(ProjectionConformanceFixture::primary().binding().topic())
        .bind(
            ProjectionConformanceFixture::primary()
                .binding()
                .contract_id(),
        )
        .bind(
            ProjectionConformanceFixture::primary()
                .binding()
                .contract_version(),
        )
        .bind(
            ProjectionConformanceFixture::primary()
                .binding()
                .schema_hash(),
        )
        .bind(serde_json::json!({ "tenantId": tenant_id }).to_string())
        .execute(&app.pool)
        .await;
        assert!(
            result.is_err(),
            "fixed append function must reject non-canonical tenantId case {label}"
        );
    }

    source_store.store_arc().shutdown().await?;
    operator_store.store_arc().shutdown().await?;
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_source_capabilities_expire_and_sweep_orphans_boundedly() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    setup_outbox(&owner).await?;
    let operator_store = crate::PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let source_store = crate::PgStore::connect_verified_projection_source_read(
        &crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_READER_ROLE,
            TEST_PROJECTION_READER_PASSWORD,
        )),
    )
    .await?;

    let (capability_first, capability_second) = issue_projection_source_capability(
        &operator_store,
        uuid::Uuid::parse_str(COTX_TENANT_A)?,
        ProjectionConformanceFixture::primary().projection_id(),
        ProjectionConformanceFixture::primary().definition_version(),
        ProjectionConformanceFixture::primary().definition_schema_hash(),
        ProjectionConformanceFixture::primary().input_generation(),
    )
    .await?;
    let expires_in_seconds: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM (capability.expires_at - pg_catalog.clock_timestamp()))::double precision \
         FROM public.projection_source_capabilities AS capability \
         WHERE capability.capability_digest = pg_catalog.sha256(\
             pg_catalog.uuid_send($1::uuid) || pg_catalog.uuid_send($2::uuid)\
         )",
    )
    .bind(&capability_first)
    .bind(&capability_second)
    .fetch_one(&owner.pool)
    .await?;
    assert!(
        (0.0..=30.0).contains(&expires_in_seconds),
        "source capability TTL must be positive and fixed at no more than 30 seconds"
    );

    sqlx::query(
        "UPDATE public.projection_source_capabilities SET expires_at = \
         pg_catalog.clock_timestamp() - interval '1 second'",
    )
    .execute(&owner.pool)
    .await?;
    let expired_read = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT public.rss_projection_source_high_water_scoped(\
         $1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7)",
    )
    .bind(capability_first)
    .bind(capability_second)
    .bind(COTX_TENANT_A)
    .bind(ProjectionConformanceFixture::primary().projection_id())
    .bind(ProjectionConformanceFixture::primary().definition_version())
    .bind(ProjectionConformanceFixture::primary().definition_schema_hash())
    .bind(ProjectionConformanceFixture::primary().input_generation())
    .fetch_one(source_store.pool())
    .await;
    let Err(error) = expired_read else {
        return Err(std::io::Error::other("expired source capability was accepted").into());
    };
    assert_database_sqlstate(&error, "22023", "expired source capability");

    sqlx::query(
        "INSERT INTO public.projection_source_capabilities (\
             capability_digest, scope_tenant_id, projection_id, projection_definition_version, \
             projection_definition_schema_digest, input_generation, expires_at\
         ) SELECT pg_catalog.sha256(pg_catalog.int8send(item)), $1::uuid, \
                  $2, $3, $4, $5, \
                  pg_catalog.clock_timestamp() - interval '1 second' \
           FROM pg_catalog.generate_series(1::bigint, 1000::bigint) AS item",
    )
    .bind(COTX_TENANT_A)
    .bind(ProjectionConformanceFixture::primary().projection_id())
    .bind(ProjectionConformanceFixture::primary().definition_version())
    .bind(ProjectionConformanceFixture::primary().definition_schema_hash())
    .bind(ProjectionConformanceFixture::primary().input_generation())
    .execute(&owner.pool)
    .await?;
    let first_sweep: i64 =
        sqlx::query_scalar("SELECT public.rss_projection_operator_sweep_source_capabilities()")
            .fetch_one(&operator_store.store_arc().pool)
            .await?;
    let second_sweep: i64 =
        sqlx::query_scalar("SELECT public.rss_projection_operator_sweep_source_capabilities()")
            .fetch_one(&operator_store.store_arc().pool)
            .await?;
    assert_eq!(first_sweep, 1000, "each sweep must be capped at 1000 rows");
    assert_eq!(
        second_sweep, 1,
        "the next sweep must remove the remaining orphan"
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM public.projection_source_capabilities")
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(
        remaining, 0,
        "expired bearer capabilities must be reclaimable"
    );

    source_store.store_arc().shutdown().await?;
    operator_store.store_arc().shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_scoped_high_water_reduces_all_bindings_to_max_lsn() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    setup_outbox(&owner).await?;
    let fixture = ProjectionConformanceFixture::primary();
    let inputs = projection_conformance_inputs(fixture);
    assert_eq!(inputs.len(), 2, "primary fixture must seal two bindings");
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let operator_store = crate::PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let source_store = crate::PgStore::connect_verified_projection_source_read(
        &crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_READER_ROLE,
            TEST_PROJECTION_READER_PASSWORD,
        )),
    )
    .await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let other_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let first_event_id = unique_event_id("projection-high-water-multi-a");
    let second_event_id = unique_event_id("projection-high-water-multi-b");
    let noise_event_id = unique_event_id("projection-high-water-multi-noise");
    let first_payload = b"multi-binding-a";
    let second_payload = b"multi-binding-b";
    let noise_payload = b"other-tenant-noise";

    let first_lsn = append_projection_source_event_with_payload_for_tenant(
        &app,
        inputs[0],
        &first_event_id,
        tenant,
        first_payload,
    )
    .await?;
    let second_lsn = append_projection_source_event_with_payload_for_tenant(
        &app,
        inputs[1],
        &second_event_id,
        tenant,
        second_payload,
    )
    .await?;
    let noise_lsn = append_projection_source_event_with_payload_for_tenant(
        &app,
        inputs[1],
        &noise_event_id,
        other_tenant,
        noise_payload,
    )
    .await?;
    assert!(
        first_lsn < second_lsn && second_lsn < noise_lsn,
        "fixture must independently commit both bindings before later cross-scope noise"
    );

    let (high_water_capability_first, high_water_capability_second) =
        issue_projection_source_capability(
            &operator_store,
            tenant.as_uuid(),
            fixture.projection_id(),
            fixture.definition_version(),
            fixture.definition_schema_hash(),
            fixture.input_generation(),
        )
        .await?;
    let high_water: Option<i64> = sqlx::query_scalar(
        "SELECT public.rss_projection_source_high_water_scoped(\
         $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)",
    )
    .bind(&high_water_capability_first)
    .bind(&high_water_capability_second)
    .bind(tenant.to_string())
    .bind(fixture.projection_id())
    .bind(fixture.definition_version())
    .bind(fixture.definition_schema_hash())
    .bind(fixture.input_generation())
    .fetch_one(source_store.pool())
    .await?;
    assert_eq!(
        high_water,
        Some(second_lsn),
        "high-water must reduce every binding tail to the greatest in-scope LSN"
    );
    let replayed_capability = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT public.rss_projection_source_high_water_scoped(\
         $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)",
    )
    .bind(&high_water_capability_first)
    .bind(&high_water_capability_second)
    .bind(tenant.to_string())
    .bind(fixture.projection_id())
    .bind(fixture.definition_version())
    .bind(fixture.definition_schema_hash())
    .bind(fixture.input_generation())
    .fetch_one(source_store.pool())
    .await;
    let Err(replay_error) = replayed_capability else {
        return Err(std::io::Error::other(
            "a consumed projection source capability was replayed successfully",
        )
        .into());
    };
    assert_database_sqlstate(&replay_error, "22023", "replayed source capability");

    let (read_capability_first, read_capability_second) = issue_projection_source_capability(
        &operator_store,
        tenant.as_uuid(),
        fixture.projection_id(),
        fixture.definition_version(),
        fixture.definition_schema_hash(),
        fixture.input_generation(),
    )
    .await?;
    let records: Vec<(i64, String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, event_id, payload \
         FROM public.rss_read_projection_events_scoped(\
         $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 0, 10)",
    )
    .bind(read_capability_first)
    .bind(read_capability_second)
    .bind(tenant.to_string())
    .bind(fixture.projection_id())
    .bind(fixture.definition_version())
    .bind(fixture.definition_schema_hash())
    .bind(fixture.input_generation())
    .fetch_all(source_store.pool())
    .await?;
    assert_eq!(
        records,
        vec![
            (first_lsn, first_event_id, first_payload.to_vec()),
            (second_lsn, second_event_id, second_payload.to_vec()),
        ],
        "scoped read must return both binding payloads in LSN order and exclude later foreign noise"
    );

    source_store.store_arc().shutdown().await?;
    operator_store.store_arc().shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_scoped_high_water_validates_scope_and_transaction_visibility() -> TestResult {
    let fixture = ProjectionHighWaterFixture::setup().await?;
    let reader = fixture.source_reader();
    assert_eq!(
        reader.source_high_water().await?,
        None,
        "a valid empty source scope must remain distinguishable from invalid scope"
    );

    let wrong_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    for (
        label,
        tenant_id,
        projection_id,
        definition_version,
        definition_digest,
        input_generation,
    ) in [
        ("missing-scope", None, None, None, None, None),
        (
            "wrong-tenant",
            Some(fixture.other_tenant_scope.tenant().to_string()),
            Some(fixture.scope.projection().as_str()),
            Some(fixture.scope.definition_version()),
            Some(fixture.scope.definition_schema_digest()),
            Some(fixture.scope.input_generation()),
        ),
        (
            "wrong-projection",
            Some(fixture.scope.tenant().to_string()),
            Some("missing-projection"),
            Some(fixture.scope.definition_version()),
            Some(fixture.scope.definition_schema_digest()),
            Some(fixture.scope.input_generation()),
        ),
        (
            "wrong-definition",
            Some(fixture.scope.tenant().to_string()),
            Some(fixture.scope.projection().as_str()),
            Some("missing-version"),
            Some(fixture.scope.definition_schema_digest()),
            Some(fixture.scope.input_generation()),
        ),
        (
            "wrong-definition-digest",
            Some(fixture.scope.tenant().to_string()),
            Some(fixture.scope.projection().as_str()),
            Some(fixture.scope.definition_version()),
            Some(wrong_digest),
            Some(fixture.scope.input_generation()),
        ),
        (
            "wrong-generation",
            Some(fixture.scope.tenant().to_string()),
            Some(fixture.scope.projection().as_str()),
            Some(fixture.scope.definition_version()),
            Some(fixture.scope.definition_schema_digest()),
            Some(wrong_digest),
        ),
    ] {
        let (capability_first, capability_second) = issue_projection_source_capability(
            &fixture.operator_store,
            fixture.scope.tenant().as_uuid(),
            fixture.scope.projection().as_str(),
            fixture.scope.definition_version(),
            fixture.scope.definition_schema_digest(),
            fixture.scope.input_generation(),
        )
        .await?;
        let result = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT public.rss_projection_source_high_water_scoped(\
             $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)",
        )
        .bind(capability_first)
        .bind(capability_second)
        .bind(tenant_id)
        .bind(projection_id)
        .bind(definition_version)
        .bind(definition_digest)
        .bind(input_generation)
        .fetch_one(fixture.source_store.pool())
        .await;
        let Err(error) = result else {
            return Err(std::io::Error::other(format!(
                "{label} high-water scope unexpectedly returned a value"
            ))
            .into());
        };
        assert_database_sqlstate(&error, "22023", label);
    }

    let (_, first_lsn) =
        append_projection_high_water_fixture_event(&fixture, "projection-high-water-first").await?;
    assert_eq!(
        reader.source_high_water().await?,
        Some(consistency::Lsn::new(u64::try_from(first_lsn)?))
    );

    let rolled_back_event_id = unique_event_id("projection-high-water-rollback");
    let rolled_back_metadata = prepare_projection_source_outbox_event(
        &fixture.owner,
        fixture.binding,
        &rolled_back_event_id,
        fixture.tenant,
    )
    .await?;
    let mut rolled_back = fixture.app.pool.begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(fixture.tenant.to_string())
        .execute(&mut *rolled_back)
        .await?;
    let rolled_back_lsn: i64 = sqlx::query_scalar(
        "SELECT public.rss_append_projection_event(\
         $1, $2, $1, $3, $4, NULL, $5, $6, $7, $8::jsonb, NULL, NULL)",
    )
    .bind(&rolled_back_event_id)
    .bind(fixture.binding.domain())
    .bind(fixture.binding.topic())
    .bind(fixture.binding.projection_id().as_bytes())
    .bind(fixture.binding.contract_id())
    .bind(fixture.binding.version())
    .bind(fixture.binding.schema_hash())
    .bind(rolled_back_metadata)
    .fetch_one(&mut *rolled_back)
    .await?;
    assert!(rolled_back_lsn > first_lsn);
    rolled_back.rollback().await?;
    assert_eq!(
        reader.source_high_water().await?,
        Some(consistency::Lsn::new(u64::try_from(first_lsn)?))
    );

    sqlx::query("SELECT public.rss_retire_projection_input_generation($1)")
        .bind(fixture.scope.input_generation())
        .execute(&fixture.owner.pool)
        .await?;
    let missing_high_water = reader.source_high_water().await;
    assert!(matches!(
        missing_high_water,
        Err(crate::projection_events::ProjectionSourceReadError::ScopeInvalid)
    ));
    let missing_read = reader
        .read_from(None, consistency::ProjectionBatchLimit::new(10)?)
        .await;
    assert!(matches!(missing_read, Err(error) if error.kind() == EngineErrorKind::Invariant));

    fixture.shutdown().await
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_scoped_high_water_stays_fixed_cost_under_mixed_scope_capacity() -> TestResult {
    let fixture = ProjectionHighWaterFixture::setup().await?;
    let foreign_binding = fixture.foreign_binding();
    let (_, first_lsn) =
        append_projection_high_water_fixture_event(&fixture, "projection-high-water-capacity")
            .await?;
    let noise_prefix = format!(
        "projection-high-water-noise-{}-",
        uuid::Uuid::new_v4().simple()
    );
    sqlx::query(
        r#"
        INSERT INTO public.projection_events (
            event_id, domain, aggregate_id, event_type, payload,
            contract_id, contract_version, schema_hash, metadata
        )
        SELECT $1 || series::text,
               CASE WHEN series <= 50000 THEN $2 ELSE $9 END,
               $1 || series::text,
               CASE WHEN series <= 50000 THEN $3 ELSE $10 END,
               CASE WHEN series <= 50000 THEN $4 ELSE $11 END,
               CASE WHEN series <= 50000 THEN $5 ELSE $12 END,
               CASE WHEN series <= 50000 THEN $6 ELSE $13 END,
               CASE WHEN series <= 50000 THEN $7 ELSE $14 END,
               pg_catalog.jsonb_build_object(
                   'tenantId', CASE WHEN series <= 50000 THEN $8 ELSE $15 END
               )
        FROM pg_catalog.generate_series(1, 100000) AS series
        "#,
    )
    .bind(&noise_prefix)
    .bind(fixture.binding.domain())
    .bind(fixture.binding.topic())
    .bind(fixture.binding.projection_id().as_bytes())
    .bind(fixture.binding.contract_id())
    .bind(fixture.binding.version())
    .bind(fixture.binding.schema_hash())
    .bind(fixture.other_tenant.to_string())
    .bind(foreign_binding.domain())
    .bind(foreign_binding.topic())
    .bind(foreign_binding.projection_id().as_bytes())
    .bind(foreign_binding.contract_id())
    .bind(foreign_binding.version())
    .bind(foreign_binding.schema_hash())
    .bind(fixture.tenant.to_string())
    .execute(&fixture.owner.pool)
    .await?;
    sqlx::query("ANALYZE public.projection_events")
        .execute(&fixture.owner.pool)
        .await?;
    let noise_rows: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*)::bigint, \
         count(*) FILTER (WHERE metadata ->> 'tenantId' = $2)::bigint, \
         count(*) FILTER (WHERE metadata ->> 'tenantId' = $3 AND contract_id = $4)::bigint \
         FROM public.projection_events WHERE event_id LIKE $1 || '%'",
    )
    .bind(&noise_prefix)
    .bind(fixture.other_tenant.to_string())
    .bind(fixture.tenant.to_string())
    .bind(foreign_binding.contract_id())
    .fetch_one(&fixture.owner.pool)
    .await?;
    assert_eq!(noise_rows, (100_000, 50_000, 50_000));
    let relation_pages: i64 = sqlx::query_scalar(
        "SELECT relpages::bigint FROM pg_catalog.pg_class \
         WHERE oid = 'public.projection_events'::regclass",
    )
    .fetch_one(&fixture.owner.pool)
    .await?;
    assert!(
        relation_pages > 64,
        "capacity fixture must not be a sparse-page hole"
    );
    assert_eq!(
        projection_source_high_water(
            &fixture.operator_store,
            fixture.source_store.pool(),
            &fixture.scope,
        )
        .await?,
        Some(first_lsn),
        "mixed-scope capacity noise must not advance the selected high-water"
    );
    let mut source_connection = fixture.source_store.pool().acquire().await?;
    for attempt in 1..=6 {
        let (capability_first, capability_second) = issue_projection_source_capability(
            &fixture.operator_store,
            fixture.scope.tenant().as_uuid(),
            fixture.scope.projection().as_str(),
            fixture.scope.definition_version(),
            fixture.scope.definition_schema_digest(),
            fixture.scope.input_generation(),
        )
        .await?;
        let warmed: Option<i64> = sqlx::query_scalar(
            "SELECT public.rss_projection_source_high_water_scoped(\
             $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)",
        )
        .bind(capability_first)
        .bind(capability_second)
        .bind(fixture.scope.tenant().to_string())
        .bind(fixture.scope.projection().as_str())
        .bind(fixture.scope.definition_version())
        .bind(fixture.scope.definition_schema_digest())
        .bind(fixture.scope.input_generation())
        .fetch_one(&mut *source_connection)
        .await?;
        assert_eq!(
            warmed,
            Some(first_lsn),
            "production high-water warm-up attempt {attempt} drifted"
        );
    }
    let (explain_capability_first, explain_capability_second) = issue_projection_source_capability(
        &fixture.operator_store,
        fixture.scope.tenant().as_uuid(),
        fixture.scope.projection().as_str(),
        fixture.scope.definition_version(),
        fixture.scope.definition_schema_digest(),
        fixture.scope.input_generation(),
    )
    .await?;
    let plan: serde_json::Value = sqlx::query_scalar(
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) \
         SELECT public.rss_projection_source_high_water_scoped(\
         $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)",
    )
    .bind(explain_capability_first)
    .bind(explain_capability_second)
    .bind(fixture.scope.tenant().to_string())
    .bind(fixture.scope.projection().as_str())
    .bind(fixture.scope.definition_version())
    .bind(fixture.scope.definition_schema_digest())
    .bind(fixture.scope.input_generation())
    .fetch_one(&mut *source_connection)
    .await?;
    let shared_blocks = projection_high_water_plan_shared_blocks(&plan).ok_or_else(|| {
        std::io::Error::other("high-water EXPLAIN omitted shared buffer counters")
    })?;
    const MAX_FIXED_COST_SHARED_BLOCKS: u64 = 128;
    assert!(
        shared_blocks <= MAX_FIXED_COST_SHARED_BLOCKS
            && shared_blocks < u64::try_from(relation_pages)?,
        "actual high-water function touched {shared_blocks} shared blocks over a {relation_pages}-page ledger (fixed budget {MAX_FIXED_COST_SHARED_BLOCKS}): {plan}"
    );
    drop(source_connection);

    fixture.shutdown().await
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_source_rejects_unknown_same_generation_binding_before_payload_release()
-> TestResult {
    let fixture = ProjectionHighWaterFixture::setup().await?;
    append_projection_high_water_fixture_event(&fixture, "projection-source-generation-drift")
        .await?;
    let (high_water_capability_first, high_water_capability_second) =
        issue_projection_source_capability(
            &fixture.operator_store,
            fixture.scope.tenant().as_uuid(),
            fixture.scope.projection().as_str(),
            fixture.scope.definition_version(),
            fixture.scope.definition_schema_digest(),
            fixture.scope.input_generation(),
        )
        .await?;
    let (read_capability_first, read_capability_second) = issue_projection_source_capability(
        &fixture.operator_store,
        fixture.scope.tenant().as_uuid(),
        fixture.scope.projection().as_str(),
        fixture.scope.definition_version(),
        fixture.scope.definition_schema_digest(),
        fixture.scope.input_generation(),
    )
    .await?;
    sqlx::query(
        "INSERT INTO public.projection_input_bindings (\
         generation, projection_id, projection_definition_version, \
         projection_definition_schema_digest, source_domain, contract_id, contract_version, \
         schema_hash, topic) VALUES ($1, 'review.unknown-projection', 'v1', $2, \
         'review', 'review.unknown-event', 'v1', $2, 'review.unknown-event')",
    )
    .bind(fixture.scope.input_generation())
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .schema_hash(),
    )
    .execute(&fixture.owner.pool)
    .await?;

    let high_water = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT public.rss_projection_source_high_water_scoped(\
         $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)",
    )
    .bind(high_water_capability_first)
    .bind(high_water_capability_second)
    .bind(fixture.scope.tenant().to_string())
    .bind(fixture.scope.projection().as_str())
    .bind(fixture.scope.definition_version())
    .bind(fixture.scope.definition_schema_digest())
    .bind(fixture.scope.input_generation())
    .fetch_one(fixture.source_store.pool())
    .await;
    let Err(high_water_error) = high_water else {
        return Err(std::io::Error::other(
            "same-generation drift unexpectedly released a high-water",
        )
        .into());
    };
    assert_database_sqlstate(
        &high_water_error,
        "22023",
        "same-generation high-water drift",
    );

    let read = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)::bigint FROM public.rss_read_projection_events_scoped(\
         $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 0, 10)",
    )
    .bind(read_capability_first)
    .bind(read_capability_second)
    .bind(fixture.scope.tenant().to_string())
    .bind(fixture.scope.projection().as_str())
    .bind(fixture.scope.definition_version())
    .bind(fixture.scope.definition_schema_digest())
    .bind(fixture.scope.input_generation())
    .fetch_one(fixture.source_store.pool())
    .await;
    let Err(read_error) = read else {
        return Err(std::io::Error::other(
            "same-generation drift unexpectedly released source payload",
        )
        .into());
    };
    assert_database_sqlstate(&read_error, "22023", "same-generation payload drift");

    let reader = fixture.source_reader();
    assert!(matches!(
        reader.source_high_water().await,
        Err(crate::projection_events::ProjectionSourceReadError::ScopeInvalid)
    ));
    assert!(matches!(
        reader
            .read_from(None, consistency::ProjectionBatchLimit::new(10)?)
            .await,
        Err(error) if error.kind() == EngineErrorKind::Invariant
    ));

    fixture.shutdown().await
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_real_postgres_replay_checkpoints_and_restarts_without_cross_scope_payload()
-> TestResult {
    let (pg, owner) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    setup_outbox(&owner).await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let other_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let fixture = ProjectionConformanceFixture::primary();
    let bindings = projection_conformance_inputs(fixture);
    let binding = bindings
        .first()
        .copied()
        .ok_or("primary projection conformance fixture must contain a binding")?;
    let definition = projection_conformance_definition(fixture)?;
    let registry = projection_conformance_registry(fixture)?;
    let projection = eventexec::ProjectionId::parse(binding.projection_id())?;
    let scope = registry.source_scope(&projection, tenant)?;
    let execution = registry.operator_execution_context(&projection, tenant)?;
    let selector = eventexec::ProjectionSelector::new(
        tenant,
        projection.clone(),
        eventexec::ProjectionVersion::parse(fixture.target_generation())?,
    );
    let target_store = std::sync::Arc::new(RecordingProjectionTargetStore::default());
    let target: std::sync::Arc<dyn eventexec::ProjectionTarget> =
        std::sync::Arc::new(eventexec::ConformingProjectionTarget::new(
            definition,
            bindings,
            std::sync::Arc::clone(&target_store),
        )?);
    let deps = crate::PgProjectionOperatorDeps::connect(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
        &crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_READER_ROLE,
            TEST_PROJECTION_READER_PASSWORD,
        )),
        fixed_clock_arc(),
    )
    .await?;
    let runner_config = eventexec::ProjectionRunnerConfig::new(
        consistency::ProjectionBatchLimit::new(10)?,
        std::time::Duration::from_millis(100),
        eventexec::ProjectionPoisonPolicy::Isolate,
    )?;

    let first_event_id = unique_event_id("projection-replay-first");
    let second_event_id = unique_event_id("projection-replay-second");
    let first_lsn =
        append_projection_source_event_for_tenant(&app, binding, &first_event_id, tenant).await?;
    let second_lsn =
        append_projection_source_event_for_tenant(&app, binding, &second_event_id, tenant).await?;
    let other_tenant_event_id = unique_event_id("projection-replay-other-tenant");
    append_projection_source_event_for_tenant(&app, binding, &other_tenant_event_id, other_tenant)
        .await?;

    let replay = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Replay,
                tenant,
                selector.projection().as_str(),
            ),
            crate::ProjectionReplayAction,
            &selector,
            scope.clone(),
        )?
        .into_replay_stores(
            execution.clone(),
            std::sync::Arc::clone(&target),
            test_dlx_payload_protector(),
        )?;
    let first_run = replay.run_once(runner_config).await;
    assert_eq!(first_run.stop, eventexec::ProjectionStop::Completed);
    assert_eq!(first_run.scanned, 2);
    assert_eq!(first_run.applied, 2);
    assert_eq!(first_run.filtered, 0);
    assert_eq!(
        target_store.applied(),
        vec![
            (first_event_id, u64::try_from(first_lsn)?),
            (second_event_id, u64::try_from(second_lsn)?),
        ],
        "real source scope must keep another tenant's payload outside the target boundary"
    );
    let checkpoint: Option<i64> = sqlx::query_scalar(
        "SELECT offset_lsn FROM public.checkpoint WHERE owner = $1 AND checkpoint_id = $2",
    )
    .bind(selector.shadow_checkpoint_owner().as_str())
    .bind(selector.shadow_checkpoint_id().as_str())
    .fetch_optional(&owner.pool)
    .await?;
    assert_eq!(checkpoint, Some(second_lsn));
    drop(replay);

    let restarted = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Replay,
                tenant,
                selector.projection().as_str(),
            ),
            crate::ProjectionReplayAction,
            &selector,
            scope,
        )?
        .into_replay_stores(
            execution,
            std::sync::Arc::clone(&target),
            test_dlx_payload_protector(),
        )?;
    let idle_restart = restarted.run_once(runner_config).await;
    assert_eq!(idle_restart.stop, eventexec::ProjectionStop::Completed);
    assert_eq!(idle_restart.scanned, 0);
    assert_eq!(idle_restart.applied, 0);

    let third_event_id = unique_event_id("projection-replay-after-restart");
    let third_lsn =
        append_projection_source_event_for_tenant(&app, binding, &third_event_id, tenant).await?;
    let resumed = restarted.run_once(runner_config).await;
    assert_eq!(resumed.stop, eventexec::ProjectionStop::Completed);
    assert_eq!(resumed.scanned, 1);
    assert_eq!(resumed.applied, 1);
    assert_eq!(
        target_store.applied().last(),
        Some(&(third_event_id, u64::try_from(third_lsn)?)),
        "restart must resume strictly after the durable PostgreSQL checkpoint"
    );

    drop(restarted);
    deps.shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_credentials_fail_startup_when_exact_capabilities_drift() -> TestResult {
    const SCOPED_TAIL_INDEX_DDL: &str = "CREATE INDEX idx_projection_events_scoped_tail ON public.projection_events (\
         domain, contract_id, contract_version, schema_hash, event_type, \
         (metadata ->> 'tenantId'), id DESC NULLS LAST)";
    let (pg, owner) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    owner.run_migrations().await?;

    let source_config = crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
        pg.owner_params(),
        TEST_PROJECTION_READER_ROLE,
        TEST_PROJECTION_READER_PASSWORD,
    ));
    let operator_config = crate::PgProjectionOperatorConfig::new(runtime_pg_config(
        pg.owner_params(),
        TEST_PROJECTION_OPERATOR_ROLE,
        TEST_PROJECTION_OPERATOR_PASSWORD,
    ));

    sqlx::query("ALTER ROLE rss_projection_reader SET statement_timeout = '1s'")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query("ALTER ROLE rss_projection_reader RESET statement_timeout")
        .execute(&owner.pool)
        .await?;

    sqlx::query("ALTER ROLE rss_projection_source_reader_owner LOGIN")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query("ALTER ROLE rss_projection_source_reader_owner NOLOGIN")
        .execute(&owner.pool)
        .await?;

    sqlx::query("ALTER ROLE rss_projection_operator_owner BYPASSRLS")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_operator(&operator_config).await,
        Err(PgError::ProjectionOperatorRoleOrGrantMismatch)
    ));
    sqlx::query("ALTER ROLE rss_projection_operator_owner NOBYPASSRLS")
        .execute(&owner.pool)
        .await?;

    sqlx::query("DROP INDEX public.idx_projection_source_capabilities_expiry")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(
        "CREATE INDEX idx_projection_source_capabilities_expiry \
         ON public.projection_source_capabilities (expires_at, capability_digest)",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_sweep_source_capabilities() \
         TO rss_projection_reader",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.rss_projection_operator_sweep_source_capabilities() \
         FROM rss_projection_reader",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "ALTER FUNCTION public.rss_projection_operator_sweep_source_capabilities() \
         SECURITY INVOKER",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_operator(&operator_config).await,
        Err(PgError::ProjectionOperatorRoleOrGrantMismatch)
    ));
    sqlx::query(
        "ALTER FUNCTION public.rss_projection_operator_sweep_source_capabilities() \
         SECURITY DEFINER",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "ALTER FUNCTION public.rss_read_projection_events_scoped(\
         uuid,uuid,uuid,text,text,text,text,bigint,integer) SET search_path = public, pg_temp",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(
        "ALTER FUNCTION public.rss_read_projection_events_scoped(\
         uuid,uuid,uuid,text,text,text,text,bigint,integer) SET search_path = pg_catalog, pg_temp",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "ALTER FUNCTION public.rss_projection_source_high_water_scoped(\
         uuid,uuid,uuid,text,text,text,text) RESET plan_cache_mode",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(
        "ALTER FUNCTION public.rss_projection_source_high_water_scoped(\
         uuid,uuid,uuid,text,text,text,text) SET plan_cache_mode = force_generic_plan",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(
        "ALTER FUNCTION public.rss_projection_source_high_water_scoped(\
         uuid,uuid,uuid,text,text,text,text) SET plan_cache_mode = force_custom_plan",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "ALTER FUNCTION public.rss_projection_operator_get_checkpoint(uuid,text,text) \
         SECURITY INVOKER",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_operator(&operator_config).await,
        Err(PgError::ProjectionOperatorRoleOrGrantMismatch)
    ));
    sqlx::query(
        "ALTER FUNCTION public.rss_projection_operator_get_checkpoint(uuid,text,text) \
         SECURITY DEFINER",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "ALTER FUNCTION public.rss_projection_operator_get_checkpoint(uuid,text,text) \
         OWNER TO rss_projection_source_reader_owner",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_operator(&operator_config).await,
        Err(PgError::ProjectionOperatorRoleOrGrantMismatch)
    ));
    sqlx::query(
        "ALTER FUNCTION public.rss_projection_operator_get_checkpoint(uuid,text,text) \
         OWNER TO rss_projection_operator_owner",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.rss_read_projection_events_scoped(\
         uuid,uuid,uuid,text,text,text,text,bigint,integer) FROM rss_projection_reader",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(
        "GRANT EXECUTE ON FUNCTION public.rss_read_projection_events_scoped(\
         uuid,uuid,uuid,text,text,text,text,bigint,integer) TO rss_projection_reader",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query("GRANT SELECT ON public.projection_source_capabilities TO rss_projection_reader")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(
        "REVOKE SELECT ON public.projection_source_capabilities FROM rss_projection_reader",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_issue_source_capability(\
         uuid,text,text,text,text) TO rss_projection_reader",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.rss_projection_operator_issue_source_capability(\
         uuid,text,text,text,text) FROM rss_projection_reader",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "ALTER FUNCTION public.rss_assert_projection_source_scope(\
         boolean,uuid,uuid,uuid,text,text,text,text) SECURITY INVOKER",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(
        "ALTER FUNCTION public.rss_assert_projection_source_scope(\
         boolean,uuid,uuid,uuid,text,text,text,text) SECURITY DEFINER",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "GRANT EXECUTE ON FUNCTION public.rss_append_projection_event(\
         text,text,text,text,bytea,text,text,text,text,jsonb,text,text) TO PUBLIC",
    )
    .execute(&owner.pool)
    .await?;
    let source_fingerprint =
        match crate::PgStore::connect_verified_projection_source_read(&source_config).await {
            Err(PgError::ProjectionSourceReadPrivileges { actual_fingerprint }) => {
                actual_fingerprint
            }
            _ => panic!("ambient PUBLIC function grant must fail source gate"),
        };
    let operator_fingerprint =
        match crate::PgStore::connect_verified_projection_operator(&operator_config).await {
            Err(PgError::ProjectionOperatorPrivileges { actual_fingerprint }) => actual_fingerprint,
            _ => panic!("ambient PUBLIC function grant must fail operator gate"),
        };
    for actual_fingerprint in [source_fingerprint, operator_fingerprint] {
        assert!(
            actual_fingerprint.starts_with("sha256:"),
            "PUBLIC-only drift must be caught by effective capability fingerprint"
        );
    }
    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.rss_append_projection_event(\
         text,text,text,text,bytea,text,text,text,text,jsonb,text,text) FROM PUBLIC",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query("DROP ROLE IF EXISTS projection_source_attacker")
        .execute(&owner.pool)
        .await?;
    sqlx::query("CREATE ROLE projection_source_attacker NOLOGIN")
        .execute(&owner.pool)
        .await?;
    sqlx::query(
        "GRANT EXECUTE ON FUNCTION public.rss_projection_source_high_water_scoped(\
         uuid,uuid,uuid,text,text,text,text) TO projection_source_attacker",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.rss_projection_source_high_water_scoped(\
         uuid,uuid,uuid,text,text,text,text) FROM projection_source_attacker",
    )
    .execute(&owner.pool)
    .await?;
    sqlx::query("DROP ROLE projection_source_attacker")
        .execute(&owner.pool)
        .await?;

    sqlx::query("DROP INDEX public.idx_projection_events_scoped_tail")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query(SCOPED_TAIL_INDEX_DDL)
        .execute(&owner.pool)
        .await?;

    sqlx::query(
        "INSERT INTO public.projection_events (\
         event_id, domain, aggregate_id, event_type, payload, contract_id, contract_version, \
         schema_hash, metadata) VALUES \
         ('projection-invalid-index-a', 'review', 'a', 'review.event', ''::bytea, \
          'review.event', 'v1', $1, \
          '{\"tenantId\":\"00000000-0000-4000-8000-000000000099\"}'::jsonb), \
         ('projection-invalid-index-b', 'review', 'b', 'review.event', ''::bytea, \
          'review.event', 'v1', $1, \
          '{\"tenantId\":\"00000000-0000-4000-8000-000000000099\"}'::jsonb)",
    )
    .bind(
        ProjectionConformanceFixture::primary()
            .binding()
            .schema_hash(),
    )
    .execute(&owner.pool)
    .await?;
    sqlx::query("DROP INDEX public.idx_projection_events_scoped_tail")
        .execute(&owner.pool)
        .await?;
    let invalid_build = sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY idx_projection_events_scoped_tail \
         ON public.projection_events ((metadata ->> 'tenantId'))",
    )
    .execute(&owner.pool)
    .await;
    assert!(
        invalid_build.is_err(),
        "duplicate fixture must leave an INVALID index"
    );
    let invalid: bool = sqlx::query_scalar(
        "SELECT NOT index_row.indisvalid OR NOT index_row.indisready \
         FROM pg_catalog.pg_index AS index_row \
         WHERE index_row.indexrelid = 'public.idx_projection_events_scoped_tail'::regclass",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert!(
        invalid,
        "failed concurrent build must materialize INVALID index evidence"
    );
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query("DROP INDEX public.idx_projection_events_scoped_tail")
        .execute(&owner.pool)
        .await?;
    sqlx::query(SCOPED_TAIL_INDEX_DDL)
        .execute(&owner.pool)
        .await?;

    sqlx::query("DROP INDEX public.idx_projection_events_scoped_tail")
        .execute(&owner.pool)
        .await?;
    sqlx::query(
        "CREATE INDEX idx_projection_events_scoped_tail \
         ON public.projection_events (id DESC)",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query("DROP INDEX public.idx_projection_events_scoped_tail")
        .execute(&owner.pool)
        .await?;
    sqlx::query(SCOPED_TAIL_INDEX_DDL)
        .execute(&owner.pool)
        .await?;

    sqlx::query("GRANT SELECT ON public.checkpoint TO rss_projection_reader")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadRoleOrGrantMismatch)
    ));
    sqlx::query("REVOKE SELECT ON public.checkpoint FROM rss_projection_reader")
        .execute(&owner.pool)
        .await?;

    sqlx::query("GRANT SELECT ON public.checkpoint TO rss_projection_operator")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_operator(&operator_config).await,
        Err(PgError::ProjectionOperatorRoleOrGrantMismatch)
    ));
    sqlx::query("REVOKE SELECT ON public.checkpoint FROM rss_projection_operator")
        .execute(&owner.pool)
        .await?;

    sqlx::query("CREATE TYPE public.projection_reader_owned_drift AS ENUM ('drift')")
        .execute(&owner.pool)
        .await?;
    sqlx::query("ALTER TYPE public.projection_reader_owned_drift OWNER TO rss_projection_reader")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadOwnership)
    ));
    sqlx::query("DROP TYPE public.projection_reader_owned_drift")
        .execute(&owner.pool)
        .await?;

    sqlx::query("CREATE TYPE public.projection_operator_owned_drift AS ENUM ('drift')")
        .execute(&owner.pool)
        .await?;
    sqlx::query(
        "ALTER TYPE public.projection_operator_owned_drift OWNER TO rss_projection_operator",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_operator(&operator_config).await,
        Err(PgError::ProjectionOperatorOwnership)
    ));
    sqlx::query("DROP TYPE public.projection_operator_owned_drift")
        .execute(&owner.pool)
        .await?;

    sqlx::query("GRANT EXECUTE ON FUNCTION pg_catalog.lo_create(oid) TO PUBLIC")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadExternalPersistencePrivileges)
    ));
    assert!(matches!(
        crate::PgStore::connect_verified_projection_operator(&operator_config).await,
        Err(PgError::ProjectionOperatorExternalPersistencePrivileges)
    ));
    sqlx::query("REVOKE EXECUTE ON FUNCTION pg_catalog.lo_create(oid) FROM PUBLIC")
        .execute(&owner.pool)
        .await?;

    let large_object_oid: i64 = sqlx::query_scalar("SELECT lo_create(0)::bigint")
        .fetch_one(&owner.pool)
        .await?;
    sqlx::query(&format!(
        "GRANT SELECT ON LARGE OBJECT {large_object_oid} TO PUBLIC"
    ))
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadExternalPersistencePrivileges)
    ));
    assert!(matches!(
        crate::PgStore::connect_verified_projection_operator(&operator_config).await,
        Err(PgError::ProjectionOperatorExternalPersistencePrivileges)
    ));
    sqlx::query(&format!(
        "REVOKE ALL PRIVILEGES ON LARGE OBJECT {large_object_oid} FROM PUBLIC"
    ))
    .execute(&owner.pool)
    .await?;
    sqlx::query(&format!("SELECT lo_unlink({large_object_oid}::oid)"))
        .execute(&owner.pool)
        .await?;

    sqlx::query("GRANT SET ON PARAMETER work_mem TO PUBLIC")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_projection_source_read(&source_config).await,
        Err(PgError::ProjectionSourceReadExternalPersistencePrivileges)
    ));
    assert!(matches!(
        crate::PgStore::connect_verified_projection_operator(&operator_config).await,
        Err(PgError::ProjectionOperatorExternalPersistencePrivileges)
    ));
    sqlx::query("REVOKE ALL PRIVILEGES ON PARAMETER work_mem FROM PUBLIC")
        .execute(&owner.pool)
        .await?;

    sqlx::query(
        r#"
        CREATE OR REPLACE FUNCTION public.rss_read_projection_events_scoped(
            p_capability_first uuid,
            p_capability_second uuid,
            p_tenant_id uuid,
            p_projection_id text,
            p_definition_version text,
            p_definition_schema_digest text,
            p_input_generation text,
            p_after bigint,
            p_limit integer
        )
        RETURNS TABLE (
            id bigint, event_id text, domain text, aggregate_id text, event_type text,
            payload bytea, contract_id text, contract_version text, schema_hash text,
            metadata jsonb, partition_key text, causation_id text
        )
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN RETURN; END; $$
        "#,
    )
    .execute(&owner.pool)
    .await?;
    let source_definition_fingerprint =
        match crate::PgStore::connect_verified_projection_source_read(&source_config).await {
            Err(PgError::ProjectionSourceReadFunctionDefinition { actual_fingerprint }) => {
                actual_fingerprint
            }
            _ => panic!("source function body drift must fail the definition gate"),
        };
    assert!(source_definition_fingerprint.starts_with("sha256:"));

    sqlx::query(
        r#"
        CREATE OR REPLACE FUNCTION public.rss_projection_operator_record_audit(
            p_occurred_at_secs bigint,
            p_occurred_at_nanos integer,
            p_operator_subject text,
            p_resource_id text,
            p_action text,
            p_outcome text,
            p_failure_reason text,
            p_request_id text,
            p_correlation_id text
        )
        RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$ BEGIN RETURN; END; $$
        "#,
    )
    .execute(&owner.pool)
    .await?;
    let operator_definition_fingerprint =
        match crate::PgStore::connect_verified_projection_operator(&operator_config).await {
            Err(PgError::ProjectionOperatorFunctionDefinitions { actual_fingerprint }) => {
                actual_fingerprint
            }
            _ => panic!("operator function body drift must fail the definition gate"),
        };
    assert!(operator_definition_fingerprint.starts_with("sha256:"));

    owner.shutdown().await?;
    Ok(())
}
