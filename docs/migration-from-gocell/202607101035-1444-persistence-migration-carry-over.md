# #1444 persistence migration carry-over ledger

Status: **audit snapshot** for GoCell persistence/eventing carry-over under epic #1644, audited on
2026-07-10 against tracker state and develop commit
`8d2768d5dd9cdea6cd798b08be506fa12a1724c2`.

The earlier #1418 review, #1114–#1124 execution set, and #1434–#1443 follow-ups are historical
provenance. The source documents below are read-only inputs for the persistence/eventing rows
imported here; some retain broader backlog semantics outside that bounded slice. This ledger is the
canonical mapping and repository-evidence snapshot for that audit only. The live forge tracker and
board are the sole source of current work-item status; consumers must query them rather than infer
live state from this snapshot, historical checkboxes, or prose.

Frozen snapshot coverage: SpecKit T001–T012 = 12/12 parents and 65/65
checkboxes; rewrite P0–P8 = 9/9; capability gaps = 30/30; schedule 607 = every parseable explicit,
range, and slash-shorthand RSS work item; crate mapping = every row in its primary mapping table;
code follow-up = every frozen/current anchor captured in this snapshot. A split source uses a suffix
such as `.a`; coverage is still charged to its unsuffixed source item.

Resolution is closed to `done-evidence`, `absorbed-by`, `needs-issue`, and `out-of-scope`.
`done-evidence` is a repository snapshot claim, `absorbed-by` points to an existing leaf without
creating a duplicate, and `needs-issue` names a PBI created by this audit. #1418 and #1644 are
containers and are never the sole canonical PBI.

Open-source benchmark retained for the governance-gate implementation:
`ref: oxidecomputer/omicron dev-tools/schema/src/main.rs@892ea874af8781301b2295a855b0f16ea86341f0`

<!-- carry-over-schema: v1 -->

| Source Set | Source ID | Capability | Resolution | Canonical Work Item | Duplicate | New PBI | Commit | Evidence Path | Proof | Scope Note |
|---|---|---|---|---|---|---|---|---|---|---|
| spec-002 | T001.1 | consistency L0-L2 red tests | done-evidence | #1114,#1617,#1618 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/outbox.rs | test: disposition_as_label_distinct | implemented |
| spec-002 | T001.2 | engine error body | done-evidence | #1114,#1617,#1618 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/error.rs | test: engine_error_kind_message_distinct | implemented |
| spec-002 | T001.3 | idempotency body | done-evidence | #1114,#1617,#1618 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/idempotency.rs | test: state_machine_claim_commit_then_duplicate | implemented |
| spec-002 | T001.4 | outbox value body | done-evidence | #1114,#1617,#1618 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/outbox.rs | test: disposition_as_label_distinct | implemented |
| spec-002 | T001.5 | L0-L2 quality gates | done-evidence | #1114,#1617,#1618 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/verify.rs | gate: workspace verify | implemented |
| spec-002 | T002.1 | consistency L3-L4 red tests | done-evidence | #1115,#1620,#1621,#1627 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/saga.rs | test: saga_definition_rejects_empty_invalid_and_duplicate_steps | implemented |
| spec-002 | T002.2 | saga value body | done-evidence | #1115,#1620,#1621,#1627 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/saga.rs | test: saga_definition_rejects_empty_invalid_and_duplicate_steps | implemented |
| spec-002 | T002.3 | reconcile value body | done-evidence | #1115,#1620,#1621,#1627 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/reconcile.rs | test: diff_classifies_desired_actual_presence_matrix | implemented |
| spec-002 | T002.4 | projection value body | done-evidence | #1115,#1620,#1621,#1627 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/projection.rs | test: projection_checkpoint_rejects_regression | implemented |
| spec-002 | T002.5 | L3-L4 quality gates | done-evidence | #1115,#1620,#1621,#1627 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/verify.rs | gate: workspace verify | implemented |
| spec-002 | T003.1 | postgres integration skeleton | done-evidence | #1116,#1423,#1426 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/integration_tests.rs | tests: pool_connects_and_shuts_down,transaction_commit_persists_and_rollback_discards,migrator_applies_and_is_idempotent | implemented |
| spec-002 | T003.2 | postgres pool transaction migrator | done-evidence | #1116,#1423,#1426 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/lib.rs | test: pg_store_guard_shutdown_lazy_pool_ok | implemented |
| spec-002 | T003.3 | migration convention and initial schema | done-evidence | #1116,#1423,#1426 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/migrations.rs | gate: cargo xtask migrations | implemented |
| spec-002 | T003.4.a | postgres integration feature and compile harness | done-evidence | #1116,#1435 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/tests/tx_capability_trybuild.rs | test: tx_capability_ui | implemented |
| spec-002 | T003.4.b | local Docker stack and environment file | out-of-scope | - | no | - | - | - | - | CI and deployment artifacts are explicitly outside persistence carry-over |
| spec-002 | T003.5 | postgres conformance gates | done-evidence | #1116,#1423,#1426 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/layerdeps.rs | gate: layer-deps and workspace verify | implemented |
| spec-002 | T004.1 | outbox relay red tests | done-evidence | #1117,#1429,#1437,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/relay.rs | test: relay_tick_recovers_to_healthy_after_clean_round | implemented |
| spec-002 | T004.2 | tenant-scoped outbox schema | done-evidence | #1117,#1429,#1437,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/tenancy_closeout.rs | gate: tenancy-closeout | implemented |
| spec-002 | T004.3 | transactional outbox store | done-evidence | #1117,#1429,#1437,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/outbox.rs | test: envelope_new_and_fields | implemented |
| spec-002 | T004.4 | relay CAS and sweeper runtime | done-evidence | #1117,#1429,#1437,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/relay.rs | test: t8_shutdown_drains_in_flight_entries | implemented |
| spec-002 | T004.5 | relay and sweeper probes | done-evidence | #1117,#1429,#1437,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/relay.rs | tests: t12_probe_names_parse_and_no_ready_suffix,t10a_worker_stopped_health_unhealthy | implemented |
| spec-002 | T004.6 | outbox atomicity governance | done-evidence | #1117,#1429,#1437,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/contract/validate.rs | gate: outbox-atomicity contract validation | implemented |
| spec-002 | T005.1 | inbox idempotency red tests | done-evidence | #1118,#1434,#1435,#1437,#1623,#1626,#1631 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/inbox.rs | test: concurrent_try_claim_same_receipt_single_fresh_winner | implemented |
| spec-002 | T005.2 | postgres inbox receipts | done-evidence | #1118,#1434,#1435,#1437,#1623,#1626,#1631 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/inbox.rs | test: commit_makes_key_permanently_duplicate | implemented |
| spec-002 | T005.3 | redis receipt claimer | done-evidence | #1118,#1434,#1435,#1437,#1623,#1626,#1631 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/redis/src/lib.rs | test: new_accepts_1ms_ttl | implemented |
| spec-002 | T005.4 | topology sealed replay resolver | done-evidence | #1118,#1434,#1435,#1437,#1623,#1626,#1631 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/bootstrap/src/replaydeps.rs | test: durable_isolated_missing_redis_fails_closed | implemented |
| spec-002 | T005.5 | inbox quality gates | done-evidence | #1118,#1434,#1435,#1437,#1623,#1626,#1631 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/inbox_cutover_guard.rs | gate: inbox-cutover-guard | implemented |
| spec-002 | T006.1 | AMQP topology red tests | done-evidence | #1119,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/bootstrap/src/eventtransport.rs | test: isolated_missing_per_domain_fails_closed_no_fallback | implemented |
| spec-002 | T006.2 | lapin publisher subscriber | done-evidence | #1119,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/amqp/src/publisher.rs | test: transport_metadata_goes_to_headers_and_sensitive_metadata_is_excluded | implemented |
| spec-002 | T006.3 | topology sealed event transport | done-evidence | #1119,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/event_transport_guard.rs | gate: event-transport-guard | implemented |
| spec-002 | T006.4.a | AMQP integration feature and adapter harness | done-evidence | #1119,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/amqp/tests/integration.rs | test: integration_publish_subscribe_roundtrip | implemented |
| spec-002 | T006.4.b | local Redis and RabbitMQ Docker services | out-of-scope | - | no | - | - | - | - | CI and deployment artifacts are explicitly outside persistence carry-over |
| spec-002 | T006.5 | AMQP credential redaction synthetic test | needs-issue | #1720 | no | #1720 | - | - | - | New PBI created and linked to #1644 for EVENTTRANSPORT-CRED-REDACT-01 |
| spec-002 | T007.1 | consumer dispatch red tests | done-evidence | #1120,#1142,#1434,#1435,#1442,#1634 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/consumer.rs | test: tc1_handler_ack_commit_once_no_dlx | implemented |
| spec-002 | T007.2 | postgres dead letter store | done-evidence | #1120,#1142,#1434,#1435,#1442,#1634 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/dead_letter.rs | test: write_dead_letter_roundtrips | implemented |
| spec-002 | T007.3 | ConsumerBase runtime | done-evidence | #1120,#1142,#1434,#1435,#1442,#1634 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/consumer.rs | test: tc1_handler_ack_commit_once_no_dlx | implemented |
| spec-002 | T007.4 | generated subscription glue | done-evidence | #1120,#1142,#1434,#1435,#1442,#1634 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/contract_binding_guard.rs | gate: active subscriber contract | implemented |
| spec-002 | T007.5 | DLX structured telemetry | done-evidence | #1120,#1142,#1434,#1435,#1442,#1634 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/consumer.rs | test: tc5_dlx_tracing_fields_and_no_payload_leak | implemented |
| spec-002 | T007.6 | consumer quality gates | done-evidence | #1120,#1142,#1434,#1435,#1442,#1634 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/verify.rs | gate: workspace verify | implemented |
| spec-002 | T008.1 | durable identity audit red journey | done-evidence | #1100,#1433,#1634,#1641 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | journeys/tests/identity_login_audit_durable_journey.rs | test: login_audit_durable_topology | implemented |
| spec-002 | T008.2 | login transactional outbox | done-evidence | #1100,#1433,#1634,#1641 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/identity/src/application/mod.rs | test: login_success_persists_once_and_response_correct | implemented |
| spec-002 | T008.3 | audit inbox idempotency | done-evidence | #1100,#1433,#1634,#1641 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/audit/src/application.rs | test: session_created_appends_verifiable_chain_entry | implemented |
| spec-002 | T008.4 | dual topology journey | done-evidence | #1100,#1433,#1634,#1641 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | journeys/tests/identity_login_audit_durable_journey.rs | test: login_audit_durable_topology | implemented |
| spec-002 | T008.5 | durable fanout governance | done-evidence | #1100,#1433,#1634,#1641 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/verify.rs | gate: consistency fault matrix | implemented |
| spec-002 | T009.1 | saga execution red tests | done-evidence | #1121,#1627,#1632,#1637,#1646,#1651 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/saga/tests.rs | test: run_three_steps_all_succeed_journal_order | implemented |
| spec-002 | T009.2 | owner checkpoint store | done-evidence | #1121,#1627,#1632,#1637,#1646,#1651 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/checkpoint.rs | test: checkpoint_cas_rejects_stale_version | implemented |
| spec-002 | T009.3 | saga journal store | done-evidence | #1121,#1627,#1632,#1637,#1646,#1651 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/saga.rs | test: saga_instance_lease_and_journal_roundtrip | implemented |
| spec-002 | T009.4 | saga executor resume compensation | done-evidence | #1121,#1627,#1632,#1637,#1646,#1651 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/saga/tests.rs | test: resume_from_step2_checkpoint_skips_step1 | implemented |
| spec-002 | T009.5 | saga topology resolver | done-evidence | #1121,#1627,#1632,#1637,#1646,#1651 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/bootstrap/src/sagaprojectiondeps.rs | test: durable_shared_with_postgres_and_redis_urls_resolves_durable | implemented |
| spec-002 | T009.6 | saga dead-letter telemetry | done-evidence | #1121,#1627,#1632,#1637,#1646,#1651 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/saga/tests.rs | test: compensation_failure_logs_fields | implemented |
| spec-002 | T009.7 | saga worker health | done-evidence | #1121,#1627,#1632,#1637,#1646,#1651 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/saga_worker.rs | test: worker_shutdown_marks_health_unhealthy | implemented |
| spec-002 | T009.8 | saga contract governance | done-evidence | #1121,#1627,#1632,#1637,#1646,#1651 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/contract/validate.rs | gate: saga contract | implemented |
| spec-002 | T010.1 | projection replay red tests | done-evidence | #1122,#1347,#1620,#1628,#1635,#1638 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/projection.rs | test: shadow_replay_journey_keeps_active_pointer_until_swap_and_rollback | implemented |
| spec-002 | T010.2 | append-only projection schema | done-evidence | #1122,#1347,#1620,#1628,#1635,#1638 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/projection_events.rs | test: projection_events_migration_append_only_and_no_rls | implemented |
| spec-002 | T010.3 | projection runner checkpoint | done-evidence | #1122,#1347,#1620,#1628,#1635,#1638 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/projection.rs | test: resume_skips_consumed_prefix | implemented |
| spec-002 | T010.4 | projection append-only gate | done-evidence | #1122,#1347,#1620,#1628,#1635,#1638 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | lints/rss_projection_append_only/src/lib.rs | gate: projection append-only | implemented |
| spec-002 | T010.5 | projection revoke grant symmetry | done-evidence | #1122,#1347,#1620,#1628,#1635,#1638 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/projection_events.rs | test: projection_events_migration_append_only_and_no_rls | implemented |
| spec-002 | T010.6 | projection rebuild proof | done-evidence | #1122,#1347,#1620,#1628,#1635,#1638 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/projection.rs | test: shadow_replay_journey_keeps_active_pointer_until_swap_and_rollback | implemented |
| spec-002 | T011.1 | reconcile fencing red tests | done-evidence | #1123,#1621,#1629,#1636,#1640 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/reconcile.rs | test: reconcile_worker_records_transient_attempt_result | implemented |
| spec-002 | T011.2 | leader elector fenced writer | done-evidence | #1123,#1621,#1629,#1636,#1640 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/reconcile.rs | test: migration_locks_reconcile_rls_and_cas_predicates | implemented |
| spec-002 | T011.3 | reconcile loop harness | done-evidence | #1123,#1621,#1629,#1636,#1640 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/reconcile.rs | test: attempt_scope_records_action_and_command_through_single_store_call | implemented |
| spec-002 | T011.4 | reconcile governance | done-evidence | #1123,#1621,#1629,#1636,#1640 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/reconcile_outbox_command_guard.rs | gate: reconcile outbox command | implemented |
| spec-002 | T012.1 | command policy red tests | done-evidence | #1124,#1441,#1636,#1443 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/command.rs | test: register_rejects_schema_hash_mismatch_before_claim | implemented |
| spec-002 | T012.2 | command contract schema | done-evidence | #1124,#1441,#1636,#1443 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/contract/validate.rs | gate: contract validate | implemented |
| spec-002 | T012.3 | typed command dispatcher | done-evidence | #1124,#1441,#1636,#1443 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/command.rs | test: register_decodes_typed_and_acks | implemented |
| spec-002 | T012.4 | command generated wrappers | done-evidence | #1124,#1441,#1636,#1443 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/codegen.rs | test: command_glue_with_wrappers_emitted | implemented |
| spec-002 | T012.5 | command symmetry governance | done-evidence | #1124,#1441,#1636,#1443 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/command_symmetry.rs | gate: command-symmetry | implemented |
| rewrite | P0.a | declaration model governance codegen and boundary gates | done-evidence | #1614,#1615,#1438,#1441,#1442,#1443 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/contract/validate.rs | gate: contract validate and topology | implemented for the contract and persistence boundary slice |
| rewrite | P0.b | scaffold CLI filesystem helpers examples and full package inventory | out-of-scope | - | no | - | - | - | - | Rewrite tooling and example inventory beyond persistence governance are outside this ledger |
| rewrite | P1.a | consistency kernel primitives | done-evidence | #1114,#1115,#1617,#1618,#1619,#1620,#1621 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/verify.rs | gate: workspace verify | implemented for persistence consistency primitives |
| rewrite | P1.b | clock lifecycle health FSM circuit breaker crypto authz context and redaction primitives | out-of-scope | - | no | - | - | - | - | Broader kernel primitives are outside persistence carry-over and retain their own current governance |
| rewrite | P2.a | composition root and module bundles | done-evidence | #1422,#1423,#1424,#1425,#1431 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/runtime_deps_guard.rs | gate: runtime dependencies | implemented |
| rewrite | P2.b | postgres runtime module single export | absorbed-by | #1541 | yes | - | - | - | - | Existing open leaf owns the remaining module export hardening |
| rewrite | P2.c | listener HTTP middleware auth and observability skeleton | out-of-scope | - | no | - | - | - | - | HTTP listener authentication and general observability are outside persistence carry-over |
| rewrite | P3.a | L1 L2 durable event spine | done-evidence | #1116,#1117,#1118,#1119,#1120,#1434,#1435,#1437 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/relay.rs | test: relay_tick_recovers_to_healthy_after_clean_round | implemented |
| rewrite | P3.b | postgres migration and approved persistence helper governance | done-evidence | #1116,#1423,#1426 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/migrations.rs | gate: cargo xtask migrations | implemented for the persistence adapter slice |
| rewrite | P3.c | AEAD field protection providers | done-evidence | #1479 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/vault/src/transit.rs | test: encrypt_sends_context_not_associated_data_and_encodes_key_path | implemented by the Vault Transit PBI leaf |
| rewrite | P3.d | cross-cell SPIFFE identity package | out-of-scope | - | no | - | - | - | - | Cross-cell mTLS and SPIFFE identity are outside persistence carry-over |
| rewrite | P4 | identity audit tracking journey | done-evidence | #1100,#1433,#1634,#1641 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | journeys/tests/identity_login_audit_durable_journey.rs | test: login_audit_durable_topology | implemented |
| rewrite | P5.a | durable settings cell | done-evidence | #1249,#1430,#1433 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/settings/src/application.rs | test: publish_config_creates_v1_and_emits | implemented |
| rewrite | P5.b | all remaining business cells | out-of-scope | - | no | - | - | - | - | Complete business-domain rollout is outside persistence carry-over |
| rewrite | P6.a | saga and projection L3 harness | done-evidence | #1121,#1122,#1627,#1628,#1632,#1635,#1637,#1638,#1646,#1651 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/saga/tests.rs | test: run_three_steps_all_succeed_journal_order | implemented |
| rewrite | P6.b | projection system execution identity | needs-issue | #1714 | no | #1714 | - | - | - | New PBI created and linked to #1644 |
| rewrite | P6.c | distinct saga terminal outcomes | needs-issue | #1718 | no | #1718 | - | - | - | New PBI created and linked to #1644 |
| rewrite | P7.a | reconcile and command L4 spine | done-evidence | #1123,#1124,#1629,#1636,#1640 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/reconcile.rs | test: attempt_scope_records_action_and_command_through_single_store_call | implemented |
| rewrite | P7.b | event-driven targeted reconcile | absorbed-by | #1221 | yes | - | - | - | - | Existing open leaf owns event-driven trigger delivery |
| rewrite | P7.c | reconcile system producer identity | needs-issue | #1715 | no | #1715 | - | - | - | New PBI created and linked to #1644 |
| rewrite | P7.d | durable device command queue | needs-issue | #1716 | no | #1716 | - | - | - | New PBI created and linked to #1644 |
| rewrite | P7.e | device command runtime and sweeper | needs-issue | #1717 | no | #1717 | - | - | - | New PBI created and linked to #1644 |
| rewrite | P7.f | certificate signing lifecycle soft CA and device identity enrollment | out-of-scope | - | no | - | - | - | - | Full PKI and device onboarding are outside persistence carry-over |
| rewrite | P7.g | MQTT device transport and broader framework-owned device contracts | out-of-scope | - | no | - | - | - | - | Full MQTT and device-domain rollout are outside persistence carry-over |
| rewrite | P8.a | durable topology and event operations | done-evidence | #1251,#1434,#1440,#1442,#1642 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/event_transport_guard.rs | gate: event transport and ops runbook | implemented |
| rewrite | P8.b | complete MQTT and external adapter rollout | out-of-scope | - | no | - | - | - | - | Full external adapter inventory is outside persistence carry-over |
| rewrite | P8.c | cross-cell mTLS registry syscore corebundle and examples | out-of-scope | - | no | - | - | - | - | Multi-process identity registry system domains bundles and examples are outside persistence carry-over |
| gap-006 | P0-1 | EST device enrollment frontend | out-of-scope | - | no | - | - | - | - | Full PKI and device onboarding are outside persistence carry-over |
| gap-006 | P0-2 | certificate issuance revocation and CRL | out-of-scope | - | no | - | - | - | - | Full PKI is outside persistence carry-over |
| gap-006 | P0-3 | credential invalidation protocol | out-of-scope | - | no | - | - | - | - | Credentials and ABAC are outside persistence carry-over |
| gap-006 | P0-4 | opaque refresh token lineage | out-of-scope | - | no | - | - | - | - | HTTP credential lifecycle is outside persistence carry-over |
| gap-006 | P0-5 | credential fence capability | out-of-scope | - | no | - | - | - | - | Credentials and authorization are outside persistence carry-over |
| gap-006 | P0-6 | ABAC PDP decision semantics | out-of-scope | - | no | - | - | - | - | Credentials and ABAC are outside persistence carry-over |
| gap-006 | P0-7 | runtime contract registry control plane | out-of-scope | - | no | - | - | - | - | Registry control-plane breadth is outside persistence carry-over |
| gap-006 | P0-8 | audit HMAC chain protocol | out-of-scope | - | no | - | - | - | - | Complete audit business capability is outside persistence carry-over |
| gap-006 | P0-9 | fenced writer and serving pool role | done-evidence | #1437,#1579,#1629,#1636,#1443 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/tenancy_closeout.rs | gate: tenancy-closeout and reconcile-command guard | implemented |
| gap-006 | P1-1 | HTTP idempotency middleware | out-of-scope | - | no | - | - | - | - | HTTP middleware and idempotency are explicitly outside scope |
| gap-006 | P1-2 | authentication HTTP middleware | out-of-scope | - | no | - | - | - | - | HTTP credentials are explicitly outside scope |
| gap-006 | P1-3.a | durable device command store schema and quota | needs-issue | #1716 | no | #1716 | - | - | - | New PBI created and linked to #1644 |
| gap-006 | P1-3.b | command attempts timeout and sweeper runtime | needs-issue | #1717 | no | #1717 | - | - | - | New PBI created and linked to #1644 |
| gap-006 | P1-4 | certificate lifecycle control plane | out-of-scope | - | no | - | - | - | - | Full PKI is explicitly outside scope |
| gap-006 | P1-5 | projection system execution context | needs-issue | #1714 | no | #1714 | - | - | - | New PBI created and linked to #1644 |
| gap-006 | P1-6 | reconcile system producer identity | needs-issue | #1715 | no | #1715 | - | - | - | New PBI created and linked to #1644 |
| gap-006 | P1-7 | webhook dispatcher and receiver | out-of-scope | - | no | - | - | - | - | Webhook capability is explicitly outside scope |
| gap-006 | P1-8 | MQTT requeue and application DLT | out-of-scope | - | no | - | - | - | - | Full MQTT adapter is explicitly outside scope |
| gap-006 | P1-9 | field protection and Vault envelope encryption | done-evidence | #1479 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/vault/src/transit.rs | test: encrypt_sends_context_not_associated_data_and_encodes_key_path | implemented by the Vault Transit PBI leaf |
| gap-006 | P1-10 | PII scrubbing funnel | out-of-scope | - | no | - | - | - | - | Complete observability redaction capability is outside persistence carry-over |
| gap-006 | P1-11 | signed cursor | out-of-scope | - | no | - | - | - | - | HTTP query authorization is outside persistence carry-over |
| gap-006 | P1-12 | account lockout | out-of-scope | - | no | - | - | - | - | Credential business logic is outside persistence carry-over |
| gap-006 | P1-13 | RBAC session synchronization | out-of-scope | - | no | - | - | - | - | Credentials ABAC and gRPC auth are outside persistence carry-over |
| gap-006 | P2-1.a | saga retry timeout and heartbeat policy | done-evidence | #1627,#1632,#1637,#1646,#1651 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/saga/tests.rs | test: policy_retries_forward_action_until_success_within_budget | implemented except distinct terminals |
| gap-006 | P2-1.b | Expired and CompensationFailed terminal distinction | needs-issue | #1718 | no | #1718 | - | - | - | New PBI created and linked to #1644 |
| gap-006 | P2-2.a | projection shadow replay control state CLI and atomic swap | done-evidence | #1638 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/projection_control.rs | test: shadow_checkpoint_must_catch_up_to_source_high_water | implemented by the closed rebuild control leaf |
| gap-006 | P2-2.b | projection replay lag and rebuild duration runtime metrics | absorbed-by | #1684 | yes | - | - | - | - | Existing open observability leaf owns the metrics that are not currently exported |
| gap-006 | P2-2.c | HTTP admin rebuild endpoint | out-of-scope | - | no | - | - | - | - | The shipped CLI is the bounded control surface; an HTTP admin endpoint is outside persistence carry-over |
| gap-006 | P2-2.d | GoCell Stop Reset Replay Catchup Phase enum and nonblocking Phase API | out-of-scope | - | no | - | - | - | - | Pre-GA Rust deliberately replaced the compatibility Phase API with typed shadow replay status and CLI control state |
| gap-006 | P2-3 | certificate renewal lifecycle | out-of-scope | - | no | - | - | - | - | Full PKI and device lifecycle are outside scope |
| gap-006 | P2-4 | distributed lock SPIFFE topology | out-of-scope | - | no | - | - | - | - | OPA SPIFFE and cross-cell topology are outside scope |
| gap-006 | P2-5.a | consumer receipt lease renewal | done-evidence | #1213,#1631 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/inbox.rs | test: extend_held_then_lost_on_takeover | implemented |
| gap-006 | P2-5.b | direct emitter loss-rate tracker | out-of-scope | - | no | - | - | - | - | Direct fail-open emitter is not part of the durable persistence path |
| gap-006 | P2-6.a | consistency backlog and settle metrics | done-evidence | #1625,#1642 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/relay_metrics.rs | test: metrics_facade_emits_publish_and_dlx_on_reject | implemented |
| gap-006 | P2-6.b | full observability adapters and endpoints | out-of-scope | - | no | - | - | - | - | Complete observability adapter inventory is outside scope |
| gap-006 | P2-7.a | event and command contract codegen | done-evidence | #1438,#1441,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/contract/validate.rs | gate: contract topology and command symmetry | implemented |
| gap-006 | P2-7.b | gRPC shared schema and TypeScript emitters | out-of-scope | - | no | - | - | - | - | gRPC and external codegen inventory are outside scope |
| gap-006 | P2-8 | cancellation key derivation and Redis cluster | out-of-scope | - | no | - | - | - | - | External adapters and auth keying are outside scope |
| schedule-607 | #991 | rewrite portfolio epic | out-of-scope | - | no | - | - | - | - | Portfolio container is provenance and #1644 is the current carry-over epic |
| schedule-607 | #999 | original tracking bullet | out-of-scope | - | no | - | - | - | - | Historical tracking bullet is not a persistence leaf |
| schedule-607 | #1000 | wide-fanout base | out-of-scope | - | no | - | - | - | - | Broad rewrite base is outside persistence carry-over |
| schedule-607 | #1002 | httpserve body | out-of-scope | - | no | - | - | - | - | HTTP surface is explicitly outside scope |
| schedule-607 | #1003 | authn body | out-of-scope | - | no | - | - | - | - | Credentials are explicitly outside scope |
| schedule-607 | #1004 | bootstrap body | out-of-scope | - | no | - | - | - | - | Broad bootstrap rollout is outside this ledger |
| schedule-607 | #1005 | eventexec umbrella | absorbed-by | #1114,#1115,#1116,#1117,#1118,#1119,#1120,#1121,#1122,#1123,#1124 | yes | - | - | - | - | Fully decomposed into the existing eventexec leaf set |
| schedule-607 | #1006 | observability body | out-of-scope | - | no | - | - | - | - | Complete observability capability is outside scope |
| schedule-607 | #1007 | distributed body | out-of-scope | - | no | - | - | - | - | Distributed topology and SPIFFE are outside scope |
| schedule-607 | #1008.a | durable device command persistence and runtime slice | needs-issue | #1716,#1717 | no | #1716,#1717 | - | - | - | Audit-created PBIs own the bounded durable queue, attempt, timeout, and sweeper slice |
| schedule-607 | #1008.b | broader device business capability | out-of-scope | - | no | - | - | - | - | Device business-domain completion beyond the durable command slice is outside persistence carry-over |
| schedule-607 | #1009 | core persistence adapters umbrella | absorbed-by | #1116,#1118,#1119 | yes | - | - | - | - | Existing postgres redis and AMQP leaves own the persistence subset |
| schedule-607 | #1010 | MQTT and soft CA adapters | out-of-scope | - | no | - | - | - | - | Full MQTT adapter and PKI are explicitly outside scope |
| schedule-607 | #1011 | remaining adapters | out-of-scope | - | no | - | - | - | - | Full external adapter inventory is explicitly outside scope |
| schedule-607 | #1012 | identity domain | out-of-scope | - | no | - | - | - | - | Complete business-domain functionality is outside scope |
| schedule-607 | #1013 | settings domain persistence | done-evidence | #1249,#1430,#1433 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/settings/src/application.rs | test: publish_config_creates_v1_and_emits | implemented |
| schedule-607 | #1014 | audit domain | out-of-scope | - | no | - | - | - | - | Complete business-domain functionality is outside scope |
| schedule-607 | #1015 | contract registry domain | out-of-scope | - | no | - | - | - | - | Registry business functionality is outside scope |
| schedule-607 | #1016 | system health domain | out-of-scope | - | no | - | - | - | - | Complete health control plane is outside scope |
| schedule-607 | #1017 | join integration umbrella | absorbed-by | #1431 | yes | - | - | - | - | Persistence module aggregation is owned by the existing leaf |
| schedule-607 | #1034 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1036 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1039 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1054 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1055 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1057 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1077 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1087 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1090 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1092 | persistence conformance follow-up | done-evidence | #1426,#1579 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/repo_scope_guard.rs | gate: repository conformance and tenancy closeout | implemented |
| schedule-607 | #1095 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1097 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1100 | durable identity audit closure | done-evidence | #1100,#1433,#1634,#1641 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | journeys/tests/identity_login_audit_durable_journey.rs | test: login_audit_durable_topology | implemented |
| schedule-607 | #1101 | event topology umbrella follow-up | absorbed-by | #1438,#1442 | yes | - | - | - | - | Existing topology leaves own the remaining persistence subset |
| schedule-607 | #1103 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1105 | approved hardening follow-up | out-of-scope | - | no | - | - | - | - | Historical generic follow-up lacks a persistence carry-over atom |
| schedule-607 | #1109 | identity follow-up | out-of-scope | - | no | - | - | - | - | Complete identity business functionality is outside scope |
| schedule-607 | #1110 | identity follow-up | out-of-scope | - | no | - | - | - | - | Complete identity business functionality is outside scope |
| schedule-607 | #1113 | rewrite scheduling follow-up | out-of-scope | - | no | - | - | - | - | Historical scheduling item is not a persistence capability atom |
| schedule-607 | #1114 | consistency L0-L2 | done-evidence | #1114 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/outbox.rs | test: disposition_as_label_distinct | implemented |
| schedule-607 | #1115 | consistency L3-L4 | done-evidence | #1115 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/saga.rs | test: saga_definition_rejects_empty_invalid_and_duplicate_steps | implemented |
| schedule-607 | #1116 | postgres persistence base | done-evidence | #1116 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/lib.rs | test: pg_store_guard_shutdown_lazy_pool_ok | implemented |
| schedule-607 | #1117 | durable outbox and relay | done-evidence | #1117 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/relay.rs | test: relay_tick_recovers_to_healthy_after_clean_round | implemented |
| schedule-607 | #1118 | inbox idempotency | done-evidence | #1118 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/inbox.rs | test: concurrent_try_claim_same_receipt_single_fresh_winner | implemented |
| schedule-607 | #1119 | AMQP transport | done-evidence | #1119 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/amqp/tests/integration.rs | test: integration_publish_subscribe_roundtrip | implemented |
| schedule-607 | #1120 | consumer and DLX | done-evidence | #1120 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/consumer.rs | test: tc1_handler_ack_commit_once_no_dlx | implemented |
| schedule-607 | #1121 | saga runtime | done-evidence | #1121 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/saga/tests.rs | test: run_three_steps_all_succeed_journal_order | implemented |
| schedule-607 | #1122 | projection runtime | done-evidence | #1122 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/projection.rs | test: shadow_replay_journey_keeps_active_pointer_until_swap_and_rollback | implemented |
| schedule-607 | #1123 | reconcile runtime | done-evidence | #1123 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/reconcile.rs | test: attempt_scope_records_action_and_command_through_single_store_call | implemented |
| schedule-607 | #1124 | command runtime | done-evidence | #1124 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/command.rs | test: register_decodes_typed_and_acks | implemented |
| schedule-607 | #1131 | platform infrastructure feature | out-of-scope | - | no | - | - | - | - | Platform engineering container is explicitly outside scope |
| schedule-607 | #1132 | CI verification lane | out-of-scope | - | no | - | - | - | - | CI and deployment are explicitly outside scope |
| schedule-607 | #1133 | supply-chain security lane | out-of-scope | - | no | - | - | - | - | CI and supply-chain automation are explicitly outside scope |
| schedule-607 | #1134 | server container image | out-of-scope | - | no | - | - | - | - | CI and deployment are explicitly outside scope |
| schedule-607 | #1135 | Kubernetes and Helm | out-of-scope | - | no | - | - | - | - | CI and deployment are explicitly outside scope |
| schedule-607 | #1136 | contract testkit | done-evidence | #1435 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/testkit/tests/harness.rs | test: ok_response_deserializes_into_typed_schema | implemented for persistence eventing |
| schedule-607 | #1137.a | postgres container-backed integration harness | done-evidence | #1137 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/integration_tests.rs | test: pool_connects_and_shuts_down | implemented by the closed integration-harness leaf |
| schedule-607 | #1137.b | redis container-backed integration harness | done-evidence | #1137 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/redis/tests/integration_claimer.rs | test: integration_first_check_is_fresh_then_duplicate | implemented by the closed integration-harness leaf |
| schedule-607 | #1137.c | rabbitmq container-backed integration harness | done-evidence | #1137 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/amqp/tests/integration.rs | test: integration_publish_subscribe_roundtrip | implemented by the closed integration-harness leaf |
| schedule-607 | #1138 | OPA decision ADR | out-of-scope | - | no | - | - | - | - | OPA is explicitly outside scope |
| schedule-607 | #1139 | SPIFFE service identity ADR | out-of-scope | - | no | - | - | - | - | SPIFFE is explicitly outside scope |
| schedule-607 | #1140 | wire compatibility gate | out-of-scope | - | no | - | - | - | - | Wire compatibility governance is outside persistence carry-over |
| crate-mapping | 异步运行时 | tokio runtime replacement | out-of-scope | - | no | - | - | - | - | Runtime library selection is provenance rather than a persistence gap |
| crate-mapping | HTTP | axum and tower replacement | out-of-scope | - | no | - | - | - | - | HTTP middleware is explicitly outside scope |
| crate-mapping | gRPC | tonic and prost replacement | out-of-scope | - | no | - | - | - | - | gRPC and external adapters are explicitly outside scope |
| crate-mapping | 序列化/DTO | serde DTO replacement | out-of-scope | - | no | - | - | - | - | Generic DTO mapping is not a persistence carry-over gap |
| crate-mapping | 契约 codegen | contract-first Rust generation | done-evidence | #1438,#1441,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/contract/validate.rs | gate: contract validate and command symmetry | implemented |
| crate-mapping | 错误 | typed consistency error channels | done-evidence | #1114 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/error.rs | test: engine_error_kind_message_distinct | implemented |
| crate-mapping | Postgres | sqlx persistence adapter | done-evidence | #1116,#1423,#1426 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/lib.rs | test: pg_store_guard_shutdown_lazy_pool_ok | implemented |
| crate-mapping | Redis | durable idempotency and coordination adapter | done-evidence | #1118,#1623 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/redis/src/lib.rs | test: new_accepts_1ms_ttl | implemented for persistence idempotency |
| crate-mapping | AMQP / MQTT.amqp | lapin durable event transport | done-evidence | #1119,#1438,#1442 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/amqp/tests/integration.rs | test: integration_publish_subscribe_roundtrip | implemented |
| crate-mapping | AMQP / MQTT.mqtt | complete MQTT adapter | out-of-scope | - | no | - | - | - | - | Full MQTT adapter is explicitly outside scope |
| crate-mapping | 对象存储 | S3 adapter selection | out-of-scope | - | no | - | - | - | - | External object-store adapter is explicitly outside scope |
| crate-mapping | OIDC / JWT | authentication provider mapping | out-of-scope | - | no | - | - | - | - | Credentials and authentication are explicitly outside scope |
| crate-mapping | 加密 / 证书 / TLS.field-protection | field protection crypto providers | done-evidence | #1479 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/vault/src/transit.rs | test: encrypt_sends_context_not_associated_data_and_encodes_key_path | implemented by the Vault Transit PBI leaf |
| crate-mapping | 加密 / 证书 / TLS.pki | complete PKI and TLS provider | out-of-scope | - | no | - | - | - | - | Full PKI is explicitly outside scope |
| crate-mapping | 可观测性.consistency | tracing and consistency metrics | done-evidence | #1625,#1642 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/relay_metrics.rs | test: metrics_facade_emits_publish_and_dlx_on_reject | implemented for persistence eventing |
| crate-mapping | 可观测性.adapters | complete telemetry adapter inventory | out-of-scope | - | no | - | - | - | - | Complete observability adapters are explicitly outside scope |
| crate-mapping | 配置 | durable settings configuration | done-evidence | #1430,#1433 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/settings/src/application.rs | test: publish_config_creates_v1_and_emits | implemented for persistence settings |
| crate-mapping | newtype/sealed | typed persistence funnels | done-evidence | #1443,#1617,#1618 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/pg_tenant_tx_guard.rs | gate: persistence hard closeout matrix | implemented |
| crate-mapping | 测试.rstest | rstest table-driven adoption | done-evidence | #1187 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/identity/src/domain/abac.rs | test: operator_cases | implemented by the closed ABAC leaf and exercised |
| crate-mapping | 测试.mockall | mockall port mock adoption | done-evidence | #1013 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/settings/src/ports.rs | test: config_repo_impls_load_into_dyn_wrapper | historical Feature #1013 has no PBI child; retained as provenance and not represented as a leaf |
| crate-mapping | 测试.insta | insta snapshot testing adoption | out-of-scope | - | no | - | - | - | - | Workspace dependency is an inert forward reservation and no member currently adopts insta |
| code-followup | acecf759:consumer.rs:119 | historical consumer worker lifecycle anchor | absorbed-by | #1301 | yes | - | - | - | - | Current open leaf owns supervision shutdown and probe residuals |
| code-followup | acecf759:projection.rs:18 | historical projection runner anchor | done-evidence | #1628,#1635 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/eventexec/src/projection.rs | test: shadow_replay_journey_keeps_active_pointer_until_swap_and_rollback | historical anchor delivered |
| code-followup | current:consumer.rs:#1301 | consumer spawn and supervision residual | absorbed-by | #1301 | yes | - | - | - | - | Existing open leaf remains canonical; no duplicate created |
| code-followup | current:consumer_worker.rs:#1142 | worker lifecycle source comment | absorbed-by | #1301 | yes | - | - | - | - | #1142 delivered the ack seam; #1301 owns remaining lifecycle work |
| code-followup | current:reconcile.rs:#1221 | event-driven reconcile residual | absorbed-by | #1221 | yes | - | - | - | - | Existing open leaf remains canonical; no duplicate created |
| code-followup | current:cotx.rs:#1579 | serving-role transaction identity | done-evidence | #1579 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | xtask/src/tenancy_closeout.rs | gate: tenancy-closeout | implemented |
| code-followup | current:module.rs:#1541 | postgres module single export residual | absorbed-by | #1541 | yes | - | - | - | - | Existing open leaf remains canonical; no duplicate created |
| code-followup | tracker:#1406 | stalled partition diagnostics | absorbed-by | #1406 | yes | - | - | - | - | Existing open observability leaf remains canonical |
| code-followup | tracker:#1681 | device command contract journey | absorbed-by | #1681 | yes | - | - | - | - | Existing open contract leaf remains canonical and is distinct from queue runtime gaps |
| code-followup | current:publisher.rs:topology-provisioning | AMQP topology provisioning readiness barrier | out-of-scope | - | no | - | - | - | - | Code defer lifecycle stays governed by #1447; this ledger does not take over its ratchet |
| code-followup | current:0012_enable_tenant_rls.sql:dual-pool | historical dual-pool migration follow-up | done-evidence | #1579 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | assemblies/runtime/src/infra/pg.rs | test: pg_migrator_config_uses_dedicated_credentials | Implemented by the closed serving-role leaf; stale migration comment remains provenance |
| code-followup | current:integration_tests.rs:envelope-metadata | trace correlation and principal envelope fields | out-of-scope | - | no | - | - | - | - | Code defer lifecycle stays governed by #1447 and observability propagation is outside this ledger |
| code-followup | current:runtime-phase-domains.rs:audit-tail-verify | cross-tenant audit tail verification sweep | out-of-scope | - | no | - | - | - | - | Complete audit operations are explicitly outside persistence carry-over |
