//! postgres adapter 集成测试（crate-internal；需真实 postgres，`integration` feature 门控；#1116 review F2/F5/F6）。
//!
//! crate-internal（非 `tests/`）；global fixture setup 可使用本 module 子树的 private support，
//! tenant production operations 必须经过真实 exact-lane `TenantDb` funnel。
//! 本 adapter 的 migration/permission tests 始终使用 fixture-owned PostgreSQL；外部 PG 不具备
//! migration 或 role-mutation capability。
//! （严格库名，单源校验在 testkit）。需 docker（容器路径）。跑 `cargo nextest run -p postgres --features integration`。
//!
//! **fail-closed（review F5/F6）**：连不上 → 测试**失败**（非静默跳过）；
//! external opt-in 由 owned fixture 入口在 SQL 前明确拒绝。
//! 连接配置由 [`crate::test_pg::connect_pg`] 统一管理，不在各测试内分散。

mod audit_persistence_tests;
mod command_journal_tests;
mod device_certificate_tests;
mod identity_persistence_tests;
mod inbox_consumer_tests;
mod migrations_tests;
mod outbox_tests;
mod pool_runtime_tests;
mod projection_events_tests;
mod provider_conformance_tests;
mod readiness_tests;
mod reconcile_tests;
mod revocation_tests;
mod saga_tests;
mod settings_persistence_tests;
mod settings_projection_tests;
mod support;
mod tenant_rls_tests;
mod transaction_tests;
