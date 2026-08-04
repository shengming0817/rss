//! Identity production outbox authoring funnel (#1235 / PR #648 F1).
//!
//! Generated `identity_v1::*::emit` stays domain-agnostic (`EnvelopeSubjectId` /
//! `OutboxActor`). This module is the **identity authoring boundary**: production
//! application/ports code feeds canonical [`ids::UserId`] (or privacy-pseudonym
//! UUID for security-event) and never constructs envelope ids via the raw opaque String funnel.
//!
//! INVARIANT: IDENTITY-OUTBOX-USERID-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "pub(crate) helpers take UserId/Uuid" }.

use consistency::IdemKey;
use diport::{EnvelopeSubjectId, OpaqueActorId, OutboxActor};
use eventexec::event::{EventEncodeError, GeneratedEventEncoder, ReviewedEvent};
use generated::event::identity_v1::device_ingress_receipted::{
    self as device_ingress_receipted, IdentityDeviceIngressReceiptedPayload,
};
use generated::event::identity_v1::policy_updated::{
    self as policy_updated, IdentityPolicyUpdatedPayload,
};
use generated::event::identity_v1::role_assigned::{
    self as role_assigned, IdentityRoleAssignedPayload,
};
use generated::event::identity_v1::role_revoked::{
    self as role_revoked, IdentityRoleRevokedPayload,
};
use generated::event::identity_v1::security_event::{
    self as security_event, IdentitySecurityEventPayload,
};
use generated::event::identity_v1::session_created::{
    self as session_created, IdentitySessionCreatedPayload,
};
use vocab::TenantId;

/// Login / session-created：envelope subject + actor = canonical [`ids::UserId`].
pub(crate) async fn emit_session_created(
    payload: IdentitySessionCreatedPayload,
    tenant: TenantId,
    user_id: ids::UserId,
    idempotency_key: IdemKey,
) -> Result<ReviewedEvent, EventEncodeError> {
    session_created::emit(
        &GeneratedEventEncoder,
        payload,
        tenant,
        EnvelopeSubjectId::from_user_id(user_id),
        OutboxActor::scoped(
            vocab::PrincipalKind::User,
            OpaqueActorId::from_user_id(user_id),
            tenant,
            vocab::ScopedTenant::SelfOnly,
        ),
        idempotency_key,
    )
    .await
}

/// RBAC assign：envelope subject_id = **actor** UserId（FR-020；非 target binding subject）。
pub(crate) async fn emit_role_assigned(
    payload: IdentityRoleAssignedPayload,
    tenant: TenantId,
    actor: ids::UserId,
    actor_kind: vocab::PrincipalKind,
    idempotency_key: IdemKey,
) -> Result<ReviewedEvent, EventEncodeError> {
    role_assigned::emit(
        &GeneratedEventEncoder,
        payload,
        tenant,
        EnvelopeSubjectId::from_user_id(actor),
        OutboxActor::scoped(
            actor_kind,
            OpaqueActorId::from_user_id(actor),
            tenant,
            vocab::ScopedTenant::Tenant,
        ),
        idempotency_key,
    )
    .await
}

/// RBAC revoke：envelope subject_id = **actor** UserId。
pub(crate) async fn emit_role_revoked(
    payload: IdentityRoleRevokedPayload,
    tenant: TenantId,
    actor: ids::UserId,
    actor_kind: vocab::PrincipalKind,
    idempotency_key: IdemKey,
) -> Result<ReviewedEvent, EventEncodeError> {
    role_revoked::emit(
        &GeneratedEventEncoder,
        payload,
        tenant,
        EnvelopeSubjectId::from_user_id(actor),
        OutboxActor::scoped(
            actor_kind,
            OpaqueActorId::from_user_id(actor),
            tenant,
            vocab::ScopedTenant::Tenant,
        ),
        idempotency_key,
    )
    .await
}

/// Policy updated：envelope subject_id = **actor** UserId。
pub(crate) async fn emit_policy_updated(
    payload: IdentityPolicyUpdatedPayload,
    tenant: TenantId,
    actor: ids::UserId,
    actor_kind: vocab::PrincipalKind,
    idempotency_key: IdemKey,
) -> Result<ReviewedEvent, EventEncodeError> {
    policy_updated::emit(
        &GeneratedEventEncoder,
        payload,
        tenant,
        EnvelopeSubjectId::from_user_id(actor),
        OutboxActor::scoped(
            actor_kind,
            OpaqueActorId::from_user_id(actor),
            tenant,
            vocab::ScopedTenant::Tenant,
        ),
        idempotency_key,
    )
    .await
}

/// Security-event：envelope subject/actor = privacy-pseudonym UUID（非 login、非 UserId 谎称）。
pub(crate) async fn emit_security_event(
    payload: IdentitySecurityEventPayload,
    tenant: TenantId,
    initiator_kind: vocab::PrincipalKind,
    target_pseudonym: uuid::Uuid,
    actor_pseudonym: uuid::Uuid,
    idempotency_key: IdemKey,
) -> Result<ReviewedEvent, EventEncodeError> {
    security_event::emit(
        &GeneratedEventEncoder,
        payload,
        tenant,
        EnvelopeSubjectId::from_uuid(target_pseudonym),
        OutboxActor::scoped(
            initiator_kind,
            OpaqueActorId::from_uuid(actor_pseudonym),
            tenant,
            vocab::ScopedTenant::SelfOnly,
        ),
        idempotency_key,
    )
    .await
}

/// Device ingress receipt: envelope subject + actor = authenticated canonical device identity.
pub(crate) async fn emit_device_ingress_receipted(
    payload: IdentityDeviceIngressReceiptedPayload,
    tenant: TenantId,
    device: ids::DeviceId,
    idempotency_key: IdemKey,
) -> Result<ReviewedEvent, EventEncodeError> {
    device_ingress_receipted::emit(
        &GeneratedEventEncoder,
        payload,
        tenant,
        EnvelopeSubjectId::from_uuid(device.as_uuid()),
        OutboxActor::scoped(
            vocab::PrincipalKind::Device,
            OpaqueActorId::from_uuid(device.as_uuid()),
            tenant,
            vocab::ScopedTenant::Tenant,
        ),
        idempotency_key,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod production_funnel_guard {
    //! Medium production-scan facet for IDENTITY-OUTBOX-USERID-FUNNEL-01.
    //! INVARIANT: IDENTITY-OUTBOX-USERID-FUNNEL-01 { level = "Medium", exec = "test", source = "code", facet = "production-scan", synthetic_red = "production_funnel_guard::synthetic_red_detects_raw_emit_outside_funnel", anti_vacuity = "production_funnel_guard::production_modules_forbid_from_opaque_and_raw_identity_emit" }.

    use std::path::{Path, PathBuf};

    fn identity_src() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("entry {}: {e}", dir.display()))
                .path();
            if path.is_dir() {
                out.extend(collect_rs_files(&path));
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
        out.sort();
        out
    }

    /// 剔除 `#[cfg(test)]` 后的 inline `mod`（对标 xtask `strip_cfg_test_modules`）。
    fn strip_cfg_test_modules(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let mut pending_attributes = Vec::new();
        let mut skipping = false;
        let mut depth = 0isize;
        for line in src.lines() {
            let trimmed = line.trim_start();
            if skipping {
                depth += brace_delta(line);
                if depth <= 0 {
                    skipping = false;
                    depth = 0;
                }
                out.push('\n');
                continue;
            }
            if !pending_attributes.is_empty() && trimmed.starts_with("#[") {
                pending_attributes.push(line);
                continue;
            }
            if !pending_attributes.is_empty()
                && matches!(trimmed.split_whitespace().next(), Some("mod" | "pub"))
                && (trimmed.starts_with("mod ") || trimmed.starts_with("pub mod "))
            {
                for _ in pending_attributes.drain(..) {
                    out.push('\n');
                }
                depth = brace_delta(line);
                skipping = depth > 0;
                out.push('\n');
                continue;
            }
            for attribute in pending_attributes.drain(..) {
                out.push_str(attribute);
                out.push('\n');
            }
            if trimmed.starts_with("#[cfg(") && trimmed.contains("test") {
                pending_attributes.push(line);
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        for attribute in pending_attributes {
            out.push_str(attribute);
            out.push('\n');
        }
        out
    }

    fn strip_line_comments(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        for line in src.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                out.push('\n');
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    fn production_source(src: &str) -> String {
        strip_line_comments(&strip_cfg_test_modules(src))
    }

    fn rel_of(path: &Path, root: &Path) -> String {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }

    const RAW_EMIT_CALLS: &[&str] = &[
        "session_created::emit(",
        "role_assigned::emit(",
        "role_revoked::emit(",
        "policy_updated::emit(",
        "security_event::emit(",
        "device_ingress_receipted::emit(",
    ];

    const FORBIDDEN_OUTSIDE_FUNNEL: &[&str] = &[
        "from_opaque",
        "EnvelopeSubjectId::from_uuid",
        "OpaqueActorId::from_uuid",
        "EnvelopeSubjectId::from_user_id",
        "OpaqueActorId::from_user_id",
    ];

    #[test]
    fn synthetic_red_detects_raw_emit_outside_funnel() {
        let bait = "fn leak() { session_created::emit(payload, tenant, actor); }";
        assert!(
            RAW_EMIT_CALLS.iter().any(|needle| bait.contains(needle)),
            "bait must exercise a raw generated emit call"
        );
        assert!(
            FORBIDDEN_OUTSIDE_FUNNEL
                .iter()
                .any(|needle| "EnvelopeSubjectId::from_opaque".contains(needle)
                    || bait.contains("from_opaque")
                    || needle.contains("from_opaque")),
            "forbidden funnel tokens must remain detectable"
        );
    }

    #[test]
    fn production_modules_forbid_from_opaque_and_raw_identity_emit() {
        let root = identity_src();
        let files = collect_rs_files(&root);
        assert!(
            files.len() > 4,
            "anti-vacuity: must recurse beyond the old 4-file whitelist, got {}",
            files.len()
        );
        assert!(
            files.iter().any(|p| rel_of(p, &root) == "lib.rs"),
            "anti-vacuity: closed set must include lib.rs"
        );

        let mut production_checked = 0usize;
        for path in &files {
            let rel = rel_of(path, &root);
            let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
            let src = production_source(&raw);

            if rel == "outbox_emit.rs" {
                assert!(
                    src.contains("from_user_id") && src.contains("from_uuid"),
                    "outbox_emit must own from_user_id/from_uuid conversions"
                );
                assert!(
                    !src.contains("from_opaque"),
                    "outbox_emit production section must not mention from_opaque"
                );
                continue;
            }

            production_checked += 1;
            for needle in FORBIDDEN_OUTSIDE_FUNNEL {
                assert!(
                    !src.contains(needle),
                    "{rel} must not use {needle}; route through crate::outbox_emit"
                );
            }
            for needle in RAW_EMIT_CALLS {
                assert!(
                    !src.contains(needle),
                    "{rel} must not call {needle} directly; use crate::outbox_emit"
                );
            }
        }
        assert!(
            production_checked >= 4,
            "anti-vacuity: expected multiple production modules, got {production_checked}"
        );
    }

    fn brace_delta(line: &str) -> isize {
        line.chars().filter(|c| *c == '{').count() as isize
            - line.chars().filter(|c| *c == '}').count() as isize
    }
}
