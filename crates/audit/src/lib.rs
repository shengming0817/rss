//! audit — RSS 审计哈希链域（AuditEntry / EntryHash / 链验证）。
//!
//! 本 crate 承载审计域的核心值类型与纯计算逻辑；所有类型字段私有，只经显式构造 funnel
//! 创建——外部不可伪造，fail-closed。域类型均在 `mod domain` 内，由 dylint
//! `rss_domain_no_serialize` 守护（禁止 Serialize/Deserialize derive）。
//!
//! # 对标
//!
//! ref: sigstore/sigstore-rs src/rekor/models/log_entry.rs@main
//! 采纳：`log_index` 单调序（→ `seq`）、`verify_inclusion` 纯验证（→ `verify_chain`）。
//! 偏离：Merkle 树 → 线性哈希链；hex String → `EntryHash([u8;32])` newtype；
//!        rekor 字段全 pub → RSS 私有字段 + funnel。
//!
//! # 签名冻结（ADR-004 C8 豁免覆盖率）
//!
//! 本 crate 当前只冻结签名（函数体 = `todo!()`）；smoke test 只绑函数指针 / 构造 Copy enum，
//! 不执行任何 `todo!()` body。

#![forbid(unsafe_code)]

pub(crate) mod domain;

// ---------------------------------------------------------------------------
// smoke test（ADR-004 C8 豁免：只绑函数指针 / 构造 Copy enum，不触 todo!() body）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod smoke {
    //! build smoke：证明签名可被引用消费 + 闭值集 enum 可构造 + Send 约束。
    //! **不调用** `todo!()` body。

    use crate::domain::{
        AuditChainLink, AuditEntry, AuditEntryId, AuditError, AuditOutcome, EntryHash, ResourceRef,
        link_hash, verify_chain,
    };

    // 证明核心类型是 Send（跨 await 点传播）。
    fn _assert_send<T: Send>() {}

    #[test]
    fn audit_types_are_send() {
        _assert_send::<AuditEntry>();
        _assert_send::<AuditChainLink>();
        _assert_send::<AuditEntryId>();
        _assert_send::<EntryHash>();
        _assert_send::<ResourceRef>();
    }

    #[test]
    fn audit_outcome_enum_is_constructable_and_exhaustive() {
        let _outcome: AuditOutcome = AuditOutcome::Success;

        // 穷尽 match（non_exhaustive crate 内合法穷举）
        match _outcome {
            AuditOutcome::Success => {}
            AuditOutcome::Denied => {}
            AuditOutcome::Error => {}
        }
    }

    #[test]
    fn audit_error_enum_is_exhaustive() {
        // 穷尽 match 证明 AuditError variant 完整（crate 内）
        let e = AuditError::ChainBroken;
        match e {
            AuditError::ChainBroken => {}
            AuditError::HashMismatch => {}
            AuditError::SequenceGap => {}
            AuditError::InvalidId => {}
        }
    }

    #[test]
    fn value_type_fn_signatures_are_consumable() {
        // 绑定构造器方法 item（不调用 → 不触 todo!()；编译期锁签名）

        // AuditEntryId funnel
        let _parse: fn(&str) -> Result<AuditEntryId, AuditError> = AuditEntryId::parse;
        let _new_id: fn(uuid::Uuid) -> AuditEntryId = AuditEntryId::new;
        let _as_uuid: fn(&AuditEntryId) -> uuid::Uuid = AuditEntryId::as_uuid;
        let _ = (_parse, _new_id, _as_uuid);

        // EntryHash funnel
        let _new_hash: fn([u8; 32]) -> EntryHash = EntryHash::new;
        let _as_bytes: fn(&EntryHash) -> &[u8; 32] = EntryHash::as_bytes;
        let _ = (_new_hash, _as_bytes);

        // ResourceRef funnel（impl Into<String> → 用 String 实例化 fn ptr）
        let _new_ref: fn(String, String) -> ResourceRef = ResourceRef::new;
        let _kind: fn(&ResourceRef) -> &str = ResourceRef::kind;
        let _id_fn: fn(&ResourceRef) -> &str = ResourceRef::id;
        let _ = (_new_ref, _kind, _id_fn);

        // AuditChainLink funnel
        let _new_link: fn(u64, EntryHash, EntryHash) -> AuditChainLink = AuditChainLink::new;
        let _chain_seq: fn(&AuditChainLink) -> u64 = AuditChainLink::seq;
        let _chain_prev_hash: fn(&AuditChainLink) -> &EntryHash = AuditChainLink::prev_hash;
        let _chain_entry_hash: fn(&AuditChainLink) -> &EntryHash = AuditChainLink::entry_hash;
        let _ = (_new_link, _chain_seq, _chain_prev_hash, _chain_entry_hash);
    }

    #[test]
    fn pure_logic_fn_signatures_are_consumable() {
        // 绑定自由函数指针（不调用 → 不触 todo!()）
        let _link: fn(&EntryHash, &AuditEntry) -> EntryHash = link_hash;
        let _verify: fn(&[AuditEntry]) -> Result<(), AuditError> = verify_chain;
        let _ = (_link, _verify);
    }

    #[test]
    fn audit_entry_accessor_signatures_are_consumable() {
        // 绑定 AuditEntry 全量 accessor 方法 item（不调用 → 不触 todo!()；编译期锁签名）

        // 构造器（含新增 tenant 位参）
        #[allow(clippy::type_complexity)]
        let _new: fn(
            u64,
            EntryHash,
            EntryHash,
            ids::UserId,
            authn::PrincipalKind,
            vocab::TenantId,
            vocab::Action,
            ResourceRef,
            AuditOutcome,
            std::time::SystemTime,
        ) -> AuditEntry = AuditEntry::new;
        let _ = _new;

        // 全量 accessor
        let _seq: fn(&AuditEntry) -> u64 = AuditEntry::seq;
        let _prev_hash: fn(&AuditEntry) -> &EntryHash = AuditEntry::prev_hash;
        let _entry_hash: fn(&AuditEntry) -> &EntryHash = AuditEntry::entry_hash;
        let _actor: fn(&AuditEntry) -> ids::UserId = AuditEntry::actor;
        let _actor_kind: fn(&AuditEntry) -> authn::PrincipalKind = AuditEntry::actor_kind;
        let _action: fn(&AuditEntry) -> &vocab::Action = AuditEntry::action;
        let _resource: fn(&AuditEntry) -> &ResourceRef = AuditEntry::resource;
        let _outcome: fn(&AuditEntry) -> AuditOutcome = AuditEntry::outcome;
        let _recorded_at: fn(&AuditEntry) -> std::time::SystemTime = AuditEntry::recorded_at;
        let _tenant: fn(&AuditEntry) -> vocab::TenantId = AuditEntry::tenant;
        let _ = (
            _seq,
            _prev_hash,
            _entry_hash,
            _actor,
            _actor_kind,
            _action,
            _resource,
            _outcome,
            _recorded_at,
            _tenant,
        );
    }
}
