//! contractreg — RSS 运行时契约登记域。
//!
//! 本 crate 管理契约元数据的运行时登记（id / kind / status / consistency_level / owner），
//! 提供 lifecycle 状态机迁移守护与元数据完整性校验。
//! DI port（仓储 / 发布订阅）归 `diport`（ADR-003）；契约单一事实源是 `contract.toml`。
//!
//! # 模块布局
//!
//! - `domain` —— 域类型与纯逻辑（dylint 守护区，禁 derive Serialize）
//!
//! # 签名冻结（ADR-004 C8 豁免覆盖率）
//!
//! 本 crate 当前只冻结签名（函数体 = `todo!()`）；smoke test 只绑函数指针 / 构造 Copy enum，
//! 不执行任何 `todo!()` body。
//!
//! ref: casbin/casbin-rs src/model/mod.rs@master（命名空间 (domain,kind,version) + lifecycle 状态机）。

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
        ConsistencyLevel, ContractId, ContractKind, ContractRecord, ContractRegError,
        ContractStatus, can_transition, validate_metadata,
    };

    fn _assert_send<T: Send>() {}

    #[test]
    fn error_enum_is_send() {
        _assert_send::<ContractRegError>();
    }

    #[test]
    fn contract_kind_enum_is_constructable_and_exhaustive() {
        let _kind = ContractKind::Http;
        match _kind {
            ContractKind::Http => {}
            ContractKind::Event => {}
            ContractKind::Command => {}
            ContractKind::Saga => {}
        }
    }

    #[test]
    fn contract_status_enum_is_constructable_and_exhaustive() {
        let _status = ContractStatus::Draft;
        match _status {
            ContractStatus::Draft => {}
            ContractStatus::Active => {}
            ContractStatus::Deprecated => {}
            ContractStatus::Retired => {}
        }
    }

    #[test]
    fn consistency_level_enum_is_constructable_and_exhaustive() {
        let _lvl = ConsistencyLevel::L0;
        match _lvl {
            ConsistencyLevel::L0 => {}
            ConsistencyLevel::L1 => {}
            ConsistencyLevel::L2 => {}
            ConsistencyLevel::L3 => {}
            ConsistencyLevel::L4 => {}
        }
    }

    #[test]
    fn contract_reg_error_enum_is_exhaustive() {
        let e = ContractRegError::IdInvalid;
        match e {
            ContractRegError::IdInvalid => {}
            ContractRegError::IllegalTransition => {}
            ContractRegError::MetadataInvalid => {}
        }
    }

    #[test]
    fn pure_logic_fn_signatures_are_consumable() {
        // 绑定函数指针（不调用 → 不触 todo!()）
        let _can: fn(ContractStatus, ContractStatus) -> bool = can_transition;
        let _ = _can;

        let _validate: fn(&ContractRecord) -> Result<(), ContractRegError> = validate_metadata;
        let _ = _validate;

        let _parse: fn(&str) -> Result<ContractId, ContractRegError> = ContractId::parse;
        let _ = _parse;

        let _new: fn(
            ContractId,
            assembly_schema::ContractOwner,
            ContractKind,
            ContractStatus,
            ConsistencyLevel,
        ) -> ContractRecord = ContractRecord::new;
        let _ = _new;
    }

    #[test]
    fn contract_id_accessor_signatures_are_consumable() {
        // 绑定 ContractId accessor（不调用 → 不触 todo!()）
        let _as_str: fn(&ContractId) -> &str = ContractId::as_str;
        let _ = _as_str;
    }

    #[test]
    fn contract_record_accessor_signatures_are_consumable() {
        // 绑定 ContractRecord 全部 accessor（不调用 → 不触 todo!()）
        let _id: fn(&ContractRecord) -> &ContractId = ContractRecord::id;
        let _ = _id;

        let _owner: fn(&ContractRecord) -> &assembly_schema::ContractOwner = ContractRecord::owner;
        let _ = _owner;

        let _kind: fn(&ContractRecord) -> ContractKind = ContractRecord::kind;
        let _ = _kind;

        let _status: fn(&ContractRecord) -> ContractStatus = ContractRecord::status;
        let _ = _status;

        let _consistency_level: fn(&ContractRecord) -> ConsistencyLevel =
            ContractRecord::consistency_level;
        let _ = _consistency_level;
    }
}
