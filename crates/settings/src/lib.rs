//! settings — RSS 版本化配置与 feature flag 域。
//!
//! 本 crate 承载配置条目（`ConfigEntry`）与 feature flag（`FlagState`/`FlagDecision`）的核心值类型与
//! 纯逻辑（`domain`）、版本化配置 CRUD/CAS + 发布/回滚 + flag 求值编排（`application`）、域形配置仓储
//! DI port（`ports::ConfigRepo`，ADR-005 Option 2）与域内 in-mem 实现（`internal`）。所有域类型字段私有，
//! 只经显式构造 funnel 创建——外部不可伪造（ADR-001）。
//!
//! # 实现状态（RW-W 行为，issue #1013）
//!
//! 签名冻结（G0）已补真实行为：`domain` newtype 校验 / `diff` / `evaluate_flag`（全 11 operator + 百分比
//! 分桶）；`application` 经 in-mem `Publisher`（L2 OutboxFact）打通配置发布/回滚接缝。真实持久化（postgres
//! adapter impl [`ports::ConfigRepo`]）+ axum 挂载留 Join。`smoke` 保留为签名冻结回归（绑函数指针锁签名）。
//!
//! # 对标
//!
//! ref: Unleash/unleash-types-rs src/client_features.rs@main
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main

#![forbid(unsafe_code)]

mod application;
pub(crate) mod domain;
mod internal;
pub mod ports;

pub use application::{
    SETTINGS_ROUTE_PREFIX, SettingsDomain, SettingsService, SettingsServiceError,
};

// ---------------------------------------------------------------------------
// smoke test（ADR-004 C8 豁免：只绑函数指针 / 构造 Copy enum，不触 todo!() body）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod smoke {
    //! crate-level build smoke：证明签名可被引用消费 + 闭值集 enum 可构造 + Send 约束。
    //! **不调用** `todo!()` body。

    use crate::domain::{
        ConfigDelta, ConfigEntry, ConfigValue, ConfigVersion, EvalContext, FlagDecision, FlagKey,
        FlagState, RolloutOperator, RolloutPercentage, RolloutRule, SettingKey, SettingsError,
        diff, evaluate_flag,
    };
    use vocab::TenantId;

    // 证明核心类型是 Send（跨 await 点传播）。
    fn _assert_send<T: Send>() {}

    #[test]
    fn domain_types_are_send() {
        _assert_send::<FlagState>();
        _assert_send::<ConfigEntry>();
        _assert_send::<EvalContext>();
    }

    #[test]
    fn rollout_operator_enum_is_constructable_and_exhaustive() {
        let _op: RolloutOperator = RolloutOperator::In;

        // 穷尽 match（non_exhaustive crate 内合法穷举）
        match _op {
            RolloutOperator::In => {}
            RolloutOperator::NotIn => {}
            RolloutOperator::StrStartsWith => {}
            RolloutOperator::StrEndsWith => {}
            RolloutOperator::StrContains => {}
            RolloutOperator::NumInRange => {}
            RolloutOperator::SemVerGte => {}
            RolloutOperator::SemVerLte => {}
            RolloutOperator::DateAfter => {}
            RolloutOperator::DateBefore => {}
            RolloutOperator::Unknown => {}
        }
    }

    #[test]
    fn flag_decision_enum_is_constructable_and_exhaustive() {
        let _d: FlagDecision = FlagDecision::Enabled;

        match _d {
            FlagDecision::Enabled => {}
            FlagDecision::Disabled => {}
        }
    }

    #[test]
    fn settings_error_enum_is_exhaustive() {
        let e = SettingsError::KeyInvalid;
        match e {
            SettingsError::KeyInvalid => {}
            SettingsError::PercentageOutOfRange => {}
            SettingsError::VersionConflict => {}
        }
    }

    #[test]
    fn config_delta_enum_is_constructable() {
        let _d = ConfigDelta::Unchanged;
        // ValueChanged 字段类型为 ConfigValue（F3：redacted Debug 传导）。
        // ConfigValue::new 是 todo!()，不直接构造——用闭包类型签名绑定字段类型，不执行 body。
        let _check_type: fn(ConfigValue, ConfigValue) -> ConfigDelta =
            |old, new| ConfigDelta::ValueChanged { old, new };
        let _ = _check_type;
        let _d3 = ConfigDelta::KeyMismatch;
    }

    #[test]
    fn value_type_fn_signatures_are_consumable() {
        // 绑定函数指针（不调用 → 不触 todo!()）
        let _parse_key: fn(&str) -> Result<SettingKey, SettingsError> = SettingKey::parse;
        let _parse_flag: fn(&str) -> Result<FlagKey, SettingsError> = FlagKey::parse;

        let _pct_new: fn(u16) -> Result<RolloutPercentage, SettingsError> = RolloutPercentage::new;
        let _pct_parse: fn(&str) -> Result<RolloutPercentage, SettingsError> =
            RolloutPercentage::parse;

        // evaluate_flag / diff 纯函数签名可绑定（显式 fn(..)->.. 断言 Hard 锁签名，漂移即编译失败）
        let _eval: fn(&FlagState, &EvalContext) -> FlagDecision = evaluate_flag;
        let _diff: fn(&ConfigEntry, &ConfigEntry) -> ConfigDelta = diff;
        let _ = (_eval, _diff);
    }

    #[test]
    fn constructor_signatures_are_consumable() {
        // ConfigValue::new 接受 impl Into<String>，用 String 实例化函数指针
        let _cv: fn(String) -> ConfigValue = ConfigValue::new;

        // ConfigVersion::new
        let _ver: fn(u64) -> ConfigVersion = ConfigVersion::new;

        // ConfigEntry::new（必填 4 参数）
        let _entry: fn(SettingKey, ConfigValue, TenantId, ConfigVersion) -> ConfigEntry =
            ConfigEntry::new;

        // RolloutRule::new（impl Into<String> 用 String 实例化）
        let _rule: fn(String, RolloutOperator, Vec<String>) -> RolloutRule = RolloutRule::new;

        // EvalContext::new
        let _ctx: fn(&[(String, String)]) -> EvalContext = EvalContext::new;

        // FlagState::new
        let _flag: fn(
            FlagKey,
            bool,
            bool,
            Vec<RolloutRule>,
            Option<RolloutPercentage>,
        ) -> FlagState = FlagState::new;
    }

    #[test]
    fn config_value_debug_is_redacted() {
        // ConfigValue 不可构造（body=todo!()），只验证 Debug impl 路径可编译（类型级检查）。
        // 实际 redact 行为在行为 PR 补充集成 smoke。
        fn _requires_debug<T: std::fmt::Debug>() {}
        _requires_debug::<ConfigValue>();
    }

    #[test]
    fn eval_context_and_rollout_rule_debug_is_redacted() {
        // EvalContext / RolloutRule 不可构造（body=todo!()），验证手写 Debug impl 编译通过
        // （类型级检查；F5：PII attrs/values 不输出原始内容）。
        fn _requires_debug<T: std::fmt::Debug>() {}
        _requires_debug::<EvalContext>();
        _requires_debug::<RolloutRule>();
    }
}
