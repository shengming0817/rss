// rss_authenticated_callsite UI fixture（allowed caller）。example target 名 `runtime` ⇒
// `runtime` 是 #1309 后的唯一组合根，但 Authenticated mint 仍只允许
// `auth_bridge::{allow_evidence,mtls_evidence}` 两个精确 wrapper。
// Principal accessor 无诊断；Authenticated main direct / nested same-name 与 settings
// capability main direct / nested same-name均产生 golden 诊断。
// 须用真 httpserve / vocab / primitives（dev-dep）；UI 测试只编译查诊断、不运行。
#![allow(unused)]

use httpserve::Authenticated;
use primitives::RequiredScheme;
use vocab::PrincipalKind;

fn main() {
    let _ev = auth_bridge::allow_evidence();
    let _mtls = auth_bridge::mtls_evidence();
    verified_service_maintenance_operator_subject();
    verified_projection_maintenance_operator_subject();
    projection_maintenance_operator_receipt();
    authenticate_dlq_operator_principal();
    dlq_operator_receipt();
    // R：runtime 非 verification wrapper 不能降维 Principal。
    let _direct_subject = authn::Principal::audit_subject;
    let _direct_caller = authn::Principal::service_caller_domain;
    // R：runtime 组合根中的任意其它函数也不能 mint evidence。
    let _direct = Authenticated::new(
        RequiredScheme::RssAccessToken,
        PrincipalKind::User,
        "subject-1",
        None,
    );
    let _direct_service = Authenticated::new_service(
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    let _config = run_settings_config_value_maintenance();
    let _direct = postgres::ConfigValueMaintenanceCapability::from_verified_service_caller(
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    nested::call_same_named_wrapper();
}

mod auth_bridge {
    use super::*;

    pub fn allow_evidence() -> Authenticated {
        let _subject = authn::Principal::audit_subject;
        let _caller = authn::Principal::service_caller_domain;
        Authenticated::new(
            RequiredScheme::RssAccessToken,
            PrincipalKind::User,
            "subject-1",
            None,
        )
    }

    pub fn mtls_evidence() -> Authenticated {
        Authenticated::new(
            RequiredScheme::Mtls,
            PrincipalKind::Service,
            "mtls-peer",
            None,
        )
    }
}

fn verified_service_maintenance_operator_subject() {
    let _ = authn::Principal::service_caller_domain;
}

fn verified_projection_maintenance_operator_subject() {
    let _ = authn::Principal::service_caller_domain;
}

fn projection_maintenance_operator_receipt() {
    let _ = authn::Principal::audit_subject;
}

fn authenticate_dlq_operator_principal() {
    let _ = authn::Principal::service_caller_domain;
}

fn dlq_operator_receipt() {
    let _ = authn::Principal::audit_subject;
    let _ = authn::Principal::service_caller_domain;
}

fn run_settings_config_value_maintenance() -> postgres::ConfigValueMaintenanceCapability {
    postgres::ConfigValueMaintenanceCapability::from_verified_service_caller(
        vocab::ServiceCallerDomain::MaintenanceOperator,
    )
}

mod nested {
    use httpserve::Authenticated;
    use primitives::RequiredScheme;
    use vocab::PrincipalKind;

    pub fn call_same_named_wrapper() {
        let _ = run_settings_config_value_maintenance();
        let _ = allow_evidence();
        verified_service_maintenance_operator_subject();
    }

    fn run_settings_config_value_maintenance() -> postgres::ConfigValueMaintenanceCapability {
        postgres::ConfigValueMaintenanceCapability::from_verified_service_caller(
            vocab::ServiceCallerDomain::MaintenanceOperator,
        )
    }

    fn allow_evidence() -> Authenticated {
        let _ = authn::Principal::audit_subject;
        Authenticated::new(
            RequiredScheme::RssAccessToken,
            PrincipalKind::User,
            "subject-1",
            None,
        )
    }

    fn verified_service_maintenance_operator_subject() {
        let _ = authn::Principal::service_caller_domain;
    }
}
