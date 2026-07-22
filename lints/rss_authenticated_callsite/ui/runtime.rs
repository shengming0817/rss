// rss_authenticated_callsite UI fixture（allowed caller）。example target 名 `runtime` ⇒
// `runtime` 是 #1309 后的唯一组合根，但 Authenticated mint 仍只允许
// `auth_bridge::{allow_evidence,mtls_evidence}` 两个精确 wrapper。
// Principal accessor 无诊断；Authenticated main direct / nested same-name 产生 golden 诊断。
// 须用真 httpserve / vocab / primitives（dev-dep）；UI 测试只编译查诊断、不运行。
#![allow(unused)]

use httpserve::Authenticated;
use vocab::PrincipalKind;

fn main() {
    let _ev = auth_bridge::allow_evidence();
    let _mtls = auth_bridge::mtls_evidence();
    let _current = auth_bridge::current_auth_grant();
    operator::projection::verified_service_maintenance_operator_subject();
    operator::projection::verified_projection_maintenance_operator_subject();
    operator::projection::projection_maintenance_operator_receipt();
    operator::dlq::authenticate_dlq_operator_principal();
    operator::dlq::dlq_operator_receipt();
    // R：runtime 非 verification wrapper 不能降维 Principal。
    let _direct_subject = authn::Principal::audit_subject;
    let _direct_caller = authn::Principal::service_caller_domain;
    // R：runtime 组合根中的任意其它函数也不能 mint evidence。
    let _direct = Authenticated::new_federated(PrincipalKind::User, "subject-1", None);
    let current = httpserve::CurrentAuthGrant::new();
    let _direct_rss = Authenticated::new_rss_user(
        current,
        "subject-1",
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
    );
    let _direct_service = Authenticated::new_service(
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    nested::call_same_named_wrapper();
}

mod auth_bridge {
    use super::*;

    pub fn allow_evidence() -> Authenticated {
        let _subject = authn::Principal::audit_subject;
        let _caller = authn::Principal::service_caller_domain;
        Authenticated::new_federated(PrincipalKind::User, "subject-1", None)
    }

    pub fn mtls_evidence() -> Authenticated {
        Authenticated::new_mtls("mtls-peer")
    }

    pub fn current_auth_grant() -> httpserve::CurrentAuthGrant {
        httpserve::CurrentAuthGrant::new()
    }
}

mod operator {
    pub(super) mod projection {
        pub(crate) fn verified_service_maintenance_operator_subject() {
            let _ = authn::Principal::service_caller_domain;
        }

        pub(crate) fn verified_projection_maintenance_operator_subject() {
            let _ = authn::Principal::service_caller_domain;
        }

        pub(crate) fn projection_maintenance_operator_receipt() {
            let _ = authn::Principal::audit_subject;
        }
    }

    pub(super) mod dlq {
        pub(crate) fn authenticate_dlq_operator_principal() {
            let _ = authn::Principal::service_caller_domain;
        }

        pub(crate) fn dlq_operator_receipt() {
            let _ = authn::Principal::audit_subject;
            let _ = authn::Principal::service_caller_domain;
        }
    }
}

mod nested {
    use httpserve::Authenticated;
    use vocab::PrincipalKind;

    pub fn call_same_named_wrapper() {
        let _ = allow_evidence();
        verified_service_maintenance_operator_subject();
    }

    fn allow_evidence() -> Authenticated {
        let _ = authn::Principal::audit_subject;
        Authenticated::new_federated(PrincipalKind::User, "subject-1", None)
    }

    fn verified_service_maintenance_operator_subject() {
        let _ = authn::Principal::service_caller_domain;
    }
}
