// rss_authenticated_callsite UI fixture（allowed caller）。example target 名 `runtime` ⇒
// `runtime` 是 #1309 后的唯一组合根，但 Authenticated mint 仍只允许
// `auth_bridge::{allow_evidence,mtls_evidence}` 两个精确 wrapper（AUTH-EVIDENCE-MINT-01 Medium）。
// Hard token 经 `authmint::AuthenticatedMint::capability()` 传入 production constructors。
// Principal accessor 无诊断；Authenticated main direct / nested same-name 产生 golden 诊断。
// 须用真 httpserve / vocab / primitives / authmint（dev-dep）；UI 测试只编译查诊断、不运行。
#![allow(unused)]

use httpserve::Authenticated;
use vocab::PrincipalKind;

fn main() {
    let _ev = auth_bridge::allow_evidence();
    let _mtls = auth_bridge::mtls_evidence();
    operator::projection::verified_service_maintenance_operator();
    operator::projection::verified_projection_maintenance_operator_subject();
    operator::projection::projection_maintenance_operator_receipt();
    operator::projection::service_maintenance_operator_audit_subject();
    operator::dlq::authenticate_dlq_operator_principal();
    operator::dlq::dlq_operator_receipt();
    // R：runtime 非 verification wrapper 不能降维 Principal。
    let _direct_subject = authn::Principal::audit_subject;
    let _direct_caller = authn::Principal::service_caller_domain;
    // R：runtime 组合根中的任意其它函数也不能 mint evidence。
    let _direct = Authenticated::new_federated(
        authmint::AuthenticatedMint::capability(),
        PrincipalKind::User,
        "subject-1",
        None,
        permissions(),
    );
    let _direct_rss = Authenticated::new_rss_user(
        authmint::AuthenticatedMint::capability(),
        "11111111-2222-4333-8444-555555555555",
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
    );
    let _direct_service = Authenticated::new_service(
        authmint::AuthenticatedMint::capability(),
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
        Authenticated::new_federated(
            authmint::AuthenticatedMint::capability(),
            PrincipalKind::User,
            "subject-1",
            None,
            crate::permissions(),
        )
    }

    pub fn mtls_evidence() -> Authenticated {
        Authenticated::new_mtls(authmint::AuthenticatedMint::capability(), "mtls-peer")
    }
}

mod operator {
    pub(super) mod projection {
        pub(crate) fn verified_service_maintenance_operator() {
            let _ = authn::Principal::service_caller_domain;
        }

        pub(crate) fn verified_projection_maintenance_operator_subject() {
            let _ = authn::Principal::service_caller_domain;
        }

        pub(crate) fn projection_maintenance_operator_receipt() {
            let _ = authn::Principal::audit_subject;
        }

        pub(crate) fn service_maintenance_operator_audit_subject() {
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
        verified_service_maintenance_operator();
    }

    fn allow_evidence() -> Authenticated {
        let _ = authn::Principal::audit_subject;
        Authenticated::new_federated(
            authmint::AuthenticatedMint::capability(),
            PrincipalKind::User,
            "subject-1",
            None,
            crate::permissions(),
        )
    }

    fn verified_service_maintenance_operator() {
        let _ = authn::Principal::service_caller_domain;
    }
}

fn permissions() -> &'static diport::VerifiedFederatedPermissions {
    unimplemented!()
}
