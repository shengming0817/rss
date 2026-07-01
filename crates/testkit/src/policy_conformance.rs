//! provider-agnostic ABAC policy store conformance helpers（#1588）。
//!
//! 本模块只表达 durable policy store 的行为断言：create/find/list/update/delete、tenant isolation、
//! active-window、malformed/unknown-field rejection、obligation round-trip。调用方用闭包适配具体
//! provider、wire/domain 类型和错误枚举；testkit 不依赖 identity 或任何 workspace 内部 domain types。

use std::fmt::Debug;
use std::future::Future;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyConformanceError {
    #[error("policy conformance: provider op failed during {stage}: {error}")]
    Provider { stage: &'static str, error: String },
    #[error("policy conformance: {stage} unexpectedly succeeded")]
    ExpectedErrorMissing { stage: &'static str },
    #[error("policy conformance: {stage} returned wrong error kind: {error}")]
    WrongErrorKind { stage: &'static str, error: String },
    #[error("policy conformance: {stage} policy mismatch; expected {expected:?}, got {actual:?}")]
    PolicyMismatch {
        stage: &'static str,
        expected: String,
        actual: String,
    },
    #[error("policy conformance: {stage} list mismatch; expected {expected:?}, got {actual:?}")]
    ListMismatch {
        stage: &'static str,
        expected: String,
        actual: String,
    },
    #[error("policy conformance: {stage} visibility mismatch; expected {expected}, got {actual}")]
    VisibilityMismatch {
        stage: &'static str,
        expected: bool,
        actual: bool,
    },
}

fn provider<E: Debug>(stage: &'static str, e: E) -> PolicyConformanceError {
    PolicyConformanceError::Provider {
        stage,
        error: format!("{e:?}"),
    }
}

fn debug_string<T: Debug>(value: &T) -> String {
    format!("{value:?}")
}

fn expect_policy<P: Debug + PartialEq>(
    stage: &'static str,
    actual: Option<P>,
    expected: Option<&P>,
) -> Result<(), PolicyConformanceError> {
    let ok = match (&actual, expected) {
        (None, None) => true,
        (Some(a), Some(e)) => a == e,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(PolicyConformanceError::PolicyMismatch {
            stage,
            expected: debug_string(&expected),
            actual: debug_string(&actual),
        })
    }
}

fn expect_list<P: Debug + PartialEq>(
    stage: &'static str,
    actual: Vec<P>,
    expected: &[P],
) -> Result<(), PolicyConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PolicyConformanceError::ListMismatch {
            stage,
            expected: debug_string(&expected),
            actual: debug_string(&actual),
        })
    }
}

fn expect_visible(
    stage: &'static str,
    actual: bool,
    expected: bool,
) -> Result<(), PolicyConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PolicyConformanceError::VisibilityMismatch {
            stage,
            expected,
            actual,
        })
    }
}

async fn expect_error<F, E, IE>(
    stage: &'static str,
    future: F,
    is_expected: &IE,
) -> Result<(), PolicyConformanceError>
where
    F: Future<Output = Result<(), E>>,
    E: Debug,
    IE: Fn(&E) -> bool,
{
    match future.await {
        Ok(()) => Err(PolicyConformanceError::ExpectedErrorMissing { stage }),
        Err(e) if is_expected(&e) => Ok(()),
        Err(e) => Err(PolicyConformanceError::WrongErrorKind {
            stage,
            error: format!("{e:?}"),
        }),
    }
}

/// Provider-specific operations and fixtures for [`assert_policy_store_lifecycle`].
pub struct PolicyLifecycleCase<T, K, P, C, F, L, U, D> {
    pub tenant: T,
    pub key: K,
    pub created_policy: P,
    pub updated_policy: P,
    pub create: C,
    pub find: F,
    pub list: L,
    pub update: U,
    pub delete: D,
}

/// create/find/list/update/delete：同租 policy 必须可 round-trip，update 覆盖 current，delete 后不可见。
pub async fn assert_policy_store_lifecycle<T, K, P, C, F, L, U, D, CF, FF, LF, UF, DF, E>(
    mut case: PolicyLifecycleCase<T, K, P, C, F, L, U, D>,
) -> Result<(), PolicyConformanceError>
where
    T: Copy + Debug,
    K: Copy + Debug,
    P: Clone + Debug + PartialEq,
    C: FnMut(T, K, P) -> CF,
    F: FnMut(T, K) -> FF,
    L: FnMut(T) -> LF,
    U: FnMut(T, K, P) -> UF,
    D: FnMut(T, K) -> DF,
    CF: Future<Output = Result<(), E>>,
    FF: Future<Output = Result<Option<P>, E>>,
    LF: Future<Output = Result<Vec<P>, E>>,
    UF: Future<Output = Result<(), E>>,
    DF: Future<Output = Result<(), E>>,
    E: Debug,
{
    (case.create)(case.tenant, case.key, case.created_policy.clone())
        .await
        .map_err(|e| provider("create policy", e))?;
    expect_policy(
        "find after create",
        (case.find)(case.tenant, case.key)
            .await
            .map_err(|e| provider("find after create", e))?,
        Some(&case.created_policy),
    )?;
    expect_list(
        "list after create",
        (case.list)(case.tenant)
            .await
            .map_err(|e| provider("list after create", e))?,
        &[case.created_policy.clone()],
    )?;

    (case.update)(case.tenant, case.key, case.updated_policy.clone())
        .await
        .map_err(|e| provider("update policy", e))?;
    expect_policy(
        "find after update",
        (case.find)(case.tenant, case.key)
            .await
            .map_err(|e| provider("find after update", e))?,
        Some(&case.updated_policy),
    )?;
    expect_list(
        "list after update",
        (case.list)(case.tenant)
            .await
            .map_err(|e| provider("list after update", e))?,
        &[case.updated_policy],
    )?;

    (case.delete)(case.tenant, case.key)
        .await
        .map_err(|e| provider("delete policy", e))?;
    expect_policy(
        "find after delete",
        (case.find)(case.tenant, case.key)
            .await
            .map_err(|e| provider("find after delete", e))?,
        None,
    )?;
    expect_list(
        "list after delete",
        (case.list)(case.tenant)
            .await
            .map_err(|e| provider("list after delete", e))?,
        &[],
    )
}

/// Provider-specific operations and fixtures for [`assert_policy_delete_leaves_tombstone`].
pub struct PolicyDeleteTombstoneCase<T, K, P, C, F, L, D, IE> {
    pub tenant: T,
    pub key: K,
    pub created_policy: P,
    pub recreated_policy: P,
    pub create: C,
    pub find: F,
    pub list: L,
    pub delete: D,
    pub is_recreate_rejected: IE,
}

/// delete must leave a tombstone: the policy disappears from active reads, but the same id cannot
/// be recreated through ordinary create and reset CAS version state.
pub async fn assert_policy_delete_leaves_tombstone<T, K, P, C, F, L, D, CF, FF, LF, DF, E, IE>(
    mut case: PolicyDeleteTombstoneCase<T, K, P, C, F, L, D, IE>,
) -> Result<(), PolicyConformanceError>
where
    T: Copy + Debug,
    K: Copy + Debug,
    P: Clone + Debug + PartialEq,
    C: FnMut(T, K, P) -> CF,
    F: FnMut(T, K) -> FF,
    L: FnMut(T) -> LF,
    D: FnMut(T, K) -> DF,
    CF: Future<Output = Result<(), E>>,
    FF: Future<Output = Result<Option<P>, E>>,
    LF: Future<Output = Result<Vec<P>, E>>,
    DF: Future<Output = Result<(), E>>,
    E: Debug,
    IE: Fn(&E) -> bool,
{
    (case.create)(case.tenant, case.key, case.created_policy.clone())
        .await
        .map_err(|e| provider("create policy before tombstone", e))?;
    (case.delete)(case.tenant, case.key)
        .await
        .map_err(|e| provider("delete policy into tombstone", e))?;

    expect_policy(
        "find after tombstone delete",
        (case.find)(case.tenant, case.key)
            .await
            .map_err(|e| provider("find after tombstone delete", e))?,
        None,
    )?;
    expect_list(
        "list after tombstone delete",
        (case.list)(case.tenant)
            .await
            .map_err(|e| provider("list after tombstone delete", e))?,
        &[],
    )?;

    expect_error(
        "recreate tombstoned policy id",
        (case.create)(case.tenant, case.key, case.recreated_policy),
        &case.is_recreate_rejected,
    )
    .await?;

    expect_policy(
        "find after rejected recreate",
        (case.find)(case.tenant, case.key)
            .await
            .map_err(|e| provider("find after rejected recreate", e))?,
        None,
    )
}

/// Provider-specific operations and fixtures for [`assert_policy_store_tenant_isolation`].
pub struct PolicyTenantIsolationCase<T, K, P, C, F, L, U, D> {
    pub tenant_a: T,
    pub tenant_b: T,
    pub key: K,
    pub tenant_a_policy: P,
    pub tenant_b_policy: P,
    pub tenant_b_updated_policy: P,
    pub create: C,
    pub find: F,
    pub list: L,
    pub update: U,
    pub delete: D,
}

/// tenant isolation：同 key 在 A/B 租户互不可见，list 只返回本租户，跨租 update/delete 不影响 owner。
pub async fn assert_policy_store_tenant_isolation<T, K, P, C, F, L, U, D, CF, FF, LF, UF, DF, E>(
    mut case: PolicyTenantIsolationCase<T, K, P, C, F, L, U, D>,
) -> Result<(), PolicyConformanceError>
where
    T: Copy + Debug + PartialEq,
    K: Copy + Debug,
    P: Clone + Debug + PartialEq,
    C: FnMut(T, K, P) -> CF,
    F: FnMut(T, K) -> FF,
    L: FnMut(T) -> LF,
    U: FnMut(T, K, P) -> UF,
    D: FnMut(T, K) -> DF,
    CF: Future<Output = Result<(), E>>,
    FF: Future<Output = Result<Option<P>, E>>,
    LF: Future<Output = Result<Vec<P>, E>>,
    UF: Future<Output = Result<(), E>>,
    DF: Future<Output = Result<(), E>>,
    E: Debug,
{
    debug_assert!(
        case.tenant_a != case.tenant_b,
        "assert_policy_store_tenant_isolation: tenant_a 与 tenant_b 必须不同"
    );

    assert_tenant_a_policy_isolated::<_, _, _, _, _, _, _, _, CF, FF, LF, UF, DF, E>(&mut case)
        .await?;
    assert_tenant_b_create_isolated::<_, _, _, _, _, _, _, _, CF, FF, LF, UF, DF, E>(&mut case)
        .await?;
    assert_tenant_b_update_isolated::<_, _, _, _, _, _, _, _, CF, FF, LF, UF, DF, E>(&mut case)
        .await?;
    assert_tenant_b_delete_isolated::<_, _, _, _, _, _, _, _, CF, FF, LF, UF, DF, E>(&mut case)
        .await
}

async fn assert_tenant_a_policy_isolated<T, K, P, C, F, L, U, D, CF, FF, LF, UF, DF, E>(
    case: &mut PolicyTenantIsolationCase<T, K, P, C, F, L, U, D>,
) -> Result<(), PolicyConformanceError>
where
    T: Copy + Debug + PartialEq,
    K: Copy + Debug,
    P: Clone + Debug + PartialEq,
    C: FnMut(T, K, P) -> CF,
    F: FnMut(T, K) -> FF,
    L: FnMut(T) -> LF,
    U: FnMut(T, K, P) -> UF,
    D: FnMut(T, K) -> DF,
    CF: Future<Output = Result<(), E>>,
    FF: Future<Output = Result<Option<P>, E>>,
    LF: Future<Output = Result<Vec<P>, E>>,
    UF: Future<Output = Result<(), E>>,
    DF: Future<Output = Result<(), E>>,
    E: Debug,
{
    (case.create)(case.tenant_a, case.key, case.tenant_a_policy.clone())
        .await
        .map_err(|e| provider("tenant A create", e))?;
    expect_policy(
        "tenant A find own policy",
        (case.find)(case.tenant_a, case.key)
            .await
            .map_err(|e| provider("tenant A find own policy", e))?,
        Some(&case.tenant_a_policy),
    )?;
    expect_policy(
        "tenant B cannot find tenant A policy",
        (case.find)(case.tenant_b, case.key)
            .await
            .map_err(|e| provider("tenant B cannot find tenant A policy", e))?,
        None,
    )?;
    expect_list(
        "tenant B list excludes tenant A policy",
        (case.list)(case.tenant_b)
            .await
            .map_err(|e| provider("tenant B list excludes tenant A policy", e))?,
        &[],
    )
}

async fn assert_tenant_b_create_isolated<T, K, P, C, F, L, U, D, CF, FF, LF, UF, DF, E>(
    case: &mut PolicyTenantIsolationCase<T, K, P, C, F, L, U, D>,
) -> Result<(), PolicyConformanceError>
where
    T: Copy + Debug + PartialEq,
    K: Copy + Debug,
    P: Clone + Debug + PartialEq,
    C: FnMut(T, K, P) -> CF,
    F: FnMut(T, K) -> FF,
    L: FnMut(T) -> LF,
    U: FnMut(T, K, P) -> UF,
    D: FnMut(T, K) -> DF,
    CF: Future<Output = Result<(), E>>,
    FF: Future<Output = Result<Option<P>, E>>,
    LF: Future<Output = Result<Vec<P>, E>>,
    UF: Future<Output = Result<(), E>>,
    DF: Future<Output = Result<(), E>>,
    E: Debug,
{
    (case.create)(case.tenant_b, case.key, case.tenant_b_policy.clone())
        .await
        .map_err(|e| provider("tenant B create", e))?;
    expect_policy(
        "tenant A remains unchanged after tenant B create",
        (case.find)(case.tenant_a, case.key)
            .await
            .map_err(|e| provider("tenant A remains unchanged after tenant B create", e))?,
        Some(&case.tenant_a_policy),
    )?;
    expect_policy(
        "tenant B find own policy",
        (case.find)(case.tenant_b, case.key)
            .await
            .map_err(|e| provider("tenant B find own policy", e))?,
        Some(&case.tenant_b_policy),
    )?;
    expect_list(
        "tenant A list excludes tenant B policy",
        (case.list)(case.tenant_a)
            .await
            .map_err(|e| provider("tenant A list excludes tenant B policy", e))?,
        std::slice::from_ref(&case.tenant_a_policy),
    )
}

async fn assert_tenant_b_update_isolated<T, K, P, C, F, L, U, D, CF, FF, LF, UF, DF, E>(
    case: &mut PolicyTenantIsolationCase<T, K, P, C, F, L, U, D>,
) -> Result<(), PolicyConformanceError>
where
    T: Copy + Debug + PartialEq,
    K: Copy + Debug,
    P: Clone + Debug + PartialEq,
    C: FnMut(T, K, P) -> CF,
    F: FnMut(T, K) -> FF,
    L: FnMut(T) -> LF,
    U: FnMut(T, K, P) -> UF,
    D: FnMut(T, K) -> DF,
    CF: Future<Output = Result<(), E>>,
    FF: Future<Output = Result<Option<P>, E>>,
    LF: Future<Output = Result<Vec<P>, E>>,
    UF: Future<Output = Result<(), E>>,
    DF: Future<Output = Result<(), E>>,
    E: Debug,
{
    (case.update)(
        case.tenant_b,
        case.key,
        case.tenant_b_updated_policy.clone(),
    )
    .await
    .map_err(|e| provider("tenant B update", e))?;
    expect_policy(
        "tenant A unchanged after tenant B update",
        (case.find)(case.tenant_a, case.key)
            .await
            .map_err(|e| provider("tenant A unchanged after tenant B update", e))?,
        Some(&case.tenant_a_policy),
    )?;
    expect_policy(
        "tenant B update applies only to tenant B",
        (case.find)(case.tenant_b, case.key)
            .await
            .map_err(|e| provider("tenant B update applies only to tenant B", e))?,
        Some(&case.tenant_b_updated_policy),
    )
}

async fn assert_tenant_b_delete_isolated<T, K, P, C, F, L, U, D, CF, FF, LF, UF, DF, E>(
    case: &mut PolicyTenantIsolationCase<T, K, P, C, F, L, U, D>,
) -> Result<(), PolicyConformanceError>
where
    T: Copy + Debug + PartialEq,
    K: Copy + Debug,
    P: Clone + Debug + PartialEq,
    C: FnMut(T, K, P) -> CF,
    F: FnMut(T, K) -> FF,
    L: FnMut(T) -> LF,
    U: FnMut(T, K, P) -> UF,
    D: FnMut(T, K) -> DF,
    CF: Future<Output = Result<(), E>>,
    FF: Future<Output = Result<Option<P>, E>>,
    LF: Future<Output = Result<Vec<P>, E>>,
    UF: Future<Output = Result<(), E>>,
    DF: Future<Output = Result<(), E>>,
    E: Debug,
{
    (case.delete)(case.tenant_b, case.key)
        .await
        .map_err(|e| provider("tenant B delete", e))?;
    expect_policy(
        "tenant A unchanged after tenant B delete",
        (case.find)(case.tenant_a, case.key)
            .await
            .map_err(|e| provider("tenant A unchanged after tenant B delete", e))?,
        Some(&case.tenant_a_policy),
    )?;
    expect_policy(
        "tenant B deleted own policy",
        (case.find)(case.tenant_b, case.key)
            .await
            .map_err(|e| provider("tenant B deleted own policy", e))?,
        None,
    )
}

/// Provider-specific operations and fixtures for [`assert_policy_active_window`].
pub struct PolicyActiveWindowCase<T, K, P, C, A> {
    pub tenant: T,
    pub expired_key: K,
    pub active_key: K,
    pub future_key: K,
    pub expired_policy: P,
    pub active_policy: P,
    pub future_policy: P,
    pub instant_before: i64,
    pub instant_during: i64,
    pub instant_after: i64,
    pub expected_before: Vec<P>,
    pub expected_during: Vec<P>,
    pub expected_after: Vec<P>,
    pub create: C,
    pub active_at: A,
}

/// active-window：只返回查询时间点生效窗口内的 policy；未生效和已过期 policy 不参与 active set。
pub async fn assert_policy_active_window<T, K, P, C, A, CF, AF, E>(
    mut case: PolicyActiveWindowCase<T, K, P, C, A>,
) -> Result<(), PolicyConformanceError>
where
    T: Copy + Debug,
    K: Copy + Debug,
    P: Clone + Debug + PartialEq,
    C: FnMut(T, K, P) -> CF,
    A: FnMut(T, i64) -> AF,
    CF: Future<Output = Result<(), E>>,
    AF: Future<Output = Result<Vec<P>, E>>,
    E: Debug,
{
    (case.create)(case.tenant, case.expired_key, case.expired_policy.clone())
        .await
        .map_err(|e| provider("create expired policy", e))?;
    (case.create)(case.tenant, case.active_key, case.active_policy.clone())
        .await
        .map_err(|e| provider("create active policy", e))?;
    (case.create)(case.tenant, case.future_key, case.future_policy.clone())
        .await
        .map_err(|e| provider("create future policy", e))?;

    expect_list(
        "active policies before current window",
        (case.active_at)(case.tenant, case.instant_before)
            .await
            .map_err(|e| provider("active policies before current window", e))?,
        &case.expected_before,
    )?;
    expect_list(
        "active policies during current window",
        (case.active_at)(case.tenant, case.instant_during)
            .await
            .map_err(|e| provider("active policies during current window", e))?,
        &case.expected_during,
    )?;
    expect_list(
        "active policies after current window",
        (case.active_at)(case.tenant, case.instant_after)
            .await
            .map_err(|e| provider("active policies after current window", e))?,
        &case.expected_after,
    )
}

/// malformed/unknown-field rejection：无效 policy 不能落库；调用方用 error predicate 绑定具体错误枚举。
pub async fn assert_policy_rejects_malformed<MI, UI, MF, UF, MFut, UFut, E, IE>(
    malformed_input: MI,
    unknown_field_input: UI,
    mut create_malformed: MF,
    mut create_unknown_field: UF,
    is_rejection: IE,
) -> Result<(), PolicyConformanceError>
where
    MF: FnMut(MI) -> MFut,
    UF: FnMut(UI) -> UFut,
    MFut: Future<Output = Result<(), E>>,
    UFut: Future<Output = Result<(), E>>,
    E: Debug,
    IE: Fn(&E) -> bool,
{
    expect_error(
        "create malformed policy",
        create_malformed(malformed_input),
        &is_rejection,
    )
    .await?;
    expect_error(
        "create policy with unknown field",
        create_unknown_field(unknown_field_input),
        &is_rejection,
    )
    .await
}

/// Provider-specific operations and fixtures for [`assert_policy_obligation_round_trip`].
pub struct PolicyObligationCase<T, K, P, O, C, F, G> {
    pub tenant: T,
    pub key: K,
    pub policy: P,
    pub expected_obligations: O,
    pub create: C,
    pub find: F,
    pub obligations: G,
}

/// obligation round-trip：policy 存储后再读出时，obligation 集合必须原样保留。
pub async fn assert_policy_obligation_round_trip<T, K, P, O, C, F, G, CF, FF, E>(
    mut case: PolicyObligationCase<T, K, P, O, C, F, G>,
) -> Result<(), PolicyConformanceError>
where
    T: Copy + Debug,
    K: Copy + Debug,
    P: Clone + Debug + PartialEq,
    O: Debug + PartialEq,
    C: FnMut(T, K, P) -> CF,
    F: FnMut(T, K) -> FF,
    G: Fn(&P) -> O,
    CF: Future<Output = Result<(), E>>,
    FF: Future<Output = Result<Option<P>, E>>,
    E: Debug,
{
    (case.create)(case.tenant, case.key, case.policy.clone())
        .await
        .map_err(|e| provider("create policy with obligations", e))?;
    let actual = (case.find)(case.tenant, case.key)
        .await
        .map_err(|e| provider("find policy with obligations", e))?;
    expect_policy(
        "find policy with obligations",
        actual.clone(),
        Some(&case.policy),
    )?;

    let actual_policy = actual.ok_or_else(|| PolicyConformanceError::PolicyMismatch {
        stage: "policy obligation round-trip",
        expected: debug_string(&Some(&case.policy)),
        actual: debug_string(&Option::<P>::None),
    })?;
    let actual_obligations = (case.obligations)(&actual_policy);
    if actual_obligations == case.expected_obligations {
        Ok(())
    } else {
        Err(PolicyConformanceError::PolicyMismatch {
            stage: "policy obligation round-trip",
            expected: debug_string(&case.expected_obligations),
            actual: debug_string(&actual_obligations),
        })
    }
}

/// route gate baseline：空 obligation allow 可通过；非空 obligation allow 必须 fail-closed deny。
pub async fn assert_route_gate_denies_nonempty_obligations<O, E, A, AF>(
    empty_obligations: O,
    nonempty_obligations: O,
    mut allows_route: A,
) -> Result<(), PolicyConformanceError>
where
    O: Debug,
    A: FnMut(O) -> AF,
    AF: Future<Output = Result<bool, E>>,
    E: Debug,
{
    expect_visible(
        "route gate allows empty obligations",
        allows_route(empty_obligations)
            .await
            .map_err(|e| provider("route gate allows empty obligations", e))?,
        true,
    )?;
    expect_visible(
        "route gate denies nonempty obligations",
        allows_route(nonempty_obligations)
            .await
            .map_err(|e| provider("route gate denies nonempty obligations", e))?,
        false,
    )
}
