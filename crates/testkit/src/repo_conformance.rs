//! repository conformance helpers（#1426）。
//!
//! 本模块只表达 provider-agnostic 的 repo 行为断言：CAS、tombstone、tenant scope、storage error、
//! co-tx both-or-neither。调用方用闭包适配具体域类型、错误枚举和存储探针；testkit 不依赖任何 workspace crate，
//! 因而本 conformance 是 Medium 机器门，不替代生产 API 的类型层 Hard 约束。
//!
//! ref: launchbadge/sqlx examples/postgres/transaction/src/main.rs@v0.8.6

use std::fmt::Debug;
use std::future::Future;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RepoConformanceError {
    #[error("repo conformance: provider op failed during {stage}: {error}")]
    Provider { stage: &'static str, error: String },
    #[error("repo conformance: {stage} unexpectedly succeeded")]
    ExpectedErrorMissing { stage: &'static str },
    #[error("repo conformance: {stage} returned wrong error kind: {error}")]
    WrongErrorKind { stage: &'static str, error: String },
    #[error("repo conformance: {stage} marker mismatch; expected {expected:?}, got {actual:?}")]
    MarkerMismatch {
        stage: &'static str,
        expected: String,
        actual: String,
    },
    #[error("repo conformance: {stage} visibility mismatch; expected {expected}, got {actual}")]
    VisibilityMismatch {
        stage: &'static str,
        expected: bool,
        actual: bool,
    },
    #[error(
        "repo conformance: {stage} latest version mismatch; expected {expected:?}, got {actual:?}"
    )]
    VersionMismatch {
        stage: &'static str,
        expected: Option<u64>,
        actual: Option<u64>,
    },
}

fn provider<E: Debug>(stage: &'static str, e: E) -> RepoConformanceError {
    RepoConformanceError::Provider {
        stage,
        error: format!("{e:?}"),
    }
}

fn marker_string<M: Debug>(marker: &Option<M>) -> String {
    format!("{marker:?}")
}

fn expect_marker<M: Debug + PartialEq>(
    stage: &'static str,
    actual: Option<M>,
    expected: Option<&M>,
) -> Result<(), RepoConformanceError> {
    let ok = match (&actual, expected) {
        (None, None) => true,
        (Some(a), Some(e)) => a == e,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(RepoConformanceError::MarkerMismatch {
            stage,
            expected: marker_string(&expected),
            actual: marker_string(&actual),
        })
    }
}

async fn expect_conflict<F, E, IC>(
    stage: &'static str,
    future: F,
    is_conflict: &IC,
) -> Result<(), RepoConformanceError>
where
    F: Future<Output = Result<(), E>>,
    E: Debug,
    IC: Fn(&E) -> bool,
{
    match future.await {
        Ok(()) => Err(RepoConformanceError::ExpectedErrorMissing { stage }),
        Err(e) if is_conflict(&e) => Ok(()),
        Err(e) => Err(RepoConformanceError::WrongErrorKind {
            stage,
            error: format!("{e:?}"),
        }),
    }
}

async fn expect_error<F, E>(stage: &'static str, future: F) -> Result<(), RepoConformanceError>
where
    F: Future<Output = Result<(), E>>,
    E: Debug,
{
    match future.await {
        Ok(()) => Err(RepoConformanceError::ExpectedErrorMissing { stage }),
        Err(_) => Ok(()),
    }
}

fn expect_visible(
    stage: &'static str,
    actual: bool,
    expected: bool,
) -> Result<(), RepoConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(RepoConformanceError::VisibilityMismatch {
            stage,
            expected,
            actual,
        })
    }
}

fn expect_version(
    stage: &'static str,
    actual: Option<u64>,
    expected: Option<u64>,
) -> Result<(), RepoConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(RepoConformanceError::VersionMismatch {
            stage,
            expected,
            actual,
        })
    }
}

/// Versioned CAS repo：v1 成功、stale/gap 冲突、max+1 成功，且冲突不覆盖当前 marker。
pub async fn assert_versioned_cas_repo<M, S, C, SF, CF, E, IC>(
    v1_marker: M,
    stale_marker: M,
    gap_marker: M,
    v2_marker: M,
    mut save: S,
    mut current: C,
    is_conflict: IC,
) -> Result<(), RepoConformanceError>
where
    M: Clone + Debug + PartialEq,
    S: FnMut(u64, M) -> SF,
    C: FnMut() -> CF,
    SF: Future<Output = Result<(), E>>,
    CF: Future<Output = Result<Option<M>, E>>,
    E: Debug,
    IC: Fn(&E) -> bool,
{
    save(1, v1_marker.clone())
        .await
        .map_err(|e| provider("save v1", e))?;
    expect_marker(
        "current after v1",
        current()
            .await
            .map_err(|e| provider("current after v1", e))?,
        Some(&v1_marker),
    )?;

    expect_conflict("stale save", save(1, stale_marker), &is_conflict).await?;
    expect_marker(
        "current after stale save",
        current()
            .await
            .map_err(|e| provider("current after stale save", e))?,
        Some(&v1_marker),
    )?;

    expect_conflict("gap save", save(3, gap_marker), &is_conflict).await?;
    expect_marker(
        "current after gap save",
        current()
            .await
            .map_err(|e| provider("current after gap save", e))?,
        Some(&v1_marker),
    )?;

    save(2, v2_marker.clone())
        .await
        .map_err(|e| provider("save v2", e))?;
    expect_marker(
        "current after v2",
        current()
            .await
            .map_err(|e| provider("current after v2", e))?,
        Some(&v2_marker),
    )
}

/// Tombstone repo：delete 后 current 不可见，历史版本保留，latest version 不重置，重复 delete 幂等。
pub async fn assert_tombstone_repo<M, S, D, C, H, L, SF, DF, CF, HF, LF, E>(
    v1_marker: M,
    v2_marker: M,
    mut save: S,
    mut delete: D,
    mut current: C,
    mut history: H,
    mut latest_version: L,
) -> Result<(), RepoConformanceError>
where
    M: Clone + Debug + PartialEq,
    S: FnMut(u64, M) -> SF,
    D: FnMut() -> DF,
    C: FnMut() -> CF,
    H: FnMut(u64) -> HF,
    L: FnMut() -> LF,
    SF: Future<Output = Result<(), E>>,
    DF: Future<Output = Result<(), E>>,
    CF: Future<Output = Result<Option<M>, E>>,
    HF: Future<Output = Result<Option<M>, E>>,
    LF: Future<Output = Result<Option<u64>, E>>,
    E: Debug,
{
    save(1, v1_marker.clone())
        .await
        .map_err(|e| provider("tombstone save v1", e))?;
    save(2, v2_marker.clone())
        .await
        .map_err(|e| provider("tombstone save v2", e))?;
    delete()
        .await
        .map_err(|e| provider("tombstone delete", e))?;

    expect_marker(
        "current after delete",
        current()
            .await
            .map_err(|e| provider("current after delete", e))?,
        None,
    )?;
    expect_marker(
        "history v1 after delete",
        history(1)
            .await
            .map_err(|e| provider("history v1 after delete", e))?,
        Some(&v1_marker),
    )?;
    expect_marker(
        "history v2 after delete",
        history(2)
            .await
            .map_err(|e| provider("history v2 after delete", e))?,
        Some(&v2_marker),
    )?;
    expect_marker(
        "history tombstone version",
        history(3)
            .await
            .map_err(|e| provider("history tombstone version", e))?,
        None,
    )?;
    expect_version(
        "latest version after delete",
        latest_version()
            .await
            .map_err(|e| provider("latest version after delete", e))?,
        Some(3),
    )?;

    delete()
        .await
        .map_err(|e| provider("tombstone repeated delete", e))?;
    expect_version(
        "latest version after repeated delete",
        latest_version()
            .await
            .map_err(|e| provider("latest version after repeated delete", e))?,
        Some(3),
    )
}

/// Provider-specific operations and fixtures for [`assert_tenant_scoped_repo`].
pub struct TenantScopedCase<T, M, S, D, C, H, L> {
    pub tenant_a: T,
    pub tenant_b: T,
    pub a_marker: M,
    pub b_marker: M,
    pub save: S,
    pub delete: D,
    pub current: C,
    pub history: H,
    pub latest_version: L,
}

impl<T, M, S, D, C, H, L> TenantScopedCase<T, M, S, D, C, H, L> {
    async fn assert_tenant_a_seed<SF, CF, HF, E>(&mut self) -> Result<(), RepoConformanceError>
    where
        T: Copy + Debug,
        M: Clone + Debug + PartialEq,
        S: FnMut(T, u64, M) -> SF,
        C: FnMut(T) -> CF,
        H: FnMut(T, u64) -> HF,
        SF: Future<Output = Result<(), E>>,
        CF: Future<Output = Result<Option<M>, E>>,
        HF: Future<Output = Result<Option<M>, E>>,
        E: Debug,
    {
        (self.save)(self.tenant_a, 1, self.a_marker.clone())
            .await
            .map_err(|e| provider("tenant A save v1", e))?;
        expect_marker(
            "tenant A round-trip",
            (self.current)(self.tenant_a)
                .await
                .map_err(|e| provider("tenant A round-trip", e))?,
            Some(&self.a_marker),
        )?;
        expect_marker(
            "tenant B cannot see tenant A",
            (self.current)(self.tenant_b)
                .await
                .map_err(|e| provider("tenant B cannot see tenant A", e))?,
            None,
        )?;
        expect_marker(
            "tenant B cannot see tenant A history v1",
            (self.history)(self.tenant_b, 1)
                .await
                .map_err(|e| provider("tenant B cannot see tenant A history v1", e))?,
            None,
        )
    }

    async fn assert_tenant_b_independent<SF, CF, HF, LF, E>(
        &mut self,
    ) -> Result<(), RepoConformanceError>
    where
        T: Copy + Debug,
        M: Clone + Debug + PartialEq,
        S: FnMut(T, u64, M) -> SF,
        C: FnMut(T) -> CF,
        H: FnMut(T, u64) -> HF,
        L: FnMut(T) -> LF,
        SF: Future<Output = Result<(), E>>,
        CF: Future<Output = Result<Option<M>, E>>,
        HF: Future<Output = Result<Option<M>, E>>,
        LF: Future<Output = Result<Option<u64>, E>>,
        E: Debug,
    {
        (self.save)(self.tenant_b, 1, self.b_marker.clone())
            .await
            .map_err(|e| provider("tenant B save v1", e))?;
        expect_marker(
            "tenant A after tenant B save",
            (self.current)(self.tenant_a)
                .await
                .map_err(|e| provider("tenant A after tenant B save", e))?,
            Some(&self.a_marker),
        )?;
        expect_marker(
            "tenant B own value",
            (self.current)(self.tenant_b)
                .await
                .map_err(|e| provider("tenant B own value", e))?,
            Some(&self.b_marker),
        )?;
        expect_marker(
            "tenant A history after tenant B save",
            (self.history)(self.tenant_a, 1)
                .await
                .map_err(|e| provider("tenant A history after tenant B save", e))?,
            Some(&self.a_marker),
        )?;
        expect_marker(
            "tenant B own history",
            (self.history)(self.tenant_b, 1)
                .await
                .map_err(|e| provider("tenant B own history", e))?,
            Some(&self.b_marker),
        )?;
        expect_version(
            "tenant A latest version",
            (self.latest_version)(self.tenant_a)
                .await
                .map_err(|e| provider("tenant A latest version", e))?,
            Some(1),
        )?;
        expect_version(
            "tenant B latest version",
            (self.latest_version)(self.tenant_b)
                .await
                .map_err(|e| provider("tenant B latest version", e))?,
            Some(1),
        )
    }

    async fn assert_cross_tenant_delete_noop<DF, CF, E>(
        &mut self,
    ) -> Result<(), RepoConformanceError>
    where
        T: Copy + Debug,
        M: Debug + PartialEq,
        D: FnMut(T) -> DF,
        C: FnMut(T) -> CF,
        DF: Future<Output = Result<(), E>>,
        CF: Future<Output = Result<Option<M>, E>>,
        E: Debug,
    {
        (self.delete)(self.tenant_b)
            .await
            .map_err(|e| provider("tenant B delete", e))?;
        expect_marker(
            "tenant B after delete",
            (self.current)(self.tenant_b)
                .await
                .map_err(|e| provider("tenant B after delete", e))?,
            None,
        )?;
        expect_marker(
            "tenant A after tenant B delete",
            (self.current)(self.tenant_a)
                .await
                .map_err(|e| provider("tenant A after tenant B delete", e))?,
            Some(&self.a_marker),
        )
    }
}

/// Tenant-scoped repo：同 key 在 A/B 租户 current/history 互不可见，版本/状态互不干扰，跨租 delete 不影响 A。
pub async fn assert_tenant_scoped_repo<T, M, S, D, C, H, L, SF, DF, CF, HF, LF, E>(
    mut case: TenantScopedCase<T, M, S, D, C, H, L>,
) -> Result<(), RepoConformanceError>
where
    T: Copy + Debug + PartialEq,
    M: Clone + Debug + PartialEq,
    S: FnMut(T, u64, M) -> SF,
    D: FnMut(T) -> DF,
    C: FnMut(T) -> CF,
    H: FnMut(T, u64) -> HF,
    L: FnMut(T) -> LF,
    SF: Future<Output = Result<(), E>>,
    DF: Future<Output = Result<(), E>>,
    CF: Future<Output = Result<Option<M>, E>>,
    HF: Future<Output = Result<Option<M>, E>>,
    LF: Future<Output = Result<Option<u64>, E>>,
    E: Debug,
{
    debug_assert!(
        case.tenant_a != case.tenant_b,
        "assert_tenant_scoped_repo: tenant_a 与 tenant_b 必须不同"
    );

    case.assert_tenant_a_seed().await?;
    case.assert_tenant_b_independent().await?;
    case.assert_cross_tenant_delete_noop().await
}

/// Tenant-scoped lifecycle/store：seed 后同租可见、跨租不可见；跨租 action 为 no-op，不改变双方可见性。
pub async fn assert_cross_tenant_noop<S, OV, CV, XA, AV, SF, OVF, CVF, XAF, AVF, E>(
    seed: S,
    own_visible: OV,
    mut cross_visible: CV,
    cross_tenant_action: XA,
    own_visible_after_cross_action: AV,
) -> Result<(), RepoConformanceError>
where
    S: FnOnce() -> SF,
    OV: FnOnce() -> OVF,
    CV: FnMut() -> CVF,
    XA: FnOnce() -> XAF,
    AV: FnOnce() -> AVF,
    SF: Future<Output = Result<(), E>>,
    OVF: Future<Output = Result<bool, E>>,
    CVF: Future<Output = Result<bool, E>>,
    XAF: Future<Output = Result<(), E>>,
    AVF: Future<Output = Result<bool, E>>,
    E: Debug,
{
    seed().await.map_err(|e| provider("cross-tenant seed", e))?;
    expect_visible(
        "cross-tenant own visible",
        own_visible()
            .await
            .map_err(|e| provider("cross-tenant own visible", e))?,
        true,
    )?;
    expect_visible(
        "cross-tenant other tenant invisible",
        cross_visible()
            .await
            .map_err(|e| provider("cross-tenant other tenant invisible", e))?,
        false,
    )?;
    cross_tenant_action()
        .await
        .map_err(|e| provider("cross-tenant action", e))?;
    expect_visible(
        "cross-tenant no-op keeps other tenant invisible",
        cross_visible()
            .await
            .map_err(|e| provider("cross-tenant no-op keeps other tenant invisible", e))?,
        false,
    )?;
    expect_visible(
        "cross-tenant no-op preserves owner",
        own_visible_after_cross_action()
            .await
            .map_err(|e| provider("cross-tenant no-op preserves owner", e))?,
        true,
    )
}

/// Storage error mapping：调用方负责破坏底座；harness 断言后续操作返回 storage 类错误。
pub async fn assert_storage_error_mapping<B, O, BF, OF, BE, E, IS>(
    break_storage: B,
    operation: O,
    is_storage_error: IS,
) -> Result<(), RepoConformanceError>
where
    B: FnOnce() -> BF,
    O: FnOnce() -> OF,
    BF: Future<Output = Result<(), BE>>,
    OF: Future<Output = Result<(), E>>,
    BE: Debug,
    E: Debug,
    IS: Fn(&E) -> bool,
{
    break_storage()
        .await
        .map_err(|e| provider("break storage", e))?;
    match operation().await {
        Ok(()) => Err(RepoConformanceError::ExpectedErrorMissing {
            stage: "storage operation",
        }),
        Err(e) if is_storage_error(&e) => Ok(()),
        Err(e) => Err(RepoConformanceError::WrongErrorKind {
            stage: "storage operation",
            error: format!("{e:?}"),
        }),
    }
}

/// One branch of a co-transaction conformance scenario.
pub struct CotxCase<A, B, O> {
    pub action: A,
    pub business_exists: B,
    pub outbox_exists: O,
}

/// L2 co-tx：成功两边皆在；业务失败两边皆无；拒绝/冲突路径不写 outbox。
pub async fn assert_cotx_both_or_neither<
    CA,
    CB,
    CO,
    FA,
    FB,
    FO,
    RA,
    RB,
    RO,
    CAF,
    CBF,
    COF,
    FAF,
    FBF,
    FOF,
    RAF,
    RBF,
    ROF,
    E,
    IR,
>(
    commit: CotxCase<CA, CB, CO>,
    failure: CotxCase<FA, FB, FO>,
    rejected: CotxCase<RA, RB, RO>,
    is_expected_rejection: IR,
) -> Result<(), RepoConformanceError>
where
    CA: FnOnce() -> CAF,
    CB: FnOnce() -> CBF,
    CO: FnOnce() -> COF,
    FA: FnOnce() -> FAF,
    FB: FnOnce() -> FBF,
    FO: FnOnce() -> FOF,
    RA: FnOnce() -> RAF,
    RB: FnOnce() -> RBF,
    RO: FnOnce() -> ROF,
    CAF: Future<Output = Result<(), E>>,
    CBF: Future<Output = Result<bool, E>>,
    COF: Future<Output = Result<bool, E>>,
    FAF: Future<Output = Result<(), E>>,
    FBF: Future<Output = Result<bool, E>>,
    FOF: Future<Output = Result<bool, E>>,
    RAF: Future<Output = Result<(), E>>,
    RBF: Future<Output = Result<bool, E>>,
    ROF: Future<Output = Result<bool, E>>,
    E: Debug,
    IR: Fn(&E) -> bool,
{
    (commit.action)()
        .await
        .map_err(|e| provider("co-tx commit action", e))?;
    expect_visible(
        "co-tx commit business row",
        (commit.business_exists)()
            .await
            .map_err(|e| provider("co-tx commit business row", e))?,
        true,
    )?;
    expect_visible(
        "co-tx commit outbox row",
        (commit.outbox_exists)()
            .await
            .map_err(|e| provider("co-tx commit outbox row", e))?,
        true,
    )?;

    expect_error("co-tx failure action", (failure.action)()).await?;
    expect_visible(
        "co-tx failure business row",
        (failure.business_exists)()
            .await
            .map_err(|e| provider("co-tx failure business row", e))?,
        false,
    )?;
    expect_visible(
        "co-tx failure outbox row",
        (failure.outbox_exists)()
            .await
            .map_err(|e| provider("co-tx failure outbox row", e))?,
        false,
    )?;

    expect_conflict(
        "co-tx rejected action",
        (rejected.action)(),
        &is_expected_rejection,
    )
    .await?;
    expect_visible(
        "co-tx rejected business row",
        (rejected.business_exists)()
            .await
            .map_err(|e| provider("co-tx rejected business row", e))?,
        false,
    )?;
    expect_visible(
        "co-tx rejected outbox row",
        (rejected.outbox_exists)()
            .await
            .map_err(|e| provider("co-tx rejected outbox row", e))?,
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeError {
        Conflict,
        Storage,
        Other,
    }

    fn is_conflict(e: &FakeError) -> bool {
        matches!(e, FakeError::Conflict)
    }

    fn is_storage(e: &FakeError) -> bool {
        matches!(e, FakeError::Storage)
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn versioned_cas_fake_passes_and_non_cas_is_caught() {
        let store: RefCell<HashMap<u64, String>> = RefCell::new(HashMap::new());
        assert_versioned_cas_repo(
            "v1".to_string(),
            "stale".to_string(),
            "gap".to_string(),
            "v2".to_string(),
            |version, marker| {
                let store = &store;
                async move {
                    let expected = store.borrow().keys().max().copied().unwrap_or(0) + 1;
                    if version == expected {
                        store.borrow_mut().insert(version, marker);
                        Ok(())
                    } else {
                        Err(FakeError::Conflict)
                    }
                }
            },
            || {
                let store = &store;
                async move {
                    Ok::<_, FakeError>(
                        store
                            .borrow()
                            .keys()
                            .max()
                            .and_then(|v| store.borrow().get(v).cloned()),
                    )
                }
            },
            is_conflict,
        )
        .await
        .expect("CAS fake passes");

        let broken: RefCell<Option<String>> = RefCell::new(None);
        let err = assert_versioned_cas_repo(
            "v1".to_string(),
            "stale".to_string(),
            "gap".to_string(),
            "v2".to_string(),
            |_, marker| {
                let broken = &broken;
                async move {
                    *broken.borrow_mut() = Some(marker);
                    Ok::<_, FakeError>(())
                }
            },
            || {
                let broken = &broken;
                async move { Ok::<_, FakeError>(broken.borrow().clone()) }
            },
            is_conflict,
        )
        .await
        .expect_err("non-CAS fake must fail");
        assert!(matches!(
            err,
            RepoConformanceError::ExpectedErrorMissing {
                stage: "stale save"
            }
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn tombstone_fake_catches_physical_delete() {
        let store: RefCell<HashMap<u64, (String, bool)>> = RefCell::new(HashMap::new());
        assert_tombstone_repo(
            "v1".to_string(),
            "v2".to_string(),
            |version, marker| {
                let store = &store;
                async move {
                    store.borrow_mut().insert(version, (marker, false));
                    Ok::<_, FakeError>(())
                }
            },
            || {
                let store = &store;
                async move {
                    store.borrow_mut().insert(3, (String::new(), true));
                    Ok::<_, FakeError>(())
                }
            },
            || {
                let store = &store;
                async move {
                    Ok::<_, FakeError>(
                        store
                            .borrow()
                            .iter()
                            .max_by_key(|(version, _)| *version)
                            .and_then(|(_, (marker, deleted))| (!deleted).then(|| marker.clone())),
                    )
                }
            },
            |version| {
                let store = &store;
                async move {
                    Ok::<_, FakeError>(
                        store
                            .borrow()
                            .get(&version)
                            .and_then(|(marker, deleted)| (!deleted).then(|| marker.clone())),
                    )
                }
            },
            || {
                let store = &store;
                async move { Ok::<_, FakeError>(store.borrow().keys().max().copied()) }
            },
        )
        .await
        .expect("tombstone fake passes");

        let physical: RefCell<HashMap<u64, (String, bool)>> = RefCell::new(HashMap::new());
        let err = assert_tombstone_repo(
            "v1".to_string(),
            "v2".to_string(),
            |version, marker| {
                let physical = &physical;
                async move {
                    physical.borrow_mut().insert(version, (marker, false));
                    Ok::<_, FakeError>(())
                }
            },
            || {
                let physical = &physical;
                async move {
                    physical.borrow_mut().clear();
                    Ok::<_, FakeError>(())
                }
            },
            || async { Ok::<_, FakeError>(None::<String>) },
            |version| {
                let physical = &physical;
                async move {
                    Ok::<_, FakeError>(
                        physical
                            .borrow()
                            .get(&version)
                            .map(|(marker, _)| marker.clone()),
                    )
                }
            },
            || {
                let physical = &physical;
                async move { Ok::<_, FakeError>(physical.borrow().keys().max().copied()) }
            },
        )
        .await
        .expect_err("physical delete must fail");
        assert!(matches!(
            err,
            RepoConformanceError::MarkerMismatch {
                stage: "history v1 after delete",
                ..
            }
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn tenant_scoped_fake_catches_leak() {
        let scoped: RefCell<HashMap<u32, HashMap<u64, String>>> = RefCell::new(HashMap::new());
        assert_tenant_scoped_repo(TenantScopedCase {
            tenant_a: 1_u32,
            tenant_b: 2_u32,
            a_marker: "a".to_string(),
            b_marker: "b".to_string(),
            save: |tenant, version, marker: String| {
                let scoped = &scoped;
                async move {
                    scoped
                        .borrow_mut()
                        .entry(tenant)
                        .or_default()
                        .insert(version, marker);
                    Ok::<_, FakeError>(())
                }
            },
            delete: |tenant| {
                let scoped = &scoped;
                async move {
                    scoped
                        .borrow_mut()
                        .entry(tenant)
                        .or_default()
                        .insert(2, String::new());
                    Ok::<_, FakeError>(())
                }
            },
            current: |tenant| {
                let scoped = &scoped;
                async move {
                    Ok::<_, FakeError>(
                        scoped
                            .borrow()
                            .get(&tenant)
                            .and_then(|rows| rows.keys().max().and_then(|v| rows.get(v).cloned()))
                            .filter(|marker| !marker.is_empty()),
                    )
                }
            },
            history: |tenant, version| {
                let scoped = &scoped;
                async move {
                    Ok::<_, FakeError>(
                        scoped
                            .borrow()
                            .get(&tenant)
                            .and_then(|rows| rows.get(&version).cloned()),
                    )
                }
            },
            latest_version: |tenant| {
                let scoped = &scoped;
                async move {
                    Ok::<_, FakeError>(
                        scoped
                            .borrow()
                            .get(&tenant)
                            .and_then(|rows| rows.keys().max().copied()),
                    )
                }
            },
        })
        .await
        .expect("tenant-scoped fake passes");

        let leaked: RefCell<HashMap<u64, String>> = RefCell::new(HashMap::new());
        let err = assert_tenant_scoped_repo(TenantScopedCase {
            tenant_a: 1_u32,
            tenant_b: 2_u32,
            a_marker: "a".to_string(),
            b_marker: "b".to_string(),
            save: |_tenant, version, marker| {
                let leaked = &leaked;
                async move {
                    leaked.borrow_mut().insert(version, marker);
                    Ok::<_, FakeError>(())
                }
            },
            delete: |_tenant| async { Ok::<_, FakeError>(()) },
            current: |_tenant| {
                let leaked = &leaked;
                async move {
                    Ok::<_, FakeError>(
                        leaked
                            .borrow()
                            .keys()
                            .max()
                            .and_then(|v| leaked.borrow().get(v).cloned()),
                    )
                }
            },
            history: |_tenant, version| {
                let leaked = &leaked;
                async move { Ok::<_, FakeError>(leaked.borrow().get(&version).cloned()) }
            },
            latest_version: |_tenant| {
                let leaked = &leaked;
                async move { Ok::<_, FakeError>(leaked.borrow().keys().max().copied()) }
            },
        })
        .await
        .expect_err("leaking fake must fail");
        assert!(matches!(
            err,
            RepoConformanceError::MarkerMismatch {
                stage: "tenant B cannot see tenant A",
                ..
            }
        ));

        let scoped_current: RefCell<HashMap<u32, HashMap<u64, String>>> =
            RefCell::new(HashMap::new());
        let leaked_history: RefCell<HashMap<u64, String>> = RefCell::new(HashMap::new());
        let err = assert_tenant_scoped_repo(TenantScopedCase {
            tenant_a: 1_u32,
            tenant_b: 2_u32,
            a_marker: "a".to_string(),
            b_marker: "b".to_string(),
            save: |tenant, version, marker: String| {
                let scoped_current = &scoped_current;
                let leaked_history = &leaked_history;
                async move {
                    scoped_current
                        .borrow_mut()
                        .entry(tenant)
                        .or_default()
                        .insert(version, marker.clone());
                    leaked_history.borrow_mut().insert(version, marker);
                    Ok::<_, FakeError>(())
                }
            },
            delete: |tenant| {
                let scoped_current = &scoped_current;
                async move {
                    scoped_current
                        .borrow_mut()
                        .entry(tenant)
                        .or_default()
                        .insert(2, String::new());
                    Ok::<_, FakeError>(())
                }
            },
            current: |tenant| {
                let scoped_current = &scoped_current;
                async move {
                    Ok::<_, FakeError>(
                        scoped_current
                            .borrow()
                            .get(&tenant)
                            .and_then(|rows| rows.keys().max().and_then(|v| rows.get(v).cloned()))
                            .filter(|marker| !marker.is_empty()),
                    )
                }
            },
            history: |_tenant, version| {
                let leaked_history = &leaked_history;
                async move { Ok::<_, FakeError>(leaked_history.borrow().get(&version).cloned()) }
            },
            latest_version: |tenant| {
                let scoped_current = &scoped_current;
                async move {
                    Ok::<_, FakeError>(
                        scoped_current
                            .borrow()
                            .get(&tenant)
                            .and_then(|rows| rows.keys().max().copied()),
                    )
                }
            },
        })
        .await
        .expect_err("history leak must fail");
        assert!(matches!(
            err,
            RepoConformanceError::MarkerMismatch {
                stage: "tenant B cannot see tenant A history v1",
                ..
            }
        ));

        let scoped_current: RefCell<HashMap<u32, HashMap<u64, String>>> =
            RefCell::new(HashMap::new());
        let global_history: RefCell<HashMap<u64, String>> = RefCell::new(HashMap::new());
        let err = assert_tenant_scoped_repo(TenantScopedCase {
            tenant_a: 1_u32,
            tenant_b: 2_u32,
            a_marker: "a".to_string(),
            b_marker: "b".to_string(),
            save: |tenant, version, marker: String| {
                let scoped_current = &scoped_current;
                let global_history = &global_history;
                async move {
                    scoped_current
                        .borrow_mut()
                        .entry(tenant)
                        .or_default()
                        .insert(version, marker.clone());
                    global_history.borrow_mut().insert(version, marker);
                    Ok::<_, FakeError>(())
                }
            },
            delete: |tenant| {
                let scoped_current = &scoped_current;
                async move {
                    scoped_current
                        .borrow_mut()
                        .entry(tenant)
                        .or_default()
                        .insert(2, String::new());
                    Ok::<_, FakeError>(())
                }
            },
            current: |tenant| {
                let scoped_current = &scoped_current;
                async move {
                    Ok::<_, FakeError>(
                        scoped_current
                            .borrow()
                            .get(&tenant)
                            .and_then(|rows| rows.keys().max().and_then(|v| rows.get(v).cloned()))
                            .filter(|marker| !marker.is_empty()),
                    )
                }
            },
            history: |tenant, version| {
                let scoped_current = &scoped_current;
                let global_history = &global_history;
                async move {
                    if scoped_current.borrow().contains_key(&tenant) {
                        Ok::<_, FakeError>(global_history.borrow().get(&version).cloned())
                    } else {
                        Ok::<_, FakeError>(None)
                    }
                }
            },
            latest_version: |tenant| {
                let scoped_current = &scoped_current;
                async move {
                    Ok::<_, FakeError>(
                        scoped_current
                            .borrow()
                            .get(&tenant)
                            .and_then(|rows| rows.keys().max().copied()),
                    )
                }
            },
        })
        .await
        .expect_err("global history overwritten by tenant B must fail");
        assert!(matches!(
            err,
            RepoConformanceError::MarkerMismatch {
                stage: "tenant A history after tenant B save",
                ..
            }
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn storage_mapping_fake_catches_wrong_error() {
        assert_storage_error_mapping(
            || async { Ok::<_, FakeError>(()) },
            || async { Err::<(), _>(FakeError::Storage) },
            is_storage,
        )
        .await
        .expect("storage fake passes");

        let err = assert_storage_error_mapping(
            || async { Ok::<_, FakeError>(()) },
            || async { Err::<(), _>(FakeError::Other) },
            is_storage,
        )
        .await
        .expect_err("wrong error kind must fail");
        assert!(matches!(
            err,
            RepoConformanceError::WrongErrorKind {
                stage: "storage operation",
                ..
            }
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn cross_tenant_noop_fake_catches_mutation() {
        let visible = RefCell::new(false);
        assert_cross_tenant_noop(
            || async {
                *visible.borrow_mut() = true;
                Ok::<_, FakeError>(())
            },
            || async { Ok::<_, FakeError>(*visible.borrow()) },
            || async { Ok::<_, FakeError>(false) },
            || async { Ok::<_, FakeError>(()) },
            || async { Ok::<_, FakeError>(*visible.borrow()) },
        )
        .await
        .expect("cross-tenant no-op fake passes");

        let broken = RefCell::new(false);
        let err = assert_cross_tenant_noop(
            || async {
                *broken.borrow_mut() = true;
                Ok::<_, FakeError>(())
            },
            || async { Ok::<_, FakeError>(*broken.borrow()) },
            || async { Ok::<_, FakeError>(false) },
            || async {
                *broken.borrow_mut() = false;
                Ok::<_, FakeError>(())
            },
            || async { Ok::<_, FakeError>(*broken.borrow()) },
        )
        .await
        .expect_err("cross-tenant mutation must fail");
        assert!(matches!(
            err,
            RepoConformanceError::VisibilityMismatch {
                stage: "cross-tenant no-op preserves owner",
                ..
            }
        ));

        let owner_visible = RefCell::new(false);
        let other_visible = RefCell::new(false);
        let err = assert_cross_tenant_noop(
            || async {
                *owner_visible.borrow_mut() = true;
                Ok::<_, FakeError>(())
            },
            || async { Ok::<_, FakeError>(*owner_visible.borrow()) },
            || async { Ok::<_, FakeError>(*other_visible.borrow()) },
            || async {
                *other_visible.borrow_mut() = true;
                Ok::<_, FakeError>(())
            },
            || async { Ok::<_, FakeError>(*owner_visible.borrow()) },
        )
        .await
        .expect_err("cross-tenant action must not expose other tenant");
        assert!(matches!(
            err,
            RepoConformanceError::VisibilityMismatch {
                stage: "cross-tenant no-op keeps other tenant invisible",
                ..
            }
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn cotx_fake_catches_split_tx() {
        let business = RefCell::new(false);
        let outbox = RefCell::new(false);
        assert_cotx_both_or_neither(
            CotxCase {
                action: || async {
                    *business.borrow_mut() = true;
                    *outbox.borrow_mut() = true;
                    Ok::<_, FakeError>(())
                },
                business_exists: || async { Ok::<_, FakeError>(*business.borrow()) },
                outbox_exists: || async { Ok::<_, FakeError>(*outbox.borrow()) },
            },
            CotxCase {
                action: || async { Err::<(), _>(FakeError::Other) },
                business_exists: || async { Ok::<_, FakeError>(false) },
                outbox_exists: || async { Ok::<_, FakeError>(false) },
            },
            CotxCase {
                action: || async { Err::<(), _>(FakeError::Conflict) },
                business_exists: || async { Ok::<_, FakeError>(false) },
                outbox_exists: || async { Ok::<_, FakeError>(false) },
            },
            is_conflict,
        )
        .await
        .expect("co-tx fake passes");

        let split_business = RefCell::new(false);
        let err = assert_cotx_both_or_neither(
            CotxCase {
                action: || async { Ok::<_, FakeError>(()) },
                business_exists: || async { Ok::<_, FakeError>(true) },
                outbox_exists: || async { Ok::<_, FakeError>(true) },
            },
            CotxCase {
                action: || async {
                    *split_business.borrow_mut() = true;
                    Err::<(), _>(FakeError::Other)
                },
                business_exists: || async { Ok::<_, FakeError>(*split_business.borrow()) },
                outbox_exists: || async { Ok::<_, FakeError>(false) },
            },
            CotxCase {
                action: || async { Err::<(), _>(FakeError::Conflict) },
                business_exists: || async { Ok::<_, FakeError>(false) },
                outbox_exists: || async { Ok::<_, FakeError>(false) },
            },
            is_conflict,
        )
        .await
        .expect_err("split transaction must fail");
        assert!(matches!(
            err,
            RepoConformanceError::VisibilityMismatch {
                stage: "co-tx failure business row",
                ..
            }
        ));
    }
}
