//! repository conformance helpers（#1426）。
//!
//! 本模块只表达 provider-agnostic 的 repo 行为断言：CAS、tombstone、tenant scope、storage error、
//! co-tx both-or-neither。调用方用闭包适配具体域类型、错误枚举和存储探针；testkit 仅经唯一内部 shipped
//! 出边 `rss-conformance` 复用 provider-neutral 错误分类，因而本 conformance 是 Medium 机器门，
//! 不替代生产 API 的类型层 Hard 约束。
//!
//! ref: launchbadge/sqlx examples/postgres/transaction/src/main.rs@v0.8.6

use rss_conformance::ConformanceErrorCategory;
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
    #[error("repo conformance: provider op failed during {stage} ({category})")]
    ClassifiedProvider {
        stage: &'static str,
        category: ConformanceErrorCategory,
    },
    #[error("repo conformance: {stage} returned {actual}; expected {expected}")]
    WrongErrorCategory {
        stage: &'static str,
        expected: ConformanceErrorCategory,
        actual: ConformanceErrorCategory,
    },
    #[error("repo conformance: {path} retry threshold must be at least {minimum}; got {actual}")]
    InvalidRetryThreshold {
        path: RetryPathKind,
        minimum: usize,
        actual: usize,
    },
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
    #[error("repo conformance: {stage} attempts mismatch; expected {expected}, got {actual}")]
    AttemptMismatch {
        stage: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("repo conformance: {stage} durable writes mismatch; expected {expected}, got {actual}")]
    DurableWriteMismatch {
        stage: &'static str,
        expected: usize,
        actual: usize,
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

/// A retry path with one or more transient failures followed by success.
pub struct TransientSuccessPath<A, C, W> {
    action: A,
    attempts: C,
    expected_transient_attempts: usize,
    durable_writes: W,
}

impl<A, C, W> TransientSuccessPath<A, C, W> {
    pub fn new(action: A, attempts: C, expected_attempts: usize, durable_writes: W) -> Self {
        Self {
            action,
            attempts,
            expected_transient_attempts: expected_attempts,
            durable_writes,
        }
    }
}

/// A conflict path, which must neither retry nor write.
pub struct ConflictPath<A, C, W> {
    action: A,
    attempts: C,
    durable_writes: W,
}

impl<A, C, W> ConflictPath<A, C, W> {
    pub fn new(action: A, attempts: C, durable_writes: W) -> Self {
        Self {
            action,
            attempts,
            durable_writes,
        }
    }
}

/// A permanent-error path, which must neither retry nor write.
pub struct PermanentPath<A, C, W> {
    action: A,
    attempts: C,
    durable_writes: W,
}

impl<A, C, W> PermanentPath<A, C, W> {
    pub fn new(action: A, attempts: C, durable_writes: W) -> Self {
        Self {
            action,
            attempts,
            durable_writes,
        }
    }
}

/// A transient path that consumes the complete retry budget without writing.
pub struct TransientExhaustionPath<A, C, W> {
    action: A,
    attempts: C,
    retry_budget: usize,
    durable_writes: W,
}

impl<A, C, W> TransientExhaustionPath<A, C, W> {
    pub fn new(action: A, attempts: C, retry_budget: usize, durable_writes: W) -> Self {
        Self {
            action,
            attempts,
            retry_budget,
            durable_writes,
        }
    }
}

/// Typed retry fixture path used by invalid-threshold diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RetryPathKind {
    TransientSuccess,
    TransientExhaustion,
}

impl std::fmt::Display for RetryPathKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::TransientSuccess => "transient-success",
            Self::TransientExhaustion => "transient-exhaustion",
        })
    }
}

/// Provider-specific retry boundary conformance scenario composed from four nominal paths.
pub struct RetryBoundaryCase<T, C, P, E> {
    transient_success: T,
    conflict: C,
    permanent: P,
    transient_exhaustion: E,
}

impl<T, C, P, E> RetryBoundaryCase<T, C, P, E> {
    pub fn new(transient_success: T, conflict: C, permanent: P, transient_exhaustion: E) -> Self {
        Self {
            transient_success,
            conflict,
            permanent,
            transient_exhaustion,
        }
    }
}

/// Retry boundary: transient success commits once; conflict/permanent never retry; exhaustion
/// reaches its budget, returns the expected transient category, and commits nothing.
#[allow(clippy::type_complexity)]
pub async fn assert_retry_boundary_policy<
    TA,
    TT,
    TW,
    CA,
    CT,
    CW,
    PA,
    PT,
    PW,
    EA,
    ET,
    EW,
    TAF,
    TWF,
    CAF,
    CWF,
    PAF,
    PWF,
    EAF,
    EWF,
    E,
    EC,
>(
    case: RetryBoundaryCase<
        TransientSuccessPath<TA, TT, TW>,
        ConflictPath<CA, CT, CW>,
        PermanentPath<PA, PT, PW>,
        TransientExhaustionPath<EA, ET, EW>,
    >,
    classify_error: EC,
) -> Result<(), RepoConformanceError>
where
    TA: FnOnce() -> TAF,
    TT: FnOnce() -> usize,
    TW: FnOnce() -> TWF,
    CA: FnOnce() -> CAF,
    CT: FnOnce() -> usize,
    CW: FnOnce() -> CWF,
    PA: FnOnce() -> PAF,
    PT: FnOnce() -> usize,
    PW: FnOnce() -> PWF,
    EA: FnOnce() -> EAF,
    ET: FnOnce() -> usize,
    EW: FnOnce() -> EWF,
    TAF: Future<Output = Result<(), E>>,
    TWF: Future<Output = Result<usize, E>>,
    CAF: Future<Output = Result<(), E>>,
    CWF: Future<Output = Result<usize, E>>,
    PAF: Future<Output = Result<(), E>>,
    PWF: Future<Output = Result<usize, E>>,
    EAF: Future<Output = Result<(), E>>,
    EWF: Future<Output = Result<usize, E>>,
    EC: Fn(&E) -> ConformanceErrorCategory,
{
    let RetryBoundaryCase {
        transient_success,
        conflict,
        permanent,
        transient_exhaustion,
    } = case;
    if transient_success.expected_transient_attempts < 2 {
        return Err(RepoConformanceError::InvalidRetryThreshold {
            path: RetryPathKind::TransientSuccess,
            minimum: 2,
            actual: transient_success.expected_transient_attempts,
        });
    }
    if transient_exhaustion.retry_budget < 2 {
        return Err(RepoConformanceError::InvalidRetryThreshold {
            path: RetryPathKind::TransientExhaustion,
            minimum: 2,
            actual: transient_exhaustion.retry_budget,
        });
    }
    (transient_success.action)().await.map_err(|error| {
        classified_provider("retry transient then success", &error, &classify_error)
    })?;
    let transient_attempts = (transient_success.attempts)();
    expect_attempts(
        "retry transient attempts",
        transient_attempts,
        transient_success.expected_transient_attempts,
    )?;
    let transient_writes = (transient_success.durable_writes)()
        .await
        .map_err(|error| {
            classified_provider("retry transient durable writes", &error, &classify_error)
        })?;
    expect_durable_writes("retry transient durable writes", transient_writes, 1)?;

    expect_safe_error(
        "retry conflict action",
        (conflict.action)().await,
        ConformanceErrorCategory::Conflict,
        &classify_error,
    )?;
    expect_attempts("retry conflict attempts", (conflict.attempts)(), 1)?;
    let conflict_writes = (conflict.durable_writes)().await.map_err(|error| {
        classified_provider("retry conflict durable writes", &error, &classify_error)
    })?;
    expect_durable_writes("retry conflict durable writes", conflict_writes, 0)?;

    expect_safe_error(
        "retry permanent action",
        (permanent.action)().await,
        ConformanceErrorCategory::Permanent,
        &classify_error,
    )?;
    expect_attempts("retry permanent attempts", (permanent.attempts)(), 1)?;
    let permanent_writes = (permanent.durable_writes)().await.map_err(|error| {
        classified_provider("retry permanent durable writes", &error, &classify_error)
    })?;
    expect_durable_writes("retry permanent durable writes", permanent_writes, 0)?;

    expect_safe_error(
        "retry transient exhaustion action",
        (transient_exhaustion.action)().await,
        ConformanceErrorCategory::Transient,
        &classify_error,
    )?;
    expect_attempts(
        "retry transient exhaustion attempts",
        (transient_exhaustion.attempts)(),
        transient_exhaustion.retry_budget,
    )?;
    let exhaustion_writes = (transient_exhaustion.durable_writes)()
        .await
        .map_err(|error| {
            classified_provider(
                "retry transient exhaustion durable writes",
                &error,
                &classify_error,
            )
        })?;
    expect_durable_writes(
        "retry transient exhaustion durable writes",
        exhaustion_writes,
        0,
    )
}

fn classified_provider<E, C>(stage: &'static str, error: &E, category: &C) -> RepoConformanceError
where
    C: Fn(&E) -> ConformanceErrorCategory,
{
    RepoConformanceError::ClassifiedProvider {
        stage,
        category: category(error),
    }
}

fn expect_safe_error<E, C>(
    stage: &'static str,
    result: Result<(), E>,
    expected: ConformanceErrorCategory,
    category: &C,
) -> Result<(), RepoConformanceError>
where
    C: Fn(&E) -> ConformanceErrorCategory,
{
    match result {
        Ok(()) => Err(RepoConformanceError::ExpectedErrorMissing { stage }),
        Err(error) if category(&error) == expected => Ok(()),
        Err(error) => Err(RepoConformanceError::WrongErrorCategory {
            stage,
            expected,
            actual: category(&error),
        }),
    }
}

fn expect_attempts(
    stage: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), RepoConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(RepoConformanceError::AttemptMismatch {
            stage,
            expected,
            actual,
        })
    }
}

fn expect_durable_writes(
    stage: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), RepoConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(RepoConformanceError::DurableWriteMismatch {
            stage,
            expected,
            actual,
        })
    }
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
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeError {
        Transient,
        Conflict,
        Permanent,
        Storage,
        Other,
    }

    fn is_conflict(e: &FakeError) -> bool {
        matches!(e, FakeError::Conflict)
    }

    fn error_category(e: &FakeError) -> ConformanceErrorCategory {
        match e {
            FakeError::Transient => ConformanceErrorCategory::Transient,
            FakeError::Conflict => ConformanceErrorCategory::Conflict,
            FakeError::Permanent => ConformanceErrorCategory::Permanent,
            FakeError::Storage => ConformanceErrorCategory::Storage,
            FakeError::Other => ConformanceErrorCategory::Other,
        }
    }

    macro_rules! retry_case {
        ($success:expr, $success_attempts:expr, $expected_success_attempts:expr, $success_writes:expr,
         $conflict:expr, $conflict_attempts:expr, $conflict_writes:expr,
         $permanent:expr, $permanent_attempts:expr, $permanent_writes:expr,
         $exhaustion:expr, $exhaustion_attempts:expr, $budget:expr, $exhaustion_writes:expr $(,)?) => {
            RetryBoundaryCase::new(
                TransientSuccessPath::new(
                    $success,
                    $success_attempts,
                    $expected_success_attempts,
                    $success_writes,
                ),
                ConflictPath::new($conflict, $conflict_attempts, $conflict_writes),
                PermanentPath::new($permanent, $permanent_attempts, $permanent_writes),
                TransientExhaustionPath::new(
                    $exhaustion,
                    $exhaustion_attempts,
                    $budget,
                    $exhaustion_writes,
                ),
            )
        };
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
    async fn retry_boundary_fake_checks_classes() {
        assert_retry_boundary_policy(
            retry_case!(
                || async { Ok::<_, FakeError>(()) },
                || 2,
                2,
                || async { Ok::<_, FakeError>(1) },
                || async { Err::<(), _>(FakeError::Conflict) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
                || async { Err::<(), _>(FakeError::Permanent) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
                || async { Err::<(), _>(FakeError::Transient) },
                || 3,
                3,
                || async { Ok::<_, FakeError>(0) },
            ),
            error_category,
        )
        .await
        .expect("retry boundary fake passes");

        let err = assert_retry_boundary_policy(
            retry_case!(
                || async { Ok::<_, FakeError>(()) },
                || 2,
                2,
                || async { Ok::<_, FakeError>(1) },
                || async { Err::<(), _>(FakeError::Conflict) },
                || 2,
                || async { Ok::<_, FakeError>(0) },
                || async { Err::<(), _>(FakeError::Permanent) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
                || async { Err::<(), _>(FakeError::Transient) },
                || 3,
                3,
                || async { Ok::<_, FakeError>(0) },
            ),
            error_category,
        )
        .await
        .expect_err("conflict retry must fail");
        assert!(matches!(
            err,
            RepoConformanceError::AttemptMismatch {
                stage: "retry conflict attempts",
                actual: 2,
                ..
            }
        ));

        let err = assert_retry_boundary_policy(
            retry_case!(
                || async { Ok::<_, FakeError>(()) },
                || 2,
                2,
                || async { Ok::<_, FakeError>(2) },
                || async { Err::<(), _>(FakeError::Conflict) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
                || async { Err::<(), _>(FakeError::Permanent) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
                || async { Err::<(), _>(FakeError::Transient) },
                || 2,
                3,
                || async { Ok::<_, FakeError>(0) },
            ),
            error_category,
        )
        .await
        .expect_err("duplicate successful write must fail");
        assert!(matches!(
            err,
            RepoConformanceError::DurableWriteMismatch {
                stage: "retry transient durable writes",
                actual: 2,
                ..
            }
        ));

        let err = assert_retry_boundary_policy(
            retry_case!(
                || async { Ok::<_, FakeError>(()) },
                || 2,
                2,
                || async { Ok::<_, FakeError>(1) },
                || async { Err::<(), _>(FakeError::Conflict) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
                || async { Err::<(), _>(FakeError::Permanent) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
                || async { Err::<(), _>(FakeError::Storage) },
                || 3,
                3,
                || async { Ok::<_, FakeError>(0) },
            ),
            error_category,
        )
        .await
        .expect_err("exhaustion must return transient error");
        assert!(matches!(
            err,
            RepoConformanceError::WrongErrorCategory {
                stage: "retry transient exhaustion action",
                ..
            }
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn retry_boundary_provider_failure_is_typed_without_debug_bound() {
        struct SensitiveError;

        let error = assert_retry_boundary_policy(
            RetryBoundaryCase::new(
                TransientSuccessPath::new(
                    || async { Err::<(), _>(SensitiveError) },
                    || 2,
                    2,
                    || async { Ok::<_, SensitiveError>(1) },
                ),
                ConflictPath::new(
                    || async { Err::<(), _>(SensitiveError) },
                    || 1,
                    || async { Ok::<_, SensitiveError>(0) },
                ),
                PermanentPath::new(
                    || async { Err::<(), _>(SensitiveError) },
                    || 1,
                    || async { Ok::<_, SensitiveError>(0) },
                ),
                TransientExhaustionPath::new(
                    || async { Err::<(), _>(SensitiveError) },
                    || 2,
                    2,
                    || async { Ok::<_, SensitiveError>(0) },
                ),
            ),
            |_| ConformanceErrorCategory::Storage,
        )
        .await
        .expect_err("provider failure must be surfaced");

        assert!(matches!(
            error,
            RepoConformanceError::ClassifiedProvider {
                stage: "retry transient then success",
                category: ConformanceErrorCategory::Storage,
            }
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn retry_boundary_requires_conflict_error() {
        let error = assert_retry_boundary_policy(
            retry_case!(
                || async { Ok::<_, FakeError>(()) },
                || 2,
                2,
                || async { Ok::<_, FakeError>(1) },
                || async { Ok::<_, FakeError>(()) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
                || async { Err::<(), _>(FakeError::Permanent) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
                || async { Err::<(), _>(FakeError::Transient) },
                || 2,
                2,
                || async { Ok::<_, FakeError>(0) },
            ),
            error_category,
        )
        .await
        .expect_err("conflict path must reject success");

        assert!(matches!(
            error,
            RepoConformanceError::ExpectedErrorMissing {
                stage: "retry conflict action",
            }
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn retry_boundary_fake_rejects_each_forbidden_attempt_or_write() {
        macro_rules! boundary {
            ($conflict_writes:expr, $permanent_attempts:expr, $permanent_writes:expr,
             $exhaustion_attempts:expr, $exhaustion_writes:expr) => {
                retry_case!(
                    || async { Ok::<_, FakeError>(()) },
                    || 2,
                    2,
                    || async { Ok::<_, FakeError>(1) },
                    || async { Err::<(), _>(FakeError::Conflict) },
                    || 1,
                    || async { Ok::<_, FakeError>($conflict_writes) },
                    || async { Err::<(), _>(FakeError::Permanent) },
                    || $permanent_attempts,
                    || async { Ok::<_, FakeError>($permanent_writes) },
                    || async { Err::<(), _>(FakeError::Transient) },
                    || $exhaustion_attempts,
                    3,
                    || async { Ok::<_, FakeError>($exhaustion_writes) },
                )
            };
        }
        macro_rules! expect_failure {
            ($case:expr, $pattern:pat, $message:literal) => {{
                let error = assert_retry_boundary_policy($case, error_category)
                    .await
                    .expect_err($message);
                assert!(matches!(error, $pattern));
            }};
        }

        expect_failure!(
            boundary!(1, 1, 0, 3, 0),
            RepoConformanceError::DurableWriteMismatch {
                stage: "retry conflict durable writes",
                ..
            },
            "conflict writes must fail"
        );
        expect_failure!(
            boundary!(0, 2, 0, 3, 0),
            RepoConformanceError::AttemptMismatch {
                stage: "retry permanent attempts",
                ..
            },
            "permanent retry must fail"
        );
        expect_failure!(
            boundary!(0, 1, 1, 3, 0),
            RepoConformanceError::DurableWriteMismatch {
                stage: "retry permanent durable writes",
                ..
            },
            "permanent writes must fail"
        );
        expect_failure!(
            boundary!(0, 1, 0, 2, 0),
            RepoConformanceError::AttemptMismatch {
                stage: "retry transient exhaustion attempts",
                ..
            },
            "short exhaustion must fail"
        );
        expect_failure!(
            boundary!(0, 1, 0, 3, 1),
            RepoConformanceError::DurableWriteMismatch {
                stage: "retry transient exhaustion durable writes",
                ..
            },
            "exhaustion writes must fail"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn retry_boundary_rejects_threshold_one_before_running_actions() {
        use rss_conformance::ConformanceErrorCategory;

        let ran = Cell::new(false);
        let case = RetryBoundaryCase::new(
            TransientSuccessPath::new(
                || async {
                    ran.set(true);
                    Ok::<_, FakeError>(())
                },
                || 1,
                1,
                || async { Ok::<_, FakeError>(0) },
            ),
            ConflictPath::new(
                || async { Err::<(), _>(FakeError::Conflict) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
            ),
            PermanentPath::new(
                || async { Err::<(), _>(FakeError::Storage) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
            ),
            TransientExhaustionPath::new(
                || async { Err::<(), _>(FakeError::Transient) },
                || 1,
                2,
                || async { Ok::<_, FakeError>(0) },
            ),
        );

        let error = assert_retry_boundary_policy(case, |_| ConformanceErrorCategory::Other)
            .await
            .expect_err("success threshold one must be rejected");
        assert!(matches!(
            error,
            RepoConformanceError::InvalidRetryThreshold {
                path: RetryPathKind::TransientSuccess,
                actual: 1,
                minimum: 2,
            }
        ));
        assert!(!ran.get(), "invalid fixtures must not execute actions");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn retry_boundary_rejects_exhaustion_budget_one_before_running_actions() {
        let ran = Cell::new(false);
        let case = RetryBoundaryCase::new(
            TransientSuccessPath::new(
                || async {
                    ran.set(true);
                    Ok::<_, FakeError>(())
                },
                || 2,
                2,
                || async { Ok::<_, FakeError>(1) },
            ),
            ConflictPath::new(
                || async { Err::<(), _>(FakeError::Conflict) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
            ),
            PermanentPath::new(
                || async { Err::<(), _>(FakeError::Permanent) },
                || 1,
                || async { Ok::<_, FakeError>(0) },
            ),
            TransientExhaustionPath::new(
                || async { Err::<(), _>(FakeError::Transient) },
                || 1,
                1,
                || async { Ok::<_, FakeError>(0) },
            ),
        );

        let error = assert_retry_boundary_policy(case, error_category)
            .await
            .expect_err("exhaustion budget one must be rejected");
        assert!(matches!(
            error,
            RepoConformanceError::InvalidRetryThreshold {
                path: RetryPathKind::TransientExhaustion,
                actual: 1,
                minimum: 2,
            }
        ));
        assert!(!ran.get(), "invalid fixtures must not execute actions");
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
