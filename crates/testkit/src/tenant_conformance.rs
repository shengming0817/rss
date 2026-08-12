//! tenant-scope repository conformance 骨架（#1437 PERSIST-016 种子）。
//!
//! 给 durable repo 提供**最小**租户隔离 conformance 入口：调用方传入「按租户写 / 按租户读存在性」两个
//! 异步闭包，骨架断言三件事：
//! 1. **正例 round-trip**：租户 A 写入后、以租户 A 读到（存在）。
//! 2. **跨租不可见**：以租户 B 读不到 A 写入的行（cross-tenant invisible）。
//! 3. **跨租不干扰**：租户 B 在自己 scope 下写后，A 仍读到自己的行（B 的写不抹除 A 的可见性）。
//!
//! 「缺失 tenant 失败」在 RSS 是**类型层强制**——repo 方法签名 `tenant: TenantId` 必填，省略即编译错误
//! （Hard，无法在运行期表达「忘记传 tenant」）；DB 层缺 SET LOCAL → `current_setting` NULL → 行不可见的
//! fail-closed 由 adapter 集成测试以 raw SQL 直证。故本骨架聚焦 repo API 可表达的隔离断言。
//!
//! 这是 #1426（完整 L1/L2 repo conformance）的**种子**；CAS / rollback / storage-error / co-tx 原子性等
//! 全套断言由 #1426 在此骨架上扩展。
//!
//! ref: docs/references/framework-comparison.md（repo conformance：oxidecomputer/omicron 手写 DI 测试范式）。

use rss_conformance::ConformanceErrorCategory;
use std::future::Future;

/// Typed provider stage used in safe diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TenantConformanceStage {
    SaveTenantA,
    ReadTenantA,
    ReadTenantB,
    SaveTenantB,
    ReadTenantAAfterTenantB,
}

impl std::fmt::Display for TenantConformanceStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::SaveTenantA => "save tenant A",
            Self::ReadTenantA => "read tenant A",
            Self::ReadTenantB => "read tenant B",
            Self::SaveTenantB => "save tenant B",
            Self::ReadTenantAAfterTenantB => "read tenant A after tenant B write",
        })
    }
}

/// tenant conformance 断言失败（库错误枚举；调用方在测试侧 `?` / `expect` 暴露）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TenantConformanceError {
    /// round-trip：A 写后 A 读不到。
    #[error("tenant conformance: round-trip failed — tenant A wrote but cannot read back")]
    RoundTripMissing,
    /// 跨租可见泄漏：B 读到了 A 的行。
    #[error("tenant conformance: cross-tenant leak — tenant B can see tenant A's row")]
    CrossTenantVisible,
    /// 跨租干扰：B 写后 A 读不到自己的行。
    #[error(
        "tenant conformance: cross-tenant interference — tenant A's row vanished after B wrote"
    )]
    CrossTenantInterference,
    /// 调用方写 / 读闭包报错；只携带低敏闭值类别。
    #[error("tenant conformance: provider op failed during {stage} ({category})")]
    Provider {
        stage: TenantConformanceStage,
        category: ConformanceErrorCategory,
    },
}

/// 断言 repo 满足最小租户隔离（round-trip + 跨租不可见 + 跨租不干扰）。
///
/// 对租户标识类型 `T` 泛型（`Copy + PartialEq`，如 `vocab::TenantId`）——harness 不依赖 adapter crate，
/// 调用方传入自己的 tenant 类型 + 按租户的写/读闭包（testkit 的唯一内部 shipped 出边为
/// `rss-conformance`，仍为零 adapter 依赖）。
///
/// - `tenant_a` / `tenant_b`：两个**不同**租户（调用方保证不等）。
/// - `save(tenant)`：在该租户 scope 下写一行（多次调用安全：幂等或唯一键由调用方自理）。
/// - `exists(tenant)`：在该租户 scope 下读「该行是否存在」（true = 可见）。
/// - `classify_error(error)`：映射到低基数、低敏的闭值类别。
///
/// 任一断言不成立 → `Err(TenantConformanceError)`。
pub async fn assert_tenant_isolation<T, S, R, SF, RF, E, C>(
    tenant_a: T,
    tenant_b: T,
    save: S,
    exists: R,
    classify_error: C,
) -> Result<(), TenantConformanceError>
where
    T: Copy + PartialEq,
    S: Fn(T) -> SF,
    R: Fn(T) -> RF,
    SF: Future<Output = Result<(), E>>,
    RF: Future<Output = Result<bool, E>>,
    C: Fn(&E) -> ConformanceErrorCategory,
{
    // 前置：两租户必须不同，否则断言 2（跨租不可见）会以误导性的 CrossTenantVisible 失败，掩盖调用方传参错误。
    debug_assert!(
        tenant_a != tenant_b,
        "assert_tenant_isolation: tenant_a 与 tenant_b 必须不同"
    );

    // 1. 正例 round-trip：A 写 → A 可见。
    save(tenant_a)
        .await
        .map_err(|error| TenantConformanceError::Provider {
            stage: TenantConformanceStage::SaveTenantA,
            category: classify_error(&error),
        })?;
    if !exists(tenant_a)
        .await
        .map_err(|error| TenantConformanceError::Provider {
            stage: TenantConformanceStage::ReadTenantA,
            category: classify_error(&error),
        })?
    {
        return Err(TenantConformanceError::RoundTripMissing);
    }

    // 2. 跨租不可见：B 读不到 A 的行。
    if exists(tenant_b)
        .await
        .map_err(|error| TenantConformanceError::Provider {
            stage: TenantConformanceStage::ReadTenantB,
            category: classify_error(&error),
        })?
    {
        return Err(TenantConformanceError::CrossTenantVisible);
    }

    // 3. 跨租不干扰：B 在自己 scope 写 → A 仍读到自己的行（B 的写不覆盖 / 不抹除 A 可见性）。
    save(tenant_b)
        .await
        .map_err(|error| TenantConformanceError::Provider {
            stage: TenantConformanceStage::SaveTenantB,
            category: classify_error(&error),
        })?;
    if !exists(tenant_a)
        .await
        .map_err(|error| TenantConformanceError::Provider {
            stage: TenantConformanceStage::ReadTenantAAfterTenantB,
            category: classify_error(&error),
        })?
    {
        return Err(TenantConformanceError::CrossTenantInterference);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashSet;

    // 测试用 tenant 键：harness 对 T 泛型，单测用简单 `u32`（无需内部 crate 类型，印证零依赖泛型化）。
    const TENANT_A: u32 = 1;
    const TENANT_B: u32 = 2;

    /// in-memory tenant-scoped 假 repo（HashSet of tenant 键）→ 满足隔离 → Ok。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn isolating_fake_repo_passes() {
        let store: RefCell<HashSet<u32>> = RefCell::new(HashSet::new());
        let save = |t: u32| {
            let store = &store;
            async move {
                store.borrow_mut().insert(t);
                Ok::<(), std::convert::Infallible>(())
            }
        };
        let exists = |t: u32| {
            let store = &store;
            async move { Ok::<bool, std::convert::Infallible>(store.borrow().contains(&t)) }
        };
        assert_tenant_isolation(TENANT_A, TENANT_B, save, exists, |_| {
            ConformanceErrorCategory::Other
        })
        .await
        .expect("isolating repo passes");
    }

    /// anti-vacuity：泄漏 repo（所有租户共享一张表，B 读得到 A 的行）→ CrossTenantVisible（守卫非恒真）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn leaking_fake_repo_is_caught() {
        let store: RefCell<bool> = RefCell::new(false);
        let save = |_t: u32| {
            let store = &store;
            async move {
                *store.borrow_mut() = true;
                Ok::<(), std::convert::Infallible>(())
            }
        };
        // 无视租户：任何租户都「可见」（泄漏）。
        let exists = |_t: u32| {
            let store = &store;
            async move { Ok::<bool, std::convert::Infallible>(*store.borrow()) }
        };
        let err = assert_tenant_isolation(TENANT_A, TENANT_B, save, exists, |_| {
            ConformanceErrorCategory::Other
        })
        .await
        .expect_err("leaking repo must fail");
        assert!(
            matches!(err, TenantConformanceError::CrossTenantVisible),
            "{err:?}"
        );
    }

    /// anti-vacuity：跨租写会抹掉 A 的可见性 → CrossTenantInterference（守卫 no-interference 非恒真）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn interfering_fake_repo_is_caught() {
        let current: RefCell<Option<u32>> = RefCell::new(None);
        let save = |t: u32| {
            let current = &current;
            async move {
                *current.borrow_mut() = Some(t);
                Ok::<(), std::convert::Infallible>(())
            }
        };
        let exists = |t: u32| {
            let current = &current;
            async move { Ok::<bool, std::convert::Infallible>(*current.borrow() == Some(t)) }
        };
        let err = assert_tenant_isolation(TENANT_A, TENANT_B, save, exists, |_| {
            ConformanceErrorCategory::Other
        })
        .await
        .expect_err("interfering repo must fail");
        assert!(
            matches!(err, TenantConformanceError::CrossTenantInterference),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn provider_failure_uses_typed_stage_and_safe_category_without_debug_bound() {
        struct SensitiveError;

        let result = assert_tenant_isolation(
            TENANT_A,
            TENANT_B,
            |_| async { Err::<(), _>(SensitiveError) },
            |_| async { Ok::<_, SensitiveError>(false) },
            |_| ConformanceErrorCategory::Storage,
        )
        .await;

        assert!(matches!(
            result,
            Err(TenantConformanceError::Provider {
                stage: TenantConformanceStage::SaveTenantA,
                category: ConformanceErrorCategory::Storage,
            })
        ));
    }
}
