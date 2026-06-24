//! `RedactedSource` —— diport provider-error wrapper 的共享 `#[source]` 字段类型。
//!
//! 把 adapter 原始错误（`Box<dyn Error>`）的「`Debug` 不展开 source」从 7 份手写 `impl Debug` 上移为
//! **单一类型保证**（Hard）：本 newtype 的 `Debug` / `Display` 固定输出 `<redacted>`、**不展开内层**
//! （redis / 网络 provider 的 source Debug 常携连接串 / 凭据，如 Redis URL）。各 wrapper 经
//! `#[source] source: RedactedSource` + `#[derive(Debug, thiserror::Error)]` 持有它，derive(Debug) 即安全
//! ——`SignerError { source: <redacted> }`。
//!
//! 顶层安全摘要由各 wrapper 的 `#[error("...")]` const `Display` 承载；需要 source 诊断时走统一脱敏
//! funnel `secure::redact_error`（顶层 `Display`、不遍历 source 链）——这是**默认安全路径**。
//!
//! **fail-closed source 链**：原始 adapter 错误被 wrapper **owned**，但**不经任何 `std::error::Error`
//! 接口暴露**——`Debug` / `Display` 恒 `<redacted>`，`Error::source()` 恒 `None`。故标准递归链遍历
//! （`anyhow` 的 `{:?}`、`std::error::Report`、`tracing` 错误捕获等通用消费方会**自动**递归 `source()`）
//! 在 `RedactedSource` 处即终止于 `<redacted>`，**永不**到达原始 adapter 错误。脱敏边界是类型层 Hard
//! 保证，不依赖「调用方不遍历 source 链」的运行期纪律。
//!
//! INVARIANT: DIPORT-ERR-SOURCE-REDACT-01（`Debug` / `Display` / `Error::source()` 均不暴露原始 source；
//! 回归见本模块 `redacted_source` 单测）。

/// 包装 adapter 原始错误的脱敏 `#[source]` 字段。私有字段 + 受控构造（`new`），`Debug` / `Display` 恒
/// `<redacted>`、不展开内层；`Error::source()` 恒 `None`——原始错误**不经任何 `Error` 接口暴露**（fail-closed）。
///
/// 内层裸 `Box<dyn Error>` 是本 newtype 的**受控持有点**（脱敏边界本身）——`rss_diport_error_debug_redacted`
/// lint（INVARIANT: DIPORT-ERR-RAWSOURCE-BAN-01）会标记 diport 内任何裸 Box source 字段，但对
/// `RedactedSource` 自身**结构性豁免**（按 enclosing struct 名）：它正是该 lint 守护要采纳的「正确实现」，
/// `Debug`/`Display` 已固定 `<redacted>`、不泄漏。结构性豁免避免在生产代码引入 `#[allow]` / cfg 噪声。
///
/// 内层 `Box` 是 **owned 但 write-only**：原始错误值保留在内存（供 panic / core-dump 事后排查），却不经
/// `Debug` / `Display` / `Error::source()` 任一接口暴露——write-only 是本脱敏边界的**设计本意**（containment），
/// 故字段标 `#[allow(dead_code)]`（非冗余字段）。
pub(crate) struct RedactedSource(
    // reason: write-only containment——原始错误 owned 供事后 debugger / core-dump 排查，但不经任何
    // `Error` 接口（`Debug`/`Display`/`source()`）暴露（fail-closed PII 边界，DIPORT-ERR-SOURCE-REDACT-01）。
    #[allow(dead_code)] Box<dyn std::error::Error + Send + Sync + 'static>,
);

impl RedactedSource {
    /// 把一个 adapter 内部错误包成脱敏 source。原始错误**不经任何 `Error` 接口**（`Debug` / `Display` /
    /// [`std::error::Error::source`]）暴露（fail-closed PII 边界）；仅 owned 保留供事后 debugger / core-dump 排查。
    pub(crate) fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(source))
    }
}

impl std::fmt::Debug for RedactedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // PII 边界（Hard）：不展开内层（其 Debug 可能携连接串 / 凭据），只输出固定脱敏占位。
        // 类型前缀对齐仓库脱敏 Debug 约定（`primitives::crypto::Signature(<redacted>)` /
        // `secure::Redacted(<redacted>)`）：wrapper derive(Debug) 渲染 `XError { source: RedactedSource(<redacted>) }`。
        f.write_str("RedactedSource(<redacted>)")
    }
}

impl std::fmt::Display for RedactedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: Display 与 Debug 一致脱敏（fail-closed）；顶层安全摘要由 wrapper 的 #[error] const 承载。
        f.write_str("<redacted>")
    }
}

impl std::error::Error for RedactedSource {
    // source() 用默认实现返回 `None`（fail-closed）：原始 adapter 错误**不**经标准 source 链暴露，
    // 通用递归遍历（`anyhow` `{:?}` / `std::error::Report` / `tracing`）在此终止于 `<redacted>`，
    // 永不到达原始内层。类型层 Hard 边界，不靠「调用方不遍历链」纪律。
}

#[cfg(test)]
mod redacted_source {
    //! `RedactedSource` `Debug` / `Display` 不展开内层（adapter 原始错误可能携连接串 / 凭据），
    //! 且 `Error::source()` 恒 `None`——原始内层不经任何 `Error` 接口暴露（fail-closed）。
    //! INVARIANT: DIPORT-ERR-SOURCE-REDACT-01.
    use super::RedactedSource;

    fn secret() -> std::io::Error {
        std::io::Error::other("redis://user:hunter2@cache.internal:6379")
    }

    #[test]
    fn debug_redacts_inner() {
        // anti-vacuity：内层自身 Debug 确实携密，否则回归断言空转。
        assert!(
            format!("{:?}", secret()).contains("hunter2"),
            "前提失效：内层 source 未携密"
        );
        let r = RedactedSource::new(secret());
        let dbg = format!("{r:?}");
        assert!(
            !dbg.contains("hunter2") && !dbg.contains("redis://"),
            "Debug 泄漏内层 source: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
    }

    #[test]
    fn display_redacts_inner() {
        let r = RedactedSource::new(secret());
        let disp = format!("{r}");
        assert!(
            !disp.contains("hunter2") && !disp.contains("redis://"),
            "Display 泄漏内层 source: {disp}"
        );
        assert!(disp.contains("<redacted>"), "缺 <redacted>: {disp}");
    }

    #[test]
    fn source_returns_none_fail_closed() {
        let r = RedactedSource::new(secret());
        // fail-closed：source() 恒 None——通用递归 source 链遍历在此终止，永不到达原始内层（含 PII）。
        assert!(
            std::error::Error::source(&r).is_none(),
            "source() 必须 None（原始内层不得经标准 Error 链暴露）"
        );
    }
}
