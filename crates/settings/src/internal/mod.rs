//! settings 域内部接缝。
//!
//! `mem` 提供配置与 secret 的 in-memory 种子实现。可替换-provider 的**配置**仓储 port 是域形 DI
//! port（`ConfigEntry` 签名），归 [`crate::ports`]（ADR-005 Option 2），不在此。
//!
//! 真实持久化（postgres adapter impl [`crate::ports::ConfigRepo`]）留 Join。

// in-mem repo 仅种子配置 / secret 测试用——随 `with_seed` 同门控（test / seed-data feature），
// 生产构建不编译（防 in-mem provider 误用进生产，对标 identity seed-login）。
#[cfg(any(test, feature = "seed-data"))]
pub(crate) mod mem;
