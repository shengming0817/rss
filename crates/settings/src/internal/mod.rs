//! settings 域内部接缝。
//!
//! `ports`：域内 flag 仓储 trait（`FlagStore`——非可替换-provider DI port，留域内，domain-patterns.md
//! §internal 模块）；`mem`：in-memory 实现（RW-W 种子配置 / flag）。可替换-provider 的**配置**仓储 port
//! 是域形 DI port（`ConfigEntry` 签名），归 [`crate::ports`]（ADR-005 Option 2），不在此。
//!
//! 真实持久化（postgres adapter impl [`crate::ports::ConfigRepo`]）留 Join。

// in-mem repo 仅种子配置 / flag demo 用——随 `with_seed` 同门控（test / seed-data feature），
// 生产构建不编译（防 in-mem provider 误用进生产，对标 identity seed-login）。
#[cfg(any(test, feature = "seed-data"))]
pub(crate) mod mem;
pub(crate) mod ports;
