//! identity 域内部接缝（非 DI-swappable provider 的仓储 trait 留域内，domain-patterns.md §internal 模块）。
//!
//! `ports`：域内仓储 trait（`UserRepo`）；`mem`：in-memory 实现（RW-G1 追踪弹种子用户）。
//! 真实持久化（postgres adapter impl）留 W——这是仓储接缝的存在意义。

// in-mem user repo 仅明文种子登录用——随 `with_seed_user` 同门控（test / seed-login feature），
// 生产构建不编译（防明文凭据路径误用，PR #186 F1）。
#[cfg(any(test, feature = "seed-login"))]
pub(crate) mod mem;
pub(crate) mod ports;
