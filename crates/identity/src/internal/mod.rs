//! identity 域内部接缝（非 DI-swappable provider 的仓储 trait 留域内，domain-patterns.md §internal 模块）。
//!
//! `ports`：域内仓储 trait（`UserRepo`，G1 tracer）；`mem`：in-memory 实现——G1 `InMemUserRepo`（明文，
//! 删除随 PR4 #1189）+ `InMemCredentialRepo`（`CredentialRepo` 域形 DI port 哈希凭据 / 锁定替身，PR3）。
//! 真实持久化（postgres adapter impl）留 W——这是仓储接缝的存在意义。

// in-mem repo 仅 test / 种子登录用——同门控（test / seed-login feature），生产构建不编译
// （防明文凭据路径误用，PR #186 F1；InMemCredentialRepo 哈希但同门控收敛 seed 路径）。
#[cfg(any(test, feature = "seed-login"))]
pub(crate) mod mem;
pub(crate) mod ports;
