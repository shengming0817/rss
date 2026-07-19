//! identity 域内部接缝（in-memory 仓储替身，test / seed-login 门控）。
//!
//! `mem`：in-memory 实现——`InMemCredentialRepo`（`CredentialRepo` 域形 DI port 哈希凭据 / 锁定替身，PR3）+
//! `InMemSessionLifecycle`（`SessionLifecycle` 域形 DI port 创建 / 查询 / 软撤销替身，合并原 `InMemSessionRepo`，
//! #1278；`#[cfg(test)]` 门控）。
//! G1 tracer（`InMemUserRepo` / `UserRepo`）已随 PR4 #1189 删除。
//! 生产持久化由 postgres adapter 实现；本模块不进入生产依赖图。

// in-mem repo 仅 test / 种子登录用——同门控（test / seed-login feature），生产构建不编译
// （防明文凭据路径误用，PR #186 F1；InMemCredentialRepo 哈希但同门控收敛 seed 路径）。
#[cfg(any(test, feature = "seed-login"))]
pub(crate) mod mem;
