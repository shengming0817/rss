# Research: Platform Public application kernel

## 结论

旧 executable contract 证明了 visibility，却无法证明真实 authority、dispatch 或 lifecycle；把它原样迁移会产生
假 façade。Release publish closure 又禁止 façade 依赖 publish=false internals，因此合法 altitude 是一个
零 workspace production dependency、provider-free 的进程内 kernel，由 internals 反向消费它。

canonical contract set 查询得到唯一 framework-owned active HTTP contract `runtime.inventory`。PlatformPublic
leakage gate 禁止公开 external/workspace-qualified type，因此所有 DTO、authority view、错误和 diagnostics 都必须
façade-owned，并把 crypto/serde 类型留在私有实现。

认证边界采用静态 ES256 JWKS，而非公开 SPI。动态刷新与 provider 资源生命周期仍属于 internal OIDC integration；
Platform owner 负责 federated ES256 的唯一签名/claims 判定。

## 对标

参考 `oxidecomputer/omicron@35ee33351a2b8e49005dea8d4ec7d30cbeddc1a0` 的
`nexus/src/context.rs` 与 `nexus/src/lib.rs`：认证/provider detail 保持 private，启动所有权使用显式阶段。
只采用 ownership altitude，不复制其 broad context 或 String error。
