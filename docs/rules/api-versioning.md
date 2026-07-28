# API 版本策略

## 何时升级版本

> 轴 B（HTTP / event / command wire）的 `active` 破坏式变更默认必须新建版本目录和
> 新 contract ID，并完整保留旧 identity。intentional no-compat 变更只有在用户明确授权且 commit
> 携带 `contract breaking` 绑定 base commit 与完整 deny findings 生成的精确
> `Contract-Breaking-Authorization` fingerprint 时才可原地实施；缺失、过期或部分授权均 fail-closed。
> 另一个分期例外是 #1696 的三条 consistency/effect posture drift：
> deny-mode ratchet 前只作精确确认的 review finding；除此之外不存在 pre-GA 或原地修改例外。

除上述精确授权的 intentional breaking 外，以下变更必须新建版本目录和新 contract ID：

- 删除或重命名响应字段
- 改变字段类型或枚举语义
- 改变鉴权要求、幂等语义、分页语义
- 改变错误码语义或 HTTP 状态码

新增可选响应字段可以留在当前版本。新增必填请求字段必须升级版本。

## 轴 A / 轴 B 边界

RSS 当前没有外部 Rust API 调用方，因此轴 A（库 crate 公开 API 与 authoring schema）
的破坏变更不保留旧 Rust API shim；公开符号面仍由 `cargo public-api` /
`cargo-semver-checks` 显式审查。

轴 B 是版本化 wire contract，不使用轴 A 的“不留 shim”结论绕过消费方隔离。
`active` wire 发生破坏式变更时必须：

- 新建 `contracts/{kind}/{domain}/{version+1}/` 与新 contract ID；
- 保留旧 contract identity 及其 wire 语义，不用新版本替换或删除旧版本；
- 完成契约扇出闭环（schema → generated → 域 crate metadata → tests → docs，见
  `contract-fanout.md`）。

`cargo xtask contract breaking` 以 base lifecycle 分级：`active` 默认 deny、`deprecated` warn、`draft`
skip。`LOCAL_ONLY_BOUNDARY_CHANGED`、`EFFECT_ADDED`、`EFFECT_REMOVED` 是 #1696 固定的 pre-ratchet
review finding，不直接否决 active 变更；但必须用命令给出的精确 `Contract-Review-Ack` commit trailer
确认后才能通过。trailer fingerprint 绑定 base commit 与排序后的 rule/subject/detail，变更漂移后不可复用。
该例外不授予其它 active wire 原地破坏权限，更不得先将 `active` 降级绕门。

intentional breaking authorization 与 review ack 正交：前者只授权 fingerprint 中精确列出的 deny，
后者只确认固定 review-only posture findings。两者都不接受 flag、环境变量、自由文本或 lifecycle 降级；
任何 contract/schema/base 漂移都会改变 fingerprint 并要求重新授权。

INVARIANT: CONSISTENCY-EFFECT-BREAKING-REVIEW-01（Hard 闭枚举/fingerprint 内核 + Medium Git/verify 门；
carrier 在 `xtask/src/contract/breaking.rs`）。active 默认 deny；固定三条 review rule 只有在精确确认存在时
保持 warn，未确认 fail-closed；无 flag、环境变量、日期窗口或自由文本豁免。

## 内部 API

`/internal/v1/` 是服务间控制面，不是绕过版本策略的后门。internal contract 同样需要：

- contract.toml 声明鉴权和 caller
- path、schema、handler、generated code 同步
- `active` 破坏式 wire 变更新增版本和 contract ID，并保留旧 identity

## Setup / bootstrap 路径

没有顶级 `/api/v1/setup/` 命名空间。首启动引导端点和所有业务端点一样挂在所属域 crate 的版本化
前缀下，遵循同一 `/api/v{N}/{domain}/...` 约定（框架归属契约 `owner: _framework` 无绑定域，
使用 contract domain 作为路径段，如 `/api/v1/deviceidentity/...`、`/api/v1/devicestate`）：

- bootstrap admin：`/api/v{N}/{domain}/setup/admin`（如 `/api/v1/access/setup/admin`）
- setup status：`/api/v{N}/{domain}/setup/status`

「setup」的特殊性在鉴权与生命周期，不在路径位置：

- 鉴权用 `auth.bootstrap:true`（HTTP Basic + 环境凭据），不是 JWT/RBAC。
- admin 创建后端点返回 410 Gone（一次性引导边界）。
- pre-auth 阶段经 `X-Tenant-ID` header 解析租户（此时还没有 JWT claim）。

bootstrap admin 路径形状由单一谓词 `metadata::is_bootstrap_path`
（`^/api/v\d+/[^/]+/setup/admin$`，强制带 domain 段）锁定；治理规则（`cargo xtask`，Medium）只允许
`auth.bootstrap:true` 出现在匹配该谓词的路径上，缺 domain 段的 `/api/v1/setup/admin` 被
fail-closed 拒绝。破坏式 wire 变更照常走所属域 crate 的版本目录升级，与上文规则一致。
