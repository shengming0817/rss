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

Saga definition 的执行语义不按“新增可选字段”处理。step 顺序、receipt schema、effect scope、
compensation effect scope、idempotency/compensation/retry class 或 retry policy 的任何变化都会形成新的
`ACTION_REGISTRY_GENERATION`；破坏式演进必须新建版本目录和新 contract ID，并完整保留旧 identity。

## 轴 A / 轴 B 边界

轴 A 只覆盖由产品面 owner 与 release artifact 明确承诺的 Rust API 和 authoring schema。RSS 当前没有外部 Rust API
调用方，因此轴 A 的破坏变更不保留旧 Rust API shim。唯一 release-check `public-api` gate 同时执行 internal
与 release exact-set、base/current 交集逐包且分别覆盖 default/all-features 的 `cargo-semver-checks`、公共依赖
和结构化类型泄漏证明。两个 feature profile 分开捕获、分开诊断，不把 all-features 当成默认面的并集。首次选入
package 不继承历史 internal `pub` 承诺；从清单显式移除 package 即终止其后续轴 A 承诺，不扫描其 internal
历史、不生成 shim，也不引入双读或退出 metadata。仍在 base/current 交集内的 package 必须完成 SemVer 证明。

Platform Application vNext 是由 #2107 原子激活的 breaking 0.x cutover；具体 package 版本从 Cargo metadata 派生，
不在规则文档复制。v0.2 exported surface 仅是历史，不构成 compatibility authority。Foundation identity/context
提取、Platform async waist、Auth/RuntimeExec bridge 与旧 baseline 已原子切换；禁止 alias、deprecated re-export、
shim、`From`/`TryFrom`、feature flag、双读写、双 dispatch 或 v0.2
fallback。旧 #2045 executable contract 已原子删除，同样不构成 compatibility authority。

`cargo xtask public-api release --check`
只验证 baseline exact-set；canonical ReleaseCheck 才聚合 default/all-features SemVer、publish closure、
forbidden-type leakage，并在同一 release-only carrier 中执行 `cargo xtask package-proof`。后者从同一 revision 的
每个 selected package 生成真实 `.crate`，验证 clean HEAD/VCS revision、结构化 package content、feature/MSRV/docs，
再建立 local-registry、独立 Git/Cargo.lock 与 `--locked --offline` consumer proof。Release Surface 的 selected、
planned 与 executed package 集合必须精确相等；package-specific behavior 只作闭合执行投影，不能另行选择 lifecycle。
任何 internal path alias、deprecated re-export、shim 或 From/TryFrom 兼容入口都不允许作为迁移手段。
publish closure 与顺序只由现有 Cargo dependency graph、`plan_publish_closure`/`stable_publish_order` 派生；
package-proof 的 selected/planned/executed 必须保持 exact-set。不得另建 release group、registry、runner、schema
或手写发布顺序作为第二真源。

根 `Cargo.toml` 的 `[workspace.metadata.release-surface]` 是轴 A 唯一正向发布选择：只有被选 package 及其
public API owner、API stability 和显式 official-profile artifact 归属进入 Release Surface；未选 package 默认
internal。package version、MSRV、Cargo publish eligibility 以及 binary/image identity 分别从同一次 Cargo metadata
和既有 assembly artifact governance 派生，不在选择中复制。选择与 Cargo publishable set 必须双向精确一致；
`profile = "production"`、artifact `supported` 或 binary/image 存在均不能自动选择或激活 official profile。设计边界
见 [`Spec 010`](../spec/010-release-surface-convergence/spec.md)。

公开品牌、registry 前缀与 internal package → public package 映射只由
[`architecture.md` §公开发布命名](architecture.md#公开发布命名) 持有。本文件只消费该命名决策，不复制 package
名称或把尚未选择的 internal package 提升为 Release API。

仓内 `pub` 只表示 Rust 跨 crate 可见性，不自动进入轴 A。`publish = false` 的 internal crate 可以保留
`cargo public-api` curated baseline 作为安全敏感 exported-symbol 漂移审查，但该 baseline 不把 internal crate 提升为
Release API，也不产生外部 SemVer 承诺；`diport` 属于这一类 Internal Provider Contract。

baseline 有且只有两个 owner：`public-api/*.txt` 是 internal signature drift carrier，
`release-api/*.txt` 是正向选择 package 的轴 A exported Rust surface carrier。二者从同一份 validated
Release Surface 派生并互斥；snapshot、`pub`、publishability 或 artifact 存在都不能替代正向选择。
更新先在 `.cache/public-api-staging/` 构造并持久化完整 immutable generation，再通过单次原子目录交换
切换 owner；shared/exclusive OS lock 覆盖同一 owner 的 check/update 全过程。进程中断只会留下 ignored
staging generation，下一次持锁更新在构造新 generation 前清理；live `public-api/` / `release-api/` 始终是
完整旧 generation 或完整新 generation，不存在逐文件发布、补偿式 rollback 或伪 content-CAS 路径。
分别使用 `cargo xtask public-api internal [--layer basis|engine|curated] [--check]` 与
`cargo xtask public-api release [--check]`。缺失、漂移、孤儿或异常目录均 fail-closed，不存在 missing
宽限、手填 package、路径 alias、双写或兼容 reader。

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

event、command、saga 与 projection 的 resolved schema hash 会进入 durable wire/instance identity；即使
JSON Schema 集合论 diff 看似兼容，只要 hash 旋转也必须产生 `RESOLVED_SCHEMA_HASH_CHANGED`。`format`
从无到有会改变 generated scalar，同样属于 `FIELD_FORMAT_CHANGED`，两者均服从上述精确 intentional
breaking authorization，不接受“仅文档”或 pre-GA 作为隐式豁免。

intentional breaking authorization 与 review ack 正交：前者只授权 fingerprint 中精确列出的 deny，
后者只确认固定 review-only posture findings。两者都不接受 flag、环境变量、自由文本或 lifecycle 降级；
任何 contract/schema/base 漂移都会改变 fingerprint 并要求重新授权。

INVARIANT: CONSISTENCY-EFFECT-BREAKING-REVIEW-01（Hard 闭枚举/fingerprint 内核 + Medium Git/verify 门；
carrier 在 `xtask/src/contract/breaking.rs`）。active 默认 deny；固定三条 review rule 只有在精确确认存在时
保持 warn，未确认 fail-closed；无 flag、环境变量、日期窗口或自由文本豁免。

## Saga definition 保留与 resume

Saga instance 固定 contract ID、definition version、schema digest 和 action registry generation。
start 使用 assembly 选择的精确 identity，resume 使用 instance 持久化的精确 identity；unknown identity
必须 fail-closed，禁止回退 latest、相似 schema 或当前 registry 成员。

registry 不提供 remove/retire API。即使 definition 已 deprecated，在 durable、跨副本 retirement proof
carrier 能证明不存在需要该 identity 的 instance 之前也必须保留；删除 Saga definition 是 breaking deny，
不能用 alias、shim、双读或默认绑定“当前版本”绕过。durable receipt/completion 与 unknown-outcome resume
统一由单一 `SagaDurableStore` 承载；不得据此恢复 split-store、兼容 reader 或双写路径。

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
