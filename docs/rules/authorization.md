# Authorization 规则

本文拥有 permission、PDP/authorizer、resource ownership、field mask、HTTP/gRPC enforcement 与 external security fact。

## Permission 与入口

- active HTTP/gRPC contract 必须声明 closed permission 或显式 closed opt-out；未知/缺失模式 fail-closed。
- authentication 只建立 principal；authorization 必须同时绑定 principal、tenant、action、resource 与 context。
- handler 只能在 enforcement 成功并消费一次性 obligation 后运行；不得调用 PDP 后忽略结果或自行 fallback RBAC。

## Authorizer 与 PDP

- authorizer 拥有 policy request 规范化、PDP 调用、fail-closed 与 obligation mint；PDP 不直接调用 handler/repository。
- allow/deny/indeterminate/error 是闭值；indeterminate、timeout、provider error 默认 deny。
- obligation 私有、move-only、一次消费，并绑定 policy revision、principal、tenant、permission 与 resource fingerprint。
- cache key 必须覆盖全部授权维度；policy/credential revision 变化使旧 decision 不可消费。

## Resource ownership 与 RowScope

- resource identity/owner fact 来自 authoritative repository 或 verified external fact，不信任请求 body。
- RowScope/FieldMask 是 typed closed obligation；repository/rendering 层消费，不通过字符串 SQL 或字段名列表旁路。
- deny 路径不得读取/渲染被拒绝资源；not-found masking 不能改变审计中的真实 deny reason。
- cross-tenant/admin action 使用独立 permission/capability 与 durable audit，不复用普通 allow。

## Durable policy

- policy identity、revision、effect、subject/resource selectors 与 lifecycle 由 typed schema 持有。
- update 使用 CAS/immutable revision；同 revision 不同内容冲突。activation 与 rollback 必须可审计且原子。
- serving runtime 只消费 active compiled snapshot；policy load、parse、compile、signature 或 storage 失败必须 deny，
  不得回退旧缓存 allow、内置 allow、RBAC baseline 或部分 policy。

## External Resource Security Fact

- authoritative fact 绑定 source coordinate、tenant/device、typed value、revision、observed time 与 expiry。
- RSS 只消费 authoritative fact，不拥有外部资源生命周期、目录或管理 API；未实现的签名与撤销不得写成现有保证。
- 缺失、未来、过期、错型、重复、tenant/resource 不匹配或 provider failure 必须在 baseline 前 deny；
  不得回退旧 revision、RBAC baseline 或从 payload 猜测 owner。

## Device policy Draft candidate

- Draft candidate authorizer 只接受 generated policy-put contract、typed write permission、User principal、
  authorized subject tenant 与 canonical path DeviceId；durable-policy basis 必须来自同次 Common ABAC 求值。
- `resource.owner` / `resource.riskClass` 只经 tenant/device-bound typed PIP 读取。Deny、NoMatch、事实缺失、
  未来、过期、错型、重复、跨 scope 或 provider failure 均拒绝，且不得回退 RBAC baseline。
- #2115 只交付未挂载的 typed candidate component 与 T1/T2 证明，不注入现有 runtime/identityaudit root；
  production 选择、装配、挂载和 T3 证据由 #2117 或后续激活 PBI 闭合。

## HTTP/gRPC 与审计

- transport adapter 必须把 verified auth context 传入同一 enforcement seam；metadata/header 不能直接铸造 obligation。
- 每个 closed authorization decision 写入一个 durable audit event，记录 verified subject、tenant、
  permission/resource coordinate、decision 与可用的闭值 reason。
- start/finish 配对只适用于确有 typed attempt ID 的 operator flow。契约要求审计的 mutation 在 append 失败时必须
  失败或回滚；禁止记录 token、credential、自由策略文本或资源 PII。

## Carrier

- Hard：closed permissions/modes、private verified principal/obligation、typed RowScope/FieldMask、必填 enforcement seam。
- Medium：contract/codegen guards、PDP/provider conformance、negative authorization、tenant/repository integration。
