# Tenant Context 规则

本文拥有 TenantId、tenant authority、RowScope 与可信来源，不拥有数据库隔离或授权执行。

## Tenant identity

- TenantId 使用 canonical typed identity；空值、非 canonical、自由字符串和跨类型转换在入口拒绝。
- tenant 是安全维度，不得从 request body、query、业务 payload、broker普通 header 或日志字段推导。
- tenant context 必须在进入 domain/provider 前完成验证并作为必填 typed 参数传播。

## HTTP 与 service identity

- 用户请求 tenant 来自 verified principal/credential 的已授权 scope；客户端 header 只能作为 challenger，
  不能扩大 principal scope。
- service-to-service tenant 必须由 signed canonical claim 绑定 issuer、audience、subject、tenant 与有效期。
- `INVARIANT: TENANCY-SERVICE-IDENTITY-SCOPE-01`：claim-bound service tenant 由私有 verified evidence、
  exact verifier 与 production callsite funnel 承载；缺失/不匹配 fail-closed。
- bootstrap/public/service-owned 例外必须是 contract closed mode，不能用空 tenant 或 special string 表示。

## Broker authority

- broker topic/header 的 tenant 不是授权事实。relay 签发的 tenant authority 必须绑定 tenant、domain、contract、
  topic、message ID、issuer/audience 与 TTL。
- consumer 在写 application DLQ 或 tenant persistence 前验证 authority；失败时不构造 tenant transaction。
- device broker principal 由 peer credential/assertion 产生，不信任 payload/user property。

## RowScope 与 visibility

- RowScope/RowVisibility 是只携带 scope/tenant 的闭值 visibility。普通 visibility 由 verified
  principal/context 或 trusted repository capability 构造；类型本身不声明 resource/action 绑定。
- handler/repository 只能消费 typed scope；不得重新解释字符串、拼 SQL 或把 trace context 当授权。
- cross-tenant/global scope 需要独立 capability 和审计，普通 tenant context 不可升级。
- audit read 不得以 operator 身份隐式绕过 tenant；跨 tenant 查询使用独立接口、显式 reason 与 durable audit。

## 失败语义与载体

- tenant 缺失、冲突、过期、issuer/audience mismatch 或 scope 扩大均 fail-closed。
- Hard：TenantId/newtype、private verified evidence、必填 context 与 move-only obligation。
- Medium：auth verifier、callsite/contract guards、broker authority integration 与 negative authorization tests。
