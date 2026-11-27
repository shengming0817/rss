# rss-identity-web-credentials

在宿主自己的 handler 中向 authenticate_request 传入 Authority、可信 HttpConfig、ExecutionBinding、HeaderMap、SessionActivity 和剩余时限。Passive 查询当前会话并保持 idle 截止；Active 在同源、请求标记、CSRF 验证通过后续期。Bearer 调用 authenticate_bearer_request。两条路径均拒绝混用凭据。

用 issued_cookie 从已提交的 IssuedSession 提取安全 Cookie 头和 CSRF 值，由产品构造响应。BrowserBinding 管理 OIDC 浏览器关联，操作证明 Cookie 专用于已绑定的一次性操作。产品持有路由、DTO、网关信任与资源授权。

在已推送的 RSS 固定提交上运行 python3 crates/identity-web-credentials/tests/consumer/verify.py，分别构建并执行四库的独立消费者。这些临时 workspace、lock 与 target 位于 rss-external-check/。
