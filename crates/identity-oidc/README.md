# rss-identity-oidc

HttpOidc 实现 Core 的上游 OIDC 接口。宿主提供可信 assurance profile、许可访问私网的 tenant/issuer/client 与 CIDR、响应大小和连接预算、缓存容量与时限。在构造 HttpOidc 和 HttpEntra 时传入 ProviderClock::new(runtime.execution_timer().clone(), SystemTime::now)，使用宿主单调时钟控制等待，并以 UTC 墙钟校验上游日期。每次 prepare、exchange 和 test 接收原请求的绝对 Deadline。上游 metadata、授权码和 JWKS 在同一 provider revision 下使用，签名验证在解释身份声明之前执行。

生产传输对目标、解析结果和 TLS 身份执行准入。私有 IdP 的 CA 作为当前 provider 凭据的一部分传入。测试宿主可显式启用 test-support 构造隔离的协议 fixture。OIDC 验签使用 jsonwebtoken 11.1.0 的 AWS-LC 后端，HTTP/TLS 使用 Rustls。应用拥有回调路由及协议错误的产品响应。
