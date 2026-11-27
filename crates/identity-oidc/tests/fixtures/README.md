RSA 私钥及 JWK 仅用于本仓签名 JWT / loopback JWKS 测试，使用 OpenSSL 随机生成，不用于部署。DER 是 PKCS#1 私钥，JSON 是对应 public JWK；第二把 key 验证错误签名与 public-key 轮换。合成 token 不代表 Microsoft Entra 或 Windows 原生互操作验收。
