# Quickstart: rss-platform v0.1

```bash
cargo xtask codegen --check
cargo test -p rss-platform
cargo xtask public-api release --check
cargo xtask package-proof
```

最小 consumer 使用 `ApplicationBuilder::new` 配置 `TrustedIssuer`，在 `ApplicationModule` 注册
`contracts::RuntimeInventory` handler，启动后经 dispatcher 验证 token 并 typed dispatch，最后消费
`RuntimeHandle` 执行 bounded shutdown。完整独立 consumer 位于
`xtask/tests/fixtures/platform_public_consumer`，但证明必须使用 package helper 生成的真实 registry artifact，
不得改为 workspace path dependency。
