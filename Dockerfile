# syntax=docker/dockerfile:1
#
# bins/server 多阶段构建 → 最小运行镜像（#1134）。
#
# 范式对标（ref: cargo-chef README.md / ref: distroless examples/rust/Dockerfile）：
#   - cargo-chef 4 阶段（chef→planner→builder→runtime）把「依赖编译」与「应用编译」分层，
#     依赖层仅在 Cargo.toml/Cargo.lock 变化时失效 → 改业务代码不重编依赖（缓存友好）。
#   - distroless/cc 运行基底：glibc + ca-certificates + 非 root uid 65532，无 shell / 包管理器
#     （攻击面最小、只读 rootfs 友好）。
#
# 复现性：base 镜像钉 tag（生产再钉 digest，见 docs/ops/202606271438-003-container-image.md）
# + `--locked` 锁 Cargo.lock + cargo-chef 钉版。二进制 TLS 走 rustls+ring（ring 静态链接），
# 无 OpenSSL/native-tls 动态依赖 → distroless/cc 即可运行。
#
# 构建：  docker build -t rss-server:dev .
# 运行：  见 deploy/docker-compose.yml（演示栈）与部署文档。

# ── chef：钉版 rust 工具链 + cargo-chef（与 rust-toolchain.toml channel=1.96.0 一致）──────────────
FROM rust:1.96.0-bookworm AS chef
# reason: cargo-chef 钉版 = 复现性输入（不取 latest，避免 recipe 算法漂移）；--locked 锁其自身依赖。
# 须 ≥0.1.71（edition 2024 支持；workspace = edition 2024 / 工具链 1.96）。
RUN cargo install cargo-chef --locked --version 0.1.77
WORKDIR /app
# 仓库级 Cargo 配置把本地构建放入 `.cache/`；镜像构建固定回 cargo-chef 预期的共享层路径。
ENV CARGO_TARGET_DIR=/app/target

# ── planner：从完整源码算依赖配方（recipe.json 只含依赖图，不含业务源 → 改代码不失效）──────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── builder：先 cook 依赖层（缓存命中点）→ 再编 server/rss bins → strip 符号 ─────────────────────────
FROM chef AS builder
# 仅 server/rss 子图的依赖被 cook（--bin 透传给底层 cargo），无关 workspace 成员不参与。
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json --bin server --bin rss
COPY . .
RUN cargo build --release --locked --bin server --bin rss
# reason: strip 符号缩体积（不改全局 [profile.release]，避免影响整个 workspace 的开发构建）。
RUN strip target/release/server target/release/rss

# ── settingsonly-builder：独立 cook/build settingsonly-server，不污染 full runtime artifact ──────────
FROM chef AS settingsonly-builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json --package settingsonly --bin settingsonly-server
COPY . .
RUN cargo build --release --locked --package settingsonly --bin settingsonly-server
RUN strip target/release/settingsonly-server

# ── settingsonly-runtime：仅含 settingsonly binary + 外部 config schema ──────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot AS settingsonly-runtime
# settingsonly 只允许 loopback plaintext；端口元数据供同 Pod TLS sidecar 与编排器显式接线。
EXPOSE 8080 8082 8083
COPY --from=settingsonly-builder /app/target/release/settingsonly-server /usr/local/bin/settingsonly-server
COPY --from=settingsonly-builder /app/assemblies/settingsonly/config.schema.json /usr/share/rss/settingsonly/config.schema.json
ENTRYPOINT ["/usr/local/bin/settingsonly-server"]

# ── identityaudit-builder：独立 cook/build identityaudit-server ─────────────────────────────────
FROM chef AS identityaudit-builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json --package identityaudit --bin identityaudit-server
COPY . .
RUN cargo build --release --locked --package identityaudit --bin identityaudit-server
RUN strip target/release/identityaudit-server

# ── identityaudit-runtime：仅含 identityaudit binary + 外部 config schema ────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot AS identityaudit-runtime
# listener 只允许 loopback plaintext；外部流量与探针由同 Pod TLS sidecar 转发。
COPY --from=identityaudit-builder /app/target/release/identityaudit-server /usr/local/bin/identityaudit-server
COPY --from=identityaudit-builder /app/assemblies/identityaudit/config.schema.json /usr/share/rss/identityaudit/config.schema.json
ENTRYPOINT ["/usr/local/bin/identityaudit-server"]

# ── runtime：distroless/cc 非 root，server 为入口，rss 供离线维护命令使用 ─────────────────────────────
# 保持最后 stage，确保普通 `docker build .` 的默认镜像语义不变。
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
# 4 个 listener（Primary/Internal/Admin/Health）默认演示端口；实际 bind 地址由 RSS_*_LISTEN_ADDR 决定。
EXPOSE 8080 8081 8082 8083
COPY --from=builder /app/target/release/server /usr/local/bin/server
COPY --from=builder /app/target/release/rss /usr/local/bin/rss
# distroless:nonroot 已内置 USER 65532:65532（只读 rootfs 友好；无 shell ⇒ 无 Docker HEALTHCHECK，
# 探针交编排器 httpGet /health/v1/readyz，见部署文档）。
ENTRYPOINT ["/usr/local/bin/server"]
