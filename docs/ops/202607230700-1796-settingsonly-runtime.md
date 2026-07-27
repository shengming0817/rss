# settingsonly 独立运行手册

> #1796。本文是 `settingsonly-server` 与 `settingsonly-runtime` 镜像的 operator 入口。配置语义单源为
> `assemblies/settingsonly/src/config.rs`，提交的 Draft-07 schema 为
> `assemblies/settingsonly/config.schema.json`，可复制样例为
> `assemblies/settingsonly/settingsonly.example.toml`。

## 最终部署语义

settingsonly 只装配 Settings、PostgreSQL、Vault、federated OIDC、rate limit、Prometheus 与
`runtimeexec`。Identity/Audit/Event transport 不在闭包内；这是最终语义而不是兼容阶段：Primary 缺失或无效
凭证返回 401，有效 federated 凭证完成验签后固定返回 403，不存在 allow 分支。

该 binary 有三个独立 loopback listener：Primary 默认 `127.0.0.1:8080`；Admin 默认
`127.0.0.1:8082`，仅承载 `GET /api/v1/runtime/inventory`；Health 默认 `127.0.0.1:8083`。inventory 要求
`runtime:inventory:read`，且精确 authorizer 只允许 Admin/SuperAdmin；认证、授权与持久审计任一步失败都不会执行
inventory handler。Primary 的 `RejectAuthorizer` 语义不受 Admin route 影响。

该 binary 当前没有 TLS listener capability，因此配置类型只接受 canonical loopback 明文地址（`127/8` 或
`[::1]`）。不得把 bearer 或匿名 metrics 暴露到公网。需要外部流量时，由同一 Pod 网络命名空间中的 TLS proxy
sidecar 终止 TLS，再转发到 loopback；不要把配置改成 wildcard bind。

## 构建与发现

仓库根执行：

```bash
./hack/cargo.sh build -p settingsonly --bin settingsonly-server
./hack/cargo.sh run -p settingsonly --bin settingsonly-server -- --help
docker build --target settingsonly-runtime -t rss-settingsonly:1796 .
```

`settingsonly-runtime` 不是 Dockerfile 默认最终 stage，必须显式传 `--target`。镜像为 distroless nonroot
（uid 65532），固定 entrypoint `/usr/local/bin/settingsonly-server`，只包含该 binary 与
`/usr/share/rss/settingsonly/config.schema.json`。

## 配置、挂载与密钥

复制 `assemblies/settingsonly/settingsonly.example.toml` 后只替换部署值。文档必须满足镜像内 schema，未知字段、
旧版本、默认回退和变量别名均拒绝。下列文件按 sample 路径只读挂载：

- settingsonly TOML；
- federated ES256 JWKS；
- PostgreSQL 私有 CA（配置 `verifyFull` 时）；
- Vault 私有 CA。

四项密钥只经固定环境名注入，建议由密管生成 `0600` 的临时 env file；不得写入 TOML、Docker argv 或日志：

```text
RSS_SETTINGSONLY_PG_WRITER_PASSWORD
RSS_SETTINGSONLY_PG_READER_PASSWORD
RSS_SETTINGSONLY_PG_MIGRATOR_PASSWORD
RSS_SETTINGSONLY_VAULT_TOKEN
```

启动还必须注入两项非 secret 构建身份，进程只在启动快照读取一次：

```text
RSS_BUILD_SOURCE_SHA=<40 位小写十六进制提交 SHA>
RSS_BUILD_IMAGE_DIGEST=sha256:<64 位小写十六进制镜像摘要>
```

`RSS_BUILD_IMAGE_DIGEST` 必须与绑定 DeploymentPlan 中 settingsonly workload 的镜像摘要完全一致，否则在 bind
socket 前失败。`RSS_BUILD_SOURCE_SHA` 是部署方声明，不代表进程完成 OCI provenance 或 same-head 自证明。

Linux 本机 smoke 可使用 host network 保持 loopback 策略：

```bash
docker run --rm --network host \
  --env-file /run/secrets/settingsonly.env \
  --mount type=bind,src=/etc/rss/settingsonly.toml,dst=/etc/rss/settingsonly.toml,readonly \
  --mount type=bind,src=/etc/rss/federated.jwks.json,dst=/run/rss/federated.jwks.json,readonly \
  --mount type=bind,src=/etc/rss/postgres-ca.pem,dst=/run/rss/postgres-ca.pem,readonly \
  --mount type=bind,src=/etc/rss/vault-ca.pem,dst=/run/rss/vault-ca.pem,readonly \
  rss-settingsonly:1796 --config /etc/rss/settingsonly.toml
```

在 Kubernetes 中使用只读 ConfigMap/Secret projection，并让 TLS proxy sidecar 与进程共享 Pod 网络命名空间。
Primary/Admin 流量和 kubelet HTTP probe 都不能直接访问 Pod IP 上的 settingsonly loopback socket：它们必须经
同 Pod sidecar 的 TLS/探针端口转发；也可让 sidecar 在同一网络命名空间内执行 loopback probe 后导出自身的
kubelet 探针端口。文件/Secret generation、DeploymentPlan、image 与两项 `RSS_BUILD_*` 必须作为同一 generation
原子发布。回滚也必须原子恢复上一组 image digest、source SHA、DeploymentPlan、配置和 Secret，不得只回滚
image 或通过旧 schema 双读、别名、digest fallback 拼接 generation。

## 探针、监控与终止

Health listener 固定提供：

- `/health/v1/healthz`：进程存活；
- `/health/v1/readyz`：聚合 PG、Vault resolver/key provider、federated JWKS 与 Settings workers；
- `/health/v1/metrics`：Prometheus 文本，仅可由本机/同 Pod collector 访问。

只有 `/readyz` 返回 200 后才能接流量。Primary、Admin、Health 均使用各自配置的独立 loopback 端口。发送
SIGTERM/SIGINT 后，`runtimeexec` 停止 listener 并按精确一次 LIFO 顺序 drain；容器停止示例：

```bash
docker stop --time 30 <container>
```

终止后必须观察进程正常退出；强制 SIGKILL 不提供 drain 保证。启动失败时不会发布 ready，已预绑定 socket 与已构造
provider 会回收。
