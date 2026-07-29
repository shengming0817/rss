# settingsonly 独立运行手册

> #1796。本文是 `settingsonly-server` 与 `settingsonly-runtime` 镜像的 operator 入口。配置语义单源为
> `assemblies/settingsonly/src/config.rs`，提交的 Draft-07 schema 为
> `assemblies/settingsonly/config.schema.json`，可复制样例为
> `assemblies/settingsonly/settingsonly.example.toml`。

## 最终部署语义

settingsonly 只接受 `schemaVersion = 2`、`profile = "production"`、
`topology = "durable-isolated"`。生产闭包包含 Settings、PostgreSQL、Settings 专属 AMQP、Redis、Vault、
S3 WORM DLX archive、federated OIDC、rate limit、Prometheus 与 `runtimeexec`；v1、demo topology、缺失
section、未知字段、别名和 ambient fallback 均拒绝。

该 binary 有三个独立 loopback listener：Primary 默认 `127.0.0.1:8080`；Admin 默认
`127.0.0.1:8082`，仅承载 `GET /api/v1/runtime/inventory`；Health 默认 `127.0.0.1:8083`。inventory 要求
`runtime:inventory:read` 精确 permission，不按 principal kind 放宽或收窄；认证、授权与持久审计任一步失败都不会执行
inventory handler。Primary 与 Admin 共用 `FederatedPermissionAuthorizer`，Settings CUD 还要求 token、principal 与
ambient tenant 三者一致。

该 binary 当前没有 TLS listener capability，因此配置类型只接受 canonical loopback 明文地址（`127/8` 或
`[::1]`）。不得把 bearer 或匿名 metrics 暴露到公网。需要外部流量时，由外部 delivery 系统在同一网络
命名空间配置 TLS proxy，再转发到 loopback；不要把配置改成 wildcard bind。

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
- Vault、Settings AMQP、Redis 与 S3 私有 CA。

secret 只经 `/var/run/rss/secrets/serving-secret-bundle` 的固定闭合字段注入；不得写入 TOML、Docker argv、
普通环境变量或日志：

```text
pgWriterPassword
pgReaderPassword
pgDlxArchiverPassword
pgDlxVerifierPassword
pgDlxPurgerPassword
vaultToken
settingsAmqpPublisherUrl
settingsAmqpSubscriberUrl
redisUrl
tenantAuthorityKey
dlxHotVaultToken
dlxArchiveVaultToken
s3AccessKeyId
s3SecretAccessKey
```

`settingsAmqpPublisherUrl` 与 `settingsAmqpSubscriberUrl` 必须为不同的 `amqps://` credential，
分别只授予 Settings exchange publish 与 queue consume/bind 所需权限；两者使用 Settings 独立 vhost。
存在 `RSS_AMQP_URL` 即启动失败，不接受单 URL alias 或 fallback。
`redisUrl` 必须为 `rediss://`。Settings、DLX hot、DLX archive 三个 Vault token 必须互不相同。S3 bucket
必须由 provider 启动探针验证 versioning、Object Lock COMPLIANCE 与严格长于 30 天的默认 retention。

Linux 本机 smoke 可使用 host network 保持 loopback 策略：

```bash
docker run --rm --network host \
  --mount type=bind,src=/etc/rss/settingsonly.toml,dst=/etc/rss/settingsonly.toml,readonly \
  --mount type=bind,src=/run/secrets/settingsonly-bundle.json,dst=/var/run/rss/secrets/serving-secret-bundle,readonly \
  --mount type=bind,src=/etc/rss/federated.jwks.json,dst=/run/rss/federated.jwks.json,readonly \
  --mount type=bind,src=/etc/rss/postgres-ca.pem,dst=/run/rss/postgres-ca.pem,readonly \
  --mount type=bind,src=/etc/rss/vault-ca.pem,dst=/run/rss/vault-ca.pem,readonly \
  --mount type=bind,src=/etc/rss/amqp-ca.pem,dst=/run/rss/amqp-ca.pem,readonly \
  --mount type=bind,src=/etc/rss/redis-ca.pem,dst=/run/rss/redis-ca.pem,readonly \
  --mount type=bind,src=/etc/rss/s3-ca.pem,dst=/run/rss/s3-ca.pem,readonly \
  rss-settingsonly:1796 --config /etc/rss/settingsonly.toml
```

外部 delivery 系统必须以只读方式投影配置、JWKS、CA 和 secret，并让 TLS proxy 在同一网络命名空间访问
loopback listener。具体调度资源不由本仓库定义。镜像、配置与 secret 必须作为同一 generation 发布和回滚，
禁止旧 schema 双读、别名或 fallback。

## 探针、监控与终止

Health listener 固定提供：

- `/health/v1/healthz`：进程存活；
- `/health/v1/readyz`：聚合下列 required probes，任一非 Healthy 都返回 503：
  - `configs_ready`：Settings PG reader/writer；
  - `keyprovider_ready`、`vault_secret_resolver_ready`：Settings Vault key/KV；
  - `federated_access_token_jwks_ready`：federated JWKS；
  - `redis_ready`：分布式 lock；
  - `settingsonly_amqp_publisher_ready`、`settingsonly_amqp_subscriber_ready`：AMQP transport；
  - `settingsonly_dlx_archive_ready`、`settingsonly_dlx_hot_key_ready`、
    `settingsonly_dlx_archive_key_ready`、`settingsonly_dlx_lifecycle`：S3 WORM 与 DLX；
  - `outbox_relay_settings`、`event_consumer_<generated-subscription-slug>`、
    `settingsonly_inbox_sweeper`、`settingsonly_outbox_sampler`、
    `settingsonly_outbox_sweeper`：relay、ConsumerTx/inbox 与 maintenance；
- `/health/v1/metrics`：Prometheus 文本，仅可由本机/同网络命名空间 collector 访问。

只有 `/readyz` 返回 200 后才能接流量。Primary、Admin、Health 均使用各自配置的独立 loopback 端口。发送
SIGTERM/SIGINT 后，`runtimeexec` 停止 listener 并按精确一次 LIFO 顺序 drain；v2 的总 drain budget 只能为
60 秒，容器停止宽限期必须严格大于该预算，并预留进程收口时间：

```bash
docker stop --time 90 <container>
```

终止后必须观察进程正常退出；强制 SIGKILL 不提供 drain 保证。启动失败时不会发布 ready，已预绑定 socket 与已构造
provider 会回收。
