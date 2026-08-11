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

PostgreSQL TLS 策略只接受 `sslMode = "verifyFull"`；其他模式在文档反序列化阶段拒绝。五个 workload role
由组合根固定为 `rss_app`、`rss_app_read`、`rss_dlx_archiver`、`rss_dlx_verifier`、`rss_dlx_purger`，
TOML 只配置各 role 的 `maxConnections`。旧 `username` 字段属于未知字段并直接拒绝，不提供 alias、默认值或兼容路径。

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

## Production artifact 机器验收

production artifact 的唯一 machine carrier 是 `journeys` 的
`settingsonly_production_artifact` target（需要 `integration` feature）。六个独立、精确可选的 T3 join
hazard 为：

```bash
./hack/cargo.sh test -p journeys --features integration --test settingsonly_production_artifact \
  settingsonly_image_mount_spiffe_readiness_join -- --exact --nocapture --test-threads=1
./hack/cargo.sh test -p journeys --features integration --test settingsonly_production_artifact \
  settingsonly_image_pg_outbox_amqp_inbox_join -- --exact --nocapture --test-threads=1
./hack/cargo.sh test -p journeys --features integration --test settingsonly_production_artifact \
  settingsonly_image_sigkill_redelivery_join -- --exact --nocapture --test-threads=1
./hack/cargo.sh test -p journeys --features integration --test settingsonly_production_artifact \
  settingsonly_image_sigterm_drain_join -- --exact --nocapture --test-threads=1
./hack/cargo.sh test -p journeys --features integration --test settingsonly_production_artifact \
  settingsonly_image_projection_shadow_start_restart_drain_join -- --exact --nocapture --test-threads=1
./hack/cargo.sh test -p journeys --features integration --test settingsonly_production_artifact \
  settingsonly_image_projection_fatal_exit_readiness_join -- --exact --nocapture --test-threads=1
```

carrier 固定构建 `settingsonly-runtime`，不接受 command/entrypoint override，并在运行期检查真实 OCI
ENTRYPOINT、进程路径和 nonroot 用户。配置、JWKS、PostgreSQL/Vault/AMQP/Redis/S3 五份私有 CA、secret
bundle 与 SPIFFE Workload API UDS 只经只读 mount/volume 提供；入口以真实 SPIFFE X.509 身份和精确
allow-set 经 mTLS 访问 production listener。Input/ready case 要求聚合 readyz 为 Healthy，且下列 11 个
provider join probe 全部为 Healthy：

```text
configs_ready
keyprovider_ready
vault_secret_resolver_ready
federated_access_token_jwks_ready
settingsonly_redis_ready
settingsonly_amqp_publisher_ready
settingsonly_amqp_subscriber_ready
settingsonly_dlx_lifecycle
settingsonly_dlx_archive_ready
settingsonly_dlx_archive_key_ready
settingsonly_dlx_hot_key_ready
```

其余五项只覆盖 production 组合后才存在的接缝：L2 join 经真实 mTLS frontend 发布一次 Settings 事件，
观察同一 event 的 PG config/outbox、Rabbit 投递与 inbox `done`；SIGKILL join 在 Rabbit 已确认 unacked 后
杀死真实 OCI 进程，以同一 image/config/provider generation 重启并验证 redelivery 收口且无第二次 domain
effect；SIGTERM join 在 inbox 已进入确定性 inflight 屏障后向真实 ENTRYPOINT 发送信号，验证停止新接入、
当前事务/Ack 收口、零码退出以及 Primary/Admin/Health 端口全部释放；projection shadow start/restart/drain
join 在真实 OCI 进程上证明 shadow projection 接纳、SIGTERM drain、同代重启后续写与再 drain；projection
fatal-exit readiness join 在撤销 projection worker 源能力后证明 readiness 转为 Unhealthy。provider fault
matrix、CRUD、ACL、rollback 和下层 settlement 语义仍由既有 T1/T2 owner 证明，不在这个 T3 carrier 中复制。

该 carrier 激活时已原子删除 legacy carrier、配套脚本和测试专用环境输入；不提供 alias、shim 或双路径。
`settingsonly_runtime` 保留为快速进程内 T1/T2 lifecycle owner，但不再是 artifact selector，也不包装或调用
上述 T3 case。精确闭集、映射和 artifact identity 的 enforcement 位于 Rust/Cargo/assembly machine carrier；
本文只解释运维和定位语义。

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
pgProjectionWorkerPassword
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

镜像身份固定为 `65532:65532`。delivery 投影必须让该身份可遍历 secret 目录并读取 bundle，同时禁止
group/other 权限和可写挂载；production artifact fixture 的精确证明采用目录 `65532:65532/0500`、文件
`65532:65532/0400` 的 Docker-owned volume，并把整个 `/var/run/rss/secrets` 只读挂入容器。外部 delivery
可以采用等效的 ownership/projected-volume 机制，但不得依赖宿主运行用户 UID、world-readable mode、root
容器或运行时 `--user` 覆盖。

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

外部 delivery 系统必须按上述 non-root 可读且非 world-readable 契约，以只读方式投影配置、JWKS、CA 和
secret，并让 TLS proxy 在同一网络命名空间访问 loopback listener。具体调度资源不由本仓库定义。镜像、
配置与 secret 必须作为同一 generation 发布和回滚，禁止旧 schema 双读、别名或 fallback。

`pgProjectionWorkerPassword` 只供 `rss_projection_worker` 登录。该角色必须保持 `NOINHERIT`、无表级权限、
无角色成员关系，并且只能执行 0095 安装的 purpose-bound tenant/source/checkpoint/DLQ/apply 函数；启动时
SettingsOnly 会在 listener 发布前校验完整 ACL 与函数 fingerprint。Projection target generation 由
`assembly.toml` 的 `WorkflowActivation::Projection.targetGeneration` 独立固定为 `v3`，经 AssemblyLock 与
RuntimePlan 签发给 worker binding；运行配置不再重复声明该身份。`postgres.projectionWorker.maxConnections`
是独立 worker pool 上限，不与 serving reader/writer pool 共用。

## 探针、监控与终止

Health listener 固定提供：

- `/health/v1/healthz`：进程存活；
- `/health/v1/readyz`：聚合下列 required probes；`Unhealthy` 返回 503，`Degraded` 保留 200
  并携带诊断，避免可重试 provider 故障或单租户隔离把整个服务摘流：
  - `configs_ready`：Settings PG reader/writer；
  - `keyprovider_ready`、`vault_secret_resolver_ready`：Settings Vault key/KV；
  - `federated_access_token_jwks_ready`：federated JWKS；
  - `settingsonly_redis_ready`：分布式 lock；
  - `settingsonly_amqp_publisher_ready`、`settingsonly_amqp_subscriber_ready`：AMQP transport；
  - `settingsonly_dlx_archive_ready`、`settingsonly_dlx_hot_key_ready`、
    `settingsonly_dlx_archive_key_ready`、`settingsonly_dlx_lifecycle`：S3 WORM 与 DLX；
  - `outbox_relay_settings`、`event_consumer_<generated-subscription-slug>`、
    `settingsonly_inbox_sweeper`、`settingsonly_outbox_sampler`、
    `settingsonly_outbox_sweeper`：relay、ConsumerTx/inbox 与 maintenance；
  - `projection_worker:settings.config-projection`：SettingsOnly shadow projection worker；启动和首次有界
    source/checkpoint 观察完成后 Healthy；可重试 provider 故障或 durable tenant quarantine 为 Degraded/200；
    checkpoint fencing 是正常竞争且不降级；catalog/target/source 等全局永久错误才终止 worker、锁为
    Unhealthy 并使 `/readyz` 返回 503；
- `/health/v1/metrics`：Prometheus 文本，仅可由本机/同网络命名空间 collector 访问。

只有 `/readyz` 返回 200 后才能接流量。Primary、Admin、Health 均使用各自配置的独立 loopback 端口。发送
SIGTERM/SIGINT 后，`runtimeexec` 停止 listener 并按精确一次 LIFO 顺序 drain；v2 的总 drain budget 只能为
60 秒，容器停止宽限期必须严格大于该预算，并预留进程收口时间：

```bash
docker stop --time 90 <container>
```

终止后必须观察进程正常退出；强制 SIGKILL 不提供 drain 保证。启动失败时不会发布 ready，已预绑定 socket 与已构造
 provider 会回收。

tenant apply 的永久、invariant、rollback-failed 或 out-of-order 结果会把精确
`tenant + projection + target generation` 写入 durable quarantine，保存闭值 reason、state 与 failed LSN。
后续 tenant discovery 排除该项，但继续轮转其他 tenant；worker 重启不会清除或热循环重试该 poison。
修复根因并用 Projection `replay` 权限重放到失败坐标后，operator 必须通过 action-bound
`recover_quarantined_tenant(expected_failed_lsn)` 执行受 fencing 的释放；expected LSN 不匹配时不改变状态。
