# Runtime 与 delivery 仓库边界

> 决策时间：2026-07-28 08:20 UTC。#1873、#1874 取代 #1779 中由应用仓库拥有部署投影的方向。

## 决策

RSS 应用仓库拥有可执行应用事实：AssemblyLock、RuntimePlan、typed 配置、provider 构造、实际 listener
绑定、health/readiness、SIGTERM drain、数据库 migration 内容，以及构建 serving/operator OCI 镜像的
Dockerfile。`deploy/docker-compose.yml` 和 `deploy/smoke.sh` 是本地开发与 release-image-on-demo-infra
验收载体，不是生产编排模板。

生产 delivery 系统拥有环境事实：不可变镜像选择与 provenance、replica 和资源预算、service/ingress、
workload identity、secret projection、网络策略、migration 调度、流量切换与终止 allowance。它可以消费
应用镜像和运行契约，并可把已选择 artifact 的 source revision/image digest 作为启动声明交给 inventory
报告；验证仍由 delivery 系统负责。它不得要求应用读取 delivery manifest、比较外部 workload identity，
或把环境投影纳入应用 fingerprint。

## 单一事实源

| 事实 | Owner |
|---|---|
| provider、listener identity/auth、domain 与 placement | RuntimePlan |
| 配置值、连接池 ceiling、secret 文件路径 | 各 assembly 的 typed 配置 |
| 实际 endpoint 与 provider/placement posture | 运行进程观测 |
| migration 顺序与 checksum | `postgres-migration-inventory` |
| migration/serving 二进制边界 | Dockerfile 的 `operator-runtime` / serving targets |
| drain 预算与信号处理 | assembly + `runtimeexec` |
| 调度、资源、网络、发布与证明 | 外部 delivery 系统 |

## 不变量

- 应用启动不读取外部 delivery 文件，也不保留兼容 reader、alias、双 fingerprint 或 fallback。
- serving 镜像不包含 migration operator；operator 镜像不承载 serving listener。
- listener 只有成功绑定并完成 provider readiness 后才接流量；SIGTERM 必须在 launcher allowance 内完成 drain。
- Health listener 和匿名 metrics 只允许 loopback 或受控内部网络；具体网络实现由外部 delivery 系统负责。
- 本仓不提交生产编排资源、渲染 golden、集群 schema 或对应工具版本门。

## 验收

本仓以 assembly/RuntimePlan gates、typed config tests、Docker image boundary、Compose smoke、readyz/provider
故障闭环和 SIGTERM exit-0 证据验收应用能力。外部 delivery 的环境级 rollout、policy 与 provenance 证据必须
在其自身仓库和真实环境中建立，不能由本仓静态载体代替。
