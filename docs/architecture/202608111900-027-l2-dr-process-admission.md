# ADR-027：L2 DR 进程级 Admission Fence

状态：Accepted
日期：2026-08-11
Issue：#2009

## 决策

RSS 为 L2 disaster recovery 提供应用内、持久化命令驱动的进程级 admission fence。每个 serving
进程只有一个 `RuntimeAdmissionCoordinator`，并 mint 三条封闭 lane：Relay、Consumer、Writes。
`pause` 在同一线性化点关闭三条 lane，已有 permit 完成后才产生该 boot 的 `drained` ack；恢复只能按
Relay、Consumer、Writes 顺序推进，每一步均等待 declared instance set 的 phase ack exact-equality。

PostgreSQL 只保存一个 active admission epoch 和 append-only per-instance phase receipts。receipt 绑定
assembly identity、verified RuntimePlan fingerprint、delivery 配置的稳定 instance ID 与随机 boot ID。
RSS 证明 `declaredInstances == acknowledgedInstances` 且没有 unexpected instance；它不发现或证明
deployment 的真实副本全集。副本清单、入口冻结、restore 与跨实例顺序仍由 delivery owner 持有。

restore 前后复用同一协议，但必须使用不同 epoch。restore 前 receipt 只进入外部 change record；它不
导入恢复后的数据库，也不能被 `apply` 消费。恢复后的 serving 以
`RSS_DR_REQUIRED_ADMISSION_EPOCH_ID` fail-closed 启动，并以同一 pause 协议的
`require-startup-epoch-witness` capability 位重新 pause/drain；数据库仅在全部 declared receipt 携 exact
epoch witness 时推进 `Drained`，随后 `apply` 才在同一 SQL
事务中消费当前 lineage 的 fence、执行恢复 mutation 并写 durable recovery receipt。

每个 operator admission 命令以同一 `request_id` 写 durable `start` 与 `finish` 审计。`start` 写入失败时
不得执行控制动作；动作已提交而 `finish` 或 cleanup 失败时，CLI 仍输出已提交的安全结果并返回显式
committed error，禁止把成功 mutation 伪装成未执行而盲目重试。

## 破坏式 cutover

迁移 0106 删除十参数无 fence apply 签名，只授予十一参数 fenced apply。所有 relay、consumer 与
mutating maintenance production runner，以及 generated BusinessWrite/BusinessTransaction route，均要求
typed gate；不保留 alias、optional gate、default-running fallback 或 mixed-version rollout。

部署必须 stop-the-world：停止旧实例，执行 0106，部署全部新实例并配置非 nil
`RSS_RUNTIME_INSTANCE_ID`，完成 post-restore pause/drain 后再恢复入口。rollback 同样停服并使用新的
forward migration，不支持旧 binary 直接回退。

## 不做

RSS 不建设 replica registry、外部 control store、Admin HTTP/gRPC、Kubernetes operator、签名服务、
dashboard、evidence DB 或新的 T3 carrier。serving role 的 workload identity attestation 属于 External
delivery/security plane。
