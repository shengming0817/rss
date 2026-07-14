# Phase 1 Data Model: eventexec 数据持久化与事件处理

durable 拓扑的 postgres 表 + 引擎类型 + 状态机。demo 拓扑以 `adapters/memory` in-mem 等价替身（同语义，不落表）。所有表遵 migration 只增不改、新字段默认值/NULL、pre-GA 普通 `CREATE INDEX`、命名 `{序号}_{动词}_{对象}.sql`。

## 引擎类型（consistency，P1/P2 兑现 body）

| 类型 | 模块 | 形态 | 校验/funnel |
|------|------|------|------------|
| `IdemKey` | idempotency(L0) | newtype(String) | parse 拒空 |
| `SeenState` | idempotency | enum {Fresh,Duplicate} | 穷尽 |
| `EventTopic` | outbox(L1) | newtype(String) | parse 拒空/非 canonical dotted/command namespace |
| `Disposition` | outbox | enum {Ack,Requeue,Reject} | as_label 闭映射 |
| `PermanentError`/`Kind` | outbox | struct/enum {Permanent,Invariant} | 排除 Transient |
| `HandleResult` | outbox | struct(私有) | ack/requeue/reject funnel |
| `EventEntry` / `StoredOutboxEntry` | outbox | producer-only / hydrated read carrier | authoring funnel 与持久化回读类型分离 |
| `EngineError`/`Kind` | error | struct/enum {Transient,Permanent,Invariant} | message &'static const |
| `StepName` | saga(L3) | newtype | parse 合法 Rust 标识符 |
| `SagaOutcome`/`CompensationOutcome` | saga | enum | 穷尽 |
| `EntityId` | reconcile(L4) | newtype | parse 拒空 |
| `Request`/`Outcome`/`Context` | reconcile | struct(私有) | default=resync；Context opaque sealed |
| `ReconcileError` | reconcile | struct | is_transient/is_permanent |
| `Lsn` | projection(L3) | newtype(u64) | 单调 |
| `ProjectionEvent` | projection | sync trait | topic/lsn/payload + persisted envelope metadata |

## Postgres 表

### outbox（P4）
| 列 | 类型 | 说明 |
|----|------|------|
| id | uuid PK | entry id |
| event_id | text UNIQUE | 幂等 key（EventId/IdemKey，opaque 全局唯一；不强绑 UUID 格式，跨租户唯一性由 IdemKey 全局唯一保证，见 migration 注释） |
| tenant_id | uuid | tenant scope（RLS / same-ID redrive scope） |
| domain | text | 归属域（per-domain relay 读） |
| topic | text | dotted topic |
| contract_id / contract_version / schema_hash | text | 契约与 schema identity |
| payload | bytea | 已编码 payload |
| metadata | jsonb | envelope: broker-visible `trace`/`correlation`/`tenantId`/`tenantAuthority`/`occurredAt`；persisted-only `subjectId`/`actor`；不序列化完整 Principal 或含 PII（refs: FR-020） |
| status | text | pending/publishing/published/dlx（值集冻结） |
| seq / partition_key | bigint / text NULL | 表级单调顺序；非空 partition 内 head-of-line gate |
| retry_count | int default 0 | |
| retry_after | timestamptz NULL | 瞬态失败延后 |
| lease_token / lease_until | uuid / timestamptz NULL | publishing 状态的 relay CAS fencing pair |
| published_at / dlx_at | timestamptz NULL | 与 terminal status 双向绑定的权威终态时间 |
| same_id_delivery_phase | text | `automatic` / `redrive` 闭值集 |
| automatic_retry_deadline | timestamptz NULL | 首次 automatic claim 冻结的绝对 deadline |
| same_id_redrive_deadline | timestamptz NULL | 首次 DLX 冻结的绝对 redrive deadline |
| created_at/updated_at | timestamptz | |

- Index: `(domain,status,retry_after)` 候选扫描；`(domain,lease_until) WHERE status='publishing'` stale
  reclaim；`(domain,partition_key,seq) WHERE partition_key IS NOT NULL AND status<>'published'` 队头 gate；
  `(published_at) WHERE status='published'` retention。
- 状态机：`automatic: pending → publishing → published|dlx|pending(retry)`；deadline 内 operator redrive
  `dlx → redrive:pending → publishing → published|dlx|pending(retry)`。redrive 只切 phase、清
  retry/lease/terminal 时间，两个绝对 deadline 不变；到期 preflight 不调用 broker，并 settle 到 DLX。
- CAS：status 转移同时比对 `lease_token + lease_until`。首次 claim 以 `COALESCE` 冻结 automatic deadline，
  首次 DLX 以 `COALESCE` 冻结 redrive deadline；operator 在 redrive deadline 到期后得到 typed `Expired`
  且不 mutation。

### event_delivery_policy（P4/P5 correctness singleton）

| 列 | 类型 | 说明 |
|----|------|------|
| singleton | boolean PK | 唯一行且必须为 true |
| policy_revision | text | 固定 `same-id-delivery-v1` |
| automatic_retry_window_seconds | bigint | 86400（24h） |
| same_id_redrive_horizon_seconds | bigint | 86400（24h） |
| safety_margin_seconds | bigint | 86400（24h） |
| inbox_receipt_retention_seconds | bigint | 604800（7d） |

- DB CHECK 强制所有值为正且 `inbox retention > automatic + redrive + safety`；runtime 通过短生命周期
  migrator/maintenance 连接读取，要求唯一行、revision 和四值与 release 完全一致，否则启动 fail-closed。
- `rss_app` 无表权限；outbox maintenance 与 inbox receipt maintenance owner 经固定 SECURITY DEFINER
  函数读取。正确性策略没有环境变量或 caller override。

### inbox_receipts（P5）
| 列 | 类型 | 说明 |
|----|------|------|
| tenant_id | uuid | tenant scope（RLS / receipt key） |
| event_id | text | 去重 key |
| consumer_group | text | 消费者组（稳定，漂移则去重失效） |
| domain/topic | text | envelope routing identity |
| contract_id / contract_version / schema_hash | text | envelope schema identity |
| trace_id / correlation_id | text NULL | bounded observability context |
| status | text | claimed/done |
| lease_token | uuid NULL | claim fencing |
| claimed_at | timestamptz | |
| committed_at | timestamptz NULL | done receipt time |

- PK: `(tenant_id, event_id, consumer_group)`。claim = tenant-scoped INSERT，stale reclaim 仅在 domain/topic/contract/schema identity 一致时更新 lease；identity mismatch 返回 invariant。
- 保留期清理（#1210/#1650）：`PgInboxSweeper` 经零参数 `rss_sweep_inbox_receipts()` 从上述 DB policy
  读取固定 7d，删 `status='done' AND committed_at ≤ DB clock-7d` 的去重记录（`claimed` 行不删），每 tick
  最多 1000 条；没有 retain 参数 overload。7d 严格覆盖 automatic 24h + redrive 24h + safety 24h，避免
  receipt 先清理后同 event id 再执行。清理索引 `(status, committed_at)`。完整三表保留期契约见
  `docs/ops/…-outbox-relay-observability.md §保留期清理`。
- runtime durable event consumer 以 PostgreSQL `inbox_receipts` 为单一幂等 claimer；Redis 不再作为 event consumer 去重后端。claim 前必须已解析 `IdemKey`、验证 schema header 与 tenantAuthority，并构造 `InboxReceiptContext`。

### dead_letter（P7）
| 列 | 类型 | 说明 |
|----|------|------|
| id | uuid PK | |
| tenant_id | uuid NOT NULL | RLS scope（物理必填） |
| message_id | text | 原 broker message id / outbox event id |
| source_kind | text | `consumer` / `outbox_relay` / `saga` / `projection` |
| producer_domain/consumer_domain/contract_id/topic | text | 可查询 provenance |
| consumer_group | text NULL | subscription consumer group；projection 来源为 projection id |
| replay_capsule | jsonb | `key-provider-v3` 一次加密的 payload + 全部 persisted metadata |
| replay_capsule_key_ref | text | hot KeyProvider/Vault transit key reference |
| payload_len | bigint | 解密后 payload 长度；DLQ list 只暴露该长度 |
| replay_capsule_encoding | text | 固定 `key-provider-v3` |
| error_summary | text | 安全摘要（经 `secure` redaction + 长度截断约 512 chars，不直接写 handler 的 Display/Debug 原文、不含原始 payload 片段；runtime 数据只经 `with_internal` 进服务端 tracing） |
| num_attempts | int | |
| first_attempt_at/last_attempt_at | timestamptz | |

- `dead_letter` 是统一 DLQ 审计表。outbox relay 进入 `dlx` 时在同一事务登记
  `dead_letter(source_kind='outbox_relay')`，但原 outbox 行仍保持 `status='dlx'` 作为 relay 状态与
  partition ordering gate。
- 0062 migration 对既有 `dead_letter` 行 fail-fast，不做数据迁移；旧列、旧 decoder 与旧函数直接删除。
  所有新写入必须经 hot `KeyProvider` 把 payload 与 metadata 一次加密，runtime durable 使用 Vault transit key
  `RSS_DLX_PAYLOAD_KEY_NAME`；`tenantAuthority` 永不持久化。
- 内部 DLQ API 区分分页 `DlqListResult { data, has_more, next_cursor }`、`DlqReplayRequest`
  （consumer/saga dead_letter → 新 outbox id）与 `DlqRedriveRequest`（outbox dlx → 原 outbox 行恢复
  pending）。replay/redrive 均必须携带 `OperatorDlqCapability`；replay 的 dead_letter id 先经 typed
  `DeadLetterId` UUID parse，非法输入不进入 SQL cast。只有 replay 使用同一 `KeyProvider` 解密；
  `redrive-outbox` 是 payload-free 原 outbox 状态转换。plaintext replay row/shape 必须失败；consumer replay
  不删除原死信、不重置 `inbox_receipts done`。outbox redrive deadline 到期返回 typed `Expired`，不修改行。
- 生命周期清理：worker 经 `rss_dlx_archiver` claim/retry、`rss_dlx_verifier` 写 verified receipt、
  `rss_dlx_purger` purge/reconcile，尽快把 hot row 归档为 verified S3 Object Lock
  `COMPLIANCE` 对象并 CAS 写 receipt；只有 `last_attempt_at ≤ now()-30d`、receipt 已验证且
  `retain_until > now()` 的行才进入每轮最多 1000 条 purge。hot 30 天固定且不可配置；archive candidates
  每轮 100，receipt reconcile 每轮 100。`rss_app` 无 lifecycle 函数权限，归档 repository 也不暴露 raw pool。

### dead_letter_archive_receipts

receipt 是 tenant-scoped FORCE RLS 证明表，记录 dead-letter id、对象 key、checksum、archive key ref、
Object Lock mode/retain-until 与 verified time。lock 到期不立即删 receipt；只有 verified archive store 的 HEAD
确认 S3 lifecycle 已删除对象，才能构造 `MissingArchiveProof` 并 CAS 回收 receipt。

### saga_instances / saga_journal（P9 + #1632）
`saga_instances`:
| 列 | 类型 | 说明 |
|----|------|------|
| tenant_id | uuid | 租户边界 |
| saga_id | uuid | saga 实例 |
| owner | text | saga owner/domain |
| contract_id | text | saga contract |
| status | text | ready/running/succeeded/compensating/compensated/failed/degraded |
| lease_token | uuid NULL | 当前 claim token |
| holder_id | text NULL | 当前 holder |
| epoch | bigint | 单调 CAS epoch |
| expires_at / heartbeat_at | timestamptz NULL | lease fencing |

`saga_journal`:
| 列 | 类型 | 说明 |
|----|------|------|
| tenant_id | uuid | 租户边界 |
| saga_id | uuid | |
| seq | bigint | append 序（journal 顺序） |
| step_name | text | |
| status | text | executing/completed/compensating/compensated/failed |
| error_summary | text NULL | 补偿失败安全摘要（静态 summary；read/resume 路径不回传） |
| occurred_at | timestamptz | |

- `saga_instances` PK: `(tenant_id, saga_id)`；claim/extend/release/status mark 均用 `lease_token + epoch + expires_at` CAS。
- `saga_journal` PK: `(tenant_id, saga_id, seq)`，composite FK 指回 `saga_instances`。append-only；同 key exact duplicate 返回 idempotent，内容不同返回 conflict。resume = 读 `seq/step_name/status` 后由 `consistency::saga` replay reducer 重建状态。
- durable journal 不持久化 step output；末步 output 只在 `run` 内存路径作为即时结果返回。
- 补偿：失败时按 definition reverse order 对 completed step 调 compensate。

### checkpoint（P9，saga+projection 共享）
| 列 | 类型 | 说明 |
|----|------|------|
| owner | text | 消费者 owner |
| checkpoint_id | text | 投影/saga 标识 |
| offset_lsn | bigint | 已处理位点(Lsn) |
| version | bigint | CAS 版本 |
| updated_at | timestamptz | |

- PK: `(owner, checkpoint_id)`。save = CAS by version（旧版本拒）。

### projection_events（P10）
| 列 | 类型 | 说明 |
|----|------|------|
| id | bigint PK（单调=Lsn 源） | |
| event_id | text UNIQUE | outbox event id；duplicate outbox emit 不重复镜像 |
| domain/aggregate_id/event_type | text | |
| payload | bytea | |
| contract_id / contract_version / schema_hash | text | generated projection input binding identity |
| metadata | jsonb | copied outbox envelope metadata；必须含 canonical non-nil `tenantId` |
| partition_key / causation_id | text NULL | copied outbox persisted metadata |
| occurred_at/correlation_id/created_at | | |

- **append-only + hard writer funnel**：生产只在 outbox insert 新增且 `(contract_id, version, schema_hash, topic)` 命中
  generated `PROJECTION_INPUTS` 时镜像；DB 写/读只经固定 `rss_append_projection_event` /
  `rss_read_projection_events` 函数，`rss_app` 无直接表权限。
- **pre-GA breaking migration**：0040 启用前要求旧 `projection_events` 为空，不 backfill。
- **projection DLQ**：Permanent / Invariant / OutOfOrder 写统一 `dead_letter(source_kind='projection')`
  后停止当前 projection，不自动 skip checkpoint；projection DLQ message id 为
  `projection:<owner>:<projection_id>:<lsn>`。Projection DLQ 行只作审计与诊断，不 redrive 成 outbox；
  read-model shadow replay 走 `rss projections replay`，输入源仍是 `projection_events`。
- **checkpoint monotonicity**：`checkpoint.offset_lsn` SQL update path 拒绝 regression，避免把 checkpoint 推过 poison/乱序 LSN。
- **append-only**：migration 内 `REVOKE UPDATE, DELETE`；代码侧 dylint `rss_projection_append_only` 拒 DELETE/TRUNCATE 字面量（PROJECTION-APPEND-ONLY-01）。
- Index: `(domain, aggregate_id)`。

### command 表（P12）
- 复用 outbox 表（topic = `<domain>.commands.<name>`，event_id=DispatchId，payload=Request JSON）；不另建表。

## DI port 数据契约（diport）

| port | 方法（async dyn） | 落地 PR |
|------|------------------|---------|
| `OwnerCheckpointStore` | get_checkpoint / save_checkpoint(CAS) | P9 |
| `LeaderElector` | acquire_lease / renew_lease(LostLease) | P11 |
| `FencedWriter` | write_fenced(key,val,epoch)→bool | P11 |
| `DeadLetterStore` | write_dead_letter | P7 |
| `TxRunner` | run_global_transaction | P3(基座)/P10(projection 用) |

> 既有 `Publisher`/`Subscriber`/`AuditSink`/`Clock`/`Signer`/`ManagedResource`/`SubscribeInitializer` 已在 diport（已实现/已冻结）。`InboxStore`/`OutboxRelay` 是 consistency 引擎 trait（native AFIT，非 diport）。

## 状态机汇总

- **outbox entry**：`automatic:pending→publishing→{published|dlx|pending(retry)}`；deadline 内
  `dlx→redrive:pending→publishing→{published|dlx|pending(retry)}`，两个 absolute deadline 单调冻结不延长。
- **inbox claim**：absent→claimed→done（重投见 claimed/done 即 Duplicate）。
- **saga**：running→{succeeded | compensating→{compensated(failed 终态) | dead-letter}}。
- **reconcile entity**：observe→{settled | requeue_after | transient-backoff}；leader 丢 lease→cancel。
- **projection checkpoint**：offset N→N+1（CAS version++）；replay 从 0。
