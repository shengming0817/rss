# Phase 1 Data Model: eventexec 数据持久化与事件处理

durable 拓扑的 postgres 表 + 引擎类型 + 状态机。demo 拓扑以 `adapters/memory` in-mem 等价替身（同语义，不落表）。所有表遵 migration 只增不改、新字段默认值/NULL、pre-GA 普通 `CREATE INDEX`、命名 `{序号}_{动词}_{对象}.sql`。

## 引擎类型（consistency，P1/P2 兑现 body）

| 类型 | 模块 | 形态 | 校验/funnel |
|------|------|------|------------|
| `IdemKey` | idempotency(L0) | newtype(String) | parse 拒空 |
| `SeenState` | idempotency | enum {Fresh,Duplicate} | 穷尽 |
| `Topic` | outbox(L1) | newtype(String) | parse 拒空/非 canonical dotted |
| `Disposition` | outbox | enum {Ack,Requeue,Reject} | as_label 闭映射 |
| `PermanentError`/`Kind` | outbox | struct/enum {Permanent,Invariant} | 排除 Transient |
| `HandleResult` | outbox | struct(私有) | ack/requeue/reject funnel |
| `Entry` | outbox | struct(私有: topic,idem_key,payload) | new funnel + envelope 注入 |
| `EngineError`/`Kind` | error | struct/enum {Transient,Permanent,Invariant} | message &'static const |
| `StepName` | saga(L3) | newtype | parse 合法 Rust 标识符 |
| `SagaOutcome`/`CompensationOutcome` | saga | enum | 穷尽 |
| `EntityId` | reconcile(L4) | newtype | parse 拒空 |
| `Request`/`Outcome`/`Context` | reconcile | struct(私有) | default=resync；Context opaque sealed |
| `ReconcileError` | reconcile | struct | is_transient/is_permanent |
| `Lsn` | projection(L3) | newtype(u64) | 单调 |
| `ProjectionEvent` | projection | sync trait | topic/lsn/payload |

## Postgres 表

### outbox（P4）
| 列 | 类型 | 说明 |
|----|------|------|
| id | uuid PK | entry id |
| event_id | text UNIQUE | 幂等 key（EventId/IdemKey，opaque 全局唯一；不强绑 UUID 格式，跨租户唯一性由 IdemKey 全局唯一保证，见 migration 注释） |
| domain | text | 归属域（per-domain relay 读） |
| topic | text | dotted topic |
| contract_id | text | 契约 id |
| payload | bytea | 已编码 payload |
| metadata | jsonb | envelope: trace/correlation/principal/occurred_at；`principal` 仅 opaque subject id（UUID），不序列化完整 Principal 或含 PII（refs: FR-020） |
| status | text | pending/publishing/published/dlx（值集冻结） |
| retry_count | int default 0 | |
| retry_after | timestamptz NULL | 瞬态失败延后 |
| lease_token | uuid NULL | relay CAS fencing |
| created_at/updated_at | timestamptz | |

- Index: `(domain, status, retry_after)`（relay 扫未发）；`(created_at)`（清理）。
- 状态机：`pending → publishing → published`；`publishing →(永久/预算耗尽)→ dlx`；`publishing →(瞬态)→ pending(+retry_after)`。
- CAS：status 转移以 `lease_token` 比对（防并发双发）。

### inbox_dedup（P5）
| 列 | 类型 | 说明 |
|----|------|------|
| event_id | text | 去重 key |
| consumer_group | text | 消费者组（稳定，漂移则去重失效） |
| status | text | claimed/done |
| lease_token | uuid NULL | claim fencing |
| claimed_at | timestamptz | |

- PK: `(event_id, consumer_group)`。claim = INSERT ON CONFLICT DO NOTHING → 首见 Fresh，冲突 Duplicate。
- 保留期清理（#1210）：`PgInboxSweeper` 删 `status='done' AND claimed_at ≤ now()-retain` 的去重记录（`claimed` 行不删）；默认 **7 天**（`INBOX_DEDUP_RETENTION_SECONDS`），**必须严格大于**最大重投窗口（`max_redelivery_window_secs`≈1023s，NServiceBus 去重铁律——低于/等于即迟到重投误判 Fresh 重复执行），编译期 const 断言 + 运行期 sweep fail-closed 双档守（INBOX-DEDUP-RETENTION-FLOOR-01）。清理索引 `(status, claimed_at)`（migration 0020）。完整三表保留期契约见 `docs/ops/…-outbox-relay-observability.md §保留期清理`。
- runtime durable event consumer 以 PostgreSQL `inbox_dedup` 为单一幂等 claimer；Redis 不再作为 event consumer 去重后端。EventId 全局唯一（UUID）保证跨租户不冲突；key 不加 tenant 段属显式决策（见 spec.md §Assumptions 租户隔离立场）。

### dead_letter（P7）
| 列 | 类型 | 说明 |
|----|------|------|
| id | uuid PK | |
| tenant_id | uuid | RLS scope（必填） |
| message_id | text | 原 broker message id / outbox event id |
| source_kind | text | `legacy` / `consumer` / `outbox_relay` / `saga` |
| domain/contract_id/topic | text | |
| consumer_group | text NULL | subscription consumer group；非 consumer 来源为 NULL |
| original_entry | jsonb | 加密原始 entry，唯一允许 shape 为 `{"ciphertext":[...]}` |
| original_entry_key_ref | text | KeyProvider/Vault transit key reference |
| original_entry_payload_len | bigint | 解密后 payload 长度；DLQ list 只暴露该长度 |
| original_entry_encoding | text | 固定 `key-provider-v1` |
| metadata | jsonb | 原始 delivery envelope metadata（重放时保留 trace/correlation/tenant） |
| error_summary | text | 安全摘要（经 `secure` redaction + 长度截断约 512 chars，不直接写 handler 的 Display/Debug 原文、不含原始 payload 片段；runtime 数据只经 `with_internal` 进服务端 tracing） |
| num_attempts | int | |
| first_attempt_at/last_attempt_at | timestamptz | |

- `dead_letter` 是统一 DLQ 审计表。outbox relay 进入 `dlx` 时在同一事务登记
  `dead_letter(source_kind='outbox_relay')`，但原 outbox 行仍保持 `status='dlx'` 作为 relay 状态与
  partition ordering gate。
- 新增加密列的 migration 对既有 `dead_letter` 行 fail-fast，不做 plaintext 迁移；DB 约束拒绝
  `original_entry` 含 `bytes` 的明文 shape。所有新写入必须经 `KeyProvider` 加密，runtime durable 使用
  Vault transit key `RSS_DLX_PAYLOAD_KEY_NAME`。
- 内部 DLQ API 区分分页 `DlqListResult { data, has_more, next_cursor }`、`DlqReplayRequest`
  （consumer/saga dead_letter → 新 outbox id）与 `DlqRedriveRequest`（outbox dlx → 原 outbox 行恢复
  pending）。replay/redrive 均必须携带 `OperatorDlqCapability`；replay 的 dead_letter id 先经 typed
  `DeadLetterId` UUID parse，非法输入不进入 SQL cast。replay/redrive 必须先用同一 `KeyProvider` 解密，
  plaintext row/shape 必须失败；consumer replay 不删除原死信、不重置 `inbox_dedup done`。
- 保留期清理（#1210）：`PgDeadLetterStore::sweep` 删 `last_attempt_at ≤ now()-retain` 的死信（**全域**，所有行均终结）；默认 **30 天**（`DEAD_LETTER_RETENTION_SECONDS`，合规导向）。清理索引 `(last_attempt_at)`（migration 0021）。语义由「immutable append（只 INSERT）」改为「保留期内不可变、超期清理」——约定 append-only（非 REVOKE 强制，DB 层允许保留期 DELETE）；清理前冷存储导出（合规归档）见 #1536。

### saga_journal（P9）
| 列 | 类型 | 说明 |
|----|------|------|
| saga_id | uuid | |
| seq | bigint | append 序（journal 顺序） |
| step_name | text | |
| status | text | executing/completed/compensating/compensated/failed |
| output | bytea NULL | step 输出 |
| error_summary | text NULL | |
| occurred_at | timestamptz | |

- PK: `(saga_id, seq)`。append-only。resume = 读 max(seq) 重建栈。
- 补偿：失败时按 seq 逆序对 completed step 调 compensate。

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
| domain/aggregate_id/event_type | text | |
| payload | bytea | |
| occurred_at/correlation_id/created_at | | |

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

> 既有 `Publisher`/`Subscriber`/`AuditSink`/`Clock`/`Signer`/`ManagedResource`/`SubscribeInitializer` 已在 diport（已实现/已冻结）。`IdempotencyStore`/`OutboxRelay` 是 consistency 引擎 trait（native AFIT，非 diport）。

## 状态机汇总

- **outbox entry**：pending→publishing→{published | dlx | pending(retry)}。
- **inbox claim**：absent→claimed→done（重投见 claimed/done 即 Duplicate）。
- **saga**：running→{succeeded | compensating→{compensated(failed 终态) | dead-letter}}。
- **reconcile entity**：observe→{settled | requeue_after | transient-backoff}；leader 丢 lease→cancel。
- **projection checkpoint**：offset N→N+1（CAS version++）；replay 从 0。
