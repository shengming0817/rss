-- projection_events：append-only CQRS 投影事件日志（changelog 源，被投影 harness replay）。
-- 全局表（无租户列 / 无 RLS，对标 outbox/saga_journal/checkpoint）。
-- 角色边界（least privilege，对齐 outbox/saga_journal/checkpoint）：**不授任何 serving role**。
--   projection_events 是全局事件日志、payload 可含跨租户业务数据；rss_app（0012）是 tenant 表 serving role，
--   授其 SELECT 会让被攻陷的 app 连接跨租读全局 payload，故不授。全局表的 serving-role grant 随 dual-pool
--   接线补（follow-up，同 outbox 注释）；当前由 owner pool 写入。
-- append-only（INVARIANT PROJECTION-APPEND-ONLY-01）：当前由 dylint rss_projection_append_only（Medium，
--   代码侧 DELETE/TRUNCATE 字面量）守 + 对 PUBLIC 显式 REVOKE UPDATE/DELETE（纵深防御）；DB 引擎
--   serving-role REVOKE 主守卫（Hard）待 dual-pool projection writer/reader role 落地一并接
--   （届时 GRANT INSERT/SELECT 给专用 role + REVOKE UPDATE/DELETE）。
-- forward-only（migrations/README.md）：REVOKE 不可逆，逆转须新前向迁移 GRANT，不写 .down.sql。
CREATE TABLE projection_events (
    id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- 单调 = Lsn 源
    domain         text        NOT NULL,
    aggregate_id   text        NOT NULL,
    event_type     text        NOT NULL,                                  -- canonical dotted（= Topic）
    payload        bytea       NOT NULL,
    correlation_id text,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_projection_events_aggregate ON projection_events (domain, aggregate_id);

-- append-only 纵深防御：对 PUBLIC 显式 REVOKE UPDATE/DELETE（不授任何 serving role，见表头注释；
-- 跨租读边界对齐 outbox——rss_app 不持全局 payload 表权限）。
REVOKE UPDATE, DELETE ON projection_events FROM PUBLIC;
