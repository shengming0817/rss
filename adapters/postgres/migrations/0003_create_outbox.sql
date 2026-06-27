-- 0003_create_outbox.sql — outbox durable store（L2 OutboxFact，P4/#1117）。
--
-- event_id 用 text（绑不透明 IdemKey；IdemKey 本质 opaque string，不强绑 UUID 格式，避免格式耦合）。
-- id 列用 gen_random_uuid()（PG 13+ core，无需扩展；若需兼容 PG < 13 可加 CREATE EXTENSION IF NOT EXISTS pgcrypto）。
-- status 值集由 CHECK 冻结（Hard，不允许自由字符串——域外不可表达不合法状态）。
-- metadata jsonb 仅存 envelope 不透明主体 id（禁完整 Principal / email / 姓名 / phone，PII 边界）。
-- retry_after NULL 表示立即可投；lease_token 用于 relay CAS fencing（崩溃重投安全）。

CREATE TABLE outbox (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id     text        NOT NULL UNIQUE,
    domain       text        NOT NULL,
    topic        text        NOT NULL,
    contract_id  text        NOT NULL,
    payload      bytea       NOT NULL,
    metadata     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    status       text        NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending','publishing','published','dlx')),
    retry_count  int         NOT NULL DEFAULT 0,
    retry_after  timestamptz,
    lease_token  uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- relay 扫描索引：pending 分支按 domain + status + retry_after 范围扫（poll_pending 主路径）。
CREATE INDEX idx_outbox_relay_scan ON outbox (domain, status, retry_after);
-- stale-publishing 重投索引（partial）：覆盖 poll_pending 的 `status='publishing' AND updated_at<=` 分支。
CREATE INDEX idx_outbox_stale_publishing ON outbox (domain, updated_at) WHERE status = 'publishing';
-- 清理索引：覆盖 sweep 的 `status='published' AND created_at<=` 谓词（pre-GA 新表，普通 CREATE INDEX）。
CREATE INDEX idx_outbox_sweep ON outbox (status, created_at);
