-- 凭据持久化表（identity CredentialRepo persistence；login 密码校验真依赖，#1316）。
--
-- adapter `PgCredentialRepo`（adapters/postgres/src/credential_repo.rs）impl `identity::ports::CredentialRepo`：
-- find_by_user_id / authenticate / save / bump_version / lockout_status——与 `PgRoleRepo` 同范式
-- （pool 注入 / SET LOCAL tenant scope / storage 收口 / hydrate 重建）。
--
-- 安全不变式（DoD #1316）：
--   * **明文密码永不落库**——仅 `password_hash`（argon2 PHC string，经 `secure::PasswordHash`）。无 `password` 明文列；
--     `ts_credentials_no_plaintext_password` 集成测试经 information_schema 断言守。
--   * **锁定态折叠进本行**（`failure_count` / `lockout_window_start` / `locked_until`）：未知主体 = 无行 =
--     无法建锁定态 ⇒ #1277 F2「未知主体不可被预置锁定、不撑大 lockout 表」类型层/结构层天然成立（无需独立锁定表）。
--     `authenticate` / `lockout_status` 在 `SELECT ... FOR UPDATE` 单行事务内做原子 read-modify-write，
--     策略阈值（5 次 / 15min 滑窗 / 15min 锁定 TTL）域内单源（`identity::AccountLockout`）、adapter 仅 I/O。
--
-- 列约定：
--   tenant_id `uuid NOT NULL`：RLS scope + SET LOCAL 注入锚点 + RLS policy current_setting 比对锚点。
--   user_id   `uuid NOT NULL`：canonical actor subject（登录成功写 session.subject / outbox envelope；audit actor）。
--   login     `text NOT NULL`：opaque 登录查找键（username/email/UPN，准 PII；攻击者可控，永不进 wire）。
--   password_hash `text NOT NULL`：argon2 PHC（read 时 adapter 经 `secure::PasswordHash::parse` 复核回读，损坏 → Storage fail-closed）。
--   version   `bigint NOT NULL`：CAS pin（密码变更经 bump_version 期望版本比对）；bigint 容纳域 `u32` 无损往返。
--   failure_count / lockout_window_start / locked_until：锁定态三列（lazy-unlock，无后台 job）；新行计数 0、时刻列 NULL。
--     failure_count `bigint`（域 `u32` 无损往返）；时刻列 `timestamptz` nullable，经 to_timestamp/extract epoch 与
--     `PgSessionLifecycle` 编码对称（不给 sqlx 加时间 feature）。
--
-- PRIMARY KEY (tenant_id, login)：authenticate / lockout_status 的查找键（与 in-mem `(tenant, login)` 键一致）；
--   同 login 可跨租户共存（每租户独立凭据空间），跨租 → 0 行 → fail-closed（find None / authenticate InvalidUnknown）。
-- UNIQUE (tenant_id, user_id)：find_by_user_id 二级索引（O(1) 按 canonical user_id 查）+ 租户内 login↔user 一一对应。
CREATE TABLE credentials (
    tenant_id            uuid        NOT NULL,
    user_id              uuid        NOT NULL,
    login                text        NOT NULL,
    password_hash        text        NOT NULL,
    version              bigint      NOT NULL,
    failure_count        bigint      NOT NULL DEFAULT 0,
    lockout_window_start timestamptz,
    locked_until         timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, login),
    -- 域不变式下沉为 DB CHECK（#1316 review F2）：version/failure_count 映射域 `u32`（非负 + u32::MAX 上界），
    -- 坏迁移 / 外部直写不可越界（hydrate i64→u32 的 unwrap_or 仅 fail-safe，DB 侧硬拒非法行）。
    -- locked_until 非空蕴含 lockout_window_start 非空：锁定必有滑窗起点（adapter record_failure 先锚定窗口再
    -- 达阈值锁，write_lockout 恒同写两列；clear/lazy-unlock 时 locked_until→NULL）——锁定态不可缺窗口（fail-closed）。
    CONSTRAINT credentials_version_u32 CHECK (version >= 0 AND version <= 4294967295),
    CONSTRAINT credentials_failure_count_u32 CHECK (failure_count >= 0 AND failure_count <= 4294967295),
    CONSTRAINT credentials_lock_requires_window CHECK (locked_until IS NULL OR lockout_window_start IS NOT NULL)
);

-- find_by_user_id 二级索引（canonical user_id 查）+ 租户内 login↔user 一一对应（pre-GA 新表，普通 CREATE INDEX
-- 留事务型 migration；非 CONCURRENTLY）。
CREATE UNIQUE INDEX idx_credentials_tenant_user ON credentials (tenant_id, user_id);

-- RLS 三件套 + GRANT（与 0009_enable_tenant_rls.sql 同范式；新表须自建——0009 已 committed 只增不改、不可回改纳入本表；
-- 非 owner serving role rss_app 由 0009 provision，本迁移在其先行 ⇒ 已存在，仅补 credentials 表 DML grant + policy）。
GRANT SELECT, INSERT, UPDATE, DELETE ON credentials TO rss_app;
ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON credentials
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);
