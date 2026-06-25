-- secret 引用坐标持久化表（settings SecretRepo persistence；L1 LocalTx，#1274）。
--
-- !! 本表**仅存引用坐标**（store_id / ref_key / ref_version），**绝无任何 secret 材料列** !!
-- 材料（密文/明文/密钥字节）存于外部 secret store（如 Vault/K8s Secrets），本表记录「到哪里取」的坐标，
-- 持久化后读者须自行经 SecretRef 坐标去 store 拉取材料——review-critical，禁止在此表新增材料列。
--
-- 版本历史模型（同 config_entries 0005 范式）：每 (tenant_id, secret_key) 保留**全部**版本行
-- （append-only，不 update-in-place）；当前活跃 = max(version) 且非 tombstone；
-- find_version 取精确版本（回滚/审计用）。PRIMARY KEY (tenant_id, secret_key, version) 防重复版本写，
-- 服务全部读路径（max via 反向扫描 / 精确等值），无需额外索引。
-- CAS（etcd 版本模型，settings ports.rs）：save 要求新版本 = 当前最高 + 1（首版 = 1），由
--   `INSERT ... SELECT ... WHERE $v = 1 + COALESCE(max(version),0)` 单语句守——0 行 affected ⇒ VersionConflict；
--   并发同版本写经 PK unique violation(23505) 亦映射 VersionConflict（adapter 侧）。
-- 删除 = tombstone 软删（同 config F1）：delete 在 max+1 追加 deleted=true 占位行（幂等：latest 已 tombstone → no-op）；
--   version 单调不重置（防 event_id 复用，与 config tombstone 同理；#1274）。
--   find / find_version 排除 tombstone（deleted=true → 视为已删 None）。
--   tombstone 占位坐标列置空字符串（store_id='', ref_key=''）/ ref_version=NULL，不携带有效坐标。
--
-- secret_key 用 `text`（绑域内 `SecretKey` newtype，opaque 串，校验在域层；同 config_entries.config_key）。
-- store_id / ref_key 用 `text`（引用坐标，opaque；tombstone 占位置 ''）。
-- ref_version 用 `text` NULL（NULL = latest；tombstone 占位 NULL）。
-- version 用 `bigint`（域 u64 版本号 wire i64；从 1 单调递增）。
-- tenant_id `uuid NOT NULL`：每行租户戳记——SET LOCAL 注入锚点 + 未来 RLS policy 比对锚点。
-- deleted `boolean NOT NULL DEFAULT false`：tombstone 标记（true ⇒ 该版本是删除墓碑，find 视为已删）。
-- created_at `DEFAULT now()`：落库兜底时间戳（版本号即业务时序，应用不显式写 created_at）。
--
-- 本表预 GA 不建 RLS policy（同 config_entries / sessions）；tenant_id 列 + 写路径 SET LOCAL + 读路径显式
-- `WHERE tenant_id` 保证 tenant-correct；RLS policy 由后续前向迁移按 tenancy.md 叠加（零数据迁移）。

CREATE TABLE secret_refs (
    tenant_id    uuid        NOT NULL,
    secret_key   text        NOT NULL,
    version      bigint      NOT NULL,
    store_id     text        NOT NULL,   -- 引用坐标：外部 store 名（非材料）；tombstone 占位 ''
    ref_key      text        NOT NULL,   -- 引用坐标：store 内 key（非材料）；tombstone 占位 ''
    ref_version  text                 DEFAULT NULL,  -- 引用坐标：store 内版本（NULL=latest；tombstone 亦 NULL）
    deleted      boolean     NOT NULL DEFAULT false,  -- tombstone 标记（true ⇒ 该版本是删除墓碑）
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, secret_key, version)
);
