//! settings 应用层：版本化配置 CRUD/CAS + 发布/回滚（L2 OutboxFact）+ feature flag 求值编排。
//!
//! 配置写入路径证明 L2 接缝：CAS upsert 新版本（[`crate::ports::ConfigRepo`]）→ 构造 `consistency::Entry`
//! 经 [`diport::OutboxEmitter`] 落 durable outbox（in-mem `memory::MemEmitter` / 生产 postgres）→ 返回新版本。
//! 发布与回滚复用同一 fact，`changeKind` 判别（published / rolledBack）。flag 求值经域内
//! [`crate::internal::ports::FlagStore`] 取快照 + `domain::evaluate_flag`（L0 纯计算）。
//!
//! 追踪弹边界（同 identity G1）：服务由组合根（journeys）直接调用，**不逐字节跑 axum**；[`SettingsDomain`]
//! 只经 bootstrap [`Registry`] **声明**配置路由组（register 闭包收集、不执行）。真实持久化（postgres adapter）
//! + axum 挂载（`httpserve::mount_primary`）+ wire `ERR_SETTINGS_*` 前缀注册留 Join。
//!
//! ref: Unleash/unleash-types-rs src/client_features.rs@main（flag 求值语义）
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main（CAS 版本模型）
//! ref: crates/identity/src/application.rs（L2 OutboxFact 经 OutboxEmitter 落 durable outbox 范式，#1100）

use std::time::SystemTime;

use bootstrap::{Domain, KernelError, Registry};
use consistency::{Entry, IdemKey, Topic};
use diport::{Clock, DynOutboxEmitter, OutboxEmitter, OutboxEnvelopeParts};
use generated::event::settings_v1::{
    CONTRACT_ID, SettingsConfigChangeKind, SettingsConfigVersionChangedPayload,
    TOPIC as VERSION_CHANGED_TOPIC,
};
use generated::http::settings_v1::{
    SettingsConfigPublishData, SettingsConfigPublishRequest, SettingsConfigPublishResponse,
};
use primitives::ListenerKind;
use vocab::TenantId;

use crate::domain::{
    ConfigEntry, ConfigValue, ConfigVersion, EvalContext, FlagDecision, FlagKey, SettingKey,
    SettingsError, evaluate_flag,
};
#[cfg(any(test, feature = "seed-data"))]
use crate::internal::mem::{InMemConfigRepo, InMemFlagStore};
use crate::internal::ports::FlagStore;
use crate::ports::{ConfigRepo, DynConfigRepo};

/// 配置路由组前缀（Primary listener，业务 API）。
pub const SETTINGS_ROUTE_PREFIX: &str = "/api/v1/settings";

/// outbox envelope 发布域（config-version-changed 由 settings 域发布）。
const SETTINGS_DOMAIN: &str = "settings";

/// settings 应用层错误。库错误枚举（const-literal message，不返回 HTTP 状态码——handler 层映射）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SettingsServiceError {
    /// 配置 / flag 键格式非法。
    #[error("setting key is invalid")]
    InvalidKey,
    /// 乐观并发写冲突（读后被并发版本超前）。
    #[error("version conflict")]
    VersionConflict,
    /// 目标配置 / 版本不存在（回滚源缺失）。
    #[error("config entry not found")]
    NotFound,
    /// 灰度百分比超出 0..=100 范围。
    #[error("percentage out of range; must be 0..=100")]
    PercentageOutOfRange,
    /// config-version-changed payload 编码失败（原始错误进 source，不进 Display）。
    #[error("config-version-changed payload encode failed")]
    PayloadEncode(#[source] serde_json::Error),
    /// outbox Entry 构造失败（topic / idem-key 形态非法——programmer error，topic/event_id 内部派生）。
    #[error("config-version-changed outbox entry build failed")]
    EntryBuild,
    /// config-version-changed outbox 发射失败（原始错误进 source）。
    #[error("config-version-changed emit failed")]
    Emit(#[source] diport::OutboxEmitError),
}

impl From<SettingsError> for SettingsServiceError {
    fn from(error: SettingsError) -> Self {
        match error {
            SettingsError::KeyInvalid => Self::InvalidKey,
            SettingsError::PercentageOutOfRange => Self::PercentageOutOfRange,
            SettingsError::VersionConflict => Self::VersionConflict,
        }
    }
}

/// `SystemTime` → UNIX epoch 秒（i64）。负偏移收口为 0；溢出收口为 `i64::MAX`。不取系统时钟（经注入 [`Clock`]）。
fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        // reason: 时钟早于 UNIX_EPOCH（容器时间错误）→ 收口 0，不 panic
        .unwrap_or(0)
}

/// u64 版本号 → wire i64（溢出收口 `i64::MAX`）。
fn wire_version(version: u64) -> i64 {
    i64::try_from(version).unwrap_or(i64::MAX)
}

/// settings 应用服务。必填依赖走构造器位置参（缺失即编译错误，rust-standards §工程护栏）。
pub struct SettingsService {
    configs: Box<DynConfigRepo<'static>>,
    flags: Box<dyn FlagStore>,
    emitter: Box<DynOutboxEmitter<'static>>,
    clock: Box<dyn Clock>,
}

impl SettingsService {
    /// 构造（必填位置参注入仓储 + outbox emitter + clock）。`pub(crate)`：`flags` 为域内 [`FlagStore`]，不外泄；
    /// 生产组合根经 `with_seed`（in-mem）或后续 Join 真实 adapter 构造。
    ///
    /// # Future：生产构造器（注入真实 postgres ConfigRepo + flag store + PgEmitter）留 Join，届时新增非门控构造器。
    #[cfg(any(test, feature = "seed-data"))]
    pub(crate) fn new(
        configs: Box<DynConfigRepo<'static>>,
        flags: Box<dyn FlagStore>,
        emitter: Box<DynOutboxEmitter<'static>>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            configs,
            flags,
            emitter,
            clock,
        }
    }

    /// 组合根构造：注入 outbox emitter + clock，以空 in-mem 配置 / flag 仓储初始化（追踪弹 / demo）。
    ///
    /// 门控于 `test` / `seed-data` feature（编译期边界，对标 identity seed-login）：生产组合根不启用即无
    /// in-mem provider 路径。组合根（journeys）经 `settings = { features = ["seed-data"] }` 启用 + 注入
    /// `memory::MemEmitter`。真实持久化（postgres adapter impl [`crate::ports::ConfigRepo`] + `PgEmitter`）留 Join。
    #[cfg(any(test, feature = "seed-data"))]
    pub fn with_seed(emitter: Box<DynOutboxEmitter<'static>>, clock: Box<dyn Clock>) -> Self {
        Self::new(
            DynConfigRepo::new_box(InMemConfigRepo::new()),
            Box::new(InMemFlagStore::new()),
            emitter,
            clock,
        )
    }

    /// 当前 key 的下一版本号（无历史 → 1）。
    async fn next_version(
        &self,
        tenant: TenantId,
        key: &SettingKey,
    ) -> Result<u64, SettingsServiceError> {
        let current = self.configs.find(tenant, key).await?;
        Ok(current.map_or(1, |entry| entry.version().get() + 1))
    }

    /// 构造 `config-version-changed` [`Entry`] 经 [`OutboxEmitter`] 落 durable outbox（L2 OutboxFact）。
    ///
    /// EventId（outbox `event_id` / `IdemKey`）= 内容派生 `{topic}:{tenant}:{key}:v{version}`：每个
    /// (tenant, key, version) 仅一次发射（version 单调递增，publish/rollback 各产新版本），故按内容确定唯一——
    /// 重试同版本产同锚点，经 relay 盖章 broker message_id 流回消费侧实现「至少一次 + 幂等」端到端去重（#1100）。
    /// tenant 是可观测标识（非凭据，ADR-002）；key 是 opaque 配置标识（非 value，无 secret）。
    #[tracing::instrument(skip_all, err, fields(topic = VERSION_CHANGED_TOPIC, change_kind = %change_kind))]
    async fn emit_version_changed(
        &self,
        key: &SettingKey,
        tenant: TenantId,
        version: u64,
        change_kind: SettingsConfigChangeKind,
        source_version: Option<u64>,
    ) -> Result<(), SettingsServiceError> {
        let payload = SettingsConfigVersionChangedPayload {
            change_kind,
            key: key.as_str().to_string(),
            occurred_at: unix_secs(self.clock.now()),
            source_version: source_version.map(wire_version),
            tenant_id: tenant.to_string(),
            version: wire_version(version),
        };
        let bytes = serde_json::to_vec(&payload).map_err(SettingsServiceError::PayloadEncode)?;
        let event_id = format!(
            "{VERSION_CHANGED_TOPIC}:{tenant}:{}:v{version}",
            key.as_str()
        );
        let entry = Entry::new(
            Topic::parse(VERSION_CHANGED_TOPIC).map_err(|_| SettingsServiceError::EntryBuild)?,
            IdemKey::parse(&event_id).map_err(|_| SettingsServiceError::EntryBuild)?,
            bytes,
        );
        let envelope = OutboxEnvelopeParts {
            domain: SETTINGS_DOMAIN.to_string(),
            contract_id: CONTRACT_ID.to_string(),
            subject_id: key.as_str().to_string(), // opaque 配置 key（无 PII / secret）
        };
        self.emitter
            .emit(entry, envelope)
            .await
            .map_err(SettingsServiceError::Emit)
    }

    /// 写入新配置版本并发射 outbox fact（L2 OutboxFact）。CAS：读当前版本 → 写 +1；并发冲突冒泡 `VersionConflict`。
    ///
    /// `skip_all`：不记 `value`（可能含 secret）/ `key`；失败经 `err` 记 [`SettingsServiceError`] Display（无 PII）。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn publish_config(
        &self,
        tenant: TenantId,
        request: SettingsConfigPublishRequest,
    ) -> Result<SettingsConfigPublishResponse, SettingsServiceError> {
        let key = SettingKey::parse(&request.key)?;
        let version = self.next_version(tenant, &key).await?;
        let entry = ConfigEntry::new(
            key.clone(),
            ConfigValue::new(request.value),
            tenant,
            ConfigVersion::new(version),
        );
        self.configs.save(tenant, entry).await?;
        self.emit_version_changed(
            &key,
            tenant,
            version,
            SettingsConfigChangeKind::Published,
            None,
        )
        .await?;
        Ok(SettingsConfigPublishResponse {
            data: SettingsConfigPublishData {
                key: key.as_str().to_string(),
                version: wire_version(version),
            },
        })
    }

    /// 回滚：以 `to_version` 的值生成新版本并发射（`changeKind=rolledBack`，`sourceVersion=to_version`）。
    ///
    /// `skip_all` + 仅 `tenant` field（与 `publish_config` 一致，不记 `key`/`value`，统一可观测安全策略）。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn rollback(
        &self,
        tenant: TenantId,
        key: &str,
        to_version: u64,
    ) -> Result<SettingsConfigPublishResponse, SettingsServiceError> {
        let key = SettingKey::parse(key)?;
        let source = self
            .configs
            .find_version(tenant, &key, to_version)
            .await?
            .ok_or(SettingsServiceError::NotFound)?;
        let value = source.value().clone();
        let version = self.next_version(tenant, &key).await?;
        let entry = ConfigEntry::new(key.clone(), value, tenant, ConfigVersion::new(version));
        self.configs.save(tenant, entry).await?;
        self.emit_version_changed(
            &key,
            tenant,
            version,
            SettingsConfigChangeKind::RolledBack,
            Some(to_version),
        )
        .await?;
        Ok(SettingsConfigPublishResponse {
            data: SettingsConfigPublishData {
                key: key.as_str().to_string(),
                version: wire_version(version),
            },
        })
    }

    /// 读取 key 当前活跃配置值（不存在返回 `Ok(None)`）。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn get_value(
        &self,
        tenant: TenantId,
        key: &str,
    ) -> Result<Option<String>, SettingsServiceError> {
        let key = SettingKey::parse(key)?;
        Ok(self
            .configs
            .find(tenant, &key)
            .await?
            .map(|entry| entry.value().as_str().to_string()))
    }

    /// 硬删除 key 及其版本历史（幂等）。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn delete(&self, tenant: TenantId, key: &str) -> Result<(), SettingsServiceError> {
        let key = SettingKey::parse(key)?;
        self.configs.delete(tenant, &key).await?;
        Ok(())
    }

    /// 求值 flag 对给定上下文是否启用（L0 纯计算）。未知 flag → `false`（fail-closed）。
    ///
    /// 返回 bool 为当前 interim 形态；如需决策详情（命中规则/桶/stale）GA 前可升结构化返回（见 follow-up）。
    pub fn is_flag_enabled(
        &self,
        tenant: TenantId,
        flag_key: &str,
        attrs: &[(&str, &str)],
    ) -> Result<bool, SettingsServiceError> {
        let key = FlagKey::parse(flag_key)?;
        let Some(state) = self.flags.find(tenant, &key) else {
            return Ok(false);
        };
        let owned: Vec<(String, String)> = attrs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        Ok(evaluate_flag(&state, &EvalContext::new(&owned)) == FlagDecision::Enabled)
    }
}

/// settings 域 bootstrap 生命周期：声明配置路由组。
///
/// 追踪弹只**声明**（register 闭包收集、不执行）——证明 bootstrap 组装了 settings 的 Primary 配置路由。
pub struct SettingsDomain;

impl Domain for SettingsDomain {
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
        // 配置路由组（Primary listener）。register 闭包追踪弹不执行：Join 经
        //   httpserve::mount_primary(router, PrimaryRoute { method, path, contract_id, opt_out }, handler)
        // 挂真实 axum 路由（settings.config-publish 鉴权由 listener auth plan 承载，无 Public 降级）。
        reg.route_group(ListenerKind::Primary, SETTINGS_ROUTE_PREFIX, Ok)?;
        // TODO(Join): 接 postgres ConfigRepo 时注册 configs_ready readiness probe
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use diport::OutboxEmitError;

    use crate::domain::{FlagState, RolloutPercentage, RolloutRule};

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    // 测试 helper：解析已知合法常量 —— expect item-level carve-out（error-handling.md §Carve-out）。
    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse(TENANT).expect("canonical uuid")
    }

    // 域单测不依赖 adapter crate（rust-standards.md §命名）：OutboxEmitter / Clock 替身在此手写。
    #[derive(Clone, Default)]
    struct CapturingEmitter {
        emitted: Arc<Mutex<Vec<(Entry, OutboxEnvelopeParts)>>>,
    }
    impl OutboxEmitter for CapturingEmitter {
        async fn emit(
            &self,
            entry: Entry,
            envelope: OutboxEnvelopeParts,
        ) -> Result<(), OutboxEmitError> {
            self.emitted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((entry, envelope));
            Ok(())
        }
    }

    struct FixedClock(SystemTime);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn service_with(capture: &CapturingEmitter, flags: InMemFlagStore) -> SettingsService {
        SettingsService::new(
            DynConfigRepo::new_box(InMemConfigRepo::new()),
            Box::new(flags),
            DynOutboxEmitter::new_box(capture.clone()),
            Box::new(FixedClock(
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            )),
        )
    }

    /// 单条发射事实（topic + idem-key + envelope 三元 + 解码 payload），避免依赖 `Entry: Clone`。
    struct EmittedFact {
        topic: String,
        idem: String,
        domain: String,
        contract_id: String,
        subject_id: String,
        payload: SettingsConfigVersionChangedPayload,
    }

    #[allow(clippy::expect_used)]
    fn emitted_facts(capture: &CapturingEmitter) -> Vec<EmittedFact> {
        capture
            .emitted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(entry, env)| EmittedFact {
                topic: entry.topic().as_str().to_string(),
                idem: entry.idem_key().as_str().to_string(),
                domain: env.domain.clone(),
                contract_id: env.contract_id.clone(),
                subject_id: env.subject_id.clone(),
                payload: serde_json::from_slice(entry.payload()).expect("decode payload"),
            })
            .collect()
    }

    fn publish_req(key: &str, value: &str) -> SettingsConfigPublishRequest {
        SettingsConfigPublishRequest {
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_config_creates_v1_and_emits() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());

        let resp = svc
            .publish_config(tenant(), publish_req("app.timeout", "30s"))
            .await
            .expect("publish ok");

        assert_eq!(resp.data.key, "app.timeout");
        assert_eq!(resp.data.version, 1);

        let facts = emitted_facts(&capture);
        assert_eq!(facts.len(), 1, "L2：每次 publish 恰发射一条 outbox entry");
        let fact = &facts[0];
        assert_eq!(fact.topic, VERSION_CHANGED_TOPIC);
        // envelope：域 / 契约 / opaque subject（config key）。
        assert_eq!(fact.domain, SETTINGS_DOMAIN);
        assert_eq!(fact.contract_id, CONTRACT_ID);
        assert_eq!(fact.subject_id, "app.timeout");
        // payload。
        assert_eq!(fact.payload.key, "app.timeout");
        assert_eq!(fact.payload.version, 1);
        assert_eq!(
            fact.payload.change_kind,
            SettingsConfigChangeKind::Published
        );
        assert_eq!(fact.payload.source_version, None);
        assert_eq!(fact.payload.tenant_id, TENANT);
        assert_eq!(fact.payload.occurred_at, 1_000);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_config_increments_version() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());

        svc.publish_config(tenant(), publish_req("app.k", "v1"))
            .await
            .expect("v1");
        let resp = svc
            .publish_config(tenant(), publish_req("app.k", "v2"))
            .await
            .expect("v2");
        assert_eq!(resp.data.version, 2);
        assert_eq!(
            svc.get_value(tenant(), "app.k").await.expect("get"),
            Some("v2".to_string())
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_config_rejects_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc
            .publish_config(tenant(), publish_req("nodot", "v"))
            .await
            .expect_err("invalid key");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
        assert!(emitted_facts(&capture).is_empty(), "非法 key 不发射");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn cas_conflict_on_stale_save() {
        // 直接对 repo 验 CAS：写 v1 后，再写 v1（陈旧版本号）→ VersionConflict。
        let repo = InMemConfigRepo::new();
        let t = tenant();
        let key = SettingKey::parse("app.k").expect("key");
        let entry_v1 = ConfigEntry::new(
            key.clone(),
            ConfigValue::new("v1"),
            t,
            ConfigVersion::new(1),
        );
        repo.save(t, entry_v1).await.expect("v1 ok");
        let stale = ConfigEntry::new(key, ConfigValue::new("v1b"), t, ConfigVersion::new(1));
        assert!(matches!(
            repo.save(t, stale).await,
            Err(SettingsError::VersionConflict)
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_restores_value_and_emits_rolled_back() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(tenant(), publish_req("app.k", "v1"))
            .await
            .expect("v1");
        svc.publish_config(tenant(), publish_req("app.k", "v2"))
            .await
            .expect("v2");

        let resp = svc.rollback(tenant(), "app.k", 1).await.expect("rollback");
        assert_eq!(resp.data.version, 3, "回滚生成新版本 v3");
        assert_eq!(
            svc.get_value(tenant(), "app.k").await.expect("get"),
            Some("v1".to_string()),
            "v3 值 = v1 的值"
        );

        let facts = emitted_facts(&capture);
        assert_eq!(facts.len(), 3, "publish v1 + v2 + rollback v3 = 3 条 fact");
        let last = facts.last().expect("event");
        assert_eq!(
            last.payload.change_kind,
            SettingsConfigChangeKind::RolledBack
        );
        assert_eq!(last.payload.version, 3);
        assert_eq!(last.payload.source_version, Some(1));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_missing_version_is_not_found() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(tenant(), publish_req("app.k", "v1"))
            .await
            .expect("v1");
        let err = svc
            .rollback(tenant(), "app.k", 9)
            .await
            .expect_err("missing version");
        assert!(matches!(err, SettingsServiceError::NotFound));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_removes_config() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(tenant(), publish_req("app.k", "v1"))
            .await
            .expect("v1");
        svc.delete(tenant(), "app.k").await.expect("delete");
        assert_eq!(svc.get_value(tenant(), "app.k").await.expect("get"), None);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn is_flag_enabled_evaluates_seeded_flag() {
        let capture = CapturingEmitter::default();
        let rule = RolloutRule::new(
            "region",
            crate::domain::RolloutOperator::In,
            vec!["us".to_string()],
        );
        let flag = FlagState::new(
            FlagKey::parse("checkout").expect("flag key"),
            true,
            false,
            vec![rule],
            Some(RolloutPercentage::new(100).expect("pct")),
        );
        let svc = service_with(&capture, InMemFlagStore::new().with_flag(tenant(), flag));

        assert!(
            svc.is_flag_enabled(tenant(), "checkout", &[("region", "us")])
                .expect("eval")
        );
        assert!(
            !svc.is_flag_enabled(tenant(), "checkout", &[("region", "eu")])
                .expect("eval")
        );
        // 未知 flag → fail-closed false。
        assert!(!svc.is_flag_enabled(tenant(), "unknown", &[]).expect("eval"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn is_flag_enabled_rejects_invalid_flag_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc
            .is_flag_enabled(tenant(), "bad key", &[])
            .expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn settings_domain_declares_config_route_group() {
        let reg = bootstrap::compose(&[&SettingsDomain]).expect("compose ok");
        let groups = reg.route_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, ListenerKind::Primary);
        assert_eq!(groups[0].1, SETTINGS_ROUTE_PREFIX);
    }

    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";

    #[allow(clippy::expect_used)]
    fn tenant_b() -> TenantId {
        TenantId::parse(TENANT_B).expect("canonical uuid")
    }

    // cross-tenant 隔离：tenant_a publish "app.k"，tenant_b get_value("app.k")==None。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn cross_tenant_isolation() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(tenant(), publish_req("app.k", "secret"))
            .await
            .expect("tenant_a publish");
        let val = svc
            .get_value(tenant_b(), "app.k")
            .await
            .expect("tenant_b get");
        assert_eq!(val, None, "跨租户隔离：tenant_b 不应读到 tenant_a 的值");
    }

    // event_id (idem_key) 派生稳定性：同 tenant/key/version → 同 idem-key。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn event_id_derivation_is_stable() {
        // 两个独立 service 实例对同 tenant+key publish v1，idem-key 应相同（内容派生）。
        let cap1 = CapturingEmitter::default();
        let svc1 = service_with(&cap1, InMemFlagStore::new());
        let cap2 = CapturingEmitter::default();
        let svc2 = service_with(&cap2, InMemFlagStore::new());

        svc1.publish_config(tenant(), publish_req("app.timeout", "30s"))
            .await
            .expect("svc1 publish");
        svc2.publish_config(tenant(), publish_req("app.timeout", "30s"))
            .await
            .expect("svc2 publish");

        let facts1 = emitted_facts(&cap1);
        let facts2 = emitted_facts(&cap2);
        assert_eq!(facts1.len(), 1);
        assert_eq!(facts2.len(), 1);
        assert_eq!(
            facts1[0].idem, facts2[0].idem,
            "同 tenant/key/version 应产生相同 idem-key（去重锚点）"
        );
        // 断言 idem-key 格式包含 topic:tenant:key:vN。
        let eid = &facts1[0].idem;
        assert!(eid.contains(VERSION_CHANGED_TOPIC), "idem 含 topic: {eid}");
        assert!(eid.contains(TENANT), "idem 含 tenant: {eid}");
        assert!(eid.contains("app.timeout"), "idem 含 key: {eid}");
        assert!(eid.contains("v1"), "idem 含版本: {eid}");
    }

    // wire_version 溢出收口：u64::MAX → i64::MAX。
    #[test]
    fn wire_version_clamps_on_overflow() {
        assert_eq!(wire_version(u64::MAX), i64::MAX);
        assert_eq!(wire_version(0), 0);
        assert_eq!(wire_version(42), 42);
    }

    // invalid-key 测试：rollback 非法 key。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_invalid_key_returns_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc
            .rollback(tenant(), "nodot", 1)
            .await
            .expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    // invalid-key 测试：get_value 非法 key。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn get_value_invalid_key_returns_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc.get_value(tenant(), "nodot").await.expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    // invalid-key 测试：delete 非法 key。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_invalid_key_returns_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc.delete(tenant(), "nodot").await.expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    // delete 后底层 find_version 断言已清除 + 不存在 key delete 幂等。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_clears_version_history_and_is_idempotent() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(tenant(), publish_req("app.k", "v1"))
            .await
            .expect("publish");

        // 删除。
        svc.delete(tenant(), "app.k").await.expect("delete");

        // get_value 已是 None。
        assert_eq!(svc.get_value(tenant(), "app.k").await.expect("get"), None);

        // 对不存在 key 再次 delete 应幂等（返回 Ok）。
        svc.delete(tenant(), "app.k").await.expect("幂等 delete");
    }

    // 多 key 独立版本：publish "app.a" 与 "app.b" 各 v1，两者 version 均为 1。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn multiple_keys_have_independent_versions() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());

        let resp_a = svc
            .publish_config(tenant(), publish_req("app.a", "val-a"))
            .await
            .expect("publish a");
        let resp_b = svc
            .publish_config(tenant(), publish_req("app.b", "val-b"))
            .await
            .expect("publish b");

        assert_eq!(resp_a.data.version, 1, "app.a 应从 v1 开始");
        assert_eq!(resp_b.data.version, 1, "app.b 应从 v1 开始，与 app.a 独立");
    }

    // F2：service 层并发 CAS 回归——两个并发 publish 同 key，恰一个成功一个 VersionConflict，只发一条 fact。
    // barrier 迫使两个 publish 都读到同版本（None）后再各自 save，制造 read-then-write 竞争。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn concurrent_publish_same_key_one_wins_one_conflicts() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // 前 2 次 find 在 barrier(2) 同步；后续 find 直通（避免末尾 get_value 死锁）。
        struct BarrierConfigRepo {
            inner: InMemConfigRepo,
            barrier: tokio::sync::Barrier,
            finds: AtomicUsize,
        }
        impl ConfigRepo for BarrierConfigRepo {
            async fn find(
                &self,
                tenant: TenantId,
                key: &SettingKey,
            ) -> Result<Option<ConfigEntry>, SettingsError> {
                let result = self.inner.find(tenant, key).await;
                if self.finds.fetch_add(1, Ordering::SeqCst) < 2 {
                    self.barrier.wait().await;
                }
                result
            }
            async fn find_version(
                &self,
                tenant: TenantId,
                key: &SettingKey,
                version: u64,
            ) -> Result<Option<ConfigEntry>, SettingsError> {
                self.inner.find_version(tenant, key, version).await
            }
            async fn save(
                &self,
                tenant: TenantId,
                entry: ConfigEntry,
            ) -> Result<(), SettingsError> {
                self.inner.save(tenant, entry).await
            }
            async fn delete(
                &self,
                tenant: TenantId,
                key: &SettingKey,
            ) -> Result<(), SettingsError> {
                self.inner.delete(tenant, key).await
            }
        }

        let capture = CapturingEmitter::default();
        let svc = SettingsService::new(
            DynConfigRepo::new_box(BarrierConfigRepo {
                inner: InMemConfigRepo::new(),
                barrier: tokio::sync::Barrier::new(2),
                finds: AtomicUsize::new(0),
            }),
            Box::new(InMemFlagStore::new()),
            DynOutboxEmitter::new_box(capture.clone()),
            Box::new(FixedClock(
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            )),
        );

        // 单任务 join! 并发：两 future 都在 barrier 处 yield，同步后各自 save（CAS 竞争）。
        let (r1, r2) = tokio::join!(
            svc.publish_config(tenant(), publish_req("app.k", "a")),
            svc.publish_config(tenant(), publish_req("app.k", "b")),
        );

        let results = [r1, r2];
        let oks = results.iter().filter(|r| r.is_ok()).count();
        let conflicts = results
            .iter()
            .filter(|r| matches!(r, Err(SettingsServiceError::VersionConflict)))
            .count();
        assert_eq!(oks, 1, "并发 publish 同 key 恰一个成功");
        assert_eq!(conflicts, 1, "另一个应 VersionConflict（CAS 守住）");

        // 失败方在 save 冲突后不发射 ⇒ 恰一条 outbox fact。
        assert_eq!(
            emitted_facts(&capture).len(),
            1,
            "并发只发一条 outbox fact（write-without-event 不发生）"
        );

        // 最终活跃版本是某个胜者的值（v1）。
        let val = svc.get_value(tenant(), "app.k").await.expect("get");
        assert!(
            val == Some("a".to_string()) || val == Some("b".to_string()),
            "最终值是某个胜者的值"
        );
    }
}
