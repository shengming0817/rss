//! Provider-neutral in-memory coordination and consistency test doubles.
//!
//! This crate is test/demo infrastructure only. Durable deployments use external providers.
//!
//! Transactional messaging stores, publishers, settlements, and clocks live in the dedicated
//! `rss-transactional-messaging-testkit` package.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use diport::{
    CasStore, CasStoreError, CasStoreOutcome, CasStoreRequest, Checkpoint, CheckpointId,
    CheckpointOffset, CheckpointOwner, CheckpointStoreError, CheckpointVersion, GlobalCasStoreKey,
    LockAcquireOutcome, LockRenewOutcome, LockStore, LockStoreError, LockStoreKey,
    OwnerCheckpointStore, SaveOutcome, SecretCoordinate, SecretMaterial,
    SecretResolver, SecretResolverError,
};
// 锁中毒（仅当持锁线程 panic 时发生）恢复 guard 而非 panic：in-mem 替身不在持锁时 panic，
// 且 lib 代码禁 unwrap/expect（clippy deny）。`unwrap_or_else(into_inner)` 取回 guard，clippy-clean。

// ── MemCasStore：in-mem state-CAS 替身（etcd-revision 条件写）──────────────────────────────────────

/// `MemCasStore` 内部 HashMap 类型别名（规避 clippy::type_complexity）。
type CasStateMap = HashMap<GlobalCasStoreKey, (Vec<u8>, vocab::Epoch)>;

/// in-mem state-CAS 替身（impl [`diport::CasStore`]）：per-key `(value, revision token)`，etcd-revision 条件写。
/// 生产替身走 etcd/redis/postgres adapter；本 crate 仅测试/demo 用。
/// INVARIANT: CAS-REVISION-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（per-key token 单调 + etcd-revision CAS；回归见本 crate 单测）。
#[derive(Clone, Default)]
pub struct MemCasStore {
    state: Arc<Mutex<CasStateMap>>,
}

impl MemCasStore {
    /// 新建空 store（各 key 无值无 token，首写 create-if-absent 恒 Applied）。
    pub fn new() -> Self {
        Self::default()
    }
}

impl CasStore for MemCasStore {
    async fn compare_and_swap(
        &self,
        request: CasStoreRequest,
    ) -> Result<CasStoreOutcome, CasStoreError> {
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 克隆现有条目（释放不可变借用），避免与后续 map.insert 的可变借用冲突。
        let existing = map.get(&request.key).map(|(v, t)| (v.clone(), *t));
        match existing {
            None => {
                // 仅 expected==None（create-if-absent）命中；否则期望某值但键不存在 → Conflict{None}。
                if request.expected.is_none() {
                    let token = vocab::Epoch::new(1);
                    map.insert(request.key, (request.new_value.into_bytes(), token));
                    Ok(CasStoreOutcome::Applied { token })
                } else {
                    Ok(CasStoreOutcome::Conflict { current: None })
                }
            }
            Some((current, current_token)) => {
                // 先判 fencing：expected_token 低于当前 token → stale，拒写。
                if matches!(request.expected_token, Some(t) if t < current_token) {
                    return Ok(CasStoreOutcome::Fenced { current_token });
                }
                // 再判值：匹配 → 写入 + token.next()；不符 → Conflict{当前值}。
                if request.expected.as_ref().map(|b| b.as_bytes()) == Some(current.as_slice()) {
                    let token = current_token.next();
                    map.insert(request.key, (request.new_value.into_bytes(), token));
                    Ok(CasStoreOutcome::Applied { token })
                } else {
                    Ok(CasStoreOutcome::Conflict {
                        current: Some(current.into()),
                    })
                }
            }
        }
    }

    async fn shutdown(&self) -> Result<(), CasStoreError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemLockStore：in-mem 分布式互斥锁替身（per-key 单调 fencing token）────────────────────────────────

/// `MemLockStore` 内部 per-key 锁条目：`held`=当前持有 token（`None`=空闲），`minted`=该 key 已发最高
/// token（单调；下次授予 = `minted+1`，跨 acquire/release/evict **不回退**）。
#[derive(Default)]
struct LockEntry {
    held: Option<vocab::Epoch>,
    minted: u64,
}

/// in-mem 分布式互斥锁替身（impl [`diport::LockStore`]）：per-key fencing token、token-as-capability 互斥。
/// **无时钟**——`ttl` 入参被忽略（TTL 过期 / holder crash 由 [`MemLockStore::evict`] 显式模拟，照
/// explicit test eviction 先例，不触 clippy disallowed-methods 系统时钟）。生产替身走 etcd/redis/consul
/// adapter；本 crate 仅测试/demo 用。INVARIANT: DISTLOCK-FENCE-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（per-key token 单调 + 互斥；回归见本 crate 单测）。
#[derive(Clone, Default)]
pub struct MemLockStore {
    state: Arc<Mutex<HashMap<LockStoreKey, LockEntry>>>,
}

impl MemLockStore {
    /// 新建空 store（各 key 无持有者、minted 从 0 起，首 acquire 授 token=1）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 测试钩子：模拟 lock TTL 过期 / holder crash——清该 key 持有者，使下次 `acquire` 可接管
    /// （接管获**新**单调 token，不回退 `minted`）。照 explicit test eviction；生产走真实 TTL 过期。
    pub fn evict(&self, key: &LockStoreKey) {
        if let Some(entry) = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(key)
        {
            entry.held = None;
        }
    }
}

impl LockStore for MemLockStore {
    async fn acquire(
        &self,
        key: LockStoreKey,
        _ttl: Duration,
    ) -> Result<LockAcquireOutcome, LockStoreError> {
        // reason: in-mem 无 TTL，`ttl` 被忽略（过期由测试 evict 模拟）；锁内同步无 await。
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(key).or_default();
        if entry.held.is_some() {
            Ok(LockAcquireOutcome::Held)
        } else {
            let token = vocab::Epoch::new(entry.minted.saturating_add(1));
            entry.minted = token.get();
            entry.held = Some(token);
            Ok(LockAcquireOutcome::Acquired { token })
        }
    }

    async fn renew(
        &self,
        key: LockStoreKey,
        token: vocab::Epoch,
        _ttl: Duration,
    ) -> Result<LockRenewOutcome, LockStoreError> {
        let map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 仅当 token 是当前持有者才续租（同任期 token 不变）；否则已易手 / 过期被接管 → Lost。
        match map.get(&key) {
            Some(entry) if entry.held == Some(token) => Ok(LockRenewOutcome::Renewed { token }),
            _ => Ok(LockRenewOutcome::Lost),
        }
    }

    async fn release(&self, key: LockStoreKey, token: vocab::Epoch) -> Result<(), LockStoreError> {
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 仅当 token 是当前持有者才放锁（幂等：stale / 已释放 → no-op，不误释他人锁）。
        if let Some(entry) = map.get_mut(&key)
            && entry.held == Some(token)
        {
            entry.held = None;
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), LockStoreError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemCheckpointStore：owner 断点续投 in-mem 替身 ─────────────────────────────

/// checkpoint store 内部 HashMap 类型别名（规避 clippy::type_complexity）。
type CheckpointMap = HashMap<(String, String), (CheckpointOffset, CheckpointVersion)>;

/// in-mem owner checkpoint store（impl [`diport::OwnerCheckpointStore`]）：
/// `(owner, id)` 主键 + `(offset, version)` CAS——`expected` 版本不符即 [`SaveOutcome::StaleVersion`]。
///
/// Owner-scoped checkpoint test double.
/// 生产替身走 postgres adapter；本 crate 仅测试/demo 用。
#[derive(Clone, Default)]
pub struct MemCheckpointStore {
    // key: (owner.as_str(), id.as_str())；value: (offset, current_version)
    inner: Arc<Mutex<CheckpointMap>>,
}

impl MemCheckpointStore {
    /// 新建空 store。
    pub fn new() -> Self {
        Self::default()
    }
}

impl OwnerCheckpointStore for MemCheckpointStore {
    async fn get_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (owner.as_str().to_string(), id.as_str().to_string());
        Ok(g.get(&key)
            .map(|&(offset, version)| Checkpoint { offset, version }))
    }

    async fn save_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
        offset: CheckpointOffset,
        expected: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (owner.as_str().to_string(), id.as_str().to_string());
        match g.get(&key) {
            // 首存：仅当 expected == version 0 时插入（约定「期望无既存行」用 version 0 表达）。
            None if expected == CheckpointVersion::new(0) => {
                g.insert(key, (offset, CheckpointVersion::new(1)));
                Ok(SaveOutcome::Saved)
            }
            // 版本 CAS 成功：存储版本 == expected → 存 offset 并推进版本。
            Some(&(_, stored_ver)) if stored_ver == expected => {
                g.insert(key, (offset, expected.next()));
                Ok(SaveOutcome::Saved)
            }
            // 其余（首存但 expected != 0，或版本失配）→ StaleVersion。
            _ => Ok(SaveOutcome::StaleVersion),
        }
    }

    async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemSecretResolver：in-mem secret 解析替身（journey / e2e / 单测用）─────────────────────────

/// `MemSecretResolver` 内部 store 类型别名（key = (tenant_uuid_str, store_id, key)；value = raw bytes）。
type SecretStoreMap = std::collections::HashMap<(String, String, String), Vec<u8>>;

/// in-mem secret 解析端口（impl [`diport::SecretResolver`]）：按 `(tenant_uuid, store_id, key)` 命中
/// 返 [`SecretMaterial`]，未命中返 [`SecretResolverError::NotFound`]。
///
/// 仅供测试 / journey 使用——不在生产组合根注入（provider 为 Vault / AWS SM 等 adapter）。
///
/// 附调试旋钮（[`MemSecretResolver::set_unreachable`]）：置位后所有 resolve 返回
/// [`SecretResolverError::StoreUnreachable`]，用于验证 fail-closed 路径。
///
/// 附调试旋钮（[`MemSecretResolver::set_forbidden`]）：置位后所有 resolve 返回
/// [`SecretResolverError::Forbidden`]，用于验证 IAM 拒绝路径。
///
/// # 安全语义
///
/// 设计与 [`diport::SecretMaterial`] 同边界：材料字节写入 store 后不存在 owned clone 路径（HashMap
/// 存储 `Vec<u8>`，`resolve` 经 `SecretMaterial::new(bytes.clone())` 新建，drop 触发 `ZeroizeOnDrop`）。
#[derive(Default)]
pub struct MemSecretResolver {
    /// key = (tenant_uuid_str, store_id, secret_key)；value = raw bytes。
    store: Arc<Mutex<SecretStoreMap>>,
    /// 旋钮：置位后所有 resolve 返 `StoreUnreachable`。
    unreachable: Arc<std::sync::atomic::AtomicBool>,
    /// 旋钮：置位后所有 resolve 返 `Forbidden`。
    forbidden: Arc<std::sync::atomic::AtomicBool>,
}

impl MemSecretResolver {
    /// 新建空 resolver（无预设 secret，默认可达且未 forbidden）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 向 store 注入一条 secret（覆盖写）。调用方持有字节，resolver 存 clone。
    ///
    /// `tenant`：租户隔离键（`store_id` + `key` 同 tenant 不同值互不干扰）。
    pub fn insert(
        &self,
        tenant: rss_request_context::TenantId,
        store_id: &str,
        key: &str,
        bytes: Vec<u8>,
    ) {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).insert(
            (tenant.to_string(), store_id.to_string(), key.to_string()),
            bytes,
        );
    }

    /// 打开 `StoreUnreachable` 旋钮（置位后所有 resolve 返 Err）。
    pub fn set_unreachable(&self, v: bool) {
        self.unreachable
            .store(v, std::sync::atomic::Ordering::Relaxed);
    }

    /// 打开 `Forbidden` 旋钮（置位后所有 resolve 返 Err）。
    pub fn set_forbidden(&self, v: bool) {
        self.forbidden
            .store(v, std::sync::atomic::Ordering::Relaxed);
    }
}

impl SecretResolver for MemSecretResolver {
    async fn resolve(
        &self,
        tenant: rss_request_context::TenantId,
        coord: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError> {
        // 旋钮检查（fail-closed 优先于命中查询）。
        if self.unreachable.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(SecretResolverError::store_unreachable(
                std::io::Error::other("mem-resolver: store marked unreachable"),
            ));
        }
        if self.forbidden.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(SecretResolverError::Forbidden);
        }
        let g = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let lookup_key = (
            tenant.to_string(),
            coord.store_id().to_string(),
            coord.key().to_string(),
        );
        match g.get(&lookup_key) {
            Some(bytes) => Ok(SecretMaterial::new(bytes.clone())),
            None => Err(SecretResolverError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_consistency_doubles_construct_without_domain_state() {
        let _ = MemCasStore::new();
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn checkpoint_compare_and_set_rejects_stale_version() {
        let store = MemCheckpointStore::new();
        let owner = CheckpointOwner::new("neutral-worker");
        let id = CheckpointId::new("partition-1");
        let v0 = CheckpointVersion::new(0);
        assert_eq!(
            store
                .save_checkpoint(&owner, &id, CheckpointOffset::new(10), v0)
                .await
                .expect("save"),
            SaveOutcome::Saved
        );
        assert_eq!(
            store
                .save_checkpoint(&owner, &id, CheckpointOffset::new(20), v0)
                .await
                .expect("save"),
            SaveOutcome::StaleVersion
        );
        let current = store
            .get_checkpoint(&owner, &id)
            .await
            .expect("read")
            .expect("present");
        assert_eq!(current.offset, CheckpointOffset::new(10));
        assert_eq!(current.version, CheckpointVersion::new(1));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_resolver_is_tenant_scoped_and_fail_closed() {
        let a = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("tenant");
        let b = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")
            .expect("tenant");
        let coordinate = SecretCoordinate::new("neutral-store", "service/key", None);
        let resolver = MemSecretResolver::new();
        resolver.insert(a, "neutral-store", "service/key", b"value".to_vec());
        assert_eq!(
            resolver
                .resolve(a, &coordinate)
                .await
                .expect("resolve")
                .expose(),
            b"value"
        );
        assert!(matches!(
            resolver.resolve(b, &coordinate).await,
            Err(SecretResolverError::NotFound)
        ));
        resolver.set_forbidden(true);
        assert!(matches!(
            resolver.resolve(a, &coordinate).await,
            Err(SecretResolverError::Forbidden)
        ));
    }
}
