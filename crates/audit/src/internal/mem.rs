//! audit::internal::mem — in-mem 每租户子链 store（`AuditRepo` 实现）。
//!
//! 单进程占位实现（域 crate + 测试自洽）：每租户一条 `Vec<AuditEntry>` append-only 子链，`Mutex` 串行化
//! append（防并发 seq 竞争）。生产 postgres（advisory-lock 串行 + FORCE RLS + `rss_audit_admin` 池）是
//! follow-up；本实现持注入的 [`AuditChainHasher`]，原子封链（读 tail → seq → prev → link → 存）。

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;
use primitives::MacVerifier;

use crate::domain::{AuditChainHasher, AuditEntry, AuditError, EntryHash};
use crate::internal::ports::{AuditListResult, AuditPage, AuditRecord};

/// in-mem 状态：每租户 append-only 子链。
#[derive(Default)]
struct State {
    chains: HashMap<vocab::TenantId, Vec<AuditEntry>>,
}

/// in-mem 审计仓储（持 hasher，`Mutex` 串行化 append）。
pub(crate) struct InMemAuditRepo<M: MacVerifier> {
    hasher: AuditChainHasher<M>,
    state: Mutex<State>,
}

impl<M: MacVerifier> InMemAuditRepo<M> {
    /// 注入链 hasher 构造（hasher 持 verifier + key）。
    pub(crate) fn new(hasher: AuditChainHasher<M>) -> Self {
        Self {
            hasher,
            state: Mutex::new(State::default()),
        }
    }
}

/// in-mem 读时链验证是 O(n) 全扫（in-mem 占位语义）；postgres provider 应做增量尾部验证，不复制全扫语义。
///
/// 测试辅助：篡改某租户首条目的 entry_hash 以触发读时链验证失败路径。
#[cfg(test)]
impl<M: MacVerifier> InMemAuditRepo<M> {
    /// 测试用：篡改某租户首条目的 entry_hash，触发 list 读时校验失败。
    pub(crate) fn corrupt_first_entry_hash(&self, tenant: vocab::TenantId) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(chain) = state.chains.get_mut(&tenant)
            && let Some(e) = chain.first()
        {
            let tampered = AuditEntry::new(
                e.seq(),
                *e.prev_hash(),
                EntryHash::new([0xAAu8; 32]),
                e.actor(),
                e.actor_kind(),
                e.tenant(),
                e.action().clone(),
                crate::domain::ResourceRef::new(e.resource().kind(), e.resource().id()),
                e.outcome(),
                e.recorded_at(),
            );
            chain[0] = tampered;
        }
    }
}

/// 把全局子链下标编码成不透明游标（base64url，对齐 [`vocab::Cursor`]）。
fn encode_cursor(index: usize) -> Option<vocab::Cursor> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(index.to_string());
    vocab::Cursor::parse(&raw).ok()
}

/// 解码游标回子链下标。
///
/// fail-closed：base64url 合法但**语义无效**（解码后非 UTF-8 / 非数字）即 `Err(InvalidCursor)`——
/// **不**静默回退首页（否则客户端续页时拿到重复首页，[F4]）。handler 将 `InvalidCursor` 映射 400。
fn decode_cursor(cursor: &vocab::Cursor) -> Result<usize, AuditError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_str())
        .map_err(|_| AuditError::InvalidCursor)?;
    std::str::from_utf8(&bytes)
        .map_err(|_| AuditError::InvalidCursor)?
        .parse()
        .map_err(|_| AuditError::InvalidCursor)
}

// inherent async 方法（无 port trait——本轮单 provider，provider 抽象 trait 随 postgres adapter follow-up，
// 见 internal/ports.rs）。futures 在 `M: Send + Sync` 下为 `Send`（被订阅 handler / axum handler 跨 await 持有）。
impl<M> InMemAuditRepo<M>
where
    M: MacVerifier + Send + Sync,
{
    pub(crate) async fn append(&self, record: AuditRecord) -> Result<(), AuditError> {
        let AuditRecord {
            tenant,
            actor,
            actor_kind,
            action,
            resource,
            outcome,
            recorded_at,
        } = record;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let chain = state.chains.entry(tenant).or_default();
        let (seq, prev) = match chain.last() {
            Some(last) => (
                last.seq().checked_add(1).ok_or(AuditError::SequenceGap)?,
                *last.entry_hash(),
            ),
            None => (0, EntryHash::genesis()),
        };
        // 先用占位 entry_hash 构造 raw 算链哈希，再用同字段 + 真 entry_hash 构造 sealed。
        let raw = AuditEntry::new(
            seq,
            prev,
            EntryHash::genesis(),
            actor,
            actor_kind,
            tenant,
            action.clone(),
            resource.clone(),
            outcome,
            recorded_at,
        );
        let entry_hash = self.hasher.link(&prev, &raw);
        let sealed = AuditEntry::new(
            seq,
            prev,
            entry_hash,
            actor,
            actor_kind,
            tenant,
            action,
            resource,
            outcome,
            recorded_at,
        );
        chain.push(sealed);
        Ok(())
    }

    /// 分页列出某租户审计条目（读时全链完整性验证，篡改即 fail-closed 返回 Err）。
    ///
    /// **性能注意**：读时对整条租户链 O(n) 全扫验证是本 in-mem 实现的占位语义；
    /// postgres provider 实现时应做增量尾部验证而非全扫（不应复制本实现的全扫逻辑）。
    pub(crate) async fn list(
        &self,
        tenant: vocab::TenantId,
        page: AuditPage,
    ) -> Result<AuditListResult, AuditError> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let chain = state.chains.get(&tenant).map(Vec::as_slice).unwrap_or(&[]);
        // 读时校验整链完整（tamper-evident，docs/rules/audit-ledger.md）：篡改即 fail-closed，不返回脏数据。
        // in-mem 进程内存不可被外部篡改，此调用是契约一致性 + 链完整回归守卫；真实 defense 在 postgres provider。
        self.hasher.verify(chain)?;
        // 续页游标语义无效即 fail-closed（不静默回退首页，防重复页，F4）。
        let start = match page.cursor.as_ref() {
            Some(cursor) => decode_cursor(cursor)?,
            None => 0,
        };
        let limit = usize::from(page.limit.get());
        let end = start.saturating_add(limit).min(chain.len());
        let entries = chain.get(start..end).unwrap_or(&[]).to_vec();
        let has_more = end < chain.len();
        let next_cursor = if has_more { encode_cursor(end) } else { None };
        Ok(AuditListResult {
            entries,
            next_cursor,
            has_more,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::domain::test_support::{TestKeyedHasher, keyed_hasher};
    use crate::domain::{AuditOutcome, ResourceRef};

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";
    const ACTOR: &str = "11111111-2222-4333-8444-555555555555";

    #[allow(clippy::expect_used)]
    fn tenant(raw: &str) -> vocab::TenantId {
        vocab::TenantId::parse(raw).expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn record(tenant_raw: &str) -> AuditRecord {
        AuditRecord {
            tenant: tenant(tenant_raw),
            actor: ids::UserId::parse(ACTOR).expect("actor"),
            actor_kind: authn::PrincipalKind::User,
            action: vocab::Action::parse("audit:read").expect("action"),
            resource: ResourceRef::new("session", "sess-1"),
            outcome: AuditOutcome::Success,
            recorded_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        }
    }

    #[allow(clippy::expect_used)]
    fn page(limit: u16, cursor: Option<vocab::Cursor>) -> AuditPage {
        AuditPage {
            limit: vocab::Limit::new(limit).expect("limit ≤500"),
            cursor,
        }
    }

    fn repo() -> InMemAuditRepo<TestKeyedHasher> {
        InMemAuditRepo::new(keyed_hasher(0x5a))
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn append_assigns_monotonic_seq_and_links_prev() {
        let repo = repo();
        for _ in 0..3 {
            repo.append(record(TENANT_A)).await.expect("append");
        }
        let listed = repo
            .list(tenant(TENANT_A), page(500, None))
            .await
            .expect("list");
        let e = &listed.entries;
        assert_eq!((e[0].seq(), e[1].seq(), e[2].seq()), (0, 1, 2));
        // 链接：e[1].prev == e[0].entry，e[2].prev == e[1].entry。
        assert_eq!(e[1].prev_hash().as_bytes(), e[0].entry_hash().as_bytes());
        assert_eq!(e[2].prev_hash().as_bytes(), e[1].entry_hash().as_bytes());
        // genesis prev 全零。
        assert_eq!(e[0].prev_hash().as_bytes(), &[0u8; 32]);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn appended_chain_verifies_on_read() {
        let repo = repo();
        for _ in 0..3 {
            repo.append(record(TENANT_A)).await.expect("append");
        }
        // list 内部读时校验整链：返回 Ok ⇒ 链完整。再以同 key hasher 显式复验页内条目。
        let listed = repo
            .list(tenant(TENANT_A), page(500, None))
            .await
            .expect("list ok ⇒ 链完整");
        assert!(keyed_hasher(0x5a).verify(&listed.entries).is_ok());
        assert_eq!(listed.entries.len(), 3);
        assert!(!listed.has_more);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn tenants_are_isolated() {
        let repo = repo();
        repo.append(record(TENANT_A)).await.expect("a0");
        repo.append(record(TENANT_A)).await.expect("a1");
        repo.append(record(TENANT_B)).await.expect("b0");
        // list 仅见本租户；各租户独立 genesis（seq 从 0 起）。
        let a = repo
            .list(tenant(TENANT_A), page(500, None))
            .await
            .expect("list a");
        let b = repo
            .list(tenant(TENANT_B), page(500, None))
            .await
            .expect("list b");
        assert_eq!(a.entries.len(), 2);
        assert_eq!(b.entries.len(), 1);
        assert_eq!(a.entries[0].seq(), 0);
        assert_eq!(b.entries[0].seq(), 0);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn pagination_walks_cursor() {
        let repo = repo();
        for _ in 0..5 {
            repo.append(record(TENANT_A)).await.expect("append");
        }
        let p1 = repo
            .list(tenant(TENANT_A), page(2, None))
            .await
            .expect("p1");
        assert_eq!(p1.entries.len(), 2);
        assert!(p1.has_more);
        let p2 = repo
            .list(tenant(TENANT_A), page(2, p1.next_cursor))
            .await
            .expect("p2");
        assert_eq!(p2.entries.len(), 2);
        assert!(p2.has_more);
        let p3 = repo
            .list(tenant(TENANT_A), page(2, p2.next_cursor))
            .await
            .expect("p3");
        assert_eq!(p3.entries.len(), 1);
        assert!(!p3.has_more);
        assert!(p3.next_cursor.is_none());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn list_empty_for_unknown_tenant() {
        let repo = repo();
        let empty = repo
            .list(tenant(TENANT_A), page(10, None))
            .await
            .expect("list");
        assert!(empty.entries.is_empty());
        assert!(!empty.has_more);
        assert!(empty.next_cursor.is_none());
    }

    /// 篡改首条 entry_hash 后 list 返回 HashMismatch（读时链完整性验证 fail-close）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn list_returns_error_when_chain_tampered() {
        let repo = repo();
        // append 2 条正常记录。
        repo.append(record(TENANT_A)).await.expect("append 0");
        repo.append(record(TENANT_A)).await.expect("append 1");
        // 篡改首条 entry_hash。
        repo.corrupt_first_entry_hash(tenant(TENANT_A));
        // list 读时链验证应失败。
        let result = repo.list(tenant(TENANT_A), page(10, None)).await;
        assert!(
            matches!(result, Err(crate::domain::AuditError::HashMismatch)),
            "篡改后 list 须返回 HashMismatch"
        );
    }

    /// 语义无效游标（base64url 合法但解码后非数字）fail-closed → `InvalidCursor`（不静默回退首页，F4）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn list_rejects_semantically_invalid_cursor() {
        let repo = repo();
        for _ in 0..3 {
            repo.append(record(TENANT_A)).await.expect("append");
        }
        // 构造 base64url 编码了 "not-a-number" 的游标（Cursor::parse 接受，但语义无效）。
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-number");
        let cursor = vocab::Cursor::parse(&raw).expect("cursor parse");
        let result = repo.list(tenant(TENANT_A), page(10, Some(cursor))).await;
        assert!(
            matches!(result, Err(AuditError::InvalidCursor)),
            "语义无效游标须 fail-closed 返回 InvalidCursor（不回退首页，防重复页）"
        );
    }
}
