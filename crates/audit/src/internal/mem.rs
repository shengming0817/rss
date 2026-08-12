//! audit::internal::mem — in-mem 每租户子链 store（read/write ports 实现）。
//!
//! 单进程占位实现（域 crate + 测试自洽）：每租户一条 `Vec<AuditEntry>` append-only 子链，`Mutex` 串行化
//! append（防并发 seq 竞争）。生产 postgres provider 使用 advisory-lock 串行 + FORCE RLS + optional
//! `rss_audit_admin` 只读池；本实现持注入的 [`AuditChainHasher`]，原子封链（读 tail → seq → prev → link → 存）。

use std::collections::HashMap;
use std::sync::Mutex;

use primitives::MacVerifier;

use crate::domain::{AuditChainHasher, AuditEntry, AuditError, EntryHash};
use crate::ports::{
    AuditListResult, AuditPage, AuditReadRepo, AuditRecord, AuditWriteRepo, TenantRepoScope,
    decode_sequence_cursor, encode_sequence_cursor,
};

/// in-mem 状态：每租户 append-only 子链。
#[derive(Default)]
struct State {
    chains: HashMap<rss_request_context::TenantId, Vec<AuditEntry>>,
}

/// in-mem 审计仓储（持 hasher，`Mutex` 串行化 append）——read/write ports 的**in-mem 参考 provider**（demo /
/// journeys / 域单测）。生产 durable provider 是 `adapters/postgres` 的 `PgAuditRepo`；组合根经
/// 共享 `Arc<Provider>` 分别装入 read/write wrapper（与 Pg provider 同注入路径）。
pub struct InMemAuditRepo<M: MacVerifier> {
    hasher: AuditChainHasher<M>,
    state: Mutex<State>,
}

impl<M: MacVerifier> InMemAuditRepo<M> {
    /// 注入链 hasher 构造（hasher 持 verifier + key；key 强度在 [`AuditChainHasher::new`] 收口）。
    pub fn new(hasher: AuditChainHasher<M>) -> Self {
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
    pub(crate) fn corrupt_first_entry_hash(&self, tenant: rss_request_context::TenantId) {
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

// 域形 repo ports 实现（ADR-005 Option 2，#1230）。futures 在 `M: Send + Sync` 下为 `Send`。
impl<M> AuditWriteRepo for InMemAuditRepo<M>
where
    M: MacVerifier + Send + Sync,
{
    async fn append(&self, scope: TenantRepoScope, record: AuditRecord) -> Result<(), AuditError> {
        let AuditRecord {
            tenant,
            actor,
            actor_kind,
            action,
            resource,
            outcome,
            recorded_at,
        } = record;
        if scope.tenant() != tenant {
            return Err(AuditError::storage(std::io::Error::other(
                "audit append tenant scope mismatch",
            )));
        }
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
}

impl<M> AuditReadRepo for InMemAuditRepo<M>
where
    M: MacVerifier + Send + Sync,
{
    async fn list(
        &self,
        scope: TenantRepoScope,
        page: AuditPage,
    ) -> Result<AuditListResult, AuditError> {
        let tenant = scope.tenant();
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let chain = state.chains.get(&tenant).map(Vec::as_slice).unwrap_or(&[]);
        // 读时校验整链完整（tamper-evident，docs/rules/audit-ledger.md）：篡改即 fail-closed，不返回脏数据。
        // in-mem 进程内存不可被外部篡改，此调用是契约一致性 + 链完整回归守卫；真实 defense 在 postgres provider。
        self.hasher.verify(chain)?;
        // 续页游标语义无效即 fail-closed（不静默回退首页，防重复页，F4）。
        let start = match page.cursor.as_ref() {
            Some(cursor) => usize::try_from(decode_sequence_cursor(cursor)?)
                .map_err(|_| AuditError::InvalidCursor)?,
            None => 0,
        };
        let limit = usize::from(page.limit.get());
        let end = start.saturating_add(limit).min(chain.len());
        let entries = chain.get(start..end).unwrap_or(&[]).to_vec();
        let has_more = end < chain.len();
        let next_cursor = if has_more {
            Some(encode_sequence_cursor(
                u64::try_from(end).map_err(|_| AuditError::InvalidCursor)?,
            )?)
        } else {
            None
        };
        Ok(AuditListResult {
            entries,
            next_cursor,
            has_more,
        })
    }

    /// 尾部增量验证：验末 `limit` 条 + 其前驱链接（[`AuditChainHasher::verify_window`]，非全扫整链）。
    /// bootstrap 启动自检 / 运维巡检用——postgres provider 同语义（取末窗口 + 1 前驱行）。
    async fn verify_tail(&self, scope: TenantRepoScope, limit: u32) -> Result<(), AuditError> {
        let tenant = scope.tenant();
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let chain = state.chains.get(&tenant).map(Vec::as_slice).unwrap_or(&[]);
        let n = chain.len();
        let take = usize::try_from(limit).unwrap_or(usize::MAX).min(n);
        let start = n - take;
        // 前驱 = 窗口外紧邻一条（start>0 时存在），用于校验窗口首条接续；start==0 ⇒ 窗口含 genesis、前驱 None。
        let predecessor = if start > 0 {
            chain.get(start - 1)
        } else {
            None
        };
        self.hasher.verify_window(predecessor, &chain[start..])
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use base64::Engine as _;

    use super::*;
    use crate::domain::test_support::{TestKeyedHasher, keyed_hasher};
    use crate::domain::{AuditOutcome, ResourceRef};

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";
    const ACTOR: &str = "11111111-2222-4333-8444-555555555555";

    #[allow(clippy::expect_used)]
    fn tenant(raw: &str) -> rss_request_context::TenantId {
        rss_request_context::TenantId::parse(raw).expect("canonical tenant")
    }

    fn scope(raw: &str) -> TenantRepoScope {
        TenantRepoScope::for_test(tenant(raw))
    }

    #[allow(clippy::expect_used)]
    fn record(tenant_raw: &str) -> AuditRecord {
        AuditRecord {
            tenant: tenant(tenant_raw),
            actor: ids::UserId::parse(ACTOR).expect("actor"),
            actor_kind: rss_request_context::PrincipalKind::User,
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
            repo.append(scope(TENANT_A), record(TENANT_A))
                .await
                .expect("append");
        }
        let listed = repo
            .list(scope(TENANT_A), page(500, None))
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
            repo.append(scope(TENANT_A), record(TENANT_A))
                .await
                .expect("append");
        }
        // list 内部读时校验整链：返回 Ok ⇒ 链完整。再以同 key hasher 显式复验页内条目。
        let listed = repo
            .list(scope(TENANT_A), page(500, None))
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
        repo.append(scope(TENANT_A), record(TENANT_A))
            .await
            .expect("a0");
        repo.append(scope(TENANT_A), record(TENANT_A))
            .await
            .expect("a1");
        repo.append(scope(TENANT_B), record(TENANT_B))
            .await
            .expect("b0");
        // list 仅见本租户；各租户独立 genesis（seq 从 0 起）。
        let a = repo
            .list(scope(TENANT_A), page(500, None))
            .await
            .expect("list a");
        let b = repo
            .list(scope(TENANT_B), page(500, None))
            .await
            .expect("list b");
        assert_eq!(a.entries.len(), 2);
        assert_eq!(b.entries.len(), 1);
        assert_eq!(a.entries[0].seq(), 0);
        assert_eq!(b.entries[0].seq(), 0);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn append_rejects_record_tenant_mismatch_without_write() {
        let repo = repo();
        let result = repo.append(scope(TENANT_A), record(TENANT_B)).await;

        assert!(matches!(result, Err(AuditError::Storage(_))));
        assert!(
            repo.list(scope(TENANT_A), page(500, None))
                .await
                .expect("list a")
                .entries
                .is_empty()
        );
        assert!(
            repo.list(scope(TENANT_B), page(500, None))
                .await
                .expect("list b")
                .entries
                .is_empty()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn pagination_walks_cursor() {
        let repo = repo();
        for _ in 0..5 {
            repo.append(scope(TENANT_A), record(TENANT_A))
                .await
                .expect("append");
        }
        let p1 = repo.list(scope(TENANT_A), page(2, None)).await.expect("p1");
        assert_eq!(p1.entries.len(), 2);
        assert!(p1.has_more);
        let p2 = repo
            .list(scope(TENANT_A), page(2, p1.next_cursor))
            .await
            .expect("p2");
        assert_eq!(p2.entries.len(), 2);
        assert!(p2.has_more);
        let p3 = repo
            .list(scope(TENANT_A), page(2, p2.next_cursor))
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
            .list(scope(TENANT_A), page(10, None))
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
        repo.append(scope(TENANT_A), record(TENANT_A))
            .await
            .expect("append 0");
        repo.append(scope(TENANT_A), record(TENANT_A))
            .await
            .expect("append 1");
        // 篡改首条 entry_hash。
        repo.corrupt_first_entry_hash(tenant(TENANT_A));
        // list 读时链验证应失败。
        let result = repo.list(scope(TENANT_A), page(10, None)).await;
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
            repo.append(scope(TENANT_A), record(TENANT_A))
                .await
                .expect("append");
        }
        // 构造 base64url 编码了 "not-a-number" 的游标（Cursor::parse 接受，但语义无效）。
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-number");
        let cursor = vocab::Cursor::parse(&raw).expect("cursor parse");
        let result = repo.list(scope(TENANT_A), page(10, Some(cursor))).await;
        assert!(
            matches!(result, Err(AuditError::InvalidCursor)),
            "语义无效游标须 fail-closed 返回 InvalidCursor（不回退首页，防重复页）"
        );
    }

    /// verify_tail 是增量窗口验证：篡改 genesis（seq 0）后，小窗口（不含 seq 0）仍 Ok，全窗口（含 seq 0）→ HashMismatch。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn verify_tail_is_incremental_window() {
        let repo = repo();
        for _ in 0..5 {
            repo.append(scope(TENANT_A), record(TENANT_A))
                .await
                .expect("append");
        }
        let t = tenant(TENANT_A);
        // 干净链：尾窗口 + 全窗口都通过。
        assert!(
            repo.verify_tail(TenantRepoScope::for_test(t), 2)
                .await
                .is_ok()
        );
        assert!(
            repo.verify_tail(TenantRepoScope::for_test(t), 10)
                .await
                .is_ok()
        );
        // 篡改首条（seq 0）。
        repo.corrupt_first_entry_hash(t);
        // 尾 2 条（seq 3,4）+ 前驱 seq 2，不触 seq 0 ⇒ 仍 Ok（增量，不全扫）。
        assert!(
            repo.verify_tail(TenantRepoScope::for_test(t), 2)
                .await
                .is_ok(),
            "尾窗口不含被篡改的 genesis ⇒ 增量验证须 Ok"
        );
        // 窗口覆盖全链（含被篡改 seq 0）⇒ HashMismatch。
        assert!(
            matches!(
                repo.verify_tail(TenantRepoScope::for_test(t), 10).await,
                Err(AuditError::HashMismatch)
            ),
            "覆盖被篡改 genesis 的窗口须 fail-closed HashMismatch"
        );
    }
}
