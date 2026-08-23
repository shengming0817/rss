//! `CasStore` —— 状态 compare-and-swap provider DI port（可替换：prod etcd/Redis/Postgres / test in-mem）。
//!
//! **字节级** state-CAS 接缝：consumer 携 `key` + `expected`（期望当前值，`None` = 期望键不存在）+
//! `new_value` + 可选 `expected_token`（fencing 防 stale）发起 swap；provider 按 **per-key 单调 revision
//! token** 做 etcd 风格条件写：
//! - **absent + expected==None**，或 **值匹配且 token 不 stale** → [`CasStoreOutcome::Applied`]（token 单调 `+1`，
//!   新值落地）；
//! - **值不符**（含 expected!=None 但键不存在）→ [`CasStoreOutcome::Conflict`]（回当前值供重读重试）；
//! - **`expected_token` 低于该 key 当前 token**（旧 leader stale 写）→ [`CasStoreOutcome::Fenced`]（拒写、回当前 token）。
//!
//! 泛型 `T` 不下沉 port（dyn-compatible 不能有泛型方法，ADR-003 §4.6）——typed `CasRequest<T>`/`CasOutcome<T>`
//! 由 `distributed::StateCas` facade 序列化成字节后经本 port 落地。
//!
//! ref: etcd-io/etcd client/v3/txn.go（`If(Compare(ModRevision)).Then(Put).Else(Get)` = compare-and-swap-by-revision）；
//! ref: databendlabs/openraft openraft/src/lib.rs（LogId/Vote 单调 = token 防脑裂）；
//! Martin Kleppmann《DDIA》§8.3 fencing token（storage 拒绝 token 低于已见高水位的写）。
//! INVARIANT: CAS-REVISION-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（**per-key** revision token 单调 + etcd-revision 条件写：absent/值匹配且
//! token 不 stale 受、值不符回 Conflict、token stale 回 Fenced。回归见 `adapters/memory` MemCasStore 测试 +
//! 本模块 smoke reference impl）。该不变式是 **Medium（运行期 `#[test]`）固有**：单调性是对**运行期** token 值的
//! 比较（当前 token 在运行期才知），无法上移编译期类型系统；守卫是 adapter 行为测试 + anti-vacuity（写后用旧
//! expected 必 Conflict / token stale 必 Fenced），非 Hard。

use dynosaur::dynosaur;

use crate::redacted::RedactedSource;
use crate::redacted_bytes::RedactedBytes;

/// CAS 操作 key（fencing/版本维度）。provider 按 key **各自**维护 revision token。
/// newtype funnel（私有字段，单一构造入口）——独立语义不复用裸 `String`。
/// 字节端口层 key，对应 typed facade `distributed::CasKey`（经 `StateCas` 映射）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CasStoreKey(String);

impl CasStoreKey {
    /// 由状态标识构造（如 `tenant-42/desired-state`、设备收敛 key）。
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }
    /// 借出底层 key。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// typed CAS 请求：`key` 目标状态 + `expected` 期望当前值（`None` = 期望键不存在）+ `new_value` 待写值
/// + 可选 `expected_token`（fencing 防 stale）。
///
/// PII 边界（类型层 Hard，同 [`crate::SignRequest`] / [`crate::FencedWriteRequest`]）：`expected` / `new_value`
/// （状态 payload，可能含敏感设备状态 / 凭据）经 [`RedactedBytes`] 持有（`Debug` 恒 `<redacted>`），故
/// `derive(Debug)` 即安全；`key` / `expected_token` 是路由 / 版本元数据，可观测。
///
/// INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, Clone)]
pub struct CasStoreRequest {
    /// 目标状态 key（revision token 按 key 隔离）。
    pub key: CasStoreKey,
    /// 期望当前值（provider-agnostic 字节，[`RedactedBytes`] 持有）；`None` = 期望键不存在（create-if-absent）。
    pub expected: Option<RedactedBytes>,
    /// 待写新值（provider-agnostic 字节，[`RedactedBytes`] 持有）。
    pub new_value: RedactedBytes,
    /// 可选 fencing token：`Some(t)` 且 `t` 低于该 key 当前 token ⇒ Fenced（旧 leader stale 写被挡）。
    pub expected_token: Option<vocab::Epoch>,
}

/// CAS 操作结论（typed outcome，非 error——conflict / fence 是预期控制流，对标 `consistency::SeenState` /
/// [`crate::WriteOutcome`]）。
///
/// PII 边界（同 [`CasStoreRequest`]）：`Conflict.current`（当前状态 payload）经 [`RedactedBytes`] 持有
/// （`Debug` 恒 `<redacted>`），故 `derive(Debug)` 即安全；`Applied.token` / `Fenced.current_token` 是版本元数据，可观测。
///
/// INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CasStoreOutcome {
    /// swap 成功落地，返回该 key 推进后的 revision token（单调 `+1`）。
    Applied { token: vocab::Epoch },
    /// 值不符（含 expected!=None 但键不存在）——回当前值供调用方重读重试。
    Conflict { current: Option<RedactedBytes> },
    /// `expected_token` 低于该 key 当前 token——旧 leader stale 写被挡，回当前 token；调用方应停写、重选举。
    Fenced { current_token: vocab::Epoch },
}

/// CAS 写失败（infra 故障，**非** conflict/fence——后两者是 [`CasStoreOutcome`] 的 `Ok`）。
///
/// PII 边界（与 [`crate::SignerError`] / [`crate::FencedWriterError`] 同范式）：source 经 [`RedactedSource`] 脱敏。
/// 见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("cas store operation failed")]
pub struct CasStoreError {
    #[source]
    source: RedactedSource,
}

impl CasStoreError {
    /// 把 adapter 内部错误包成 CAS 写失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// 状态 CAS provider DI port（async）。
///
/// 公开 [`CasStore`] 是 **Send 变体**（adapters `impl CasStore for ...`），[`DynCasStore`] 是其 dyn-compatible
/// wrapper（组合根经 `Box<DynCasStore>` 注入、`distributed::StateCas` facade 消费）。非 Send 基 trait
/// `CasStoreLocal` 不在 crate 根 re-export。
#[trait_variant::make(CasStore: Send)]
#[dynosaur(pub DynCasStore = dyn(box) CasStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `CasStore` 变体 +
// dynosaur `DynCasStore` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait CasStoreLocal {
    /// 按 [`CasStoreRequest`] 做 etcd-revision 条件写：absent+expected==None / 值匹配且 token 不 stale ⇒
    /// [`CasStoreOutcome::Applied`]（token 单调 `+1`）；值不符 ⇒ [`CasStoreOutcome::Conflict`]；
    /// `expected_token` 低于当前 ⇒ [`CasStoreOutcome::Fenced`]；`Err` 仅表 infra 故障。
    async fn compare_and_swap(
        &self,
        request: CasStoreRequest,
    ) -> Result<CasStoreOutcome, CasStoreError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`
    /// 由 `bootstrap::ShutdownStack` 统一编排；本方法是 port-local 关闭路径。
    async fn shutdown(&self) -> Result<(), CasStoreError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynCasStore>` 跨 spawn（Send）动态注入，
    //! 并以一个 etcd-revision reference impl 断言 Applied/Conflict/Fenced 三态契约（CAS-REVISION-MONO-01）。
    use super::{
        CasStore, CasStoreError, CasStoreKey, CasStoreOutcome, CasStoreRequest, DynCasStore,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn cas_store_error_redacts_source() {
        let err = CasStoreError::new(std::io::Error::other("leak-marker-cas"));
        assert_eq!(err.to_string(), "cas store operation failed");
        assert!(std::error::Error::source(&err).is_some());
        assert!(
            !format!("{err:?}").contains("leak-marker-cas"),
            "source 泄漏: {err:?}"
        );
    }

    #[test]
    fn cas_store_key_round_trips() {
        let key = CasStoreKey::new("tenant-42/desired-state");
        assert_eq!(key.as_str(), "tenant-42/desired-state");
    }

    #[test]
    fn cas_store_request_debug_redacts_payload() {
        // anti-vacuity：原始 Vec<u8> Debug 把 0xDE 渲染成 "222"。
        assert!(format!("{:?}", vec![0xDE_u8]).contains("222"));
        let req = CasStoreRequest {
            key: CasStoreKey::new("state-1"),
            expected: Some(vec![0xDE, 0xAD].into()),
            new_value: vec![0xBE, 0xEF].into(),
            expected_token: Some(vocab::Epoch::new(7)),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("222"), "expected 字节泄漏: {dbg}");
        assert!(!dbg.contains("190"), "new_value 字节泄漏: {dbg}"); // 0xBE = 190
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains('7'), "expected_token 应可见: {dbg}");
        assert!(dbg.contains("state-1"), "key 应可见: {dbg}");
    }

    #[test]
    fn cas_store_outcome_conflict_debug_redacts_current() {
        assert!(format!("{:?}", vec![0xDE_u8]).contains("222"));
        let outcome = CasStoreOutcome::Conflict {
            current: Some(vec![0xDE, 0xAD].into()),
        };
        let dbg = format!("{outcome:?}");
        assert!(!dbg.contains("222"), "current 字节泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        // `current: None`（expected!=None 但键不存在）路径：derive(Debug) 渲染 `None`、无 `<redacted>`、不泄漏。
        let none = CasStoreOutcome::Conflict { current: None };
        let none_dbg = format!("{none:?}");
        assert!(
            none_dbg.contains("None"),
            "current=None 应渲染 None: {none_dbg}"
        );
        assert!(
            !none_dbg.contains("<redacted>"),
            "current=None 不应有 <redacted>: {none_dbg}"
        );
        // Applied/Fenced 的 token 可观测（版本元数据）。
        let applied = CasStoreOutcome::Applied {
            token: vocab::Epoch::new(9),
        };
        assert!(format!("{applied:?}").contains('9'), "token 应可见");
    }

    /// etcd-revision reference store：per-key `(value, token)`；token 单调 `+1`。
    #[derive(Default)]
    struct RevStore {
        state: Mutex<HashMap<String, (Vec<u8>, vocab::Epoch)>>,
    }

    impl CasStore for RevStore {
        async fn compare_and_swap(
            &self,
            request: CasStoreRequest,
        ) -> Result<CasStoreOutcome, CasStoreError> {
            let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match m.get(request.key.as_str()) {
                None => {
                    if request.expected.is_none() {
                        let token = vocab::Epoch::new(1);
                        m.insert(
                            request.key.as_str().to_owned(),
                            (request.new_value.into_bytes(), token),
                        );
                        Ok(CasStoreOutcome::Applied { token })
                    } else {
                        Ok(CasStoreOutcome::Conflict { current: None })
                    }
                }
                Some((current, current_token)) => {
                    if matches!(request.expected_token, Some(t) if t < *current_token) {
                        return Ok(CasStoreOutcome::Fenced {
                            current_token: *current_token,
                        });
                    }
                    if request.expected.as_ref().map(|b| b.as_bytes()) == Some(current.as_slice()) {
                        let token = current_token.next();
                        m.insert(
                            request.key.as_str().to_owned(),
                            (request.new_value.into_bytes(), token),
                        );
                        Ok(CasStoreOutcome::Applied { token })
                    } else {
                        Ok(CasStoreOutcome::Conflict {
                            current: Some(current.clone().into()),
                        })
                    }
                }
            }
        }
        async fn shutdown(&self) -> Result<(), CasStoreError> {
            // reason: in-mem reference store 无 infra 资源，关闭无需释放。
            Ok(())
        }
    }

    /// Fix 4：RevStore reference impl——expected=Some + 键不存在 → Conflict{current:None}（None 路径边界）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path assert，item-level carve-out。
    async fn rev_store_expected_some_on_absent_key_returns_conflict_none() {
        let store: Box<DynCasStore> = DynCasStore::new_box(RevStore::default());
        let outcome = store
            .compare_and_swap(CasStoreRequest {
                key: CasStoreKey::new("absent"),
                expected: Some(b"expect-something".to_vec().into()),
                new_value: b"new".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("cas ok");
        assert_eq!(
            outcome,
            CasStoreOutcome::Conflict { current: None },
            "expected=Some 但键不存在 → Conflict{{current:None}}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cas_store_is_dyn_injectable_and_honors_three_states() {
        let store: Box<DynCasStore> = DynCasStore::new_box(RevStore::default());
        let outcome = tokio::spawn(async move {
            // create-if-absent → Applied{token=1}。
            let applied = store
                .compare_and_swap(CasStoreRequest {
                    key: CasStoreKey::new("k"),
                    expected: None,
                    new_value: b"v1".to_vec().into(),
                    expected_token: None,
                })
                .await?;
            assert_eq!(
                applied,
                CasStoreOutcome::Applied {
                    token: vocab::Epoch::new(1)
                }
            );

            // 值不符（期望 v-wrong）→ Conflict{current=v1}。
            let conflict = store
                .compare_and_swap(CasStoreRequest {
                    key: CasStoreKey::new("k"),
                    expected: Some(b"v-wrong".to_vec().into()),
                    new_value: b"v2".to_vec().into(),
                    expected_token: None,
                })
                .await?;
            assert_eq!(
                conflict,
                CasStoreOutcome::Conflict {
                    current: Some(b"v1".to_vec().into())
                }
            );

            // stale token（expected_token=0 < 当前 1）→ Fenced{current_token=1}。
            let fenced = store
                .compare_and_swap(CasStoreRequest {
                    key: CasStoreKey::new("k"),
                    expected: Some(b"v1".to_vec().into()),
                    new_value: b"v2".to_vec().into(),
                    expected_token: Some(vocab::Epoch::new(0)),
                })
                .await?;
            assert_eq!(
                fenced,
                CasStoreOutcome::Fenced {
                    current_token: vocab::Epoch::new(1)
                }
            );

            store.shutdown().await?;
            Ok::<_, CasStoreError>(())
        })
        .await;
        assert!(matches!(outcome, Ok(Ok(()))));
    }
}
