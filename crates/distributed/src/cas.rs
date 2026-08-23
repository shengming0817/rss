//! Crate-private global maintenance state-CAS：把 `CasRequest<T>` 序列化成 **canonical JSON**
//! 字节经 [`diport::DynCasStore`] 落地。
//!
//! 泛型 `T` 留在本层（dyn port 不能有泛型方法，ADR-003 §4.6）。
//!
//! **canonical 编码（正确性关键）**：typed facade 把「语义值相等」降成「字节相等」做 CAS 比较，但
//! 本 workspace 的 `serde_json` 启用了 `preserve_order`（依赖 `indexmap`），普通序列化保留插入序、**非
//! canonical**——无序 map（如 `HashMap`）同一语义值会产不同字节序、被误判 `Conflict`。故经
//! [`serde_json_canonicalizer`]（RFC 8785 JSON Canonicalization Scheme）编码，保证同值同字节。
//! JSON number 遵循 IEEE 754 double（JCS）；绝对值严格大于 `2⁵³−1`（JS safe integer）的整数在
//! [`canonical_json_bytes`] **fail-closed** 拒绝（`serde_json::Error` → `DistError::Fatal`），避免不同
//! `u64` 静默丢精度后编码成相同字节、误 `Applied`。超出该精度的整型请用 string 字段承载。
//!
//! ref: etcd-io/etcd client/v3/txn.go（etcd-revision 条件写）；
//! ref: databendlabs/openraft openraft/src/lib.rs（LogId/Vote 单调性 = fencing token）；
//! ref: RFC 8785 JSON Canonicalization Scheme via `serde_json_canonicalizer`.

use crate::maintenance::GlobalCasKey;
use crate::{DistError, FencingToken};
use diport::CasStore as _;

/// Crate-private typed CAS 请求；仅 sealed maintenance coordinator 可生产消费。
#[derive(Clone)]
pub(crate) struct CasRequest<T> {
    pub(crate) key: GlobalCasKey,
    pub(crate) expected: Option<T>,
    pub(crate) new_value: T,
    pub(crate) token: Option<FencingToken>,
}

/// Crate-private typed CAS 结论。
#[derive(Clone)]
pub(crate) enum CasOutcome<T> {
    Applied { token: FencingToken },
    Conflict { current: Option<T> },
    Fenced { token: FencingToken },
}

impl<T> std::fmt::Debug for CasRequest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CasRequest")
            .field("key", &self.key)
            .field("expected", &"<redacted>")
            .field("new_value", &"<redacted>")
            .field("token", &self.token)
            .finish()
    }
}

impl<T> std::fmt::Debug for CasOutcome<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Applied { token } => f.debug_struct("Applied").field("token", token).finish(),
            Self::Conflict { .. } => f
                .debug_struct("Conflict")
                .field("current", &"<redacted>")
                .finish(),
            Self::Fenced { token } => f.debug_struct("Fenced").field("token", token).finish(),
        }
    }
}

/// IEEE 754 binary64 / JS `Number.MAX_SAFE_INTEGER`：`2⁵³ − 1`。
const JS_SAFE_INTEGER_MAX: u64 = (1u64 << 53) - 1;

fn number_exceeds_js_safe_integer(n: &serde_json::Number) -> bool {
    if let Some(u) = n.as_u64() {
        return u > JS_SAFE_INTEGER_MAX;
    }
    if let Some(i) = n.as_i64() {
        return i.unsigned_abs() > JS_SAFE_INTEGER_MAX;
    }
    false
}

fn value_has_unsafe_integer(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Number(n) => number_exceeds_js_safe_integer(n),
        serde_json::Value::Array(items) => items.iter().any(value_has_unsafe_integer),
        serde_json::Value::Object(map) => map.values().any(value_has_unsafe_integer),
        _ => false,
    }
}

/// 把 `T` 编码为 RFC 8785 canonical JSON 字节。
///
/// 先 `serde_json::to_value`，再递归拒绝绝对值 `> 2⁵³−1` 的整数（JCS/IEEE double 会丢精度，
/// 不同整型可碰撞成相同字节），通过后才走 [`serde_json_canonicalizer::to_vec`]。
fn canonical_json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    if value_has_unsafe_integer(&value) {
        return Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "JSON integer outside JS safe integer range (±(2^53-1)); use string fields",
        )));
    }
    serde_json_canonicalizer::to_vec(&value)
}

/// Typed state-CAS facade。组合根经构造器注入 [`diport::DynCasStore`] provider（必填位置参，缺失即编译错误）。
pub(crate) struct StateCas {
    store: Box<diport::DynCasStore<'static>>,
}

impl StateCas {
    /// 组合根注入 CAS provider（必填位置参，缺失即编译错误）。
    pub(crate) fn new(store: Box<diport::DynCasStore<'static>>) -> Self {
        Self { store }
    }

    /// Typed compare-and-swap：序列化 `expected`/`new_value`（canonical JSON），映射 token，调 port，映回 typed outcome。
    ///
    /// - `Ok(CasOutcome::Applied{token})`：成功落地，token 单调 +1。
    /// - `Ok(CasOutcome::Conflict{current})`：值不符，回当前值供重读。
    /// - `Ok(CasOutcome::Fenced{token})`：`expected_token` stale，回当前 token，调用方应停写重选举（fence 是预期控制流）。
    /// - `Err(DistError::Fatal)`：serde 序列化/反序列化失败（payload 不合法，不可重试）。
    /// - `Err(DistError::Transport)`：infra 故障（port 返回 `CasStoreError`，可重试）。
    pub(crate) async fn compare_and_swap<T>(
        &self,
        request: CasRequest<T>,
    ) -> Result<CasOutcome<T>, DistError>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let CasRequest {
            key,
            expected,
            new_value,
            token,
        } = request;
        let key = key.into_store_key();
        let expected = match expected {
            Some(v) => Some(canonical_json_bytes(&v).map_err(|e| {
                tracing::warn!(error = %e, "cas facade: serialize expected failed");
                DistError::Fatal
            })?),
            None => None,
        };
        let new_value = canonical_json_bytes(&new_value).map_err(|e| {
            tracing::warn!(error = %e, "cas facade: serialize new_value failed");
            DistError::Fatal
        })?;
        let expected_token = token.map(|t| vocab::Epoch::new(t.value()));

        let outcome = self
            .store
            .compare_and_swap(diport::CasStoreRequest {
                key,
                expected: expected.map(diport::RedactedBytes::new),
                new_value: diport::RedactedBytes::new(new_value),
                expected_token,
            })
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "cas facade: store transport failure");
                DistError::Transport
            })?;

        match outcome {
            diport::CasStoreOutcome::Applied { token } => Ok(CasOutcome::Applied {
                token: FencingToken::new(token.get()),
            }),
            diport::CasStoreOutcome::Conflict { current } => {
                let current = match current {
                    Some(bytes) => Some(
                        serde_json::from_slice::<T>(bytes.as_bytes()).map_err(|e| {
                            // serde_json::Error Display 含出错位置的 payload 片段（PII 边界，#1155 安全 review）；
                            // 用 classify() 取无 PII 的错误类别（Data/Syntax/Eof/Io），对齐 audit handler 范式。
                            tracing::warn!(category = ?e.classify(), "cas facade: deserialize conflict current failed");
                            DistError::Fatal
                        })?,
                    ),
                    None => None,
                };
                Ok(CasOutcome::Conflict { current })
            }
            diport::CasStoreOutcome::Fenced { current_token } => {
                tracing::debug!(?current_token, "cas facade: fenced (expected_token stale)");
                // fence 是预期控制流：保留当前 token 供调用方重读/停写，不压扁进无字段错误。
                Ok(CasOutcome::Fenced {
                    token: FencingToken::new(current_token.get()),
                })
            }
            // reason: CasStoreOutcome 是 #[non_exhaustive]，跨 crate match 须带 catch-all；
            // 未来新增变体保守映射为 infra 级 Fatal（fail-safe，不静默成功）。
            _ => Err(DistError::Fatal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// 内联 FakeCasStore（etcd-revision 逻辑）——仅在 #[cfg(test)] 子树，不被 dylint impl-allowlist 扫描。
    #[derive(Default)]
    struct FakeCasStore {
        state: Mutex<HashMap<String, (Vec<u8>, vocab::Epoch)>>,
    }

    impl diport::CasStore for FakeCasStore {
        async fn compare_and_swap(
            &self,
            request: diport::CasStoreRequest,
        ) -> Result<diport::CasStoreOutcome, diport::CasStoreError> {
            let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match m.get(request.key.as_str()) {
                None => {
                    if request.expected.is_none() {
                        let token = vocab::Epoch::new(1);
                        m.insert(
                            request.key.as_str().to_owned(),
                            (request.new_value.into_bytes(), token),
                        );
                        Ok(diport::CasStoreOutcome::Applied { token })
                    } else {
                        Ok(diport::CasStoreOutcome::Conflict { current: None })
                    }
                }
                Some((current, current_token)) => {
                    if matches!(request.expected_token, Some(t) if t < *current_token) {
                        return Ok(diport::CasStoreOutcome::Fenced {
                            current_token: *current_token,
                        });
                    }
                    if request.expected.as_ref().map(|b| b.as_bytes()) == Some(current.as_slice()) {
                        let token = current_token.next();
                        m.insert(
                            request.key.as_str().to_owned(),
                            (request.new_value.into_bytes(), token),
                        );
                        Ok(diport::CasStoreOutcome::Applied { token })
                    } else {
                        Ok(diport::CasStoreOutcome::Conflict {
                            current: Some(current.clone().into()),
                        })
                    }
                }
            }
        }

        async fn shutdown(&self) -> Result<(), diport::CasStoreError> {
            // reason: in-mem fake store 无 infra 资源，关闭无需释放。
            Ok(())
        }
    }

    fn make_facade() -> StateCas {
        StateCas::new(diport::DynCasStore::<'static>::new_box(
            FakeCasStore::default(),
        ))
    }

    #[test]
    fn global_cas_key_preserves_physical_bytes_and_redacts_debug() {
        let resource = concat!(
            "runtime/event/outbox-backlog/",
            "000000000000000000000000000000000000000000000000000000000000002a"
        );
        let key = GlobalCasKey::for_test(42);
        let dbg = format!("{key:?}");
        assert!(!dbg.contains(resource), "global CAS key leaked: {dbg}");
        assert!(dbg.contains("<redacted>"), "missing redaction: {dbg}");
        assert_eq!(key.into_store_key().as_str(), resource);
    }

    #[test]
    fn cas_request_and_outcome_debug_redact_key_and_payload() {
        let request = CasRequest {
            key: GlobalCasKey::for_test(1),
            expected: Some("top-secret"),
            new_value: "new-secret",
            token: Some(FencingToken::new(7)),
        };
        let dbg = format!("{request:?}");
        for secret in [
            concat!(
                "runtime/event/outbox-backlog/",
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            "top-secret",
            "new-secret",
        ] {
            assert!(!dbg.contains(secret), "CAS request leaked {secret}: {dbg}");
        }
        assert!(dbg.contains("<redacted>"), "missing redaction: {dbg}");
        assert!(dbg.contains('7'), "token should remain observable: {dbg}");

        let conflict: CasOutcome<&str> = CasOutcome::Conflict {
            current: Some("top-secret"),
        };
        let dbg = format!("{conflict:?}");
        assert!(
            !dbg.contains("top-secret"),
            "conflict leaked payload: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "missing redaction: {dbg}");
    }

    /// create-if-absent（expected=None）→ Applied{token=FencingToken(1)}。
    #[tokio::test]
    async fn create_if_absent_returns_applied_with_token_one() -> Result<(), DistError> {
        let cas = make_facade();
        let outcome = cas
            .compare_and_swap(CasRequest {
                key: GlobalCasKey::for_test(2),
                expected: None::<u64>,
                new_value: 42u64,
                token: None,
            })
            .await?;
        assert!(
            matches!(outcome, CasOutcome::Applied { token } if token.value() == 1),
            "expected Applied{{token=1}}, got {outcome:?}",
        );
        Ok(())
    }

    /// 值匹配 → Applied，token 较上次 +1（bump）。
    #[tokio::test]
    async fn matching_value_returns_applied_with_bumped_token() -> Result<(), DistError> {
        let cas = make_facade();

        // 先建 key。
        cas.compare_and_swap(CasRequest {
            key: GlobalCasKey::for_test(3),
            expected: None::<u64>,
            new_value: 100u64,
            token: None,
        })
        .await?;

        // 值匹配更新 → Applied{token=2}。
        let outcome = cas
            .compare_and_swap(CasRequest {
                key: GlobalCasKey::for_test(3),
                expected: Some(100u64),
                new_value: 200u64,
                token: None,
            })
            .await?;
        assert!(
            matches!(outcome, CasOutcome::Applied { token } if token.value() == 2),
            "expected Applied{{token=2}}, got {outcome:?}",
        );
        Ok(())
    }

    /// 值不符 → Conflict{current=Some(反序列化回的 T)}。
    #[tokio::test]
    async fn mismatched_value_returns_conflict_with_current() -> Result<(), DistError> {
        let cas = make_facade();

        cas.compare_and_swap(CasRequest {
            key: GlobalCasKey::for_test(4),
            expected: None::<u64>,
            new_value: 77u64,
            token: None,
        })
        .await?;

        // Conflict 是 Ok 分支，不是 Err，用 `?` 正常传播。
        let outcome = cas
            .compare_and_swap(CasRequest {
                key: GlobalCasKey::for_test(4),
                expected: Some(999u64), // 故意错误
                new_value: 88u64,
                token: None,
            })
            .await?;
        assert!(
            matches!(&outcome, CasOutcome::Conflict { current: Some(v) } if *v == 77u64),
            "expected Conflict{{current=Some(77)}}, got {outcome:?}",
        );
        Ok(())
    }

    /// expected_token stale（低于当前）→ Ok(CasOutcome::Fenced{token=当前高水位})——fence 是预期控制流，
    /// 保留当前 token 供调用方重读/停写（F3：不再压扁成无字段 FencingMismatch）。
    #[tokio::test]
    async fn stale_token_returns_fenced_with_current_token() -> Result<(), DistError> {
        let cas = make_facade();

        // 建 key，current_token = 1。
        cas.compare_and_swap(CasRequest {
            key: GlobalCasKey::for_test(5),
            expected: None::<u64>,
            new_value: 1u64,
            token: None,
        })
        .await?;

        // expected_token=0 < current_token=1 → Fenced{token=1}（Ok 分支，携当前高水位）。
        let outcome = cas
            .compare_and_swap(CasRequest::<u64> {
                key: GlobalCasKey::for_test(5),
                expected: Some(1u64),
                new_value: 2u64,
                token: Some(FencingToken::new(0)),
            })
            .await?;
        assert!(
            matches!(outcome, CasOutcome::Fenced { token } if token.value() == 1),
            "expected Fenced{{token=1}}, got {outcome:?}",
        );
        Ok(())
    }

    /// Medium：独立 RFC 8785 golden 字节（写死期望，禁止与 crate 自指比较）。
    /// 覆盖嵌套未排序 object、float（`1.0` / `-0`）、Unicode key/string。
    #[test]
    fn canonical_json_matches_rfc8785_golden_vectors() {
        let cases: &[(&str, serde_json::Value, &str)] = &[
            (
                "nested_unsorted_object",
                serde_json::json!({"z":{"b":1,"a":2},"a":0}),
                r#"{"a":0,"z":{"a":2,"b":1}}"#,
            ),
            (
                "float_one_point_zero",
                serde_json::json!({"n":1.0}),
                r#"{"n":1}"#,
            ),
            ("negative_zero", serde_json::json!({"n":-0.0}), r#"{"n":0}"#),
            (
                "unicode_keys_and_nested_float",
                serde_json::json!({"z":{"β":1.5,"α":-0.0},"你好":"x"}),
                "{\"z\":{\"\u{03b1}\":0,\"\u{03b2}\":1.5},\"\u{4f60}\u{597d}\":\"x\"}",
            ),
            (
                "large_exponent_float",
                serde_json::json!({"n":1e20}),
                r#"{"n":100000000000000000000}"#,
            ),
        ];
        for (name, value, expected) in cases {
            let actual = canonical_json_bytes(value)
                .unwrap_or_else(|e| panic!("{name}: canonical_json_bytes failed: {e}"));
            let actual_str = String::from_utf8(actual)
                .unwrap_or_else(|e| panic!("{name}: canonical bytes are not UTF-8: {e}"));
            assert_eq!(actual_str, *expected, "{name}: RFC 8785 golden mismatch");
        }
    }

    /// F2 canonical 回归：同一语义值的 `HashMap`，插入顺序不同应产相同 canonical 字节 → Applied（非 Conflict）。
    /// 若退回非 canonical `serde_json::to_vec`（保留插入序），字节序不同 → 误判 Conflict，本测试 fail。
    #[tokio::test]
    async fn canonical_encoding_ignores_map_insertion_order() -> Result<(), DistError> {
        let cas = make_facade();

        let mut initial = HashMap::new();
        initial.insert("beta".to_owned(), 2u64);
        initial.insert("alpha".to_owned(), 1u64);
        cas.compare_and_swap(CasRequest {
            key: GlobalCasKey::for_test(6),
            expected: None::<HashMap<String, u64>>,
            new_value: initial,
            token: None,
        })
        .await?;

        // 语义相等但**插入序相反**的 expected → canonical 编码后字节相同 → 命中 → Applied{token=2}。
        let mut expected = HashMap::new();
        expected.insert("alpha".to_owned(), 1u64);
        expected.insert("beta".to_owned(), 2u64);
        let mut next = HashMap::new();
        next.insert("alpha".to_owned(), 9u64);
        let outcome = cas
            .compare_and_swap(CasRequest {
                key: GlobalCasKey::for_test(6),
                expected: Some(expected),
                new_value: next,
                token: None,
            })
            .await?;
        assert!(
            matches!(outcome, CasOutcome::Applied { token } if token.value() == 2),
            "canonical 编码应让不同插入序的同值 map 命中 Applied，got {outcome:?}",
        );
        Ok(())
    }

    /// serde 往返：JS-safe 整数（≤ 2⁵³−1）在 RFC 8785 / IEEE double 下精确可逆。
    #[tokio::test]
    async fn serde_round_trip_u64() -> Result<(), DistError> {
        let cas = make_facade();
        // JCS number = IEEE double；超出 JS safe integer 精度不保证，故锁定 2⁵³−1。
        const JS_SAFE_MAX: u64 = (1u64 << 53) - 1;

        cas.compare_and_swap(CasRequest {
            key: GlobalCasKey::for_test(7),
            expected: None::<u64>,
            new_value: JS_SAFE_MAX,
            token: None,
        })
        .await?;

        let outcome = cas
            .compare_and_swap(CasRequest {
                key: GlobalCasKey::for_test(7),
                expected: Some(JS_SAFE_MAX),
                new_value: 0u64,
                token: None,
            })
            .await?;
        assert!(
            matches!(outcome, CasOutcome::Applied { .. }),
            "expected Applied"
        );
        Ok(())
    }

    /// Hard fail-closed：`JS_SAFE_MAX + 1`（`2⁵³`）经 `compare_and_swap` → `Err(DistError::Fatal)`。
    #[tokio::test]
    async fn unsafe_integer_compare_and_swap_returns_fatal() {
        let cas = make_facade();
        let err = cas
            .compare_and_swap(CasRequest {
                key: GlobalCasKey::for_test(8),
                expected: None::<u64>,
                new_value: JS_SAFE_INTEGER_MAX + 1,
                token: None,
            })
            .await
            .expect_err("integer > 2^53-1 must fail-closed as Fatal");
        assert!(
            matches!(err, DistError::Fatal),
            "expected DistError::Fatal, got {err:?}"
        );
    }

    /// unit/表驱动：unsafe 整数被 `canonical_json_bytes` 拒绝；边界 `JS_SAFE_MAX` 仍接受。
    #[test]
    fn canonical_json_bytes_rejects_integers_outside_js_safe_range() {
        let cases: &[(&str, serde_json::Value, bool)] = &[
            (
                "js_safe_max_u64",
                serde_json::json!(JS_SAFE_INTEGER_MAX),
                true,
            ),
            (
                "js_safe_max_plus_one",
                serde_json::json!(JS_SAFE_INTEGER_MAX + 1),
                false,
            ),
            ("two_pow_53", serde_json::json!(1u64 << 53), false),
            (
                "nested_unsafe",
                serde_json::json!({"n": JS_SAFE_INTEGER_MAX + 1}),
                false,
            ),
            (
                "array_unsafe",
                serde_json::json!([1, JS_SAFE_INTEGER_MAX + 1]),
                false,
            ),
            (
                "js_safe_min_i64",
                serde_json::json!(-(JS_SAFE_INTEGER_MAX as i64)),
                true,
            ),
            (
                "js_safe_min_minus_one",
                serde_json::json!(-((JS_SAFE_INTEGER_MAX + 1) as i64)),
                false,
            ),
            (
                "float_large_exponent_ok",
                serde_json::json!({"n": 1e20}),
                true,
            ),
        ];
        for (name, value, expect_ok) in cases {
            let result = canonical_json_bytes(value);
            assert_eq!(
                result.is_ok(),
                *expect_ok,
                "{name}: expected ok={expect_ok}, got {result:?}"
            );
        }
    }

    /// 说明为何 fail-closed：raw JCS 下 `2⁵³` 与 `2⁵³+1` 编码成相同字节（IEEE double 碰撞）。
    #[test]
    fn raw_jcs_collides_beyond_js_safe_integer() {
        let a = serde_json_canonicalizer::to_vec(&(1u64 << 53)).expect("raw JCS 2^53");
        let b = serde_json_canonicalizer::to_vec(&((1u64 << 53) + 1)).expect("raw JCS 2^53+1");
        assert_eq!(
            a, b,
            "raw JCS must collide at 2^53 vs 2^53+1 (motivation for fail-closed)"
        );
        assert!(
            canonical_json_bytes(&(1u64 << 53)).is_err(),
            "facade must reject colliding integers"
        );
        assert!(
            canonical_json_bytes(&((1u64 << 53) + 1)).is_err(),
            "facade must reject colliding integers"
        );
    }

    /// Fix 4：expected=Some + 键不存在 → Conflict{current:None}（None 路径不触发反序列化）。
    #[tokio::test]
    async fn expected_some_key_absent_returns_conflict_with_current_none() -> Result<(), DistError>
    {
        let cas = make_facade();
        let outcome = cas
            .compare_and_swap(CasRequest::<u64> {
                key: GlobalCasKey::for_test(9),
                expected: Some(42u64),
                new_value: 99u64,
                token: None,
            })
            .await?;
        assert!(
            matches!(outcome, CasOutcome::Conflict { current: None }),
            "expected Conflict{{current:None}}, got {outcome:?}",
        );
        Ok(())
    }

    /// Fix 5：expected_token == current_token（相等=不 stale，应 Applied 非 Fenced）——anti-mutation：防误改 < 为 <=。
    #[tokio::test]
    async fn equal_token_is_not_fenced() -> Result<(), DistError> {
        let cas = make_facade();
        // create → current_token = FencingToken(1)
        cas.compare_and_swap(CasRequest {
            key: GlobalCasKey::for_test(10),
            expected: None::<u64>,
            new_value: 1u64,
            token: None,
        })
        .await?;
        // expected_token=Some(FencingToken(1)) == 当前 token → Applied（非 Fenced）
        let outcome = cas
            .compare_and_swap(CasRequest::<u64> {
                key: GlobalCasKey::for_test(10),
                expected: Some(1u64),
                new_value: 2u64,
                token: Some(FencingToken::new(1)),
            })
            .await?;
        assert!(
            matches!(outcome, CasOutcome::Applied { token } if token.value() == 2),
            "expected_token == current_token 应 Applied，got {outcome:?}",
        );
        Ok(())
    }

    /// serde 往返：自定义 struct 编解码正确。
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
    struct DeviceState {
        version: u32,
        label: String,
    }

    #[tokio::test]
    async fn serde_round_trip_struct() -> Result<(), DistError> {
        let cas = make_facade();
        let initial = DeviceState {
            version: 1,
            label: "alpha".into(),
        };

        cas.compare_and_swap(CasRequest {
            key: GlobalCasKey::for_test(11),
            expected: None::<DeviceState>,
            new_value: initial.clone(),
            token: None,
        })
        .await?;

        // 值不符 → Conflict，current 应反序列化回 initial。Conflict 是 Ok 分支。
        let outcome = cas
            .compare_and_swap(CasRequest {
                key: GlobalCasKey::for_test(11),
                expected: Some(DeviceState {
                    version: 99,
                    label: "wrong".into(),
                }),
                new_value: DeviceState {
                    version: 2,
                    label: "beta".into(),
                },
                token: None,
            })
            .await?;
        assert!(
            matches!(&outcome, CasOutcome::Conflict { current: Some(s) } if *s == initial),
            "expected Conflict with initial struct, got {outcome:?}",
        );
        Ok(())
    }
}
