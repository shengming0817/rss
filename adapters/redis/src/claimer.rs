//! 幂等 claimer 逻辑 helper（L0 纯计算 + backend 异步 impl）。
//!
//! feature 无关的 helper（`namespaced_key` / `interpret_setnx`）始终编译，
//! `backend` feature 门控的异步 `check_impl` 引入 deadpool-redis 类型。

use consistency::{ConsumerGroup, IdemKey, SeenState};

/// claim key 命名空间（固定 `idem` role 段，对齐 observability.md §Redis Namespace）。
///
/// **结构互斥**（review F1）：`_runtime:idem:` 的字面 `idem` 第二段与其它 `_runtime` 原语
/// （`_runtime:{eventID}:lease|done`、`_runtime:<tenant>:{key}:…`，二者第二段均为 UUID 形）
/// 不可能相等，故整环 key 空间互斥。
///
/// **组维度**（review #216 F5）：claim key 在 namespace 后**显式**带 `ConsumerGroup` 段——
/// `_runtime:idem:<group>:<idem_key>`。group 是幂等去重 PK 第二维度（同一 key 在不同组各自首见），
/// 由 `RedisStore` 构造期绑定（对标 `PgInboxStore` 的 `(event_id, consumer_group)` 双列 PK 与
/// `InMemClaimer` 的 `(group, key)` 集合）；**不**靠调用方把 group 拼进 opaque `IdemKey`
/// （`IdemKey` 仅承载稳定 message/event id）。
// reason: feature-off build 仅测试使用；feature-on 经 backend::check_impl 引用。
#[cfg_attr(not(feature = "backend"), allow(dead_code))]
pub(crate) const NAMESPACE: &str = "_runtime:idem";

/// claim key = `_runtime:idem:<group>:<idem_key>`（group 段隔离消费组，见模块 §组维度）。
// reason: feature-off build 仅测试使用；feature-on 经 backend::check_impl 引用。
#[cfg_attr(not(feature = "backend"), allow(dead_code))]
pub(crate) fn namespaced_key(group: &ConsumerGroup, key: &IdemKey) -> String {
    format!("{NAMESPACE}:{}:{}", group.as_str(), key.as_str())
}

/// `SET ... NX` 返回 `Some(...)`=首次写入(Fresh) / `None`(nil)=key 已存在(Duplicate)。
// reason: feature-off build 仅测试使用；feature-on 经 backend::check_impl 引用。
#[cfg_attr(not(feature = "backend"), allow(dead_code))]
pub(crate) fn interpret_setnx(set: Option<String>) -> SeenState {
    match set {
        Some(_) => SeenState::Fresh,
        None => SeenState::Duplicate,
    }
}

#[cfg(feature = "backend")]
pub(crate) use backend::{check_impl, commit_impl, release_impl};

#[cfg(feature = "backend")]
mod backend {
    use consistency::{ConsumerGroup, EngineError, EngineErrorKind, IdemKey, SeenState};
    use deadpool_redis::{Pool, PoolError, redis::RedisError};

    use super::{interpret_setnx, namespaced_key};

    /// redis 错误 → 引擎错误种类。
    ///
    /// IO / 连接断开 / 连接拒绝 / 超时 = 可重试 Transient；其余（协议/鉴权/解析）= Permanent。
    pub(crate) fn classify_redis_error(e: &RedisError) -> EngineErrorKind {
        if e.is_io_error()
            || e.is_connection_dropped()
            || e.is_connection_refusal()
            || e.is_timeout()
        {
            EngineErrorKind::Transient
        } else {
            EngineErrorKind::Permanent
        }
    }

    /// 池错误 → 引擎错误种类：Backend 委托 redis 分类；其余（Timeout/Closed 等）= Transient。
    pub(crate) fn classify_pool_error(e: &PoolError) -> EngineErrorKind {
        match e {
            PoolError::Backend(re) => classify_redis_error(re),
            _ => EngineErrorKind::Transient,
        }
    }

    /// claimed→done：`PERSIST key`（去除 TTL，使 key 永久存在代表 done）。
    ///
    /// absent key 时 `PERSIST` 返回 0（key 不存在），幂等 no-op。
    /// 后端错误 → `EngineErrorKind::Transient`；原始 redis 错误不进 Display（PII 边界）。
    pub(crate) async fn commit_impl(
        pool: &Pool,
        group: &ConsumerGroup,
        key: &IdemKey,
    ) -> Result<(), EngineError> {
        let mut conn = pool.get().await.map_err(|e| {
            let kind = classify_pool_error(&e);
            tracing::warn!(
                resource = "redis",
                operation = "idem-commit",
                ?kind,
                error = %secure::redact_error(&e),
                "redis pool acquire failed"
            );
            EngineError::new(kind)
        })?;
        let k = super::namespaced_key(group, key);
        // PERSIST 将 key 从有 TTL 改为永久；key 不存在时返回 0（幂等 no-op）。
        let _: i64 = deadpool_redis::redis::cmd("PERSIST")
            .arg(&k)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                let kind = classify_redis_error(&e);
                tracing::warn!(
                    resource = "redis",
                    operation = "idem-commit",
                    ?kind,
                    error = %secure::redact_error(&e),
                    "redis PERSIST failed"
                );
                consistency::EngineError::new(kind)
            })?;
        Ok(())
    }

    /// claimed→absent：`DEL key`（删除 claim，使后续重放可重新 Fresh）。
    ///
    /// absent key 时 `DEL` 返回 0，幂等 no-op。
    /// 后端错误 → `EngineErrorKind::Transient`；原始 redis 错误不进 Display（PII 边界）。
    pub(crate) async fn release_impl(
        pool: &Pool,
        group: &ConsumerGroup,
        key: &IdemKey,
    ) -> Result<(), EngineError> {
        let mut conn = pool.get().await.map_err(|e| {
            let kind = classify_pool_error(&e);
            tracing::warn!(
                resource = "redis",
                operation = "idem-release",
                ?kind,
                error = %secure::redact_error(&e),
                "redis pool acquire failed"
            );
            EngineError::new(kind)
        })?;
        let k = super::namespaced_key(group, key);
        let _: i64 = deadpool_redis::redis::cmd("DEL")
            .arg(&k)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                let kind = classify_redis_error(&e);
                tracing::warn!(
                    resource = "redis",
                    operation = "idem-release",
                    ?kind,
                    error = %secure::redact_error(&e),
                    "redis DEL failed"
                );
                consistency::EngineError::new(kind)
            })?;
        Ok(())
    }

    pub(crate) async fn check_impl(
        pool: &Pool,
        ttl: core::time::Duration,
        group: &ConsumerGroup,
        key: &IdemKey,
    ) -> Result<SeenState, EngineError> {
        let mut conn = pool.get().await.map_err(|e| {
            // F3：低基数诊断字段 + redacted error（不记 key 原文，避免 PII / 高基数）。
            let kind = classify_pool_error(&e);
            tracing::warn!(
                resource = "redis",
                operation = "idem-claim",
                ?kind,
                error = %secure::redact_error(&e),
                "redis pool acquire failed"
            );
            EngineError::new(kind)
        })?;
        let k = namespaced_key(group, key);
        // F2：用 PX 毫秒精度（不截断），TTL 已由 `RedisStore::new` 构造期保证 ≥ 1ms（不静默钳制）。
        let ttl_millis = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        let set: Option<String> = deadpool_redis::redis::cmd("SET")
            .arg(&k)
            .arg(1u8)
            .arg("NX")
            .arg("PX")
            .arg(ttl_millis)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                let kind = classify_redis_error(&e);
                tracing::warn!(
                    resource = "redis",
                    operation = "idem-claim",
                    ?kind,
                    error = %secure::redact_error(&e),
                    "redis SET NX failed"
                );
                EngineError::new(kind)
            })?;
        Ok(interpret_setnx(set))
    }

    #[cfg(test)]
    mod backend_tests {
        use super::{classify_pool_error, classify_redis_error};
        use consistency::EngineErrorKind;
        use deadpool_redis::PoolError;
        use deadpool_redis::redis::{ErrorKind, RedisError};

        #[test]
        fn io_error_is_transient() {
            let e = RedisError::from((ErrorKind::Io, "io error"));
            assert_eq!(classify_redis_error(&e), EngineErrorKind::Transient);
        }

        #[test]
        fn auth_error_is_permanent() {
            let e = RedisError::from((ErrorKind::AuthenticationFailed, "auth failed"));
            assert_eq!(classify_redis_error(&e), EngineErrorKind::Permanent);
        }

        #[test]
        fn parse_error_is_permanent() {
            let e = RedisError::from((ErrorKind::InvalidClientConfig, "bad config"));
            assert_eq!(classify_redis_error(&e), EngineErrorKind::Permanent);
        }

        #[test]
        fn pool_backend_redis_io_is_transient() {
            let redis_err = RedisError::from((ErrorKind::Io, "io"));
            let pool_err = PoolError::Backend(redis_err);
            assert_eq!(classify_pool_error(&pool_err), EngineErrorKind::Transient);
        }

        #[test]
        fn pool_closed_is_transient() {
            let pool_err: PoolError = PoolError::Closed;
            assert_eq!(classify_pool_error(&pool_err), EngineErrorKind::Transient);
        }
    }
}

#[cfg(test)]
mod tests {
    use consistency::{ConsumerGroup, IdemKey, SeenState};
    use rstest::rstest;

    use super::{NAMESPACE, interpret_setnx, namespaced_key};

    #[allow(clippy::unwrap_used)]
    // reason: test helper — 非空 raw，parse 必成功；item-level carve-out。
    fn grp(raw: &str) -> ConsumerGroup {
        ConsumerGroup::parse(raw).unwrap()
    }

    #[rstest]
    #[case("a", "_runtime:idem:grp:a")]
    #[case("some-key-123", "_runtime:idem:grp:some-key-123")]
    #[case(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "_runtime:idem:grp:f47ac10b-58cc-4372-a567-0e02b2c3d479"
    )]
    #[case(
        "session.created:tenant-42:evt-1",
        "_runtime:idem:grp:session.created:tenant-42:evt-1"
    )]
    fn namespaced_key_has_idem_prefix(#[case] raw: &str, #[case] expected: &str) {
        #[allow(clippy::unwrap_used)]
        // reason: test happy-path — raw is non-empty so parse always succeeds；item-level carve-out。
        let key = IdemKey::parse(raw).unwrap();
        let group = grp("grp");
        assert_eq!(namespaced_key(&group, &key), expected);
        assert!(namespaced_key(&group, &key).starts_with(NAMESPACE));
    }

    // 结构互斥（review F1）：claimer key 的第二段恒为字面 `idem`，与 `_runtime:{eventID}:…` /
    // `_runtime:<tenant>:…`（第二段为 UUID）不可能碰撞——group 段在 `idem` 之后（第三段），不影响互斥前提。
    #[test]
    fn namespaced_key_second_segment_is_literal_idem() {
        #[allow(clippy::unwrap_used)]
        // reason: 非空 raw，parse 必成功；item-level carve-out。
        let key = IdemKey::parse("evt-1").unwrap();
        let k = namespaced_key(&grp("audit"), &key);
        assert_eq!(
            k.split(':').nth(1),
            Some("idem"),
            "second segment must be `idem`"
        );
    }

    // review #216 F5（去重正确性 bug 回归）：同一 IdemKey 在不同 ConsumerGroup 下产生**不同** redis
    // claim key——故跨组不会互相去重（修前 namespaced_key 丢 group ⇒ ka==kb ⇒ 跨组误去重）。
    // 对标 PgInboxStore `(event_id, consumer_group)` / InMemClaimer `(group, key)` 的组隔离语义。
    #[test]
    fn different_groups_yield_distinct_keys_for_same_idem_key() {
        #[allow(clippy::unwrap_used)]
        // reason: 非空 raw，parse 必成功；item-level carve-out。
        let key = IdemKey::parse("evt-shared").unwrap();
        let ka = namespaced_key(&grp("audit"), &key);
        let kb = namespaced_key(&grp("settings"), &key);
        assert_ne!(ka, kb, "跨组同 key 须产生不同 claim key（组维度隔离）");
        assert_eq!(ka, "_runtime:idem:audit:evt-shared");
        assert_eq!(kb, "_runtime:idem:settings:evt-shared");
    }

    #[rstest]
    #[case(Some("OK".to_string()), SeenState::Fresh)]
    #[case(Some("ok".to_string()), SeenState::Fresh)]
    #[case(Some(String::new()), SeenState::Fresh)]
    #[case(None, SeenState::Duplicate)]
    fn interpret_setnx_maps_option(#[case] set: Option<String>, #[case] expected: SeenState) {
        assert_eq!(interpret_setnx(set), expected);
    }
}
