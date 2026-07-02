//! 幂等 claimer 逻辑 helper（L0 纯计算 + backend 异步 impl）。
//!
//! feature 无关的 helper（`namespaced_key` / `interpret_setnx`）始终编译，
//! `backend` feature 门控的异步 `try_claim_impl` 引入 deadpool-redis 类型。

use consistency::{ConsumerGroup, IdemKey, SeenState};

/// claim key 命名空间（固定 `idem` role 段，对齐 observability.md §Redis Namespace）。
///
/// **结构互斥**（review F1）：`_runtime:idem:` 的字面 `idem` 第二段与其它 `_runtime` 原语
/// （`_runtime:{eventID}:lease|done`、`_runtime:<tenant>:{key}:…`，二者第二段均为 UUID 形）
/// 不可能相等，故整环 key 空间互斥。
///
/// **组维度**（review #216 F5）：claim key 在 namespace 后带 `ConsumerGroup` 段。group 是幂等去重 PK
/// 第二维度（同一 key 在不同组各自首见），由 `RedisInboxStore` 句柄绑定（对标 `PgInboxStore` 的
/// `(event_id, consumer_group)` 双列 PK 与 `InMemClaimer` 的 `(group, key)` 集合）；**不**靠调用方把 group
/// 拼进 opaque `IdemKey`（`IdemKey` 仅承载稳定 message/event id）。
///
/// **字段边界封闭**（#279 review F3）：`ConsumerGroup` / `IdemKey` 均 opaque（仅拒空、**允许冒号**），裸
/// `<group>:<key>` 冒号拼接可碰撞——`(group="a", key="b:c")` 与 `(group="a:b", key="c")` 拼出同串 ⇒ 跨组误
/// 去重。故 key 形如 `_runtime:idem:<glen>:<group>:<idem_key>`：**group 段前缀其字节长度**，使 group/key
/// 边界单射（`len(group)` 不同 ⇒ 前缀段不同；相同 ⇒ group 占定长前缀位、`(group,key)` 一一对应），消除碰撞面。
// reason: feature-off build 仅测试使用；feature-on 经 backend::try_claim_impl 引用。
#[cfg_attr(not(feature = "backend"), allow(dead_code))]
pub(crate) const NAMESPACE: &str = "_runtime:idem";

/// claim key = `_runtime:idem:<glen>:<group>:<idem_key>`（`glen` = group 字节长度前缀，使 group/key 边界
/// 单射，杜绝冒号拼接碰撞；见模块 §字段边界封闭）。
// reason: feature-off build 仅测试使用；feature-on 经 backend::try_claim_impl 引用。
#[cfg_attr(not(feature = "backend"), allow(dead_code))]
pub(crate) fn namespaced_key(group: &ConsumerGroup, key: &IdemKey) -> String {
    // group 段以字节长度前缀单射封边：len(group) 不同 ⇒ 整串不同；相同 ⇒ group 占定长位、(group,key) 一一对应。
    format!(
        "{NAMESPACE}:{}:{}:{}",
        group.as_str().len(),
        group.as_str(),
        key.as_str()
    )
}

/// `SET ... NX` 返回 `Some(...)`=首次写入(Fresh) / `None`(nil)=key 已存在(Duplicate)。
// reason: feature-off build 仅测试使用；feature-on 经 backend::try_claim_impl 引用。
#[cfg_attr(not(feature = "backend"), allow(dead_code))]
pub(crate) fn interpret_setnx(set: Option<String>) -> SeenState {
    match set {
        Some(_) => SeenState::Fresh,
        None => SeenState::Duplicate,
    }
}

#[cfg(feature = "backend")]
pub(crate) use backend::{commit_impl, extend_impl, release_impl, try_claim_impl};

#[cfg(feature = "backend")]
mod backend {
    use consistency::{
        ConsumerGroup, EngineError, EngineErrorKind, IdemKey, LeaseOutcome, LeaseToken, SeenState,
    };
    use deadpool_redis::{Pool, PoolError, redis::RedisError};

    use super::{interpret_setnx, namespaced_key};

    // ─── 低基数诊断字段常量（resource = RESOURCE 出现 ≥ 3 次，抽 const 守去重规则）─────────
    const RESOURCE: &str = "redis";
    const POOL_ACQUIRE_FAILED: &str = "redis pool acquire failed";
    // EVAL 命令名出现于 extend / commit / release 三处 CAS 调用，抽 const 守去重规则。
    const REDIS_CMD_EVAL: &str = "EVAL";

    /// done 状态哨兵值（commit 把 claimed value 从 `<token>` 改写成本哨兵，#279 review F1/F2）。
    ///
    /// **状态编码**：claimed 的 redis value = lease token（uuid v4 文本，带 TTL）；done 的 value = 本哨兵
    /// （无 TTL，永久去重）。哨兵含下划线、**结构上不可能等于任何 uuid v4 token**，故 done 行对
    /// `extend`/`release` 的 `GET == token` CAS 恒不命中——done key **不可**被同 token 再 `PEXPIRE` 续租
    /// （否则 done 行重获 TTL 会过期 → 去重丢失，F1）或被 `DEL` 删除（F2）。对标 PG `status='claimed'` /
    /// memory `!done` 的显式状态位（C1：Redis 之前缺状态位，claimed/done 同为 raw token 不可区分）。
    const DONE_SENTINEL: &str = "__rss_idem_done__";

    // ─── Lua CAS 脚本（每条仅使用一次，但为可审计性与常量化要求各定义为 const）──────────────

    /// Lua CAS：令牌匹配（仅 claimed 行，value=token）则刷新 TTL（`PEXPIRE`），返回 1=Held / 0=Lost。
    ///
    /// `KEYS[1]` = claim key；`ARGV[1]` = lease token；`ARGV[2]` = ttl_millis。done 行 value=哨兵≠token → 0（不续租）。
    const LUA_EXTEND_CAS: &str = "if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('PEXPIRE', KEYS[1], ARGV[2]); return 1 else return 0 end";

    /// Lua CAS：令牌匹配（claimed 行）则原子切 done——`SET key <done 哨兵>`（无 EX ⇒ 清 TTL ⇒ 永久去重），
    /// 返回 1=Held / 0=Lost。
    ///
    /// `KEYS[1]` = claim key；`ARGV[1]` = lease token；`ARGV[2]` = done 哨兵。claimed→done 一步原子，
    /// done value≠任何 token ⇒ 后续 extend/release CAS 不命中（F1/F2 修：旧实现 `PERSIST` 保留 token value，
    /// done 行仍被同 token 续租/删除）。
    const LUA_COMMIT_CAS: &str = "if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('SET', KEYS[1], ARGV[2]); return 1 else return 0 end";

    /// Lua CAS：令牌匹配（仅 claimed 行）则删除 claim（`DEL` = absent），不匹配 no-op；恒返回 0。
    ///
    /// `KEYS[1]` = claim key；`ARGV[1]` = lease token。令牌不符（含 done 行 value=哨兵）时原样返回 0，
    /// 不删他人 claim、不删 done 去重记录（F2）。
    const LUA_RELEASE_CAS: &str =
        "if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('DEL', KEYS[1]) end return 0";

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

    /// claim 并查询首见：`SET key <lease_token> NX PX <ttl_ms>`。
    ///
    /// Token 作为 redis 值存入，供后续 `extend`/`commit`/`release` CAS 比对。
    /// F3：低基数诊断字段 + redacted error（不记 key 原文，避免 PII / 高基数）。
    pub(crate) async fn try_claim_impl(
        pool: &Pool,
        ttl: core::time::Duration,
        group: &ConsumerGroup,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<SeenState, EngineError> {
        let mut conn = pool.get().await.map_err(|e| {
            let kind = classify_pool_error(&e);
            tracing::warn!(
                resource = RESOURCE,
                operation = "idem-claim",
                ?kind,
                error = %secure::redact_error(&e),
                "{}", POOL_ACQUIRE_FAILED
            );
            EngineError::new(kind)
        })?;
        let k = namespaced_key(group, key);
        // F2：用 PX 毫秒精度（不截断）；TTL 已由 `RedisInboxStore` 构造期保证 ≥ 1ms（不静默钳制）。
        let ttl_millis = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        // SET key <lease_token> NX PX <ttl_millis>：token 作为值落库，后续 CAS 凭此比对。
        let set: Option<String> = deadpool_redis::redis::cmd("SET")
            .arg(&k)
            .arg(lease.as_str())
            .arg("NX")
            .arg("PX")
            .arg(ttl_millis)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                let kind = classify_redis_error(&e);
                tracing::warn!(
                    resource = RESOURCE,
                    operation = "idem-claim",
                    ?kind,
                    error = %secure::redact_error(&e),
                    "redis SET NX failed"
                );
                EngineError::new(kind)
            })?;
        Ok(interpret_setnx(set))
    }

    /// 续租：令牌 CAS 匹配则 `PEXPIRE`（刷新 TTL）→ `Held`；不符 → `Lost`（claim 已被重捞或不存在）。
    pub(crate) async fn extend_impl(
        pool: &Pool,
        ttl: core::time::Duration,
        group: &ConsumerGroup,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<LeaseOutcome, EngineError> {
        let mut conn = pool.get().await.map_err(|e| {
            let kind = classify_pool_error(&e);
            tracing::warn!(
                resource = RESOURCE,
                operation = "idem-extend",
                ?kind,
                error = %secure::redact_error(&e),
                "{}", POOL_ACQUIRE_FAILED
            );
            EngineError::new(kind)
        })?;
        let k = namespaced_key(group, key);
        let ttl_millis = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        let result: i64 = deadpool_redis::redis::cmd(REDIS_CMD_EVAL)
            .arg(LUA_EXTEND_CAS)
            .arg(1)
            .arg(&k)
            .arg(lease.as_str())
            .arg(ttl_millis)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                let kind = classify_redis_error(&e);
                tracing::warn!(
                    resource = RESOURCE,
                    operation = "idem-extend",
                    ?kind,
                    error = %secure::redact_error(&e),
                    "redis EVAL extend CAS failed"
                );
                EngineError::new(kind)
            })?;
        Ok(if result == 1 {
            LeaseOutcome::Held
        } else {
            LeaseOutcome::Lost
        })
    }

    /// claimed → done（CAS）：令牌匹配则原子 `SET key <done 哨兵>`（清 TTL，永久去重）→ `Held`；不符 → `Lost`
    /// （hard-fence）。
    ///
    /// done value=哨兵≠任何 token ⇒ 后续 extend/release 不命中（F1/F2）。absent key 时 `GET` 返回 nil ≠ token
    /// → `Lost`（消费方须降级 Requeue，不 Ack）。
    pub(crate) async fn commit_impl(
        pool: &Pool,
        group: &ConsumerGroup,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<LeaseOutcome, EngineError> {
        let mut conn = pool.get().await.map_err(|e| {
            let kind = classify_pool_error(&e);
            tracing::warn!(
                resource = RESOURCE,
                operation = "idem-commit",
                ?kind,
                error = %secure::redact_error(&e),
                "{}", POOL_ACQUIRE_FAILED
            );
            EngineError::new(kind)
        })?;
        let k = namespaced_key(group, key);
        let result: i64 = deadpool_redis::redis::cmd(REDIS_CMD_EVAL)
            .arg(LUA_COMMIT_CAS)
            .arg(1)
            .arg(&k)
            .arg(lease.as_str())
            .arg(DONE_SENTINEL)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                let kind = classify_redis_error(&e);
                tracing::warn!(
                    resource = RESOURCE,
                    operation = "idem-commit",
                    ?kind,
                    error = %secure::redact_error(&e),
                    "redis EVAL commit CAS failed"
                );
                EngineError::new(kind)
            })?;
        Ok(if result == 1 {
            LeaseOutcome::Held
        } else {
            LeaseOutcome::Lost
        })
    }

    /// claimed → absent（CAS）：令牌匹配则 `DEL`；不匹配 no-op（不误删他人 claim）。
    ///
    /// Lua 脚本（[`LUA_RELEASE_CAS`]）恒返回 0；`Ok(())` 表示操作完成（含 no-op）。
    pub(crate) async fn release_impl(
        pool: &Pool,
        group: &ConsumerGroup,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<(), EngineError> {
        let mut conn = pool.get().await.map_err(|e| {
            let kind = classify_pool_error(&e);
            tracing::warn!(
                resource = RESOURCE,
                operation = "idem-release",
                ?kind,
                error = %secure::redact_error(&e),
                "{}", POOL_ACQUIRE_FAILED
            );
            EngineError::new(kind)
        })?;
        let k = namespaced_key(group, key);
        let _: i64 = deadpool_redis::redis::cmd(REDIS_CMD_EVAL)
            .arg(LUA_RELEASE_CAS)
            .arg(1)
            .arg(&k)
            .arg(lease.as_str())
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                let kind = classify_redis_error(&e);
                tracing::warn!(
                    resource = RESOURCE,
                    operation = "idem-release",
                    ?kind,
                    error = %secure::redact_error(&e),
                    "redis EVAL release CAS failed"
                );
                EngineError::new(kind)
            })?;
        Ok(())
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

    // group "grp" 字节长度 = 3，故 key 形如 `_runtime:idem:3:grp:<idem_key>`（glen 前缀单射封边，F3）。
    #[rstest]
    #[case("a", "_runtime:idem:3:grp:a")]
    #[case("some-key-123", "_runtime:idem:3:grp:some-key-123")]
    #[case(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "_runtime:idem:3:grp:f47ac10b-58cc-4372-a567-0e02b2c3d479"
    )]
    #[case(
        "session.created:tenant-42:evt-1",
        "_runtime:idem:3:grp:session.created:tenant-42:evt-1"
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
    // `_runtime:<tenant>:…`（第二段为 UUID）不可能碰撞——glen/group 段在 `idem` 之后，不影响互斥前提。
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
        // glen 前缀：audit=5、settings=8。
        assert_eq!(ka, "_runtime:idem:5:audit:evt-shared");
        assert_eq!(kb, "_runtime:idem:8:settings:evt-shared");
    }

    // #279 review F3（字段边界碰撞回归）：`ConsumerGroup`/`IdemKey` 均 opaque（允许冒号），裸拼接下
    // `(group="a", key="b:c")` 与 `(group="a:b", key="c")` 会碰撞；group 段长度前缀使二者单射可分。
    #[test]
    fn namespaced_key_length_prefix_prevents_group_key_collision() {
        #[allow(clippy::unwrap_used)]
        // reason: 非空 raw（含冒号合法，仅拒空），parse 必成功；item-level carve-out。
        let key_bc = IdemKey::parse("b:c").unwrap();
        #[allow(clippy::unwrap_used)]
        // reason: 同上。
        let key_c = IdemKey::parse("c").unwrap();
        let k1 = namespaced_key(&grp("a"), &key_bc); // (group="a", key="b:c")
        let k2 = namespaced_key(&grp("a:b"), &key_c); // (group="a:b", key="c")
        assert_ne!(k1, k2, "长度前缀须使 (a,b:c) 与 (a:b,c) 产生不同 claim key");
        assert_eq!(k1, "_runtime:idem:1:a:b:c");
        assert_eq!(k2, "_runtime:idem:3:a:b:c");
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
