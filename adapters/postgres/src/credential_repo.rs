//! `PgCredentialRepo` —— identity 凭据仓储的 postgres adapter（#1316）。
//!
//! impl `identity::ports::CredentialRepo`（find_by_user_id / authenticate / save / apply_password_change / lockout_status），
//! 作 durable login 密码校验真依赖，替换 in-mem `InMemCredentialRepo`（test/seed 门控）。adapter→域 DIP 内向边
//! （postgres 依赖 identity、native AFIT impl 其域形 port，经 deny.toml identity wrapper + `allows(Adapter,Domain)`
//! 放行；adapter 仍不被域依赖）。
//!
//! 持久化模型（`0015_create_credentials.sql`）：credentials 表 PK (tenant_id, login) + UNIQUE (tenant_id, user_id)；
//! **锁定态折叠进同一行**（failure_count / lockout_window_start / locked_until）——未知主体无行 ⇒ 无法建锁定态
//! （#1277 F2「未知主体不可预置锁定、不撑大 lockout 表」**结构层**天然成立，无独立锁定表）。明文密码**永不落库**，
//! 仅 `password_hash`（argon2 PHC，经 `secure::PasswordHash`）。
//!
//! 原子性：authenticate / lockout_status / apply_password_change 经 `SELECT ... FOR UPDATE` 单行事务做原子 read-modify-write
//! （跨实例行级锁，避免负载均衡下各实例独立计数 / 并发丢更新）。策略阈值（5 次 / 15min 滑窗 / 15min 锁定 TTL）
//! 域内单源（`identity::ports::AccountLockout`），adapter 仅 I/O：`from_parts` 重建 → `record_failure` /
//! `try_lazy_unlock` 推进 → 访问器回写三列。
//!
//! 恒定成本验签（#1277 F3）：authenticate 无论凭据是否存在都跑 `secure::verify_password_constant_time`（消登录
//! 枚举时序差），再据「已知/未知 + 验签成败」原子分流（F1+F2）。tenant scope 经 `SET LOCAL`（读经
//! `tenant_scoped_read`，写经事务内 `set_local_tenant`，与 0009 RLS policy `current_setting` 锚点对齐）+ 显式
//! `WHERE tenant_id`（双重隔离，跨租 → 0 行 → fail-closed）。读出 PHC 经 `secure::PasswordHash::parse` 复核
//! （损坏持久化值 → `Storage`，fail-closed）。
//!
//! ref: kanidm server/lib/src/credential/softlock.rs@master（`CredSoftLock` lazy-unlock 无后台 job 状态机；本 adapter
//!   有意偏离其纯内存 softlock——多实例 PostgreSQL 须持久化 + 行锁原子 RMW，kanidm 自身注释亦承认内存方案分布式 bypass）
//! ref: RustCrypto/password-hashes argon2/src/lib.rs@master（PHC string at-rest，经 `secure::PasswordHash`）
//! ref: adapters/postgres/src/role_repo.rs（#1250 pool 注入 / SET LOCAL / storage 收口 / hydrate 范本）
//! ref: adapters/postgres/src/session_lifecycle.rs（#1278 epoch↔SystemTime 编码对称）

#[cfg(all(test, feature = "integration"))]
use std::collections::HashMap;
#[cfg(all(test, feature = "integration"))]
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use identity::ports::{
    AccountLockout, AuthOutcome, Credential, CredentialRepo, IdentityError, LoginIdentifier,
    PasswordChangeMutation, TenantId, TenantRepoScope,
};
use sqlx::{PgConnection, Row};

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::outbox::{epoch_secs_to_time, unix_secs};
use crate::tx_retry::{classify_identity_error, run_pg_localtx_retry};

/// identity 凭据仓储的 PostgreSQL adapter。
///
/// 经 [`PgStore`] 的 `pool`（`pub(crate)`，share-pool 注入，同 [`crate::PgRoleRepo`]）clone 构造。
/// 不持 `Clock`：authenticate / lockout_status 的 `now` 由调用方（`LoginService`，经注入 `Clock`）传入
/// （域类型不持 clock，rust-standards §工程护栏；时间判定全经入参 `now`）。
pub struct PgCredentialRepo {
    pool: PgTenantPool,
    #[cfg(all(test, feature = "integration"))]
    password_change_post_update_gate: Option<Arc<PasswordChangeCasPauseGate>>,
    #[cfg(all(test, feature = "integration"))]
    password_change_faults: Arc<Mutex<CredentialFaultState>>,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
pub(crate) enum CredentialMutationFault {
    Permanent,
    Transient,
    TransientBeforeWrite,
    CommitUnknown,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
struct CredentialFaultPlan {
    fault: CredentialMutationFault,
    remaining: usize,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Default)]
struct CredentialFaultState {
    plans: HashMap<String, CredentialFaultPlan>,
    attempts: HashMap<String, usize>,
}

/// 实例级 CAS 编排门：第一写者完成 UPDATE 后通知测试，并等待显式放行后才返回事务闭包。
#[cfg(all(test, feature = "integration"))]
pub(crate) struct PasswordChangeCasPauseGate {
    updated: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(all(test, feature = "integration"))]
impl PasswordChangeCasPauseGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            updated: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        })
    }

    pub(crate) async fn wait_until_updated(&self) {
        self.updated.notified().await;
    }

    pub(crate) fn release(&self) {
        self.release.notify_one();
    }

    async fn pause_after_update(&self) {
        self.updated.notify_one();
        self.release.notified().await;
    }
}

impl PgCredentialRepo {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::credential_repo` 收口。
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: PgTenantPool::new(store),
            #[cfg(all(test, feature = "integration"))]
            password_change_post_update_gate: None,
            #[cfg(all(test, feature = "integration"))]
            password_change_faults: Arc::new(Mutex::new(CredentialFaultState::default())),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_password_change_post_update_pause(
        mut self,
        gate: Arc<PasswordChangeCasPauseGate>,
    ) -> Self {
        self.password_change_post_update_gate = Some(gate);
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_password_change_fault(
        self,
        login: &str,
        fault: CredentialMutationFault,
        remaining: usize,
    ) -> Self {
        assert!(remaining > 0, "fault plan must affect at least one attempt");
        self.password_change_faults
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .plans
            .insert(login.to_owned(), CredentialFaultPlan { fault, remaining });
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn password_change_attempts(&self, login: &str) -> usize {
        self.password_change_faults
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .attempts
            .get(login)
            .copied()
            .unwrap_or_default()
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，adapter 边界收口；同 `PgRoleRepo`）。
fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

#[cfg(all(test, feature = "integration"))]
fn record_password_change_attempt(state: &Mutex<CredentialFaultState>, login: &str) {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *state.attempts.entry(login.to_owned()).or_default() += 1;
}

#[cfg(all(test, feature = "integration"))]
fn take_credential_fault_if(
    state: &Mutex<CredentialFaultState>,
    login: &str,
    predicate: impl FnOnce(CredentialMutationFault) -> bool,
) -> Option<CredentialMutationFault> {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let plan = state.plans.get_mut(login)?;
    let fault = plan.fault;
    if !predicate(fault) {
        return None;
    }
    plan.remaining -= 1;
    if plan.remaining == 0 {
        state.plans.remove(login);
    }
    Some(fault)
}

/// `TenantId` → SQL bind 参数（stringify UUID 绑 `$N::uuid` server-side cast；不给 sqlx 加 uuid feature）。
fn tenant_param(tenant: TenantId) -> String {
    tenant.as_uuid().to_string()
}

/// 由持久化三列重建 [`AccountLockout`]：窗口列 NULL（从未失败）→ `new(now)`，否则 `from_parts`（策略阈值留域）。
fn rebuild_lockout(
    failure_count: i64,
    window: Option<i64>,
    until: Option<i64>,
    now: SystemTime,
) -> AccountLockout {
    match window {
        // 从未失败（窗口未锚定）→ 新锁定态（锚定 now）。
        None => AccountLockout::new(now),
        Some(w) => AccountLockout::from_parts(
            u32::try_from(failure_count).unwrap_or(0),
            epoch_secs_to_time(w),
            until.map(epoch_secs_to_time),
        ),
    }
}

/// 清除锁定态（成功登录原子清零失败计数 + 解锁；同 in-mem `lockouts.remove`）。
async fn clear_lockout(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    login: &str,
) -> Result<(), IdentityError> {
    sqlx::query(
        "UPDATE credentials SET failure_count = 0, lockout_window_start = NULL, locked_until = NULL \
         WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant_uuid)
    .bind(login)
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    Ok(())
}

/// 回写锁定态三列（`to_timestamp($n)`；`locked_until` None → NULL bind → to_timestamp(NULL)=NULL）。
async fn write_lockout(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    login: &str,
    lockout: &AccountLockout,
) -> Result<(), IdentityError> {
    sqlx::query(
        "UPDATE credentials \
         SET failure_count = $3, lockout_window_start = to_timestamp($4), locked_until = to_timestamp($5) \
         WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant_uuid)
    .bind(login)
    .bind(i64::from(lockout.failure_count()))
    .bind(unix_secs(lockout.window_start()))
    .bind(lockout.locked_until().map(unix_secs))
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    Ok(())
}

impl CredentialRepo for PgCredentialRepo {
    async fn find_by_user_id(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<Option<Credential>, IdentityError> {
        let tenant = scope.tenant();
        let tenant_uuid = tenant_param(tenant);
        let user_uuid = user_id.as_uuid().to_string();
        let tenant_uuid_q = tenant_uuid.clone();
        let user_uuid_q = user_uuid.clone();

        // 经 tenant_scoped_read 注入 SET LOCAL（与 0009 RLS policy current_setting 锚点对齐）；读闭包仅 fetch +
        // try_get 返回 owned 原始值，hydrate（PHC 复核 / Credential 重建）在 tx 外（域错误不依赖 sqlx）。
        let raw = self
            .pool
            .read(scope, move |conn| {
                Box::pin(async move {
                    let row = sqlx::query(
                        r#"
                    SELECT login, password_hash, version
                    FROM credentials
                    WHERE tenant_id = $1::uuid AND user_id = $2::uuid
                    "#,
                    )
                    .bind(tenant_uuid_q)
                    .bind(user_uuid_q)
                    .fetch_optional(&mut *conn)
                    .await?;
                    match row {
                        None => Ok(None),
                        Some(r) => {
                            let login: String = r.try_get("login")?;
                            let password_hash: String = r.try_get("password_hash")?;
                            let version: i64 = r.try_get("version")?;
                            Ok(Some((login, password_hash, version)))
                        }
                    }
                })
            })
            .await
            .map_err(storage)?;

        match raw {
            None => Ok(None),
            Some((login, phc, version)) => {
                // 受控重建（WHERE 已锁 tenant + user_id = 入参）：PHC 经 parse 复核（损坏 → Storage fail-closed，
                // 同 Role::hydrate 范式）；version i64→u32（持久化非负，越界回 0 fail-safe，仅影响 CAS 不影响验签）。
                let password_hash = secure::PasswordHash::parse(&phc)
                    .map_err(|e| IdentityError::Storage(Box::new(e)))?;
                let version = u32::try_from(version).unwrap_or(0);
                Ok(Some(Credential::hydrate(
                    &login,
                    user_id,
                    tenant,
                    password_hash,
                    version,
                )))
            }
        }
    }

    async fn authenticate(
        &self,
        scope: TenantRepoScope,
        login: LoginIdentifier,
        candidate: String,
        now: SystemTime,
    ) -> Result<AuthOutcome, IdentityError> {
        let tenant = scope.tenant();
        let tenant_uuid = tenant_param(tenant);
        let login_str = login.as_str().to_owned();
        self.pool
            .write(
                scope,
                move |conn| {
                    Box::pin(async move {
                        authenticate_in_tx(conn.conn(), &tenant_uuid, &login_str, &candidate, now)
                            .await
                    })
                },
                storage,
            )
            .await
    }

    async fn save(
        &self,
        scope: TenantRepoScope,
        credential: Credential,
    ) -> Result<(), IdentityError> {
        let tenant = scope.tenant();
        if credential.tenant() != tenant {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "credential save tenant scope mismatch",
            ))));
        }
        let tenant_uuid = tenant_param(tenant);
        self.pool
            .write(
                scope,
                move |conn| {
                    Box::pin(
                        async move { save_in_tx(conn.conn(), &tenant_uuid, &credential).await },
                    )
                },
                storage,
            )
            .await
    }

    async fn apply_password_change(
        &self,
        scope: TenantRepoScope,
        mutation: PasswordChangeMutation,
    ) -> Result<(), IdentityError> {
        let (expected, next, observation) = mutation.into_parts();
        let tenant = scope.tenant();
        if next.tenant() != tenant {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "credential bump tenant scope mismatch",
            ))));
        }
        let tenant_uuid = tenant_param(tenant);
        let login_str = next.login().as_str().to_owned();
        #[cfg(all(test, feature = "integration"))]
        let post_update_gate = self.password_change_post_update_gate.clone();
        #[cfg(all(test, feature = "integration"))]
        let password_change_faults = Arc::clone(&self.password_change_faults);
        run_pg_localtx_retry(
            observation,
            |_attempt| {
                let tenant_uuid = tenant_uuid.clone();
                let login_str = login_str.clone();
                let next = next.clone();
                #[cfg(all(test, feature = "integration"))]
                let post_update_gate = post_update_gate.clone();
                #[cfg(all(test, feature = "integration"))]
                let password_change_faults = Arc::clone(&password_change_faults);
                #[cfg(all(test, feature = "integration"))]
                record_password_change_attempt(&password_change_faults, &login_str);
                async move {
                    self.pool
                        .retry_write(
                            scope,
                            move |tx| {
                                Box::pin(async move {
                                    #[cfg(all(test, feature = "integration"))]
                                    if take_credential_fault_if(
                                        &password_change_faults,
                                        &login_str,
                                        |fault| {
                                            matches!(
                                                fault,
                                                CredentialMutationFault::TransientBeforeWrite
                                            )
                                        },
                                    )
                                    .is_some()
                                    {
                                        return Err(storage(sqlx::Error::PoolTimedOut));
                                    }
                                    apply_password_change_in_tx(
                                        tx.conn(),
                                        &tenant_uuid,
                                        &login_str,
                                        expected,
                                        &next,
                                    )
                                    .await?;
                                    #[cfg(all(test, feature = "integration"))]
                                    if let Some(gate) = post_update_gate {
                                        gate.pause_after_update().await;
                                    }
                                    #[cfg(all(test, feature = "integration"))]
                                    if let Some(fault) = take_credential_fault_if(
                                        &password_change_faults,
                                        &login_str,
                                        |fault| {
                                            !matches!(
                                                fault,
                                                CredentialMutationFault::TransientBeforeWrite
                                            )
                                        },
                                    ) {
                                        match fault {
                                            CredentialMutationFault::Permanent => {
                                                return Err(IdentityError::Storage(Box::new(
                                                    std::io::Error::other(
                                                        "injected credential post-update failure",
                                                    ),
                                                )));
                                            }
                                            CredentialMutationFault::Transient => {
                                                return Err(storage(sqlx::Error::PoolTimedOut));
                                            }
                                            CredentialMutationFault::TransientBeforeWrite => {
                                                unreachable!(
                                                    "before-write fault is consumed before SQL"
                                                )
                                            }
                                            CredentialMutationFault::CommitUnknown => {
                                                tx.inject_commit_unknown_after_commit()
                                                    .await
                                                    .map_err(storage)?;
                                            }
                                        }
                                    }
                                    Ok(())
                                })
                            },
                            storage,
                        )
                        .await
                }
            },
            classify_identity_error,
        )
        .await
    }

    async fn lockout_status(
        &self,
        scope: TenantRepoScope,
        login: LoginIdentifier,
        now: SystemTime,
    ) -> Result<bool, IdentityError> {
        let tenant = scope.tenant();
        let tenant_uuid = tenant_param(tenant);
        let login_str = login.as_str().to_owned();
        self.pool
            .write(
                scope,
                move |conn| {
                    Box::pin(async move {
                        lockout_status_in_tx(conn.conn(), &tenant_uuid, &login_str, now).await
                    })
                },
                storage,
            )
            .await
    }
}

/// 行类型：已知主体 SELECT FOR UPDATE 读出（user_id PHC + 锁定三列）；未知主体 → None。
type AuthRow = (String, String, i64, Option<i64>, Option<i64>);

/// authenticate 事务体（SET LOCAL → 单行 FOR UPDATE → 恒定成本验签 → 原子分流；#1277 F1+F2+F3）。
async fn authenticate_in_tx(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    login: &str,
    candidate: &str,
    now: SystemTime,
) -> Result<AuthOutcome, IdentityError> {
    let found = auth_row(tx, tenant_uuid, login).await?;
    // PHC parse（已知主体）。损坏 PHC = 存储完整性问题 → fail-closed `Storage`，但**先跑等价 KDF 再早退**：
    // 否则「已知主体 + 损坏 PHC」走 ~0 成本早退，与「未知主体」跑满 argon2 KDF 的耗时可区分，泄漏主体存在性
    // （#1277 F3 边缘时序盲区）。与 `application.rs` change_password not-found 路径同款「dummy KDF 后早退」防御。
    let hash = match &found {
        Some((_, phc, ..)) => match secure::PasswordHash::parse(phc) {
            Ok(h) => Some(h),
            Err(e) => {
                let _ = secure::verify_password_constant_time(candidate, None);
                return Err(IdentityError::Storage(Box::new(e)));
            }
        },
        None => None,
    };
    // 恒定成本验签（F3）：未知主体亦跑等价 KDF（消枚举时序差）。
    let ok = secure::verify_password_constant_time(candidate, hash.as_ref());
    match (found, ok) {
        // 已知 + 正确：原子清锁 + 返回 canonical actor subject。
        (Some((user_id_str, ..)), true) => {
            clear_lockout(tx, tenant_uuid, login).await?;
            let user_id = ids::UserId::parse(&user_id_str)
                .map_err(|e| IdentityError::Storage(Box::new(e)))?;
            Ok(AuthOutcome::Authenticated(user_id))
        }
        // 已知 + 错：原子推进 lockout（达阈值即锁），回写三列；对外仍 InvalidCredentials。
        // 注：本分支较 InvalidUnknown 多一次 write_lockout（RTT 差），但两路径均已跑满 argon2 KDF（~100ms）主导
        // 耗时，该写差在 KDF 噪音量级内——属 `ports.rs` 标注的 SHOULD-level 容忍（与 in-mem 替身同语义，#1277）。
        (Some((_, _, failure_count, window, until)), false) => {
            let mut lockout = rebuild_lockout(failure_count, window, until, now);
            lockout.record_failure(now);
            write_lockout(tx, tenant_uuid, login, &lockout).await?;
            Ok(AuthOutcome::InvalidKnownUser)
        }
        // 查无凭据：KDF 已跑；**不建 / 不动** lockout（F2：未知主体无行 ⇒ 无锁可建）。
        (None, _) => Ok(AuthOutcome::InvalidUnknown),
    }
}

/// 单行 FOR UPDATE 读凭据 + 锁定三列（已知主体）；未知主体 0 行 → None（不建锁，F2）。
async fn auth_row(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    login: &str,
) -> Result<Option<AuthRow>, IdentityError> {
    let row = sqlx::query(
        r#"
        SELECT user_id::text AS user_id,
               password_hash,
               failure_count,
               extract(epoch from lockout_window_start)::bigint AS lockout_window_start,
               extract(epoch from locked_until)::bigint AS locked_until
        FROM credentials
        WHERE tenant_id = $1::uuid AND login = $2
        FOR UPDATE
        "#,
    )
    .bind(tenant_uuid)
    .bind(login)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    match row {
        None => Ok(None),
        Some(r) => {
            let user_id: String = r.try_get("user_id").map_err(storage)?;
            let phc: String = r.try_get("password_hash").map_err(storage)?;
            let failure_count: i64 = r.try_get("failure_count").map_err(storage)?;
            let window: Option<i64> = r.try_get("lockout_window_start").map_err(storage)?;
            let until: Option<i64> = r.try_get("locked_until").map_err(storage)?;
            Ok(Some((user_id, phc, failure_count, window, until)))
        }
    }
}

/// save 事务体：upsert key = (tenant_id, login)（F2：key 派生自 credential 自身）；ON CONFLICT 只更
/// user_id / password_hash / version，**不触锁定列**（与 in-mem save 不动 lockout 一致；新行锁定列取默认）。
async fn save_in_tx(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    credential: &Credential,
) -> Result<(), IdentityError> {
    sqlx::query(
        r#"
        INSERT INTO credentials (tenant_id, user_id, login, password_hash, version)
        VALUES ($1::uuid, $2::uuid, $3, $4, $5)
        ON CONFLICT (tenant_id, login) DO UPDATE
        SET user_id = EXCLUDED.user_id,
            password_hash = EXCLUDED.password_hash,
            version = EXCLUDED.version
        "#,
    )
    .bind(tenant_uuid)
    .bind(credential.user_id().as_uuid().to_string())
    .bind(credential.login().as_str())
    .bind(credential.password_hash().as_str())
    .bind(i64::from(credential.version()))
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    Ok(())
}

/// password-change 事务体：单行 FOR UPDATE 读版本 → CAS 分支（None=CredentialNotFound / 不匹配=VersionConflict /
/// 命中→替换 hash+version，保留锁定列，同 in-mem bump 不动 lockout）。key 派生自 `next`（F2）。
async fn apply_password_change_in_tx(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    login: &str,
    expected: u32,
    next: &Credential,
) -> Result<(), IdentityError> {
    let row = sqlx::query(
        "SELECT version FROM credentials WHERE tenant_id = $1::uuid AND login = $2 FOR UPDATE",
    )
    .bind(tenant_uuid)
    .bind(login)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    let Some(r) = row else {
        return Err(IdentityError::CredentialNotFound);
    };
    let current: i64 = r.try_get("version").map_err(storage)?;
    // 越界损坏值 → u32::MAX（除非 expected 恰为 MAX 否则不匹配 → VersionConflict，fail-closed）。
    if u32::try_from(current).unwrap_or(u32::MAX) != expected {
        return Err(IdentityError::VersionConflict);
    }
    sqlx::query(
        "UPDATE credentials SET password_hash = $3, version = $4 \
         WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant_uuid)
    .bind(login)
    .bind(next.password_hash().as_str())
    .bind(i64::from(next.version()))
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    Ok(())
}

/// lockout_status 事务体：单行 FOR UPDATE → locked_until NULL / 无行 → false；否则原子 lazy-unlock（TTL 过则
/// 回写清零持久化）→ 返 is_locked（同 in-mem `try_lazy_unlock` + `is_locked`）。
async fn lockout_status_in_tx(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    login: &str,
    now: SystemTime,
) -> Result<bool, IdentityError> {
    let row = sqlx::query(
        r#"
        SELECT failure_count,
               extract(epoch from lockout_window_start)::bigint AS lockout_window_start,
               extract(epoch from locked_until)::bigint AS locked_until
        FROM credentials
        WHERE tenant_id = $1::uuid AND login = $2
        FOR UPDATE
        "#,
    )
    .bind(tenant_uuid)
    .bind(login)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    // 无行 = 未锁定（查无凭据 / 跨租 fail-closed）。
    let Some(r) = row else {
        return Ok(false);
    };
    let until: Option<i64> = r.try_get("locked_until").map_err(storage)?;
    // 未锁定（locked_until NULL）→ 直接 false（无需 lazy-unlock；与 is_locked 语义一致）。
    if until.is_none() {
        return Ok(false);
    }
    let failure_count: i64 = r.try_get("failure_count").map_err(storage)?;
    let window: Option<i64> = r.try_get("lockout_window_start").map_err(storage)?;
    let mut lockout = rebuild_lockout(failure_count, window, until, now);
    // 原子 lazy-unlock：TTL 过则回写清零（持久化解锁，无后台 job）。
    if lockout.try_lazy_unlock(now) {
        write_lockout(tx, tenant_uuid, login, &lockout).await?;
    }
    Ok(lockout.is_locked(now))
}
