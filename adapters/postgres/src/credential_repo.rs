//! `PgCredentialRepo` —— identity 凭据仓储的 postgres adapter（#1316）。
//!
//! impl `identity::ports::CredentialRepo`（find_by_user_id / authenticate / insert），
//! 作 durable login 密码校验真依赖，替换 in-mem `InMemCredentialRepo`（test/seed 门控）。adapter→域 DIP 内向边
//! （postgres 依赖 identity、native AFIT impl 其域形 port，经 deny.toml identity wrapper + `allows(Adapter,Domain)`
//! 放行；adapter 仍不被域依赖）。
//!
//! 持久化模型（`0015_create_credentials.sql`）：credentials 表 PK (tenant_id, login) + UNIQUE (tenant_id, user_id)；
//! **锁定态折叠进同一行**（failure_count / lockout_window_start / locked_until）——未知主体无行 ⇒ 无法建锁定态
//! （#1277 F2「未知主体不可预置锁定、不撑大 lockout 表」**结构层**天然成立，无独立锁定表）。明文密码**永不落库**，
//! 仅 `password_hash`（argon2 PHC，经 `secure::PasswordHash`）。
//!
//! 原子性：authenticate 固定锁序 `credentials → account_security_states`，在一个 writer 事务内完成
//! lifecycle/temporary-lock/KDF/rehash。密码变更只经 `PgIdentitySecurityLifecycle`。策略阈值（5 次 / 15min 滑窗 / 15min 锁定 TTL）
//! 域内单源（`identity::ports::AccountLockout`），adapter 仅 I/O：`from_parts` 重建 → `record_failure` /
//! `try_lazy_unlock` 推进 → 访问器回写三列。
//!
//! 有界 KDF 验签（#1277 F3）：authenticate 无论凭据是否存在都跑 typed `secure::verify_password`，未知
//! 主体支付当前档工作以关闭零 KDF 快路径；变量 PHC profile 不承诺严格等时。随后据「已知/未知 + 验签成败」
//! 原子分流（F1+F2）。tenant scope 经 `SET LOCAL`（读经
//! `tenant_scoped_read`，写经事务内 `set_local_tenant`，与 0009 RLS policy `current_setting` 锚点对齐）+ 显式
//! `WHERE tenant_id`（双重隔离，跨租 → 0 行 → fail-closed）。读出 PHC 经 `secure::PasswordHash::parse` 复核
//! （损坏持久化值 → `Storage`，fail-closed）。
//!
//! ref: kanidm server/lib/src/credential/softlock.rs@master（`CredSoftLock` lazy-unlock 无后台 job 状态机；本 adapter
//!   有意偏离其纯内存 softlock——多实例 PostgreSQL 须持久化 + 行锁原子 RMW，kanidm 自身注释亦承认内存方案分布式 bypass）
//! ref: RustCrypto/password-hashes argon2/src/lib.rs@master（PHC string at-rest，经 `secure::PasswordHash`）
//! ref: adapters/postgres/src/role_repo.rs（#1250 pool 注入 / SET LOCAL / storage 收口 / hydrate 范本）
//! ref: adapters/postgres/src/auth_grant_lifecycle.rs（#1278 epoch↔SystemTime 编码对称）

#[cfg(all(test, feature = "integration"))]
use std::collections::HashSet;
#[cfg(all(test, feature = "integration"))]
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use identity::ports::{
    AccountLockout, AccountStatus, AuthOutcome, BruteForceDecision, Credential, CredentialRepo,
    IdentityError, LoginIdentifier, TenantRepoScope,
};

use crate::account_security_repo::SecurityRow;
use crate::cotx::identity::IdentityTx;
use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb};
use crate::outbox::epoch_secs_to_time;
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};

/// identity 凭据仓储的 PostgreSQL adapter。
///
/// 仅由已验证 reader/writer capability 构造（同 [`crate::PgRoleRepo`]）。
/// 不持 `Clock`：authenticate 的 `now` 由调用方（`LoginService`，经注入 `Clock`）传入
/// （域类型不持 clock，rust-standards §工程护栏；时间判定全经入参 `now`）。
pub struct PgCredentialRepo {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
    #[cfg(all(test, feature = "integration"))]
    authenticate_post_write_faults: Arc<Mutex<HashSet<String>>>,
}

impl PgCredentialRepo {
    /// 由已验证 reader/writer capability 构造。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::credential_repo` 收口。
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
            #[cfg(all(test, feature = "integration"))]
            authenticate_post_write_faults: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(store),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
            authenticate_post_write_faults: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Inject one failure after authentication has applied its credential-row writes but before
    /// the enclosing transaction commits.
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_authenticate_post_write_fault(self, login: &str) -> Self {
        self.authenticate_post_write_faults
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(login.to_owned());
        self
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，adapter 边界收口；同 `PgRoleRepo`）。
fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

#[cfg(all(test, feature = "integration"))]
fn take_authenticate_post_write_fault(state: &Mutex<HashSet<String>>, login: &str) -> bool {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(login)
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
    tx: &mut IdentityTx<'_, '_, ServingWriteLane>,
    login: &str,
) -> Result<(), IdentityError> {
    tx.identity()
        .clear_credential_lockout(login)
        .await
        .map_err(storage)
}

/// 回写锁定态三列（`to_timestamp($n)`；`locked_until` None → NULL bind → to_timestamp(NULL)=NULL）。
async fn write_lockout(
    tx: &mut IdentityTx<'_, '_, ServingWriteLane>,
    login: &str,
    lockout: &AccountLockout,
) -> Result<(), IdentityError> {
    tx.identity()
        .write_credential_lockout(login, lockout)
        .await
        .map_err(storage)
}

impl CredentialRepo for PgCredentialRepo {
    async fn find_by_user_id(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<Option<Credential>, IdentityError> {
        let tenant = scope.tenant();
        let query_user = user_id;

        // 经 tenant_scoped_read 注入 SET LOCAL（与 0009 RLS policy current_setting 锚点对齐）；读闭包仅 fetch +
        // try_get 返回 owned 原始值，hydrate（PHC 复核 / Credential 重建）在 tx 外（域错误不依赖 sqlx）。
        let raw = self
            .read_pool
            .identity_read(scope, move |mut conn| {
                Box::pin(async move { conn.identity().credential_by_user(&query_user).await })
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
        candidate: secure::RawPassword,
        now: SystemTime,
    ) -> Result<AuthOutcome, IdentityError> {
        let login_str = login.as_str().to_owned();
        #[cfg(all(test, feature = "integration"))]
        let authenticate_post_write_faults = Arc::clone(&self.authenticate_post_write_faults);
        self.write_pool
            .identity_write(
                scope,
                move |mut conn| {
                    Box::pin(async move {
                        let outcome =
                            authenticate_in_tx(&mut conn, &login_str, candidate, now).await?;
                        #[cfg(all(test, feature = "integration"))]
                        if take_authenticate_post_write_fault(
                            &authenticate_post_write_faults,
                            &login_str,
                        ) {
                            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                                "injected authenticate post-write failure",
                            ))));
                        }
                        Ok(outcome)
                    })
                },
                storage,
            )
            .await
    }

    async fn insert(
        &self,
        scope: TenantRepoScope,
        credential: Credential,
    ) -> Result<(), IdentityError> {
        let tenant = scope.tenant();
        if credential.tenant() != tenant {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "credential insert tenant scope mismatch",
            ))));
        }
        self.write_pool
            .identity_write(
                scope,
                move |mut conn| Box::pin(async move { insert_in_tx(&mut conn, &credential).await }),
                storage,
            )
            .await
    }
}

/// 行类型：已知主体 SELECT FOR UPDATE 读出（user_id PHC + 锁定三列）；未知主体 → None。
pub(crate) type AuthRow = (String, String, i64, Option<i64>, Option<i64>);

/// authenticate 事务体（SET LOCAL → 单行 FOR UPDATE → 有界 KDF 验签 → 原子分流；#1277 F1+F2+F3）。
pub(crate) async fn authenticate_in_tx(
    tx: &mut IdentityTx<'_, '_, ServingWriteLane>,
    login: &str,
    candidate: secure::RawPassword,
    now: SystemTime,
) -> Result<AuthOutcome, IdentityError> {
    let found = auth_row(tx, login).await?;
    let security = match &found {
        Some((user_id, ..)) => security_row_for_update(tx, user_id).await?,
        None => None,
    };
    // PHC parse（已知主体）。损坏 PHC = 存储完整性问题 → fail-closed `Storage`，但**先跑当前档 KDF 再早退**：
    // 否则「已知主体 + 损坏 PHC」走 ~0 成本早退，与「未知主体」跑满 argon2 KDF 的耗时可区分，泄漏主体存在性
    // （#1277 F3 边缘时序盲区）。与 `application.rs` change_password not-found 路径同款「dummy KDF 后早退」防御。
    let hash = match &found {
        Some((_, phc, ..)) => match secure::PasswordHash::parse(phc) {
            Ok(h) => Some(h),
            Err(e) => {
                let _ = secure::verify_password(candidate, None);
                return Err(IdentityError::Storage(Box::new(e)));
            }
        },
        None => None,
    };
    // 有界 KDF 验签（F3）：未知主体亦跑当前档 KDF，关闭无主体零成本快路径。
    let verification = secure::verify_password(candidate, hash.as_ref())
        .map_err(|error| IdentityError::Storage(Box::new(error)))?;
    let security = match (&found, security) {
        (Some((user_id, ..)), Some(row)) => {
            let user_id = ids::UserId::parse(user_id)
                .map_err(|error| IdentityError::Storage(Box::new(error)))?;
            let tenant = tx.tenant();
            Some(crate::account_security_repo::hydrate_security(
                tenant, user_id, row,
            )?)
        }
        (Some(_), None) => {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "credential is missing account security state",
            ))));
        }
        (None, None) => None,
        (None, Some(_)) => {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "account security state exists without credential",
            ))));
        }
    };
    match (found, verification) {
        // 已知主体始终先门控 durable lifecycle 与 temporary brute-force lock.
        (Some((_, _, failure_count, window, until)), verification) => {
            let state = security.ok_or_else(|| {
                IdentityError::Storage(Box::new(std::io::Error::other(
                    "credential is missing account security state",
                )))
            })?;
            let mut lockout = rebuild_lockout(failure_count, window, until, now);
            if lockout.try_lazy_unlock(now) {
                write_lockout(tx, login, &lockout).await?;
            }
            if state.status() != AccountStatus::Active || lockout.is_locked(now) {
                return Ok(AuthOutcome::RejectedKnown);
            }
            match verification {
                secure::PasswordVerification::Verified(receipt) => {
                    if let Some(replacement) = receipt.upgraded_hash() {
                        replace_password_hash(tx, login, &replacement).await?;
                    }
                    clear_lockout(tx, login).await?;
                    Ok(AuthOutcome::Authenticated(state))
                }
                secure::PasswordVerification::Invalid => {
                    let _decision: BruteForceDecision = lockout.record_failure(now);
                    write_lockout(tx, login, &lockout).await?;
                    Ok(AuthOutcome::RejectedKnown)
                }
            }
        }
        // 查无凭据：KDF 已跑；**不建 / 不动** lockout（F2：未知主体无行 ⇒ 无锁可建）。
        (None, secure::PasswordVerification::Invalid) => Ok(AuthOutcome::RejectedUnknown),
        (None, secure::PasswordVerification::Verified(_)) => Err(IdentityError::Storage(Box::new(
            std::io::Error::other("dummy password verification returned success"),
        ))),
    }
}

/// Replace only the PHC maintenance field while preserving the business credential version.
/// The caller holds the credential row lock and the enclosing transaction also clears lockout.
async fn replace_password_hash(
    tx: &mut IdentityTx<'_, '_, ServingWriteLane>,
    login: &str,
    replacement: &secure::PasswordHash,
) -> Result<(), IdentityError> {
    tx.identity()
        .replace_credential_password_hash(login, replacement)
        .await
        .map_err(storage)
}

/// 单行 FOR UPDATE 读凭据 + 锁定三列（已知主体）；未知主体 0 行 → None（不建锁，F2）。
async fn auth_row(
    tx: &mut IdentityTx<'_, '_, ServingWriteLane>,
    login: &str,
) -> Result<Option<AuthRow>, IdentityError> {
    tx.identity()
        .lock_credential_auth_row(login)
        .await
        .map_err(storage)
}

/// The second and final row lock in authentication's fixed
/// `credentials -> account_security_states` order.
async fn security_row_for_update(
    tx: &mut IdentityTx<'_, '_, ServingWriteLane>,
    user_id: &str,
) -> Result<Option<SecurityRow>, IdentityError> {
    tx.identity()
        .lock_account_security_row(user_id)
        .await
        .map_err(storage)
}

/// Insert credential and its mandatory initial account-security row in one transaction.
async fn insert_in_tx(
    tx: &mut IdentityTx<'_, '_, ServingWriteLane>,
    credential: &Credential,
) -> Result<(), IdentityError> {
    tx.identity()
        .insert_credential_with_security(credential)
        .await
        .map_err(storage)
}
