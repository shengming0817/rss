//! 本地文件 JWKS key 源（#1109/T003）：从受 OS 保护的本地路径读 JWKS 文档（外部 agent / init-container /
//! controller 经**各自的** TLS 拉取 + 轮转后写入），解析成 kid 索引的 [`KeySet`] 快照 + 后台 poll 周期重载 +
//! fail-closed。
//!
//! **零 in-app HTTP/TLS provider**：传输完整性重定位到基础设施层——文件权限 / k8s Secret RBAC / 挂载 namespace
//! 隔离（机器强制），落 spec.md FR-005「本地 sidecar / 文件源」分支，与 SPIFFE（UDS 内核 peer 鉴别）/
//! cert-manager（Secret RBAC + 挂载）同构。**绝不裸 plain-HTTP-over-network**（research.md F2：内网 MITM 可替换
//! 公钥）。选此 altitude 的根因：2026-06 无 license-clean 且生产成熟的 rustls TLS provider——`ring`/`aws-lc-rs`=
//! OpenSSL 派生（deny.toml 拒）、`rustls-rustcrypto`=alpha「勿用于生产」、`graviola`=纯 Rust 但未审计。in-app
//! HTTPS = follow-up（待成熟 provider，复用本模块 [`KeySet`]/poll seam，仅换 transport）。
//!
//! fail-closed 不变式：源不可读 / 畸形 / 无可用 key → 构造期 fail-fast 拒；运行期刷新失败 → **保留 last-good
//! 快照** + `is_ready=false`（degraded），**绝不** swap 进空集或宽放；token kid 不在当前快照 → 无候选 → 验签
//! 必失败（[`crate::config`] `entry_matches`）。后台刷新句柄经 [`JwksKeySource::shutdown`] 真实关闭（由
//! [`crate::OidcProvider`] 的 `ManagedResource::shutdown` 级联，对齐 bootstrap ShutdownStack）。
//!
//! ref: maxlambrecht/rust-spiffe（`JwtSource`：本地缓存 JWK bundle + 自动刷新 + 按 kid 查找 + 离线验签）；
//! RFC 7517（JWK / JWK Set）；RFC 7518 §6.2（EC `crv`/`x`/`y`）、§6.4（oct `k`）。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use diport::ShutdownError;
use p256::ecdsa::VerifyingKey;
use serde::Deserialize;
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{KeyEntry, KeySet, MIN_HS256_SECRET_BYTES};
use crate::verify::LOG_TARGET;

/// JWKS 文档体积上界（字节）。JWKS 是小文档（数把 key 的 `x`/`y`/`k` base64url），256 KiB 远超正常上限；
/// 超此值视为误挂载（如把大 CA bundle 错挂到 key 路径）→ 拒读，防同步读阻塞 tokio worker（DoS 边界前移）。
const MAX_JWKS_BYTES: u64 = 256 * 1024;

/// JWKS 文件源构造期 / 刷新错误（fail-fast）。`#[non_exhaustive]`：新增校验项不破坏 match。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwksError {
    /// 源路径不可读（文件不存在 / 权限不足 / I/O 错误 / 超过 [`MAX_JWKS_BYTES`]）。
    #[error("jwks source path could not be read")]
    Unreadable,
    /// JWKS 文档非合法 JSON（畸形）。
    #[error("jwks document is malformed json")]
    Malformed,
    /// JWKS 文档解析后无任何可用 key（全部 key 不符 ES256/HS256 白名单或格式非法）。
    #[error("jwks document contains no usable keys")]
    NoUsableKeys,
    /// 刷新间隔为零（`tokio::time::interval` 要求 period > 0；零间隔是误配，构造期拒）。
    #[error("jwks refresh interval must be greater than zero")]
    ZeroInterval,
    /// 不在 tokio runtime 上下文构造（后台 poll 任务需 `tokio::spawn`）。构造期 fail-fast（typed `Err`），
    /// 而非运行期 `tokio::spawn` panic——与 fail-fast 设计对齐（评审：Soft panic → Medium typed error）。
    #[error("jwks source must be constructed within a tokio runtime context")]
    NoRuntime,
}

impl JwksError {
    /// 失败原因闭值标签（脱敏日志用；纯枚举名、**无 PII**——不含 path / 字节 / key 材料）。
    fn reason_label(&self) -> &'static str {
        match self {
            JwksError::Unreadable => "unreadable",
            JwksError::Malformed => "malformed",
            JwksError::NoUsableKeys => "no_usable_keys",
            JwksError::ZeroInterval => "zero_interval",
            JwksError::NoRuntime => "no_runtime",
        }
    }
}

/// 可 clone 的 JWKS readiness 句柄（运维观测面，与资源所有权**解耦**）：组合根在 [`JwksKeySource`] 被 move 进
/// `VerifierConfig`/`OidcProvider` **之前**取本句柄，move 后仍能读 `is_ready()`（readyz probe 注册，#1109/T004）。
/// 持共享 `ready` 标志 + 低基数 `source_id`（多 IdP/多源时定位哪个源 degraded；**无 PII**——operator 控制的稳定标识）。
#[derive(Clone)]
pub struct JwksReadinessHandle {
    ready: Arc<AtomicBool>,
    source_id: Arc<str>,
}

impl JwksReadinessHandle {
    /// 上次刷新是否成功（degraded = false）。
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    /// operator 控制的低基数源标识（日志 / probe detail 用）。
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
}

/// JWKS key 快照存储（读写 poison recovery 的唯一 funnel）。外部刷新 / 验签路径不得直接触碰裸
/// `RwLock<Arc<KeySet>>`，避免读写侧可观测性漂移。
struct JwksSnapshotStore {
    inner: RwLock<Arc<KeySet>>,
}

impl JwksSnapshotStore {
    fn new(initial: KeySet) -> Self {
        Self {
            inner: RwLock::new(Arc::new(initial)),
        }
    }

    /// 取当前验签 key 快照（verify 同步路径调；`Arc` clone 零拷贝、与刷新换出无锁竞争撕裂）。
    ///
    /// 锁中毒时记 error 并继续复用恢复出的快照（`into_inner`）；不静默——日志暴露异常，避免
    /// 「中毒后悄悄供旧 key」无可观测性。
    fn snapshot(&self) -> Arc<KeySet> {
        let guard = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!(
                target: LOG_TARGET,
                resource = LOG_TARGET,
                reason = "jwks_snapshot_lock_poisoned",
                operation = "read",
                "jwks snapshot rwlock poisoned; serving recovered snapshot"
            );
            poisoned.into_inner()
        });
        Arc::clone(&guard)
    }

    /// 原子换出 fresh 快照。写锁中毒时与读侧同源记录 error，再恢复 guard 并继续替换，保持刷新成功语义。
    /// fresh 覆盖完成后清除 poison 状态，避免一次已恢复异常在后续读写路径上永久重复报错。
    fn replace(&self, set: KeySet) {
        let mut guard = self.inner.write().unwrap_or_else(|poisoned| {
            tracing::error!(
                target: LOG_TARGET,
                resource = LOG_TARGET,
                reason = "jwks_snapshot_lock_poisoned",
                operation = "write",
                "jwks snapshot rwlock poisoned; applying fresh snapshot after recovery"
            );
            poisoned.into_inner()
        });
        *guard = Arc::new(set);
        self.inner.clear_poison();
    }
}

/// **本地文件** JWKS key 源（**仅文件路径，不做任何 in-app HTTP/TLS 拉取**——见模块文档；in-app HTTPS 直连
/// 远程 IdP = follow-up）。持当前快照（后台刷新原子换出）+ readiness 标志 + 刷新任务句柄。
///
/// **生命周期约束**（资源管理，调用方/组合根须遵守）：
/// - 须在 **tokio runtime 上下文**构造（`load_and_watch` 内 `tokio::spawn` 后台 poll 任务；非 runtime →
///   `JwksError::NoRuntime` fail-fast，不 panic）。
/// - 构造成功后**必须经 [`Self::shutdown`] 关闭**——直接 drop 会孤立后台 poll 任务（`JoinHandle` 未 await）。
///   生产路径经 [`crate::OidcProvider`] `ManagedResource::shutdown` 级联（ShutdownStack 编排）。
/// - 注入的 `token` 生命周期应 ≥ 本源关闭时刻——外层提前 cancel 会令 poll 任务提前停止（`is_ready()` 不自动转 false）。
pub struct JwksKeySource {
    /// operator 控制的低基数源标识（日志 / readiness 句柄；多源定位用）。
    source_id: Arc<str>,
    /// 源路径（[`Self::reload`] 重读 + 诊断用）。
    path: PathBuf,
    /// 当前验签 key 快照（读侧 clone `Arc`；刷新侧整体换出；poison recovery 经 [`JwksSnapshotStore`] 单源）。
    snapshot: Arc<JwksSnapshotStore>,
    /// 上次刷新是否成功（FR-005 `oidc_jwks_ready` 信号源；probe 注册 = #1109/T004）。
    ready: Arc<AtomicBool>,
    /// 刷新任务取消信号（`shutdown` 触发；幂等——ShutdownStack 阶段 1 可能已 cancel）。
    token: CancellationToken,
    /// 后台 poll 任务句柄（`shutdown` 取走 + await 收敛；`tokio::sync::Mutex` 供 `&self` 异步关闭）。
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for JwksKeySource {
    /// RAII 兜底（资源启动与所有权提交非同一事务的释放协议）：未经 [`Self::shutdown`] 直接 drop 时（如
    /// `VerifierConfigBuilder::build` 失败、key 源被覆盖），cancel token + abort 后台 poll 任务，防任务泄漏。
    /// 优雅关闭仍应走 `shutdown`（await 收敛）；本 Drop 是漏调 shutdown 的安全网。
    fn drop(&mut self) {
        self.token.cancel();
        // 独占 drop，try_lock 必成功；shutdown 已取走句柄则 None（幂等）。
        let Ok(mut guard) = self.handle.try_lock() else {
            return;
        };
        if let Some(handle) = guard.take() {
            handle.abort();
        }
    }
}

impl JwksKeySource {
    /// 从本地路径读 JWKS 文档构造 + 启动后台周期刷新。
    ///
    /// **初始加载 fail-fast**（误配在组合根接线期暴露，不静默 noop）：非 tokio runtime → `NoRuntime`；零间隔 →
    /// `ZeroInterval`；路径不可读 / 超 [`MAX_JWKS_BYTES`] → `Unreadable`；畸形 → `Malformed`；无可用 key →
    /// `NoUsableKeys`。成功后 `tokio::spawn` poll 任务，每 `refresh_interval` 重读、解析成功才原子换出快照，失败保留
    /// last-good + 标 degraded。
    ///
    /// 调用约束：
    /// - `source_id`：operator 控制的低基数稳定标识（如 `"primary-idp"`）——日志 / readiness 句柄定位多源用，**勿**含 PII。
    /// - `path` **必须**是 operator 受控挂载点下的路径（如 `/etc/oidc-jwks/keys.json`）——传输/写入完整性属 infra
    ///   层（文件权限 / k8s Secret RBAC / 挂载隔离），应用只读。**禁**用业务/用户可控的任意路径（组合根负责约束前缀）。
    /// - `refresh_interval` 建议 ≥ 5s（key 轮转是小时/天级；过小间隔只增无谓 stat/read syscall，无运维价值）。
    /// - 返回值的生命周期/关闭约束见 [`JwksKeySource`] 类型文档（**必须 `shutdown`**、token 生命周期、tokio runtime）。
    pub fn load_and_watch(
        source_id: impl Into<Arc<str>>,
        path: impl Into<PathBuf>,
        refresh_interval: Duration,
        token: CancellationToken,
    ) -> Result<Self, JwksError> {
        // 非 tokio runtime → 构造期 typed fail-fast（spawn_poll 内 tokio::spawn 否则运行期 panic）。
        if Handle::try_current().is_err() {
            return Err(JwksError::NoRuntime);
        }
        if refresh_interval.is_zero() {
            return Err(JwksError::ZeroInterval);
        }
        let source_id = source_id.into();
        let path = path.into();
        let initial = read_and_parse(&path)?; // 初始 fail-fast（含非空校验）。
        let snapshot = Arc::new(JwksSnapshotStore::new(initial));
        let ready = Arc::new(AtomicBool::new(true));
        let handle = spawn_poll(
            Arc::clone(&source_id),
            path.clone(),
            refresh_interval,
            Arc::clone(&snapshot),
            Arc::clone(&ready),
            token.clone(),
        );
        Ok(Self {
            source_id,
            path,
            snapshot,
            ready,
            token,
            handle: Mutex::new(Some(handle)),
        })
    }

    /// 取可 clone 的 readiness 句柄（与所有权解耦）：组合根在本源 move 进 config/provider **之前**取它，move 后
    /// 仍能读 `is_ready()` 注册 readyz probe（#1109/T004）。
    pub fn readiness_handle(&self) -> JwksReadinessHandle {
        JwksReadinessHandle {
            ready: Arc::clone(&self.ready),
            source_id: Arc::clone(&self.source_id),
        }
    }

    /// 取当前验签 key 快照（verify 同步路径调；poison recovery / 日志经 [`JwksSnapshotStore`] 单源）。
    pub(crate) fn snapshot(&self) -> Arc<KeySet> {
        self.snapshot.snapshot()
    }

    /// 上次刷新是否成功（FR-005 `oidc_jwks_ready` readiness 信号；degraded = 源刷新失败但仍持 last-good 快照）。
    /// `pub`：供**组合根（#1109/T004）**跨 crate 注册 readiness probe 消费——本 adapter 切片仅暴露状态、不接
    /// httpserve（probe 注册 + verbose readyz + 失败计数 = T004）。acquire-release 与 [`refresh`] 写侧配对、跨线程可见。
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// 立即重读源文件并刷新快照（返回刷新后 readiness）。后台 poll 与本方法共用同一 [`refresh`] 原语。
    /// `pub`：供**组合根（#1109/T004）** SIGHUP 类按需重载消费（本切片暂无 in-crate 生产调用方，故 `pub` 而非
    /// `pub(crate)`——`pub(crate)` 在无 in-crate 调用方时触发 dead-code，且 T004 跨 crate 须 `pub`）/ 测试驱动轮转。
    pub fn reload(&self) -> bool {
        refresh(&self.source_id, &self.path, &self.snapshot, &self.ready);
        self.is_ready()
    }

    /// 关闭：取消刷新任务（幂等）+ await 任务收敛。由 [`crate::config::KeySource::shutdown`] →
    /// [`crate::OidcProvider`] `ManagedResource::shutdown` 级联调用。再次调用 no-op（句柄已取走）。
    pub(crate) async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        // 先取出句柄并释放锁，再 await 任务收敛（不锁跨 await）。再次 shutdown → 句柄已取走 → no-op。
        let handle = self.handle.lock().await.take();
        let Some(handle) = handle else {
            return Ok(());
        };
        match handle.await {
            Ok(()) => Ok(()),
            Err(join_err) => {
                // JoinError Display 无 PII（任务 panic / abort 摘要）。
                tracing::error!(
                    target: LOG_TARGET,
                    resource = LOG_TARGET,
                    err = %join_err,
                    "jwks refresh task join error on shutdown"
                );
                Err(ShutdownError::new(join_err))
            }
        }
    }
}

/// 后台周期刷新任务：每 `period` 重读源 + 刷新快照，直到 `token` 取消。首个立即 tick 被消费（初始快照已在
/// 构造期同步加载）。
fn spawn_poll(
    source_id: Arc<str>,
    path: PathBuf,
    period: Duration,
    snapshot: Arc<JwksSnapshotStore>,
    ready: Arc<AtomicBool>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        // 刷新慢于 period 时跳过堆积 tick（不抢跑），避免 burst 重读。
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // 消费立即触发的首 tick。
        loop {
            tokio::select! {
                biased;
                () = token.cancelled() => break,
                _ = ticker.tick() => refresh(&source_id, &path, &snapshot, &ready),
            }
        }
        tracing::debug!(
            target: LOG_TARGET,
            resource = LOG_TARGET,
            source_id = %source_id,
            "jwks refresh task stopped"
        );
    })
}

/// 刷新原语（poll 任务与 [`JwksKeySource::reload`] 共用单源）：重读 + 解析成功才**原子换出**快照 +
/// `ready=true`；失败保留 last-good + `ready=false`（degraded），**绝不** swap 空集或宽放（fail-closed）。
// incidental: 预存阻塞（PR-254 #1197）。认知复杂度 16/15 由 `tracing::{debug,warn}!` 宏展开的条件分支撑高——
// 非业务逻辑复杂（函数体仅一个 match + 两臂原子写）；这是 tracing 宏对 clippy::cognitive_complexity 的已知
// false-positive，拆 helper 只搬走 tracing 调用、不增可读性。item-level carve-out（error-handling.md §Carve-out）。
// 本 PR（#1274/#1272）随 workspace 门绿顺带收口此预存阻塞，不改 refresh 行为。
#[allow(clippy::cognitive_complexity)]
fn refresh(source_id: &str, path: &Path, snapshot: &JwksSnapshotStore, ready: &AtomicBool) {
    match read_and_parse(path) {
        Ok(set) => apply_fresh(source_id, snapshot, ready, set),
        Err(e) => mark_degraded(source_id, ready, &e),
    }
}

/// 解析成功：原子换出快照 + `ready=true`（degraded 复位）。
/// 从 [`refresh`] 抽出（tracing 宏膨胀使 `refresh` cognitive_complexity 触阈，拆分而非 carve-out）。
fn apply_fresh(source_id: &str, snapshot: &JwksSnapshotStore, ready: &AtomicBool, set: KeySet) {
    snapshot.replace(set);
    ready.store(true, Ordering::Release);
    tracing::debug!(
        target: LOG_TARGET,
        resource = LOG_TARGET,
        source_id = source_id,
        "jwks snapshot refreshed"
    );
}

/// 解析失败：保留 last-good 快照（不清空 → 不宽放、不误拒已签发合法 token），标 degraded 供 readiness。
/// `source_id` 定位多源中哪个坏；`error_kind` = 闭值枚举标签（均无 PII，无 path/字节/key 材料）。
fn mark_degraded(source_id: &str, ready: &AtomicBool, e: &JwksError) {
    ready.store(false, Ordering::Release);
    tracing::warn!(
        target: LOG_TARGET,
        resource = LOG_TARGET,
        source_id = source_id,
        reason = "jwks_refresh_failed",
        error_kind = e.reason_label(),
        "jwks source refresh failed; retaining last-good snapshot"
    );
}

/// 读源文件 + 解析 + 非空校验。空集（无可用 key）视为错误（构造期拒 / 刷新期保留 last-good）。
fn read_and_parse(path: &Path) -> Result<KeySet, JwksError> {
    // 体积前置闸：超 MAX_JWKS_BYTES（误挂载大文件）→ 拒读，防同步读阻塞 tokio worker（先 metadata 不读全量）。
    if std::fs::metadata(path)
        .map_err(|_| JwksError::Unreadable)?
        .len()
        > MAX_JWKS_BYTES
    {
        return Err(JwksError::Unreadable);
    }
    // 本地小文件（≤ MAX_JWKS_BYTES）同步读；poll 周期秒级、读耗时微秒级，不阻塞 executor。
    let bytes = std::fs::read(path).map_err(|_| JwksError::Unreadable)?;
    let set = parse_jwks(&bytes)?;
    if set.is_empty() {
        return Err(JwksError::NoUsableKeys);
    }
    Ok(set)
}

/// JWKS 文档（RFC 7517 §5）：`{"keys":[...]}`。未知顶层字段忽略。
#[derive(Deserialize)]
struct JwksDoc {
    #[serde(default)]
    keys: Vec<Jwk>,
}

/// 单个 JWK（RFC 7517 §4 / RFC 7518 §6）。仅取本验签器关心的字段；未知字段（`use`/`x5c`/`n`/`e`…）忽略。
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    k: Option<String>,
}

/// 解析 JWKS 文档 → [`KeySet`]。仅 EC P-256（→ ES256）/ oct（→ HS256）入集（OIDC-ALG-WHITELIST-01 同源）；
/// 其它 kty / 格式非法的 key **逐个跳过**（不污染快照、不整体失败——单 key 坏不应拖垮整组轮转）。
fn parse_jwks(bytes: &[u8]) -> Result<KeySet, JwksError> {
    let doc: JwksDoc = serde_json::from_slice(bytes).map_err(|_| JwksError::Malformed)?;
    let mut es256 = Vec::new();
    let mut hs256 = Vec::new();
    for jwk in &doc.keys {
        match jwk.kty.as_str() {
            "EC" => {
                if let Some(entry) = parse_ec_p256(jwk) {
                    es256.push(entry);
                }
            }
            "oct" => {
                if let Some(entry) = parse_oct(jwk) {
                    hs256.push(entry);
                }
            }
            // reason: RSA(`RSA`)/OKP/未知 kty 不在 ES256/HS256 白名单——跳过，绝不引入新算法面（alg-confusion 前移）。
            _ => {}
        }
    }
    Ok(KeySet::new(es256, hs256))
}

/// 强制 JWKS key 携带非空 `kid`（**安全不变式**，#254 review F1）：JWKS entry 必须 kid-tagged，使
/// [`crate::config`] `entry_matches` 的「untagged=通配候选」规则**只**适用于 operator 注入的静态 key
/// （[`crate::config::StaticKeySource`]，无 kid 概念、operator 受信）——动态 JWKS key 一律精确 kid 匹配 +
/// fail-closed（spec FR-005：JWKS `kid` 缺失/未知必须拒，绝不让无-kid JWK 变成任意 token 的通配候选）。
/// 无 kid / 空 kid → `None`（该 key 跳过）。
fn require_kid(jwk: &Jwk) -> Option<String> {
    let kid = jwk.kid.clone()?;
    if kid.is_empty() {
        return None;
    }
    Some(kid)
}

/// EC JWK → ES256 公钥 entry。**必须带 `kid`**（无 kid → 跳过，见 [`require_kid`]，安全不变式）；仅 P-256
/// （`crv:"P-256"`）；`x`/`y` base64url decode 后拼 SEC1 未压缩点 `0x04||x||y`（与
/// [`crate::config::StaticKeySourceBuilder::add_es256_sec1`] 同形）；`from_sec1_bytes` 做 on-curve 校验
/// （拒非曲线点）。任一不符 → `None`（跳过）。
///
/// **`alg` 缺省即推断 ES256（有意设计）**：`alg` 是 JWK 可选字段（RFC 7517 §4.4），缺省时由 `kty=EC + crv=P-256`
/// 组合推断为 ES256（RFC 7518 §3.1 P-256↔ES256 唯一映射）；若**声明**了 `alg` 则须 `== "ES256"`，否则跳过。
/// 本地受信文件源场景安全（写入方受控）；未来扩展到公网 HTTP JWKS 源时须复核是否收紧为强制显式 `alg`。
fn parse_ec_p256(jwk: &Jwk) -> Option<KeyEntry<VerifyingKey>> {
    let kid = require_kid(jwk)?;
    if jwk.crv.as_deref() != Some("P-256") {
        return None;
    }
    if matches!(jwk.alg.as_deref(), Some(alg) if alg != "ES256") {
        return None;
    }
    let x = decode_b64(jwk.x.as_deref()?)?;
    let y = decode_b64(jwk.y.as_deref()?)?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let key = VerifyingKey::from_sec1_bytes(&sec1).ok()?;
    Some(KeyEntry {
        kid: Some(kid),
        key,
    })
}

/// oct JWK → HS256 密钥 entry。**必须带 `kid`**（见 [`require_kid`]）；若声明 `alg` 须为 `HS256`；`k` base64url
/// decode；< 32 bytes（弱 MAC key，含空）跳过（与 [`crate::config`] `MIN_HS256_SECRET_BYTES` 同源约束）。
fn parse_oct(jwk: &Jwk) -> Option<KeyEntry<Vec<u8>>> {
    let kid = require_kid(jwk)?;
    if matches!(jwk.alg.as_deref(), Some(alg) if alg != "HS256") {
        return None;
    }
    let secret = decode_b64(jwk.k.as_deref()?)?;
    if secret.len() < MIN_HS256_SECRET_BYTES {
        return None;
    }
    Some(KeyEntry {
        kid: Some(kid),
        key: secret,
    })
}

/// base64url（URL_SAFE_NO_PAD，RFC 7515 §2）解码；失败 → `None`。
fn decode_b64(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

#[cfg(test)]
mod tests {
    //! JWKS 解析矩阵 + 文件源加载 / 轮转 / fail-closed / degraded / shutdown。
    //! 测试 expect/unwrap carve-out 按 error-handling.md §Carve-out 用 **item-level** `#[allow]` 逐 fn 标注。
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use diport::{Clock, PdpError, RawCredential};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    use super::*;
    use crate::config::VerifierConfigBuilder;
    use crate::verify::verify_credential;

    const ISS: &str = "https://issuer.example";
    const AUD: &str = "rss-api";
    const NOW: i64 = 1_700_000_000;
    const SK1_BYTES: [u8; 32] = [0x42; 32];
    const SK2_BYTES: [u8; 32] = [0x11; 32];

    struct NoopReplayGuard;

    impl diport::ServiceTokenReplayGuard for NoopReplayGuard {
        fn check_and_record(
            &self,
            _nonce: &str,
            _expires_at: std::time::SystemTime,
        ) -> Result<(), diport::ServiceTokenReplayError> {
            Ok(())
        }
    }

    fn replay_guard() -> Arc<dyn diport::ServiceTokenReplayGuard> {
        Arc::new(NoopReplayGuard)
    }

    /// 确定性 tracing 捕获（JWKS poison recovery 回归测试用）。仅包住本测试触发的新 callsite，避免与
    /// `verify.rs` 的全局 subscriber fixture 争抢全局状态。
    mod capture {
        use std::cell::RefCell;
        use std::io::Write;

        use tracing_subscriber::fmt::MakeWriter;

        thread_local! {
            static BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        }

        struct ThreadLocalWriter;
        impl Write for ThreadLocalWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                BUF.with(|b| b.borrow_mut().extend_from_slice(buf));
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for ThreadLocalWriter {
            type Writer = ThreadLocalWriter;

            fn make_writer(&'a self) -> Self::Writer {
                ThreadLocalWriter
            }
        }

        pub(super) fn collect(f: impl FnOnce()) -> String {
            BUF.with(|b| b.borrow_mut().clear());
            let subscriber = tracing_subscriber::fmt()
                .with_writer(ThreadLocalWriter)
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                f();
                captured()
            })
        }

        #[allow(clippy::expect_used)]
        fn captured() -> String {
            BUF.with(|b| String::from_utf8(b.borrow().clone()).expect("utf8"))
        }
    }

    /// 唯一临时文件 + RAII 清理（零 tempfile 依赖：`temp_dir` + pid + 进程内自增序号）。
    static SEQ: AtomicU64 = AtomicU64::new(0);
    struct TempJwks {
        path: PathBuf,
    }
    impl TempJwks {
        #[allow(clippy::expect_used)]
        fn new(contents: &str) -> Self {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("rss-oidc-jwks-{}-{n}.json", std::process::id()));
            std::fs::write(&path, contents).expect("write temp jwks");
            Self { path }
        }
        #[allow(clippy::expect_used)]
        fn rewrite(&self, contents: &str) {
            std::fs::write(&self.path, contents).expect("rewrite temp jwks");
        }
        fn remove(&self) {
            let _ = std::fs::remove_file(&self.path);
        }
        fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempJwks {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    struct FixedClock(i64);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(self.0 as u64)
        }
    }

    #[allow(clippy::expect_used)]
    fn sk(bytes: &[u8; 32]) -> SigningKey {
        SigningKey::from_slice(bytes).expect("valid P-256 scalar")
    }

    /// SigningKey → EC JWK JSON（含 kid + alg=ES256，x/y base64url）。
    #[allow(clippy::expect_used)]
    fn ec_jwk(signing: &SigningKey, kid: &str) -> String {
        let vk = signing.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("x coord"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("y coord"));
        format!(r#"{{"kty":"EC","crv":"P-256","kid":"{kid}","alg":"ES256","x":"{x}","y":"{y}"}}"#)
    }

    /// oct JWK JSON（含 kid + alg=HS256，k base64url）。
    fn oct_jwk(secret: &[u8], kid: &str) -> String {
        let k = URL_SAFE_NO_PAD.encode(secret);
        format!(r#"{{"kty":"oct","kid":"{kid}","alg":"HS256","k":"{k}"}}"#)
    }

    fn jwks_doc(keys: &[String]) -> String {
        format!(r#"{{"keys":[{}]}}"#, keys.join(","))
    }

    fn payload(exp: i64) -> String {
        format!(r#"{{"sub":"alice","exp":{exp},"iss":"{ISS}","aud":"{AUD}"}}"#)
    }

    /// 用 ES256 私钥签发带 kid 的 JWT。
    fn mint_es256_kid(signing: &SigningKey, kid: &str, payload_json: &str) -> String {
        let header =
            URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#).as_bytes());
        let body = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header}.{body}");
        let sig: Signature = signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    static PANIC_HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[allow(clippy::panic)]
    fn poison_snapshot_store_write_lock(store: &JwksSnapshotStore) {
        let _hook_guard = match PANIC_HOOK_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = match store.inner.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            panic!("snapshot-store-test-poison");
        }));
        std::panic::set_hook(previous_hook);
        assert!(
            result.is_err(),
            "poison helper must panic while holding the write lock"
        );
    }

    // ── JWKS 快照锁 poison recovery funnel ─────────────────────────────────────
    #[test]
    #[allow(clippy::expect_used)]
    fn snapshot_store_read_poison_logs_and_serves_snapshot() {
        let set = parse_jwks(jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]).as_bytes()).expect("jwks");
        let store = JwksSnapshotStore::new(set);
        poison_snapshot_store_write_lock(&store);

        let logged = capture::collect(|| {
            let snap = store.snapshot();
            assert_eq!(snap.es256_candidates(Some("k1")).count(), 1);
        });

        assert!(logged.contains("jwks_snapshot_lock_poisoned"));
        assert!(logged.contains("serving recovered snapshot"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn snapshot_store_write_poison_logs_and_replaces_snapshot() {
        let initial =
            parse_jwks(jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]).as_bytes()).expect("initial");
        let fresh =
            parse_jwks(jwks_doc(&[ec_jwk(&sk(&SK2_BYTES), "k2")]).as_bytes()).expect("fresh");
        let store = JwksSnapshotStore::new(initial);
        poison_snapshot_store_write_lock(&store);

        let logged = capture::collect(|| store.replace(fresh));

        assert!(logged.contains("jwks_snapshot_lock_poisoned"));
        assert!(logged.contains("applying fresh snapshot after recovery"));
        assert!(
            !store.inner.is_poisoned(),
            "fresh replacement should clear recovered poison state"
        );
        let reread_logged = capture::collect(|| {
            let snap = store.snapshot();
            assert_eq!(snap.es256_candidates(Some("k2")).count(), 1);
            assert_eq!(snap.es256_candidates(Some("k1")).count(), 0);
        });
        assert!(!reread_logged.contains("jwks_snapshot_lock_poisoned"));
    }

    // ── JWKS 文档解析矩阵 ───────────────────────────────────────────────────────
    #[test]
    #[allow(clippy::expect_used)]
    fn parse_valid_ec_p256_jwk_kid_indexed() {
        let doc = jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]);
        let set = parse_jwks(doc.as_bytes()).expect("valid jwks");
        // tagged k1：仅 token kid=k1 命中；k2 / 无 kid 不命中（不盲扫 tagged key）。
        assert_eq!(set.es256_candidates(Some("k1")).count(), 1);
        assert_eq!(set.es256_candidates(Some("k2")).count(), 0);
        assert_eq!(set.es256_candidates(None).count(), 0);
        assert_eq!(set.hs256_candidates(Some("k1")).count(), 0);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_valid_oct_jwk() {
        let secret = [0x33u8; 32];
        let doc = jwks_doc(&[oct_jwk(&secret, "svc-1")]);
        let set = parse_jwks(doc.as_bytes()).expect("valid jwks");
        assert_eq!(set.hs256_candidates(Some("svc-1")).count(), 1);
        assert_eq!(set.es256_candidates(Some("svc-1")).count(), 0);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_skips_invalid_keys() {
        // 非 P-256 crv / 短 x / 弱 oct / 未知 kty / alg 失配 → 全跳过；其中混一把合法 EC → 仅它入集。
        let good = ec_jwk(&sk(&SK1_BYTES), "good");
        let wrong_crv = r#"{"kty":"EC","crv":"P-384","kid":"a","x":"AAAA","y":"AAAA"}"#.to_string();
        let short_xy = r#"{"kty":"EC","crv":"P-256","kid":"b","x":"AAAA","y":"AAAA"}"#.to_string();
        let weak_oct = oct_jwk(&[0x01u8; 16], "c"); // 16 bytes < 32
        let unknown_kty = r#"{"kty":"RSA","kid":"d","n":"x","e":"AQAB"}"#.to_string();
        let alg_mismatch =
            r#"{"kty":"EC","crv":"P-256","kid":"e","alg":"ES384","x":"AAAA","y":"AAAA"}"#
                .to_string();
        let doc = jwks_doc(&[
            good,
            wrong_crv,
            short_xy,
            weak_oct,
            unknown_kty,
            alg_mismatch,
        ]);
        let set = parse_jwks(doc.as_bytes()).expect("valid jwks json");
        assert_eq!(set.es256_len(), 1, "仅 good 入集");
        assert_eq!(set.hs256_len(), 0);
        assert_eq!(set.es256_candidates(Some("good")).count(), 1);
    }

    #[test]
    fn parse_rejects_malformed_json() {
        assert!(matches!(parse_jwks(b"not json"), Err(JwksError::Malformed)));
        assert!(matches!(
            parse_jwks(br#"{"keys": "#),
            Err(JwksError::Malformed)
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_empty_keys_yields_empty_set() {
        // 合法 JSON 但无可用 key → 空集（read_and_parse 会据此 NoUsableKeys）。
        let set = parse_jwks(br#"{"keys":[]}"#).expect("valid empty jwks");
        assert!(set.is_empty());
    }

    // ── 构造期 fail-fast ────────────────────────────────────────────────────────
    #[tokio::test]
    async fn load_missing_file_fails_fast() {
        let missing = std::env::temp_dir().join("rss-oidc-jwks-does-not-exist-zzz.json");
        let r = JwksKeySource::load_and_watch(
            "test-idp",
            missing,
            Duration::from_secs(60),
            CancellationToken::new(),
        );
        assert!(matches!(r, Err(JwksError::Unreadable)));
    }

    #[tokio::test]
    async fn load_empty_doc_fails_fast() {
        let tmp = TempJwks::new(r#"{"keys":[]}"#);
        let r = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(60),
            CancellationToken::new(),
        );
        assert!(matches!(r, Err(JwksError::NoUsableKeys)));
    }

    #[tokio::test]
    async fn load_malformed_fails_fast() {
        let tmp = TempJwks::new("garbage{");
        let r = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(60),
            CancellationToken::new(),
        );
        assert!(matches!(r, Err(JwksError::Malformed)));
    }

    #[tokio::test]
    async fn load_zero_interval_fails_fast() {
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let r = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::ZERO,
            CancellationToken::new(),
        );
        assert!(matches!(r, Err(JwksError::ZeroInterval)));
    }

    // ── 文件源加载 + reload 轮转（确定性，不依赖 poll 时序）───────────────────────
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn reload_rotates_snapshot_kid() {
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let src = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(3600),
            CancellationToken::new(),
        )
        .expect("initial load");
        assert_eq!(src.snapshot().es256_candidates(Some("k1")).count(), 1);

        // 轮转：换成 k2。
        tmp.rewrite(&jwks_doc(&[ec_jwk(&sk(&SK2_BYTES), "k2")]));
        assert!(src.reload(), "reload 应成功 → ready");
        let snap = src.snapshot();
        assert_eq!(snap.es256_candidates(Some("k2")).count(), 1, "新 kid 入集");
        assert_eq!(
            snap.es256_candidates(Some("k1")).count(),
            0,
            "旧 kid 轮转出快照（fail-closed）"
        );
        src.shutdown().await.expect("shutdown");
    }

    // ── degraded：刷新失败保留 last-good + ready=false ───────────────────────────
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_failure_retains_last_good_and_marks_degraded() {
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let src = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(3600),
            CancellationToken::new(),
        )
        .expect("initial load");
        assert!(src.is_ready());

        // 源被删除 → reload 失败。
        tmp.remove();
        assert!(!src.reload(), "刷新失败 → ready=false");
        assert!(!src.is_ready());
        // last-good 保留：k1 仍在快照（不宽放、不清空）。
        assert_eq!(
            src.snapshot().es256_candidates(Some("k1")).count(),
            1,
            "degraded 应保留 last-good 快照"
        );
        src.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_into_empty_keeps_last_good() {
        // 文件被改成空集（无可用 key）→ NoUsableKeys → 绝不 swap 空集。
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let src = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(3600),
            CancellationToken::new(),
        )
        .expect("initial load");
        tmp.rewrite(r#"{"keys":[]}"#);
        assert!(!src.reload(), "空集刷新视为失败");
        assert_eq!(
            src.snapshot().es256_candidates(Some("k1")).count(),
            1,
            "空集不得换出 last-good"
        );
        src.shutdown().await.expect("shutdown");
    }

    // ── 端到端①：JWKS 源 + 带 kid token 经完整 verify 路径通过；未知 kid fail-closed ──────────
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn end_to_end_jwks_verifies_kid_and_rejects_unknown_kid() {
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let src = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(3600),
            CancellationToken::new(),
        )
        .expect("initial load");
        let config = VerifierConfigBuilder::new(ISS, AUD)
            .keys_jwks(src)
            .service_token_replay_guard(replay_guard())
            .build()
            .expect("config");

        // 命中 kid=k1 → 通过完整 scheme dispatch → kid 候选 → 签名 → claim 校验。
        let tok_k1 = mint_es256_kid(&sk(&SK1_BYTES), "k1", &payload(NOW + 3600));
        assert!(
            verify_credential(&config, &FixedClock(NOW), &RawCredential::jwt(tok_k1)).is_ok(),
            "k1 token 应通过"
        );
        // 未知 kid（不在快照）→ 无候选 → 签名 key 不在受信集 → Untrusted（即便用同一把 sk1 签发）。
        let tok_unknown = mint_es256_kid(&sk(&SK1_BYTES), "not-in-jwks", &payload(NOW + 3600));
        let r = verify_credential(&config, &FixedClock(NOW), &RawCredential::jwt(tok_unknown));
        assert!(
            matches!(r, Err(PdpError::Untrusted)),
            "未知 kid 应 fail-closed (Untrusted): {r:?}"
        );
    }

    // ── 端到端②：文件轮转后旧 kid token fail-closed、新 kid 通过（reload 后 build config）──────
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn end_to_end_kid_rotation_fail_closed() {
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let src = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(3600),
            CancellationToken::new(),
        )
        .expect("initial load");
        // 轮转源到 k2（在移入 config 前 reload，使快照 = k2）。
        tmp.rewrite(&jwks_doc(&[ec_jwk(&sk(&SK2_BYTES), "k2")]));
        assert!(src.reload(), "reload 成功");
        let config = VerifierConfigBuilder::new(ISS, AUD)
            .keys_jwks(src)
            .service_token_replay_guard(replay_guard())
            .build()
            .expect("config");

        // 旧 k1 token（kid 已轮转出快照）→ 无候选 → fail-closed (Untrusted，spec SC-005 / 验收场景②)。
        let tok_k1 = mint_es256_kid(&sk(&SK1_BYTES), "k1", &payload(NOW + 3600));
        let r_old = verify_credential(&config, &FixedClock(NOW), &RawCredential::jwt(tok_k1));
        assert!(
            matches!(r_old, Err(PdpError::Untrusted)),
            "旧 kid 轮转后应 fail-closed (Untrusted): {r_old:?}"
        );
        // 新 k2 token → 通过。
        let tok_k2 = mint_es256_kid(&sk(&SK2_BYTES), "k2", &payload(NOW + 3600));
        assert!(
            verify_credential(&config, &FixedClock(NOW), &RawCredential::jwt(tok_k2)).is_ok(),
            "k2 token 应通过"
        );
    }

    // ── shutdown 幂等 + 任务收敛 ────────────────────────────────────────────────
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn shutdown_is_idempotent() {
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let src = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(3600),
            CancellationToken::new(),
        )
        .expect("initial load");
        src.shutdown().await.expect("first shutdown ok");
        src.shutdown()
            .await
            .expect("second shutdown ok (idempotent)");
    }

    // ── 后台 poll 任务确定性轮转（start_paused + advance 驱动 interval tick，非 wall-clock）──────────
    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    async fn background_poll_refreshes_snapshot() {
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let interval = Duration::from_secs(10);
        let src = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            interval,
            CancellationToken::new(),
        )
        .expect("initial load");
        assert_eq!(src.snapshot().es256_candidates(Some("k1")).count(), 1);

        // 文件轮转到 k2，推进时间驱动后台 poll tick。有界循环 advance+yield（不依赖单次 tick 的调度时序、
        // 不挂死）：后台任务须先消费构造期立即 tick、再在 interval 到点触发 refresh。
        tmp.rewrite(&jwks_doc(&[ec_jwk(&sk(&SK2_BYTES), "k2")]));
        let mut rotated = false;
        for _ in 0..10 {
            tokio::time::advance(interval).await;
            tokio::task::yield_now().await;
            if src.snapshot().es256_candidates(Some("k2")).count() == 1 {
                rotated = true;
                break;
            }
        }
        assert!(rotated, "后台 poll 应在数个 interval 内换出 k2");
        let snap = src.snapshot();
        assert_eq!(
            snap.es256_candidates(Some("k1")).count(),
            0,
            "后台 poll 应轮转出旧 kid k1（fail-closed）"
        );
        assert!(src.is_ready());
        src.shutdown().await.expect("shutdown");
    }

    // ── 多 kty 隔离：EC kid 不被 hs256 候选、oct kid 不被 es256 候选 ─────────────────
    #[test]
    #[allow(clippy::expect_used)]
    fn parse_multi_kty_kid_isolation() {
        let doc = jwks_doc(&[
            ec_jwk(&sk(&SK1_BYTES), "ec-1"),
            oct_jwk(&[0x55u8; 32], "oct-1"),
        ]);
        let set = parse_jwks(doc.as_bytes()).expect("valid jwks");
        assert_eq!(set.es256_len(), 1);
        assert_eq!(set.hs256_len(), 1);
        // 跨 kty kid 不交叉命中（路径隔离 + kid 过滤双闸）。
        assert_eq!(set.es256_candidates(Some("ec-1")).count(), 1);
        assert_eq!(set.es256_candidates(Some("oct-1")).count(), 0);
        assert_eq!(set.hs256_candidates(Some("oct-1")).count(), 1);
        assert_eq!(set.hs256_candidates(Some("ec-1")).count(), 0);
    }

    // ── 安全（#254 F1）：JWKS 中无 kid 的 JWK 被跳过——不得变成任意 token 的通配候选 ──────────────
    #[test]
    #[allow(clippy::expect_used)]
    fn parse_jwks_skips_kidless_jwk() {
        // EC JWK 缺 kid 字段（RFC 合法但安全上不可接受）→ require_kid 跳过 → 不入集（绝不 untagged 通配）。
        let vk = sk(&SK1_BYTES).verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(vk.x().expect("x"));
        let y = URL_SAFE_NO_PAD.encode(vk.y().expect("y"));
        let no_kid = format!(r#"{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{x}","y":"{y}"}}"#);
        // 空 kid 同样跳过。
        let empty_kid =
            format!(r#"{{"kty":"EC","crv":"P-256","kid":"","alg":"ES256","x":"{x}","y":"{y}"}}"#);
        // 混一把合法 kid'd key（good）+ 无 kid + 空 kid + 无 kid 的 oct。
        let good = ec_jwk(&sk(&SK2_BYTES), "good");
        let kidless_oct =
            r#"{"kty":"oct","alg":"HS256","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#
                .to_string();
        let set = parse_jwks(jwks_doc(&[good, no_kid, empty_kid, kidless_oct]).as_bytes())
            .expect("valid jwks");
        assert_eq!(
            set.es256_len(),
            1,
            "仅 good（带 kid）入集，无 kid/空 kid 跳过"
        );
        assert_eq!(set.hs256_len(), 0, "无 kid 的 oct 跳过");
        // 无 kid token → 无候选（JWKS 快照永无 untagged entry → fail-closed）。
        assert_eq!(
            set.es256_candidates(None).count(),
            0,
            "JWKS 无 untagged，无 kid token 无候选（fail-closed）"
        );
        assert_eq!(set.es256_candidates(Some("good")).count(), 1);
    }

    // ── 安全端到端（#254 F1）：JWKS 源 + 无 kid token → Untrusted（不被任意通配 key 验签）──────────
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn end_to_end_jwks_no_kid_token_fail_closed() {
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let src = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(3600),
            CancellationToken::new(),
        )
        .expect("initial load");
        let config = VerifierConfigBuilder::new(ISS, AUD)
            .keys_jwks(src)
            .service_token_replay_guard(replay_guard())
            .build()
            .expect("config");
        // 无 kid 的 token（用 k1 私钥签发，但 header 不带 kid）→ JWKS 快照无 untagged → 无候选 → Untrusted。
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#);
        let body = URL_SAFE_NO_PAD.encode(payload(NOW + 3600).as_bytes());
        let signing_input = format!("{header}.{body}");
        let sig: Signature = sk(&SK1_BYTES).sign(signing_input.as_bytes());
        let tok = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        let r = verify_credential(&config, &FixedClock(NOW), &RawCredential::jwt(tok));
        assert!(
            matches!(r, Err(PdpError::Untrusted)),
            "JWKS 无 kid token 应 fail-closed (Untrusted): {r:?}"
        );
    }

    // ── F3：重复设置 key 源 → build fail-fast（ConflictingKeySources）───────────────
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn conflicting_key_sources_rejected() {
        use crate::config::{ConfigError, StaticKeySource};
        let static_keys = StaticKeySource::builder()
            .add_es256_sec1(
                sk(&SK1_BYTES)
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes(),
            )
            .expect("static key")
            .build();
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK2_BYTES), "k2")]));
        let jwks = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(3600),
            CancellationToken::new(),
        )
        .expect("jwks load");
        // 先静态后 JWKS → 二次设置 → build 拒（覆盖的 jwks 经 Drop 兜底取消任务）。
        let r = VerifierConfigBuilder::new(ISS, AUD)
            .keys(static_keys)
            .keys_jwks(jwks)
            .build();
        // VerifierConfig 无 Debug（domain 封装），不格式化 Ok 变体。
        assert!(matches!(r, Err(ConfigError::ConflictingKeySources)));
    }

    // ── F4：readiness 句柄 move 后仍可读（组合根 T004 注册 readyz 接缝）────────────────
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn readiness_handle_survives_move_into_config() {
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let src = JwksKeySource::load_and_watch(
            "primary-idp",
            tmp.path(),
            Duration::from_secs(3600),
            CancellationToken::new(),
        )
        .expect("initial load");
        // move 进 config 前取句柄。
        let handle = src.readiness_handle();
        assert_eq!(handle.source_id(), "primary-idp");
        assert!(handle.is_ready());
        let _config = VerifierConfigBuilder::new(ISS, AUD)
            .keys_jwks(src)
            .service_token_replay_guard(replay_guard())
            .build()
            .expect("config");
        // src 已 move 进 config，句柄仍读共享 ready（组合根据此注册 oidc_jwks_ready probe）。
        assert!(handle.is_ready(), "move 后句柄仍反映 readiness");
    }

    // ── F2：未 shutdown 直接 drop → Drop 兜底 cancel token（防后台任务泄漏）──────────
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn drop_without_shutdown_cancels_token() {
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let token = CancellationToken::new();
        let src = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(3600),
            token.clone(),
        )
        .expect("initial load");
        assert!(!token.is_cancelled());
        drop(src); // 未调 shutdown，Drop 兜底 cancel + abort。
        assert!(
            token.is_cancelled(),
            "Drop 应 cancel token（防 poll 任务泄漏）"
        );
    }

    // ── 构造期 fail-fast：非 tokio runtime / 超大文件 ──────────────────────────────
    #[test]
    fn load_outside_tokio_runtime_fails_fast() {
        // 非 tokio runtime 上下文（plain #[test]）→ NoRuntime（typed Err，非 spawn panic）。
        let tmp = TempJwks::new(&jwks_doc(&[ec_jwk(&sk(&SK1_BYTES), "k1")]));
        let r = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(60),
            CancellationToken::new(),
        );
        assert!(matches!(r, Err(JwksError::NoRuntime)));
    }

    #[tokio::test]
    async fn load_oversized_file_rejected() {
        // 超 MAX_JWKS_BYTES（误挂载大文件）→ Unreadable（防同步读阻塞 worker）。
        let big = format!(
            r#"{{"keys":[],"pad":"{}"}}"#,
            "A".repeat(MAX_JWKS_BYTES as usize)
        );
        let tmp = TempJwks::new(&big);
        let r = JwksKeySource::load_and_watch(
            "test-idp",
            tmp.path(),
            Duration::from_secs(60),
            CancellationToken::new(),
        );
        assert!(matches!(r, Err(JwksError::Unreadable)));
    }
}
