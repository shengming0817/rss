//! HMAC blind index 원语（#1478）。
//!
//! 设计单源：**ADR-011 D4**（deterministic 默认 off / per-field opt-in / 等值-only / 稳定子集 scope）。
//! 模型 = CipherSweet HMAC blind index（**非** AES-SIV）：随机化 AEAD 值不变，旁路一列截断 keyed-HMAC
//! 做等值查询；scope 绑定 = tenant/domain/field/index_name（不含 schema-version，schema 演进不静默破坏）。
//!
//! **primary API**：通过 [`BlindIndex`] struct 统一 scope / transform / filter_bits 配置，
//! 写路径与读路径只能经同一 funnel 计算，避免 transform 链不一致。
//!
//! ref: paragonie/ciphersweet src/BlindIndex.php@master（filterBits 截断 + transformations[]）
//! ref: paragonie/ciphersweet src/EncryptedRow.php@master（per-(table,col,index) HMAC-SHA256 子密钥）
//! ref: paragonie/ciphersweet src/Backend/BoringCrypto.php@master（bit-mask 截断）
//! ref: rails/rails activerecord/lib/active_record/encryption/encryptable_record.rb@main（previous: 轮换窗口）

use hmac::Hmac;
// `hmac::Mac` trait 提供 new_from_slice/update/finalize；`as _` 引入方法不绑定名（避免与命名冲突）。
use hmac::Mac as _;
use sha2::Sha256;
use vocab::tenant::TenantId;

// ── 域分隔常量 ─────────────────────────────────────────────────────────────────

/// HMAC 子密钥派生的域分隔 + 版本钩（任一变更即 drift 不同 subkey，强制意识到）。
const CONTEXT: &[u8] = b"rss.blind-index.subkey.v1";

// ── 错误 ──────────────────────────────────────────────────────────────────────

/// HMAC 盲索引操作错误（const-literal message，无 panic）。
///
/// `#[non_exhaustive]`：未来可能加变体而不破坏现有匹配。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlindIndexError {
    /// root key 长度不足 32 字节（256-bit 下限，CipherSweet root-key 尺寸）。
    /// 真实熵量由调用方（KeyProvider，#1466）保证；此处只强制长度下限。
    #[error("blind index key too short")]
    KeyTooShort,
    /// `FilterBits` 超出有效范围 `1..=256`。
    #[error("blind index filter bits out of range")]
    FilterBitsOutOfRange,
    /// 经 Transform 管道处理后明文为空，拒绝索引（fail-closed：不把所有空值归同一 bucket）。
    #[error("blind index plaintext empty after transforms")]
    EmptyPlaintext,
    /// `IndexScope` 任一字符串字段为空串（零信任 fail-fast：空 domain/field/index_name 破坏 scope 隔离）。
    #[error("blind index scope field must not be empty")]
    EmptyScope,
}

// ── BlindIndexKey ─────────────────────────────────────────────────────────────

/// Root key 物料（sealed；仅 `from_bytes` 可铸，无 Clone，drop 自动清零）。
///
/// 真实密钥来源属 KeyProvider DI port（#1466），本原语只接受已验证长度的字节材料。
/// Debug 渲染 `BlindIndexKey(<redacted>)` by `#[derive(secure::Redact)]`，不泄原字节。
#[derive(zeroize::ZeroizeOnDrop, secure::Redact)]
pub struct BlindIndexKey(#[redact(sensitivity = secret)] Vec<u8>);

impl BlindIndexKey {
    /// 由字节构造 root key（受控 funnel；< 32 字节 → `KeyTooShort`）。
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, BlindIndexError> {
        let b = bytes.into();
        if b.len() < 32 {
            return Err(BlindIndexError::KeyTooShort);
        }
        Ok(Self(b))
    }

    /// 借出 key 字节（`pub(crate)`：全部 HMAC 在模块内完成，key 不出 crate）。
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ── IndexScope ────────────────────────────────────────────────────────────────

/// 稳定子集 scope 绑定（ADR-011 D4）：tenant / domain（表或 config-key）/ field / index_name。
///
/// 不含 schema-version——schema 演进不应静默废掉已存 index：改 scope 字段值即 drift 新 subkey，
/// 演进须 re-index + 双写过渡（由消费方 settings #1467 处理，不在原语层）。
/// 非密、plain derives 即可。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexScope<'a> {
    tenant: TenantId,
    /// 表名或 config-key（CipherSweet 的 "table" 维）。
    domain: &'a str,
    field: &'a str,
    /// 同一列可有多个命名 index（CipherSweet 支持多 transform/bits 组合）。
    index_name: &'a str,
}

impl<'a> IndexScope<'a> {
    /// 构造 scope（零信任 fail-fast：domain/field/index_name 为空串 → `EmptyScope`）。
    ///
    /// tenant 已在 [`TenantId`] 构造 funnel 中收敛为 canonical UUID，空值 / nil / 非 canonical
    /// 表示无法进入本类型。
    pub fn new(
        tenant: TenantId,
        domain: &'a str,
        field: &'a str,
        index_name: &'a str,
    ) -> Result<Self, BlindIndexError> {
        if domain.is_empty() || field.is_empty() || index_name.is_empty() {
            return Err(BlindIndexError::EmptyScope);
        }
        Ok(Self {
            tenant,
            domain,
            field,
            index_name,
        })
    }
}

// ── SubKey ────────────────────────────────────────────────────────────────────

/// 域/字段级 HMAC 子密钥（sealed；仅 `derive_subkey` 可铸，无 Clone，drop 自动清零）。
///
/// 不暴露 expose 访问器——子密钥不出模块，全部 HMAC 计算在本模块内完成。
/// Debug 渲染 `SubKey(<redacted>)` by `#[derive(secure::Redact)]`。
#[derive(zeroize::ZeroizeOnDrop, secure::Redact)]
pub(crate) struct SubKey(#[redact(sensitivity = secret)] [u8; 32]);

// ── HMAC 内部工具 ─────────────────────────────────────────────────────────────

/// 长度前缀编码 `lp(x) = u64-BE(len(x)) ++ x`（CipherSweet `pack` 类比）。
/// 防拼接歧义：`(a, bc)` ≠ `(ab, c)`（长度前缀使分段不可混淆）。
fn encode_lp(buf: &mut Vec<u8>, x: &[u8]) {
    buf.extend_from_slice(&(x.len() as u64).to_be_bytes());
    buf.extend_from_slice(x);
}

/// HMAC-SHA256(key, msg) → [u8; 32]（内部工具）。
///
/// HMAC-SHA256 的 `new_from_slice` 对任意长度 key 均成功（RFC 2104 §2 无 key 长度上限；
/// 短 key 经 block-size padding 处理）。Err 臂在实践中不可达——用 `unreachable!` 明确语义，
/// 避免静默返回零子密钥（密码学上危险：退化为公知常数 key，破坏所有 tenant scope 隔离）。
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mut h) => {
            h.update(msg);
            h.finalize().into_bytes().into()
        }
        Err(_) => {
            unreachable!("HMAC-SHA256 new_from_slice does not fail for any key length")
        }
    }
}

// ── derive_subkey ─────────────────────────────────────────────────────────────

/// 由 root key + scope 派生域/字段级子密钥（对标 CipherSweet `hash_hmac('sha256', pack(...), rootKey)`）。
///
/// ```text
/// msg = lp(CONTEXT) || lp(tenant.to_string()) || lp(domain) || lp(field) || lp(index_name)
/// lp(x) = u64-BE(len(x)) ++ x.as_bytes()
/// SubKey = HMAC-SHA256(key = root.as_bytes(), message = msg)
/// ```
///
/// 长度前缀 = Hard 载体：`(tenant="a", domain="bc")` ≠ `(tenant="ab", domain="c")`（防拼接歧义）。
pub(crate) fn derive_subkey(root: &BlindIndexKey, scope: &IndexScope<'_>) -> SubKey {
    let mut msg = Vec::new();
    let tenant = scope.tenant.to_string();
    encode_lp(&mut msg, CONTEXT);
    encode_lp(&mut msg, tenant.as_bytes());
    encode_lp(&mut msg, scope.domain.as_bytes());
    encode_lp(&mut msg, scope.field.as_bytes());
    encode_lp(&mut msg, scope.index_name.as_bytes());
    SubKey(hmac_sha256(root.as_bytes(), &msg))
}

// ── Transform ────────────────────────────────────────────────────────────────

/// 明文规范化变换（对标 CipherSweet `TransformationInterface[]`）。
///
/// 顺序语义：左→右依次 apply（`fold`），顺序是调用方契约。
/// 示例：
/// - email 等值：`[Transform::Lowercase]`
/// - 手机/卡号后四位：`[Transform::DigitsOnly, Transform::LastN(4)]`（同 CipherSweet `LastFourDigits`）
/// - 去空 + 大小写归一：`[Transform::Trim, Transform::Lowercase]`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transform {
    /// `str::to_lowercase()`——全 Unicode，locale-independent，确定性。
    Lowercase,
    /// 去除首尾空白（`str::trim()`）。
    Trim,
    /// 仅保留 ASCII 十进制数字（电话/卡号场景）。
    DigitsOnly,
    /// 保留末 N 个 **char**（UTF-8 安全；e.g. `LastN(4)` on "12345" → "2345"）。
    LastN(usize),
}

/// 对明文依次 apply 变换管道（infallible；空结果不在此层拒绝，由 `compute` fail-closed）。
pub(crate) fn apply_transforms(plaintext: &str, transforms: &[Transform]) -> String {
    transforms
        .iter()
        .fold(plaintext.to_owned(), |s, t| match t {
            Transform::Lowercase => s.to_lowercase(),
            Transform::Trim => s.trim().to_owned(),
            Transform::DigitsOnly => s.chars().filter(|c| c.is_ascii_digit()).collect(),
            Transform::LastN(n) => {
                // 按 char 计数（UTF-8 安全）；saturating_sub 处理 n≥len 和 n=0 边界。
                let chars: Vec<char> = s.chars().collect();
                let skip = chars.len().saturating_sub(*n);
                chars.into_iter().skip(skip).collect()
            }
        })
}

// ── FilterBits ────────────────────────────────────────────────────────────────

/// 盲索引截断位数（`1..=256`；默认 256 = 全 HMAC 输出，实践中无碰撞）。
///
/// 截断越少 ⇒ 更多 bit → 等值泄漏更精准、碰撞率更低；
/// 截断越多 ⇒ 更少 bit → Bloom-ish 隐私（碰撞候选须经 AEAD 解密后过滤，但泄漏更钝化）。
/// 权衡由字段所有者在 `x-protection.mode=blindIndex` 的 `reason` 中说明。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterBits(u16);

impl FilterBits {
    /// 默认截断位数（256 = CipherSweet 默认；保留完整 HMAC-SHA256 输出）。
    ///
    /// ⚠ 256 bit = 最大等值性暴露；低基数字段（如性别、国家码等有限枚举值）建议降低
    /// FilterBits 钝化等值性，以换取更强的集合归属隐私。参见 ADR-011 D4 §威胁矩阵。
    pub const DEFAULT: FilterBits = FilterBits(256);

    /// 构造并校验截断位数（`1..=256`；越界 → `FilterBitsOutOfRange`）。
    pub fn new(bits: u16) -> Result<Self, BlindIndexError> {
        if bits == 0 || bits > 256 {
            return Err(BlindIndexError::FilterBitsOutOfRange);
        }
        Ok(Self(bits))
    }

    /// 读出位数。
    pub fn get(self) -> u16 {
        self.0
    }
}

// ── BlindIndexValue ───────────────────────────────────────────────────────────

/// 截断 HMAC 盲索引值（等值-only；sealed 构造；无 Ord/PartialOrd/PartialEq/Eq）。
///
/// **INVARIANT: FIELDPROT-BLINDIDX-EQUALITYONLY-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }**（Hard，类型系统载体）——
/// `Ord`/`PartialOrd`/`PartialEq`/`Eq` **故意未 derive**，完全对标 `primitives::Mac`：
/// 等值比较唯一入口是常数时间 `ct_eq`，范围/前缀查询在类型层不可表达（无 `<`/`>` 运算符，
/// 无 `Eq` 实现 → 不能用作 `HashMap` key / `BTreeMap` key / `==` 比较）。
/// 消除 "不小心 == 比较导致时序泄漏" 和 "加了 range 查询但 HMAC 不保序" 两类错误。
///
/// Debug 渲染 `BlindIndexValue(<redacted>)`——索引值不进日志（防频率/字典分析）。
pub struct BlindIndexValue {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for BlindIndexValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 盲索引值脱敏，不泄截断 HMAC 字节（同 Mac/Digest 范式）。
        f.write_str("BlindIndexValue(<redacted>)")
    }
}

impl subtle::ConstantTimeEq for BlindIndexValue {
    /// 常数时间字节比较。
    ///
    /// **仅当两值字节长度相同（即来自同一 `FilterBits` 配置）时为常数时间**；
    /// 跨 `FilterBits` 比较无架构意义（索引维度不同），且 `subtle` 对不等长切片
    /// 会短路，造成长度泄漏。调用方须确保两端使用相同 `FilterBits`。
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // 开发态防护：不等长即为调用约定违反（程序员错误，非运行时错误）。
        debug_assert_eq!(
            self.bytes.len(),
            other.bytes.len(),
            "ct_eq called on BlindIndexValues with different lengths (different FilterBits?)"
        );
        // UFCS 明确路径，避免需要顶层 `use subtle::ConstantTimeEq`（[u8]: ConstantTimeEq）。
        subtle::ConstantTimeEq::ct_eq(self.bytes.as_slice(), other.bytes.as_slice())
    }
}

impl BlindIndexValue {
    /// 由字节构造索引值（`pub(crate)` funnel：只有 `compute`/`lookup_set` 可铸，外部不可伪造）。
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// 借出索引字节（canonical `BYTEA` 存储形态 / IN(...) 查询参数）。
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 小写 hex 字符串（文本列 / 查询参数编码；手写避免引入 `hex` 依赖）。
    ///
    /// 该值是完整 raw index 编码，禁止写入日志 / trace；诊断输出使用 [`Debug`] 或
    /// [`crate::safe`]，两者均固定脱敏。
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(self.bytes.len() * 2);
        for byte in &self.bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// 常数时间等值比较（`subtle::ConstantTimeEq`；唯一合法的 in-proc 等值检查路径）。
    ///
    /// 故意命名为 `ct_eq` 而非实现 `PartialEq`——强制调用方意识到这是常数时间操作，
    /// 不能用 `==`（INVARIANT: FIELDPROT-BLINDIDX-EQUALITYONLY-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
    ///
    /// **仅当两值来自相同 `FilterBits` 配置时调用**；跨 FilterBits 比较无意义且非常数时间。
    pub fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

// ── compute ───────────────────────────────────────────────────────────────────

/// HMAC-SHA256(subkey, transformed_plaintext) 截断到 `filter_bits`（CipherSweet BoringCrypto 截断）。
///
/// 截断算法（对标 `BoringCrypto.php`）：
/// - `nbytes = ceil(bits / 8)`；取 `tag[..nbytes]`。
/// - `bits % 8 ≠ 0`：末字节按高位保留，清除低 `8 - bits%8` bit。
/// - `bits % 8 == 0`：整字节，不掩码。
///
/// `transformed_plaintext` 为空 → `EmptyPlaintext`（fail-closed：不把所有空值索引到同一 bucket）。
pub(crate) fn compute(
    subkey: &SubKey,
    transformed_plaintext: &str,
    filter_bits: FilterBits,
) -> Result<BlindIndexValue, BlindIndexError> {
    if transformed_plaintext.is_empty() {
        return Err(BlindIndexError::EmptyPlaintext);
    }

    let tag = hmac_sha256(&subkey.0, transformed_plaintext.as_bytes());

    let bits = usize::from(filter_bits.get());
    let nbytes = bits.div_ceil(8);
    let mut result = tag[..nbytes].to_vec();

    if bits % 8 != 0 {
        // 保留末字节高位（CipherSweet bit order），清除低位。
        let mask = u8::MAX << (8 - (bits % 8));
        result[nbytes - 1] &= mask;
    }

    Ok(BlindIndexValue::new(result))
}

// ── index / lookup_set ────────────────────────────────────────────────────────

/// 写路径：用 current key 计算单个盲索引值（`derive_subkey` + `apply_transforms` + `compute` 一体）。
///
/// crate 内部实现；外部消费方只能通过 [`BlindIndex`] funnel 绑定同一组配置。
pub(crate) fn index(
    root: &BlindIndexKey,
    scope: &IndexScope<'_>,
    transforms: &[Transform],
    plaintext: &str,
    filter_bits: FilterBits,
) -> Result<BlindIndexValue, BlindIndexError> {
    let transformed = apply_transforms(plaintext, transforms);
    let subkey = derive_subkey(root, scope);
    compute(&subkey, &transformed, filter_bits)
}

/// 读路径（轮换窗口 OR-set）：current key 在前，previous keys 依次追加。
///
/// 调用方将返回的 `Vec<BlindIndexValue>` 绑入 `WHERE idx IN ($1, $2, …)` 查询。
/// `idx IN` 只筛出候选集；命中行须用可信 AAD 解密后，再按同一 transform 链比较明文，
/// 过滤 FilterBits 截断碰撞造成的误命中。
/// 无 dedup（`BlindIndexValue` 无 Eq；current == previous 的重复在 IN() 中无害）。
/// 对标 Rails `ActiveRecord::Encryption` 的 `previous: [...]` 轮换窗口语义。
///
/// crate 内部实现；外部消费方只能通过 [`BlindIndex`] funnel 绑定同一组配置。
pub(crate) fn lookup_set(
    current: &BlindIndexKey,
    previous: &[BlindIndexKey],
    scope: &IndexScope<'_>,
    transforms: &[Transform],
    plaintext: &str,
    filter_bits: FilterBits,
) -> Result<Vec<BlindIndexValue>, BlindIndexError> {
    let mut result = Vec::with_capacity(1 + previous.len());
    result.push(index(current, scope, transforms, plaintext, filter_bits)?);
    for prev_key in previous {
        result.push(index(prev_key, scope, transforms, plaintext, filter_bits)?);
    }
    Ok(result)
}

// ── BlindIndex cohesive funnel ────────────────────────────────────────────────

/// 内聚 funnel：把 scope / transforms / filter_bits 绑在一处，统一写路径与读路径 transform 链。
///
/// primary API：通过 `BlindIndex` 绑定配置，再调 `index`/`lookup_set` 方法。
pub struct BlindIndex<'a> {
    scope: IndexScope<'a>,
    transforms: &'a [Transform],
    filter_bits: FilterBits,
}

impl<'a> BlindIndex<'a> {
    /// 构造 funnel（绑定 scope + transforms + filter_bits）。
    pub fn new(
        scope: IndexScope<'a>,
        transforms: &'a [Transform],
        filter_bits: FilterBits,
    ) -> Self {
        Self {
            scope,
            transforms,
            filter_bits,
        }
    }

    /// 写路径（current key only）。
    pub fn index(
        &self,
        root: &BlindIndexKey,
        plaintext: &str,
    ) -> Result<BlindIndexValue, BlindIndexError> {
        index(
            root,
            &self.scope,
            self.transforms,
            plaintext,
            self.filter_bits,
        )
    }

    /// 读路径 OR-set（current 在前，previous 依次追加）。
    pub fn lookup_set(
        &self,
        current: &BlindIndexKey,
        previous: &[BlindIndexKey],
        plaintext: &str,
    ) -> Result<Vec<BlindIndexValue>, BlindIndexError> {
        lookup_set(
            current,
            previous,
            &self.scope,
            self.transforms,
            plaintext,
            self.filter_bits,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const TENANT_A: &str = "11111111-1111-4111-8111-111111111111";
    const TENANT_B: &str = "22222222-2222-4222-8222-222222222222";

    fn tenant(raw: &str) -> TenantId {
        match TenantId::parse(raw) {
            Ok(id) => id,
            Err(_) => unreachable!("test fixture tenant IDs are canonical UUIDs"),
        }
    }

    // ── 编译期证明 ──────────────────────────────────────────────────────────────

    #[allow(dead_code)]
    fn _assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn compile_proof_zeroize_on_drop() {
        // BlindIndexKey 和 SubKey 均实现 ZeroizeOnDrop（类型约束不满足 → 编译失败）。
        _assert_zeroize_on_drop::<BlindIndexKey>();
        _assert_zeroize_on_drop::<SubKey>();
    }

    // ── KAT: derive_subkey ─────────────────────────────────────────────────────

    /// `derive_subkey` 已知答案测试（anti-vacuity：证实现非空转，锁住 HMAC + 长度前缀编码）。
    ///
    /// 可重现命令（生成 msg.bin 后送 openssl）：
    /// ```text
    /// # msg = lp(CONTEXT)||lp(TENANT_A)||lp("d")||lp("f")||lp("n") (hex, 104 字节):
    /// # 00000000000000197273732e626c696e642d696e6465782e7375626b65792e7631
    /// # 000000000000002431313131313131312d313131312d343131312d383131312d313131313131313131313131
    /// # 00000000000000016400000000000000016600000000000000016e
    /// # key = 0x42 * 32 (hex: 4242...42)
    /// printf '\x00\x00\x00\x00\x00\x00\x00\x19rss.blind-index.subkey.v1\x00\x00\x00\x00\x00\x00\x00\x2411111111-1111-4111-8111-111111111111\x00\x00\x00\x00\x00\x00\x00\x01d\x00\x00\x00\x00\x00\x00\x00\x01f\x00\x00\x00\x00\x00\x00\x00\x01n' \
    ///   | openssl dgst -sha256 -mac HMAC -macopt hexkey:4242424242424242424242424242424242424242424242424242424242424242
    /// ```
    #[test]
    fn derive_subkey_known_answer() -> Result<(), BlindIndexError> {
        let root = BlindIndexKey::from_bytes(vec![0x42u8; 32])?;
        let scope = IndexScope::new(tenant(TENANT_A), "d", "f", "n")?;
        let subkey = derive_subkey(&root, &scope);
        let hex: String = subkey.0.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "d27631662f7ae1c8d236b44f5def9c99d9a33ec3be4cc08cf8e8b1196181fa82",
            "derive_subkey KAT mismatch (HMAC 引擎或长度前缀编码漂移)"
        );
        Ok(())
    }

    // ── KAT: compute ──────────────────────────────────────────────────────────

    /// `compute` 已知答案测试（FilterBits::DEFAULT = 256；直接构造 SubKey 控制 HMAC key）。
    ///
    /// 可重现命令（subkey = 0xAB * 32，plaintext = "hello"）：
    /// ```text
    /// printf 'hello' | openssl dgst -sha256 -mac HMAC \
    ///   -macopt hexkey:abababababababababababababababababababababababababababababababababab
    /// ```
    #[test]
    fn compute_known_answer() -> Result<(), BlindIndexError> {
        let subkey = SubKey([0xABu8; 32]);
        let value = compute(&subkey, "hello", FilterBits::DEFAULT)?;
        assert_eq!(
            value.to_hex(),
            "ec64f44ab22c4027951ec308296e7083fa7686e49bf274c509478ef90b09fc09",
            "compute KAT mismatch (HMAC 引擎或截断逻辑漂移)"
        );
        Ok(())
    }

    // ── 截断正确性 ────────────────────────────────────────────────────────────

    /// 验证各 FilterBits 的字节长度、字节对齐、末字节掩码（从 full-256 程序化推导）。
    ///
    /// subkey=[0xAB;32], plaintext="hello" → full tag: ec64f44ab22c4027951ec308296e7083fa7686e49bf274c509478ef90b09fc09
    /// - byte[0]  = 0xEC = 1110_1100
    /// - byte[31] = 0x09 = 0000_1001
    ///
    /// 掩码验证：
    /// - bits=7  → mask=0xFE → 0xEC & 0xFE = 0xEC（保留高 7 位，证掩码有效）
    /// - bits=249 → mask=0x80 → 0x09 & 0x80 = 0x00 ≠ 0x09（与 bits=256 不同，证末字节掩码有效）
    #[rstest]
    #[case(1, 1, "80")] // 0xEC & 0x80 = 0x80（仅保留最高位）
    #[case(7, 1, "ec")] // 0xEC & 0xFE = 0xEC（保留高 7 位；证掩码生效）
    #[case(8, 1, "ec")] // 整字节，无掩码
    #[case(12, 2, "ec60")] // 0x64 & 0xF0 = 0x60
    #[case(16, 2, "ec64")] // 整字节，无掩码
    #[case(64, 8, "ec64f44ab22c4027")]
    #[case(
        249,
        32,
        "ec64f44ab22c4027951ec308296e7083fa7686e49bf274c509478ef90b09fc00"
    )] // bits%8=1, mask=0x80; 0x09→0x00 ≠ bits=256 的 0x09（证末字节掩码生效）
    #[case(
        256,
        32,
        "ec64f44ab22c4027951ec308296e7083fa7686e49bf274c509478ef90b09fc09"
    )]
    fn truncation_correctness(
        #[case] bits: u16,
        #[case] expected_len: usize,
        #[case] expected_hex: &str,
    ) -> Result<(), BlindIndexError> {
        let subkey = SubKey([0xABu8; 32]);
        let fb = FilterBits::new(bits)?;
        let value = compute(&subkey, "hello", fb)?;
        assert_eq!(value.as_bytes().len(), expected_len, "bits={bits} 长度错误");
        assert_eq!(value.to_hex(), expected_hex, "bits={bits} hex 错误");
        Ok(())
    }

    // ── 确定性 ────────────────────────────────────────────────────────────────

    #[test]
    fn determinism_same_input_same_output() -> Result<(), BlindIndexError> {
        let root = BlindIndexKey::from_bytes(vec![0x42u8; 32])?;
        let scope = IndexScope::new(tenant(TENANT_A), "users", "email", "email_eq")?;
        let a = index(
            &root,
            &scope,
            &[Transform::Lowercase],
            "Alice@Example.com",
            FilterBits::DEFAULT,
        )?;
        let b = index(
            &root,
            &scope,
            &[Transform::Lowercase],
            "Alice@Example.com",
            FilterBits::DEFAULT,
        )?;
        assert!(a.ct_eq(&b), "同输入须产相同索引值");
        Ok(())
    }

    // ── scope 隔离 + 长度前缀 anti-ambiguity ────────────────────────────────

    #[rstest]
    #[case(
        IndexScope::new(tenant(TENANT_B), "users", "email", "eq"),
        "tenant 不同 → 不同 subkey"
    )]
    #[case(
        IndexScope::new(tenant(TENANT_A), "OTHER", "email", "eq"),
        "domain 不同 → 不同 subkey"
    )]
    #[case(
        IndexScope::new(tenant(TENANT_A), "users", "OTHER", "eq"),
        "field 不同 → 不同 subkey"
    )]
    #[case(
        IndexScope::new(tenant(TENANT_A), "users", "email", "OTHER"),
        "index_name 不同 → 不同 subkey"
    )]
    fn scope_isolation_different_dimension_yields_different_value(
        #[case] scope2: Result<IndexScope<'_>, BlindIndexError>,
        #[case] msg: &str,
    ) -> Result<(), BlindIndexError> {
        let scope2 = scope2?;
        let root = BlindIndexKey::from_bytes(vec![0x42u8; 32])?;
        let scope1 = IndexScope::new(tenant(TENANT_A), "users", "email", "eq")?;
        let v1 = index(&root, &scope1, &[], "hello", FilterBits::DEFAULT)?;
        let v2 = index(&root, &scope2, &[], "hello", FilterBits::DEFAULT)?;
        assert!(!v1.ct_eq(&v2), "{msg}");
        Ok(())
    }

    /// 长度前缀 anti-ambiguity：`(domain="a", field="bc")` 和 `(domain="ab", field="c")` 产不同 subkey。
    /// 证明无 lp 的简单拼接会歧义，而有 lp 不会。
    #[test]
    fn anti_ambiguity_length_prefix_prevents_scope_collision() -> Result<(), BlindIndexError> {
        let root = BlindIndexKey::from_bytes(vec![0x42u8; 32])?;
        let scope_a_bc = IndexScope::new(tenant(TENANT_A), "a", "bc", "n")?;
        let scope_ab_c = IndexScope::new(tenant(TENANT_A), "ab", "c", "n")?;
        let v1 = index(&root, &scope_a_bc, &[], "hello", FilterBits::DEFAULT)?;
        let v2 = index(&root, &scope_ab_c, &[], "hello", FilterBits::DEFAULT)?;
        assert!(
            !v1.ct_eq(&v2),
            "长度前缀必须防止 (domain=a,field=bc) == (domain=ab,field=c) 的 scope 碰撞"
        );
        Ok(())
    }

    // ── Transform 变换表 ──────────────────────────────────────────────────────

    #[rstest]
    #[case(&[Transform::Lowercase], "Hello World", "hello world")]
    #[case(&[Transform::Trim], "  hello  ", "hello")]
    #[case(&[Transform::DigitsOnly], "abc123def456", "123456")]
    #[case(&[Transform::DigitsOnly], "no-digits", "")]
    #[case(&[Transform::LastN(4)], "12345", "2345")]
    #[case(&[Transform::LastN(10)], "abc", "abc")] // n > len → 全保留
    #[case(&[Transform::LastN(0)], "abc", "")] // n=0 → 空串
    #[case(&[Transform::Trim, Transform::Lowercase], "  HELLO  ", "hello")]
    #[case(&[Transform::DigitsOnly, Transform::LastN(4)], "phone: +8613812345678", "5678")]
    fn transform_table(
        #[case] transforms: &[Transform],
        #[case] input: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(apply_transforms(input, transforms), expected);
    }

    /// `LastN` 对多字节 UTF-8 字符正确按 char 计数（不按字节）。
    #[test]
    fn last_n_utf8_char_boundary() {
        // "中文AB" = 4 chars；LastN(3) 应得 "文AB"（非截字节）。
        let result = apply_transforms("中文AB", &[Transform::LastN(3)]);
        assert_eq!(result, "文AB");
        // "日本語テスト" = 6 chars；LastN(2) → "スト"
        let result2 = apply_transforms("日本語テスト", &[Transform::LastN(2)]);
        assert_eq!(result2, "スト");
    }

    /// 幂等性：normalize 型变换连续两次结果不变。
    #[test]
    fn transform_idempotence_normalizing_transforms() {
        for t in &[Transform::Lowercase, Transform::Trim, Transform::DigitsOnly] {
            let input = "  Hello World 123  ";
            let once = apply_transforms(input, std::slice::from_ref(t));
            let twice = apply_transforms(&once, std::slice::from_ref(t));
            assert_eq!(once, twice, "Transform::{t:?} 应幂等");
        }
    }

    // ── OR-set lookup_set ─────────────────────────────────────────────────────

    #[test]
    fn lookup_set_length_and_order() -> Result<(), BlindIndexError> {
        let current = BlindIndexKey::from_bytes(vec![0x01u8; 32])?;
        let prev1 = BlindIndexKey::from_bytes(vec![0x02u8; 32])?;
        let prev2 = BlindIndexKey::from_bytes(vec![0x03u8; 32])?;
        let scope = IndexScope::new(tenant(TENANT_A), "d", "f", "n")?;

        let set = lookup_set(
            &current,
            &[prev1, prev2],
            &scope,
            &[],
            "hello",
            FilterBits::DEFAULT,
        )?;
        assert_eq!(set.len(), 3, "current + 2 previous = 3");

        // element[0] == index(current)
        let v_current = index(&current, &scope, &[], "hello", FilterBits::DEFAULT)?;
        assert!(set[0].ct_eq(&v_current), "element[0] 须等于 index(current)");

        // element[1] == index(prev1)；BlindIndexKey 无 Clone，重建同字节 key 验证（注释说明原因）。
        let prev1_ref = BlindIndexKey::from_bytes(vec![0x02u8; 32])?;
        let v_prev1 = index(&prev1_ref, &scope, &[], "hello", FilterBits::DEFAULT)?;
        assert!(set[1].ct_eq(&v_prev1), "element[1] 须等于 index(prev1)");

        // element[2] == index(prev2)
        let prev2_ref = BlindIndexKey::from_bytes(vec![0x03u8; 32])?;
        let v_prev2 = index(&prev2_ref, &scope, &[], "hello", FilterBits::DEFAULT)?;
        assert!(set[2].ct_eq(&v_prev2), "element[2] 须等于 index(prev2)");

        Ok(())
    }

    #[test]
    fn lookup_set_empty_previous_yields_single_element() -> Result<(), BlindIndexError> {
        let current = BlindIndexKey::from_bytes(vec![0xAAu8; 32])?;
        let scope = IndexScope::new(tenant(TENANT_A), "d", "f", "n")?;
        let set = lookup_set(&current, &[], &scope, &[], "hello", FilterBits::DEFAULT)?;
        assert_eq!(set.len(), 1);
        Ok(())
    }

    // ── 常数时间等值比较 ──────────────────────────────────────────────────────

    #[test]
    fn ct_eq_same_value_returns_true() -> Result<(), BlindIndexError> {
        let subkey = SubKey([0x11u8; 32]);
        let a = compute(&subkey, "value", FilterBits::DEFAULT)?;
        let b = compute(&subkey, "value", FilterBits::DEFAULT)?;
        assert!(a.ct_eq(&b), "同输入 ct_eq 须为 true");
        Ok(())
    }

    #[test]
    fn ct_eq_flipped_bit_returns_false() {
        // 白盒：直接构造 BlindIndexValue，翻转一 bit，验证 ct_eq = false。
        let original = BlindIndexValue::new(vec![0xEC, 0x64, 0x00]);
        let mut tampered_bytes = original.as_bytes().to_vec();
        tampered_bytes[0] ^= 0x01;
        let tampered = BlindIndexValue::new(tampered_bytes);
        assert!(!original.ct_eq(&tampered), "翻转 1 bit 后 ct_eq 须为 false");
    }

    // ── 错误路径 ──────────────────────────────────────────────────────────────

    #[test]
    fn key_too_short_below_32_bytes() {
        let result = BlindIndexKey::from_bytes(vec![0u8; 31]);
        assert!(matches!(result, Err(BlindIndexError::KeyTooShort)));
    }

    #[test]
    fn key_exact_32_bytes_succeeds() {
        let result = BlindIndexKey::from_bytes(vec![0u8; 32]);
        assert!(result.is_ok());
    }

    #[rstest]
    #[case(0)]
    #[case(257)]
    fn filter_bits_out_of_range(#[case] bits: u16) {
        let result = FilterBits::new(bits);
        assert!(matches!(result, Err(BlindIndexError::FilterBitsOutOfRange)));
    }

    #[rstest]
    #[case(1)]
    #[case(128)]
    #[case(256)]
    fn filter_bits_valid_range(#[case] bits: u16) -> Result<(), BlindIndexError> {
        FilterBits::new(bits)?;
        Ok(())
    }

    #[test]
    fn empty_plaintext_after_transforms_yields_empty_plaintext_error() -> Result<(), BlindIndexError>
    {
        let subkey = SubKey([0x11u8; 32]);
        let result = compute(&subkey, "", FilterBits::DEFAULT);
        assert!(matches!(result, Err(BlindIndexError::EmptyPlaintext)));
        Ok(())
    }

    #[test]
    fn digits_only_on_alpha_yields_empty_plaintext_via_index() -> Result<(), BlindIndexError> {
        let root = BlindIndexKey::from_bytes(vec![0x42u8; 32])?;
        let scope = IndexScope::new(tenant(TENANT_A), "d", "f", "n")?;
        // "abc" → DigitsOnly → "" → EmptyPlaintext
        let result = index(
            &root,
            &scope,
            &[Transform::DigitsOnly],
            "abc",
            FilterBits::DEFAULT,
        );
        assert!(matches!(result, Err(BlindIndexError::EmptyPlaintext)));
        Ok(())
    }

    #[test]
    fn lookup_set_propagates_empty_plaintext() -> Result<(), BlindIndexError> {
        let current = BlindIndexKey::from_bytes(vec![0x42u8; 32])?;
        let scope = IndexScope::new(tenant(TENANT_A), "d", "f", "n")?;
        let result = lookup_set(
            &current,
            &[],
            &scope,
            &[Transform::DigitsOnly],
            "abc",
            FilterBits::DEFAULT,
        );
        assert!(matches!(result, Err(BlindIndexError::EmptyPlaintext)));
        Ok(())
    }

    /// `IndexScope::new` 任一非 tenant 字段为空串 → `EmptyScope`（零信任 fail-fast）。
    #[rstest]
    #[case("", "email", "eq", "empty domain")]
    #[case("users", "", "eq", "empty field")]
    #[case("users", "email", "", "empty index_name")]
    fn scope_empty_field_yields_empty_scope_error(
        #[case] domain: &str,
        #[case] field: &str,
        #[case] index_name: &str,
        #[case] msg: &str,
    ) {
        let result = IndexScope::new(tenant(TENANT_A), domain, field, index_name);
        assert!(
            matches!(result, Err(BlindIndexError::EmptyScope)),
            "{msg}: expected EmptyScope"
        );
    }

    // ── Debug 脱敏 anti-vacuity ───────────────────────────────────────────────

    #[test]
    fn blind_index_key_debug_redacts_and_is_nontrivial() -> Result<(), BlindIndexError> {
        // anti-vacuity：证 raw Vec<u8> Debug 包含字节值（"66" for 0x42），
        // 因此 BlindIndexKey Debug 中没有 "66" 是有意义的断言。
        assert!(format!("{:?}", vec![0x42u8]).contains("66"));

        let key = BlindIndexKey::from_bytes(vec![0x42u8; 32])?;
        let dbg = format!("{key:?}");
        assert_eq!(dbg, "BlindIndexKey(<redacted>)");
        assert!(!dbg.contains("66"), "Debug 不得泄漏 key 字节");
        Ok(())
    }

    #[test]
    fn subkey_debug_redacts() -> Result<(), BlindIndexError> {
        let root = BlindIndexKey::from_bytes(vec![0x42u8; 32])?;
        let scope = IndexScope::new(tenant(TENANT_A), "d", "f", "n")?;
        let subkey = derive_subkey(&root, &scope);
        let dbg = format!("{subkey:?}");
        assert_eq!(dbg, "SubKey(<redacted>)");
        Ok(())
    }

    #[test]
    fn blind_index_value_debug_redacts() -> Result<(), BlindIndexError> {
        let subkey = SubKey([0xABu8; 32]);
        let value = compute(&subkey, "hello", FilterBits::DEFAULT)?;
        let dbg = format!("{value:?}");
        assert_eq!(dbg, "BlindIndexValue(<redacted>)");
        // anti-vacuity：to_hex 有内容（不是空串）
        assert!(!value.to_hex().is_empty(), "to_hex 不应为空");
        assert!(
            !dbg.contains(&value.to_hex()[..4]),
            "Debug 不得泄漏 index 字节"
        );
        Ok(())
    }

    // ── BlindIndex funnel ─────────────────────────────────────────────────────

    #[test]
    fn blind_index_funnel_index_matches_free_fn() -> Result<(), BlindIndexError> {
        let root = BlindIndexKey::from_bytes(vec![0x42u8; 32])?;
        let scope = IndexScope::new(tenant(TENANT_A), "users", "email", "email_eq")?;
        let transforms = [Transform::Trim, Transform::Lowercase];
        let fb = FilterBits::DEFAULT;

        let bi = BlindIndex::new(scope.clone(), &transforms, fb);
        let via_funnel = bi.index(&root, "  Alice@Example.com  ")?;
        let via_free = index(&root, &scope, &transforms, "  Alice@Example.com  ", fb)?;

        assert!(
            via_funnel.ct_eq(&via_free),
            "funnel index 须等于 free fn index"
        );
        Ok(())
    }

    #[test]
    fn blind_index_funnel_lookup_set_matches_free_fn() -> Result<(), BlindIndexError> {
        let current = BlindIndexKey::from_bytes(vec![0x01u8; 32])?;
        let prev = BlindIndexKey::from_bytes(vec![0x02u8; 32])?;
        let scope = IndexScope::new(tenant(TENANT_A), "d", "f", "n")?;
        let fb = FilterBits::DEFAULT;

        let bi = BlindIndex::new(scope.clone(), &[], fb);
        let via_funnel = bi.lookup_set(&current, &[prev], "hello")?;
        let prev2 = BlindIndexKey::from_bytes(vec![0x02u8; 32])?;
        let via_free = lookup_set(&current, &[prev2], &scope, &[], "hello", fb)?;

        assert_eq!(via_funnel.len(), via_free.len());
        for (a, b) in via_funnel.iter().zip(via_free.iter()) {
            assert!(a.ct_eq(b), "funnel lookup_set 元素须与 free fn 一致");
        }
        Ok(())
    }
}
