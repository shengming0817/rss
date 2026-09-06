//! Field protection AAD derived only from trusted request or maintenance coordinates.
use rss_request_context::TenantId;
const AAD_DOMAIN_LABEL: &[u8] = b"rss-field-protection-aad-v2";
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AadError {
    #[error("protection aad dimension is empty")]
    EmptyDimension,
    #[error("protection aad version is invalid")]
    InvalidVersion,
}
/// Stored coordinates are identifiers, never decryption authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionAad {
    tenant: TenantId,
    config_key: Box<str>,
    field: Box<str>,
    schema_version: u32,
}
impl ProtectionAad {
    pub fn new(
        tenant: TenantId,
        config_key: &str,
        field: &str,
        schema_version: u32,
    ) -> Result<Self, AadError> {
        if config_key.is_empty() || field.is_empty() {
            return Err(AadError::EmptyDimension);
        }
        if schema_version == 0 {
            return Err(AadError::InvalidVersion);
        }
        Ok(Self {
            tenant,
            config_key: config_key.into(),
            field: field.into(),
            schema_version,
        })
    }
    fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = AAD_DOMAIN_LABEL.to_vec();
        let tenant = self.tenant.to_string();
        for dimension in [
            tenant.as_bytes(),
            self.config_key.as_bytes(),
            self.field.as_bytes(),
            &self.schema_version.to_be_bytes(),
        ] {
            out.extend_from_slice(&(dimension.len() as u32).to_be_bytes());
            out.extend_from_slice(dimension);
        }
        out
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionContext {
    aad: ProtectionAad,
}
impl ProtectionContext {
    /// 受信源 ①：已鉴权请求上下文（tenant 由调用方从可信认证边界提取后传入——`rss-data-protection` 是 L0，
    /// 不可见业务 principal）。
    pub fn authenticated_request(
        tenant: TenantId,
        config_key: &str,
        field: &str,
        schema_version: u32,
    ) -> Result<Self, AadError> {
        Ok(Self {
            aad: ProtectionAad::new(tenant, config_key, field, schema_version)?,
        })
    }

    /// 受信源 ②：经授权的维护/迁移上下文（backfill/rewrap/key rotation 离线路径，按已知记录坐标重派生）。
    ///
    /// 与 [`Self::authenticated_request`] 给定**相同坐标**时产出**完全相同**的 [`DerivedAad`]——受信源类别
    /// 不编入 canonical bytes，故 #1467 离线 rewrap/backfill 能解开线上由请求路径加密的密文（source 区分仅是
    /// 调用意图的显式自文档，不改密文绑定）。
    pub fn authorized_maintenance(
        tenant: TenantId,
        config_key: &str,
        field: &str,
        schema_version: u32,
    ) -> Result<Self, AadError> {
        Ok(Self {
            aad: ProtectionAad::new(tenant, config_key, field, schema_version)?,
        })
    }

    /// 从受信坐标**派生** [`DerivedAad`]——这是 [`DerivedAad`] 的**唯一**产出口。
    pub fn derive(&self) -> DerivedAad {
        DerivedAad {
            canonical: self.aad.to_canonical_bytes(),
            aad: self.aad.clone(),
        }
    }
}

/// 受信派生的 AAD「凭证」（`FIELDPROT-AAD-DERIVE-FROM-CTX-01`，Hard）。
///
/// 私有字段 + **无 `from_bytes`/`from_stored_bytes`**：crate 外只能经 [`ProtectionContext::derive`] 取得，
/// 无法用 DB stored bytes 裸拼。[`crate::Aead::seal`]/[`crate::Aead::open`] 只接受 `&DerivedAad`，故
/// `open(&env, env.aad())`（回灌 envelope 存储的 [`ProtectionAad`]）**类型不匹配、编译失败** → 杜绝跨租重放。
#[derive(Clone)]
pub struct DerivedAad {
    canonical: Vec<u8>,
    aad: ProtectionAad,
}

impl DerivedAad {
    /// 规范 AAD 字节——供 [`crate::Aead`] 实现方（#1466 adapter）喂给底层 AEAD 原语。可读不可造。
    pub fn as_canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// 对应坐标（供实现方写入 envelope 的标识/审计 AAD）。
    pub fn coordinates(&self) -> &ProtectionAad {
        &self.aad
    }
}

// AAD 非机密，但 Debug 不打印裸 canonical 字节噪声；委托非机密坐标。
impl std::fmt::Debug for DerivedAad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedAad")
            .field("coordinates", &self.aad)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{AAD_DOMAIN_LABEL, AadError, DerivedAad, ProtectionAad, ProtectionContext};
    use rss_request_context::TenantId;
    use rstest::rstest;

    const TENANT_A: &str = "11111111-2222-4333-8444-555555555555";
    const TENANT_B: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    #[allow(clippy::expect_used)]
    fn tenant(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant")
    }

    // 测试 helper：构造/派生失败即测试设置错误，应 panic 暴露——expect 收敛在 helper（item-level carve-out，
    // 对齐 cookie/password 测试范式）。
    #[allow(clippy::expect_used)]
    fn aad(tenant: &str, key: &str, field: &str, ver: u32) -> ProtectionAad {
        ProtectionAad::new(self::tenant(tenant), key, field, ver).expect("valid aad")
    }

    #[allow(clippy::expect_used)]
    fn der(tenant: &str, key: &str, field: &str, ver: u32) -> DerivedAad {
        ProtectionContext::authenticated_request(self::tenant(tenant), key, field, ver)
            .expect("ctx")
            .derive()
    }

    #[allow(clippy::expect_used)]
    fn der_maint(tenant: &str, key: &str, field: &str, ver: u32) -> DerivedAad {
        ProtectionContext::authorized_maintenance(self::tenant(tenant), key, field, ver)
            .expect("ctx")
            .derive()
    }

    #[test]
    fn new_accepts_nonempty_coordinates() {
        let a = aad(TENANT_A, "db.dsn", "password", 3);
        assert!(matches!(
            a,
            ProtectionAad {
                tenant: actual_tenant,
                ref config_key,
                ref field,
                schema_version: 3,
            } if actual_tenant == tenant(TENANT_A)
                && config_key.as_ref() == "db.dsn"
                && field.as_ref() == "password"
        ));
    }

    #[rstest]
    #[case("", "f")]
    #[case("k", "")]
    fn new_rejects_empty_dimension(#[case] key: &str, #[case] field: &str) {
        let result = ProtectionAad::new(tenant(TENANT_A), key, field, 1);
        assert!(
            matches!(result, Err(AadError::EmptyDimension)),
            "empty dimension must fail-closed"
        );
    }

    #[test]
    fn new_rejects_zero_schema_version() {
        let result = ProtectionAad::new(tenant(TENANT_A), "k", "f", 0);
        assert!(matches!(result, Err(AadError::InvalidVersion)));
    }

    #[test]
    fn authenticated_request_rejects_zero_schema_version() {
        let result = ProtectionContext::authenticated_request(tenant(TENANT_A), "k", "f", 0);
        assert!(matches!(result, Err(AadError::InvalidVersion)));
    }

    #[test]
    fn authorized_maintenance_rejects_zero_schema_version() {
        let result = ProtectionContext::authorized_maintenance(tenant(TENANT_A), "k", "f", 0);
        assert!(matches!(result, Err(AadError::InvalidVersion)));
    }

    #[test]
    fn canonical_is_deterministic_for_same_coordinates() {
        let a = der(TENANT_A, "k", "f", 1);
        let b = der(TENANT_A, "k", "f", 1);
        assert_eq!(a.as_canonical_bytes(), b.as_canonical_bytes());
    }

    #[test]
    fn canonical_carries_domain_label() {
        let d = der(TENANT_A, "k", "f", 1);
        assert!(
            d.as_canonical_bytes().starts_with(AAD_DOMAIN_LABEL),
            "canonical AAD must be domain-separated"
        );
    }

    #[rstest]
    // 改任一维度都必须改变 canonical 字节（绑定到每一维）：tenant / config-key / field / schema-version。
    #[case((TENANT_A, "k", "f", 1), (TENANT_B, "k", "f", 1))]
    #[case((TENANT_A, "k", "f", 1), (TENANT_A, "X", "f", 1))]
    #[case((TENANT_A, "k", "f", 1), (TENANT_A, "k", "X", 1))]
    #[case((TENANT_A, "k", "f", 1), (TENANT_A, "k", "f", 2))]
    fn canonical_changes_when_any_dimension_changes(
        #[case] lhs: (&str, &str, &str, u32),
        #[case] rhs: (&str, &str, &str, u32),
    ) {
        let l = der(lhs.0, lhs.1, lhs.2, lhs.3);
        let r = der(rhs.0, rhs.1, rhs.2, rhs.3);
        assert_ne!(l.as_canonical_bytes(), r.as_canonical_bytes());
    }

    #[test]
    fn canonical_is_injective_against_boundary_shift() {
        // length-prefix 单射性：("ab","c",..) 与 ("a","bc",..) 若无长度前缀会拼接歧义同字节。
        let lhs = der(TENANT_A, "ab", "c", 1);
        let rhs = der(TENANT_A, "a", "bc", 1);
        assert_ne!(
            lhs.as_canonical_bytes(),
            rhs.as_canonical_bytes(),
            "length-prefix must prevent concatenation collision"
        );
    }

    #[test]
    fn two_trusted_sources_with_equal_coordinates_derive_equal_aad() {
        // 受信源类别（请求 vs 维护）不进 AAD——同坐标必产同密文绑定（否则 backfill 解不开线上密文）。
        let req = der(TENANT_A, "k", "f", 7);
        let maint = der_maint(TENANT_A, "k", "f", 7);
        assert_eq!(req.as_canonical_bytes(), maint.as_canonical_bytes());
    }

    #[test]
    fn derived_coordinates_round_trip() {
        let d = der_maint(TENANT_A, "svc.key", "token", 4);
        let c = d.coordinates();
        assert!(matches!(
            c,
            ProtectionAad {
                tenant: actual_tenant,
                config_key,
                field,
                schema_version: 4,
            } if *actual_tenant == tenant(TENANT_A)
                && config_key.as_ref() == "svc.key"
                && field.as_ref() == "token"
        ));
    }

    #[test]
    fn derived_aad_debug_shows_coordinates_not_raw_bytes() {
        let d = der(TENANT_A, "k", "f", 1);
        let dbg = format!("{d:?}");
        assert!(
            dbg.contains("coordinates"),
            "debug surfaces coordinates field"
        );
        assert!(
            dbg.contains(TENANT_A),
            "non-secret tenant value visible (not just the field name): {dbg}"
        );
    }
}
