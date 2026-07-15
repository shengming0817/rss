// rss_diport_dto_debug_redacted UI fixture（LOCAL_CRATE == "diport"，红例 + 绿子例）。
// golden 见 diport.stderr：裸字节缓冲字段触发；绿子例不触发。
// 须用 #![allow(unknown_lints)]：普通 `cargo build` 本 example 时不认 rss_diport_dto_debug_redacted
// （仅 dylint driver 认），抑制 G4 逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
#![allow(dead_code, unused, unknown_lints)]

// R1（红例，Vec<u8>）：diport DTO struct 持裸 Vec<u8> 字段 → 触发。
struct A {
    f: Vec<u8>,
}

// R2（红例，[u8; N]）：固定大小字节数组 → 触发。
struct B {
    f: [u8; 32],
}

// R3（红例，Box<[u8]>）：装箱字节切片 → 触发。
struct C {
    f: Box<[u8]>,
}

// R4（红例，Option<Vec<u8>>）：Option 包一层字节缓冲 → 触发。
struct D {
    f: Option<Vec<u8>>,
}

// R5（红例，嵌套 mod 绕过闭合，#1155 review F1）：`mod outer::redacted_bytes::RedactedBytes` 前缀含中间
// module（`...::outer`）→ 非 canonical（is_canonical_redacted_bytes 前缀须无 `::`）→ 不豁免、内层裸字节触发。
// 锁住「只有 crate 根下 redacted_bytes::RedactedBytes 才豁免」，防嵌套同名假类型绕过。
mod outer {
    pub mod redacted_bytes {
        pub struct RedactedBytes {
            pub f: Vec<u8>,
        }
    }
}

// G1（结构性豁免 anti-vacuity）：canonical `redacted_bytes::RedactedBytes` 持裸 Vec<u8> → 不触发。
// 证明脱敏 newtype 自身（受控持有点）经 DefId 路径豁免，无需 #[allow]。
// （路径 `::redacted_bytes::RedactedBytes` 与 canonical `crates/diport/src/redacted_bytes.rs` 对应。）
mod redacted_bytes {
    pub struct RedactedBytes(pub Vec<u8>);
}

// G2（specificity anti-vacuity）：字段类型 String → 不触发（非字节缓冲）。
// 证明 lint 非「任意字段」，而是特定字节形状。
struct E {
    f: String,
}

// G3（specificity anti-vacuity）：字段类型 Vec<u32> → 不触发（非 u8 元素）。
// 证明 lint 非「任意 Vec 字段」，而是特定 Vec<u8> 形状。
struct F {
    f: Vec<u32>,
}

// G4（lint property：逃生门）：item-level #[allow] 抑制 → 不触发。证明 lint 经 field.hir_id 报、尊重 #[allow]。
// 注：生产代码**不**用 #[allow]（dylint 未加载时触发 unknown_lints）；公开 / secure-governed 字节走下方
// `is_structural_carve_out` 名单（G5/G6），本例仅锁 lint 的 #[allow] 尊重属性、属 test-only。
#[allow(rss_diport_dto_debug_redacted)] // reason: UI fixture 验证逃生门属性
struct G {
    f: Vec<u8>,
}

// G5-G7：只有三个 canonical DefId path 获得结构性 carve-out。
mod revocation_store {
    pub struct CertSerial(pub Vec<u8>);
}
mod secret_resolver {
    pub struct SecretMaterial(pub Vec<u8>);
}
mod dlx_lifecycle {
    pub struct ArchiveChecksum(pub [u8; 32]);
}

// R6-R8（同名伪造红例）：兄弟模块中的相同短名不能继承 canonical carve-out。
mod sibling {
    pub struct CertSerial(pub Vec<u8>);
    pub struct SecretMaterial(pub Vec<u8>);
    pub struct ArchiveChecksum(pub [u8; 32]);
}

fn main() {}
