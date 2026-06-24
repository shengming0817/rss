// rss_diport_error_debug_redacted UI fixture（LOCAL_CRATE == "diport"，红例 + 绿子例）。
// golden 见 diport.stderr：struct 持裸 Box<dyn Error> 字段触发；绿子例不触发。
// 须用 #![allow(unknown_lints)]：普通 `cargo build` 本 example 时不认 rss_diport_error_debug_redacted
// （仅 dylint driver 认），抑制 G3 逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
#![allow(dead_code, unused, unknown_lints)]

// R（红例，触发）：diport error struct 持裸 `Box<dyn Error + Send + Sync + 'static>` 字段。
struct SignerError {
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

// R2（type-alias 绕过 anti-vacuity，#1144 review F2）：字段类型是 `Box<dyn Error>` 的 **type alias** →
// Ty 层展开后命中。旧 HIR 语法匹配会漏（最后路径段名是 alias 名 `BoxedDynError` 而非 `Box`）。
type BoxedDynError = Box<dyn std::error::Error + Send + Sync + 'static>;
struct AliasBoxedError {
    source: BoxedDynError,
}

// R3（dyn-alias 绕过 anti-vacuity，#1144 review F2）：`dyn Error` 经 type alias、再 `Box<Alias>` →
// Ty 层展开后命中。旧 HIR 语法匹配会漏（`Box` 的泛型实参是 alias 路径 `DynStdError` 而非 `TraitObject`）。
type DynStdError = dyn std::error::Error + Send + Sync + 'static;
struct DynAliasBoxedError {
    source: Box<DynStdError>,
}

// G1（specificity anti-vacuity）：Box<ConcreteType>（非 trait-object）→ 不触发。
// 证明 lint 非「任意 Box 字段」，而是特定 Box<dyn Error> trait-object 形状。
#[derive(Debug)]
struct MyConcreteError(String);
impl std::fmt::Display for MyConcreteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for MyConcreteError {}

struct WithConcreteBox {
    source: Box<MyConcreteError>, // Box<具体类型>，非 dyn Error → 不触发
}

// G2（specificity anti-vacuity）：普通非 Box 字段 → 不触发。
struct WithString {
    msg: String,
    code: u64,
}

// G3（逃生门）：item-level #[allow] 抑制——struct 持裸 Box<dyn Error> 但有 allow attr，不触发。
#[allow(rss_diport_error_debug_redacted)] // reason: UI fixture 验证逃生门
struct AllowedRawBox {
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

// G4（结构性豁免 anti-vacuity）：名为 `RedactedSource` 的 struct 持裸 Box<dyn Error> → 不触发。
// 证明脱敏 newtype 自身（受控持有点）经 enclosing-struct 名豁免，无需 #[allow]。
struct RedactedSource(Box<dyn std::error::Error + Send + Sync + 'static>);

fn main() {}
