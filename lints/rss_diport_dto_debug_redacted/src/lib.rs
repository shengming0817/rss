#![feature(rustc_private)]
//! `rss_diport_dto_debug_redacted` — RSS 治理 dylint lint：`diport` crate 内 struct 字段禁持裸
//! 字节缓冲（`Vec<u8>` / `[u8; N]` / `Box<[u8]>` 或 `Option` 包一层）；动态 payload 改用
//! `RedactedBytes`，固定宽度结构字节改用 crate-internal `RedactedFixedBytes<N>`。
//!
//! INVARIANT: DIPORT-DTO-RAWBYTES-BAN-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! 上下游强度（ai-robust.md §审查要求「Funnel 类约束分别说明上游 / 下游」）：
//! - 上游（Hard，`diport` 内）：`RedactedBytes` / `RedactedFixedBytes<N>` 的 `Debug`/`Display`
//!   实现**强制脱敏**——
//!   类型系统保证，不可绕过（INVARIANT: DIPORT-DTO-BYTES-REDACT-01，载体为
//!   `crates/diport/src/redacted_bytes.rs`）。
//! - 下游（本 lint，Medium）：守「`diport` crate 内 struct 的字节缓冲字段必须使用匹配形态的 canonical carrier，
//!   不得裸持 `Vec<u8>` / `[u8; N]` / `Box<[u8]>` 或其 `Option` 包装」——
//!   两个 carrier 字段都是命名 ADT 类型，天然不命中；carrier 定义自身的裸字节字段按完整 `DefId`
//!   路径结构性豁免。
//!
//! 守护范围（MANDATORY）：仅当 `cx.tcx.crate_name(LOCAL_CRATE).as_str() == "diport"` 时激活。
//! `diport` 直接承载 DI port 契约 DTO 的字节 payload 脱敏边界；其它 crate 暂不纳入，避免误报普通
//! 业务 byte 字段（如 HTTP body 缓冲）。
//!
//! 检测面：`check_field_def` 逐字段在 **Ty 层（typeck 后）** 判定真实字段类型——type alias 在此
//! **透明展开**，故 `type Bytes = Vec<u8>; f: Bytes` 同样命中：
//! 1. `cx.tcx.type_of(field.def_id).instantiate_identity()` 取字段真实 `Ty`。
//! 2. 判 `Vec<u8>`：`ty::Adt` 且 `cx.tcx.is_diagnostic_item(sym::Vec, did)`，首个类型实参 `u8`
//!    （`ty::Uint(ty::UintTy::U8)`）。
//! 3. 判 `[u8; N]`：`ty::Array(elem, _)`，`elem` 为 `u8`。
//! 4. 判 `Box<[u8]>`：`ty::Adt` 且 `adt_def.is_box()`，被装类型 `ty::Slice(elem)`，`elem` 为 `u8`。
//! 5. 以上被 `Option<_>` 包一层（`cx.tcx.is_diagnostic_item(sym::Option, did)`）也命中——解一层
//!    `Option` 后对内层再判步骤 2–4。
//! 诊断 span 置于字段类型（type alias 名亦原样高亮）；item-level
//! `#[allow(rss_diport_dto_debug_redacted)]` 逃生门有效。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`DYLINT_RUSTFLAGS=-D warnings`
//! fail-closed）拦，azure 无 CI ⇒ verify 是唯一实际 gate；② `#[cfg(test)]` 子树默认不被扫（test-only
//! 字节 field 放行）；③ 守护范围限 `diport`，其它 crate 合法裸持 `Vec<u8>` 不误报；④ 不检测
//! `#[redact]` derive helper attr（late pass 可能已被消除）——已用 `secure::Redact` 治理的 `SecretMaterial`
//! 与公开 / 结构性字节类型 `CertSerial` 由 `is_structural_carve_out` 名单豁免
//! （非生产 `#[allow]`，避免 `unknown_lints` 噪声）。
//! anti-vacuity（守卫非恒真 / 恒假，两向 UI golden 锁）：红向由 `ui/diport.rs` 的
//! `Vec<u8>` / `[u8;N]` / `Box<[u8]>` / `Option<Vec<u8>>` struct **必报** + golden 非空锁；
//! 绿向由 `ui/not_diport.rs`（crate 名不在守护范围）同形字段 **不报** + 空 golden 锁（验
//! `LOCAL_CRATE` 分支非恒报）。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use clippy_utils::sym;
use rustc_hir::FieldDef;
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty;

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记 `diport` crate 内 struct 字段类型为裸字节缓冲（`Vec<u8>` / `[u8; N]` / `Box<[u8]>`
    /// 或 `Option` 包一层）的情形。动态 payload 使用 `RedactedBytes`，固定宽度结构字节使用
    /// crate-internal `RedactedFixedBytes<N>`；两者的 `Debug`/`Display` 都固定脱敏。
    ///
    /// ### Why is this bad?
    /// 裸字节缓冲字段的 `derive(Debug)` 会以十六进制或 UTF-8 字节序列展开，可能把密钥材料、
    /// 证书字节、token payload 泄入日志或 trace（PII 及密钥边界问题）。
    /// 上游 canonical carrier 已用类型系统（Hard）保证 `Debug`/`Display` 恒脱敏；
    /// 本 lint 作为下游 Medium gate，确保 `diport` DTO 确实采纳对应 carrier。
    /// INVARIANT: DIPORT-DTO-RAWBYTES-BAN-01 { level = "Medium", exec = "check", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；`#[cfg(test)]`
    /// 子树默认不被扫（test-only 字节字段放行）。守护范围限 `diport` crate；其它 crate 的同形字段不命中。
    /// 不检测 `#[redact]` derive helper attr（late pass 中可能已被消除）——已 `derive(secure::Redact)`
    /// 治理的字段（`SecretMaterial`）与公开字节（`CertSerial`）由
    /// `is_structural_carve_out` 名单豁免，
    /// **非**生产 `#[allow]`（dylint 未加载时 `#[allow(rss_*)]` 触发 `unknown_lints`、`-D warnings` 红）。
    ///
    /// canonical `diport::redacted_bytes::{RedactedBytes, RedactedFixedBytes}` 自身是受控持有点，按完整
    /// `DefId` path 精确豁免。重命名、移动或嵌套同名伪造都会使 UI golden 失败。
    ///
    /// anti-vacuity（两向 UI golden 锁）：红向由 `ui/diport.rs` 的裸字节 struct **必报** + golden 非空锁；
    /// 绿向由 `ui/not_diport.rs`（LOCAL_CRATE 不在守护范围）同形字段 **不报** + 空 golden 锁。
    ///
    /// ### Example
    /// ```ignore
    /// // 触发（裸字节缓冲字段）：
    /// struct CertPayload {
    ///     der: Vec<u8>,
    /// }
    /// ```
    /// Use instead:
    /// ```ignore
    /// // 不触发（RedactedBytes newtype，Debug/Display 脱敏）：
    /// struct CertPayload {
    ///     der: RedactedBytes,
    /// }
    /// ```
    pub RSS_DIPORT_DTO_DEBUG_REDACTED,
    Warn,
    "diport DTO 字段不得持裸字节缓冲（Vec<u8>/[u8;N]/Box<[u8]>/Option 包装）：改用 canonical redacted carrier（INVARIANT DIPORT-DTO-RAWBYTES-BAN-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssDiportDtoDebugRedacted {
    fn check_field_def(&mut self, cx: &LateContext<'tcx>, field: &'tcx FieldDef<'tcx>) {
        // 守护范围：仅 diport crate。其它 crate 裸持 Vec<u8> 等是合法业务代码，不报。
        if cx.tcx.crate_name(LOCAL_CRATE).as_str() != "diport" {
            return;
        }
        // 结构性豁免：canonical dynamic/fixed redacted carrier 是受控持有点，其内层裸字节合法。
        // 按完整 DefId 路径豁免，防止根级或嵌套同名假类型绕过。
        let parent_did = cx.tcx.parent(field.def_id.to_def_id());
        if is_canonical_redacted_carrier(cx, parent_did) {
            // reason: canonical redacted carrier 是授权受控持有点，内层裸字节即实现载体
            return;
        }
        // 结构性 carve-out（公开 / secure-governed 字节，刻意保留裸 `Vec<u8>`）。用 in-lint 名单而非生产
        // `#[allow]`——dylint 未加载时（`cargo clippy`）`#[allow(rss_*)]` 触发 `unknown_lints`、`-D warnings` 红
        // （工作区无 `unknown_lints=allow`）。carve-out 须同步 ADR-013 registry（error-handling.md §Carve-out）。
        if is_structural_carve_out(cx, parent_did) {
            return;
        }
        let field_ty = cx.tcx.type_of(field.def_id).instantiate_identity();
        if is_raw_bytes_ty(cx, field_ty) {
            span_lint_hir_and_then(
                cx,
                RSS_DIPORT_DTO_DEBUG_REDACTED,
                field.hir_id,
                field.ty.span,
                "diport DTO 字段不得持裸字节缓冲（Vec<u8> / [u8;N] / Box<[u8]> 或其 Option 包装）：改用 canonical redacted carrier（Debug/Display 脱敏）",
                |diag| {
                    diag.help(
                        "动态 payload 改用 `RedactedBytes`，固定宽度结构字节改用 crate-internal `RedactedFixedBytes<N>`\
                        （均位于 `crates/diport/src/redacted_bytes.rs`，`Debug`/`Display` 脱敏）；\
                        极少数公开字节（如 CRL 序列号）或已 `derive(secure::Redact)` 治理的字段，三步同步：\
                        加 `is_structural_carve_out` 名单 + ADR-013 §4 carve-out registry + `ui/diport.rs` 加绿例\
                        （生产代码不用 `#[allow]`——dylint 未加载时触发 `unknown_lints`、`-D warnings` 红）",
                    );
                },
            );
        }
    }
}

/// 字段的**真实类型**（Ty 层，typeck 后）是否为裸字节缓冲或其 `Option` 包装。
///
/// type alias 在 Ty 层已**透明展开**：`type Bytes = Vec<u8>; f: Bytes` 归一化为 `Vec<u8>` Ty 命中，
/// 关闭旧 HIR 语法匹配的 alias 绕过面。
///
/// 判定流程：
/// 1. 先对 Ty 本身判步骤 2–4（`is_raw_bytes_inner`）；
/// 2. 若 Ty 是 `Option<T>`（`is_diagnostic_item(sym::Option, ...)`），解包 T 后对 T 再判步骤 2–4。
/// 3. `Vec<u8>`：`ty::Adt` + `is_diagnostic_item(sym::Vec, did)` + 首个类型实参 `ty::Uint(ty::UintTy::U8)`。
/// 4. `[u8; N]`：`ty::Array(elem, _)` + elem 为 `u8`。
/// 5. `Box<[u8]>`：`ty::Adt` + `adt_def.is_box()` + 被装类型 `ty::Slice(elem)` + elem 为 `u8`。
fn is_raw_bytes_ty<'tcx>(cx: &LateContext<'tcx>, ty: ty::Ty<'tcx>) -> bool {
    // 直接字节缓冲形态
    if is_raw_bytes_inner(cx, ty) {
        return true;
    }
    // 解一层 Option<T>，对内层 T 再判
    if let ty::Adt(adt_def, args) = ty.kind() {
        if cx.tcx.is_diagnostic_item(sym::Option, adt_def.did()) {
            return is_raw_bytes_inner(cx, args.type_at(0));
        }
    }
    false
}

/// 对 `Ty` 本身（不含 Option 包装）判定是否为 `Vec<u8>` / `[u8; N]` / `Box<[u8]>`。
fn is_raw_bytes_inner<'tcx>(cx: &LateContext<'tcx>, ty: ty::Ty<'tcx>) -> bool {
    match ty.kind() {
        // Vec<u8>：diagnostic item `Vec`，首个类型实参为 u8
        ty::Adt(adt_def, args) if cx.tcx.is_diagnostic_item(sym::Vec, adt_def.did()) => {
            is_u8_ty(args.type_at(0))
        }
        // [u8; N]：数组元素为 u8
        ty::Array(elem_ty, _) => is_u8_ty(*elem_ty),
        // Box<[u8]>：lang-item box，被装类型是 u8 切片
        ty::Adt(adt_def, args) if adt_def.is_box() => {
            let inner = args.type_at(0);
            if let ty::Slice(elem_ty) = inner.kind() {
                is_u8_ty(*elem_ty)
            } else {
                false
            }
        }
        _ => false,
    }
}

/// 判定 `Ty` 是否为 `u8`（`ty::Uint(ty::UintTy::U8)`）。
fn is_u8_ty(ty: ty::Ty<'_>) -> bool {
    matches!(ty.kind(), ty::Uint(ty::UintTy::U8))
}

/// canonical redacted carrier 的完整 `DefId` path。语义 wrapper 持这些 ADT 后不再直接持裸字节。
const CANONICAL_REDACTED_CARRIER_PATHS: [&[&str]; 2] = [
    &["diport", "redacted_bytes", "RedactedBytes"],
    &["diport", "redacted_bytes", "RedactedFixedBytes"],
];

fn is_canonical_redacted_carrier(cx: &LateContext<'_>, did: DefId) -> bool {
    let path = cx.get_def_path(did);
    CANONICAL_REDACTED_CARRIER_PATHS.iter().any(|expected| {
        path.iter()
            .map(|part| part.as_str())
            .eq(expected.iter().copied())
    })
}

/// 公开 / secure-governed 字节字段的结构性 carve-out。每项按 enclosing struct 的完整 `DefId`
/// canonical path 判定；同 crate 内根级、兄弟或嵌套模块的同名类型均不命中。
/// 这些类型的裸 `Vec<u8>` 是设计本意、不采纳 `RedactedBytes`：
/// - `CertSerial`：RFC5280 证书序列号是公开 CRL 字段，`derive(Debug)` 有意可见原值（非机密，与密码学物料相反）。
/// - `SecretMaterial`：已 `#[derive(secure::Redact)]` `#[redact(sensitivity = secret)]`——完整 Wire + 日志策略由 `secure` 承载
///   （`RedactedBytes` 仅覆盖 `Debug`/`Display`、不含 Wire 范围），故保留 derive(Redact) + 裸 `Vec<u8>`。
///
/// 刻意窄名单（非启发式）。新增 carve-out 须同步本函数 + ADR-013 §4 carve-out registry + `ui/diport.rs` 绿例
/// （error-handling.md §Carve-out）；重命名这些类型会使豁免失配 → lint 对其内层裸字节误报红（UI golden 漂移）即自救。
///
const STRUCTURAL_CARVE_OUT_PATHS: [&[&str]; 2] = [
    &["diport", "revocation_store", "CertSerial"],
    &["diport", "secret_resolver", "SecretMaterial"],
];

fn is_structural_carve_out(cx: &LateContext<'_>, did: DefId) -> bool {
    let path = cx.get_def_path(did);
    STRUCTURAL_CARVE_OUT_PATHS.iter().any(|expected| {
        path.iter()
            .map(|part| part.as_str())
            .eq(expected.iter().copied())
    })
}

#[test]
fn ui_diport_red() {
    // example target 名 `diport`（LOCAL_CRATE=="diport"）→ struct 持裸字节缓冲字段触发；
    // 内嵌绿子例（canonical carrier 精确放行 / 非 u8 / 非字节类型 / item-level #[allow]）验 anti-vacuity。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "diport");
}

#[test]
fn ui_not_diport_green() {
    // example target 名 `not_diport`（LOCAL_CRATE=="not_diport" 不在守护范围）→ 同形字段不触发；
    // golden ui/not_diport.stderr 为空（anti-vacuity：验 LOCAL_CRATE 分支非恒报）。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "not_diport");
}

#[test]
fn structural_carve_out_paths_are_canonical_golden() {
    assert_eq!(
        STRUCTURAL_CARVE_OUT_PATHS,
        [
            &["diport", "revocation_store", "CertSerial"][..],
            &["diport", "secret_resolver", "SecretMaterial"][..],
        ]
    );
}

#[test]
fn canonical_redacted_carrier_paths_are_exact_golden() {
    assert_eq!(
        CANONICAL_REDACTED_CARRIER_PATHS,
        [
            &["diport", "redacted_bytes", "RedactedBytes"][..],
            &["diport", "redacted_bytes", "RedactedFixedBytes"][..],
        ]
    );
}
