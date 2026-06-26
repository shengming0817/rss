//! `securederive` —— 字段级脱敏 `#[derive(Redactable)]` proc-macro（#1360）。
//!
//! 从每字段的 `#[redact(...)]` 策略派生两个 impl：
//! - `impl ::secure::Redactable`：调 `::secure::redact_struct` 公开 funnel 产出 `Redacted`
//!   （`Redacted::new` 仍 `pub(crate)` 封闭——脱敏逻辑在 `secure` 内单源，外部不可伪造安全值）。
//! - `impl ::core::fmt::Debug`：`write!(f, "{}", self.redact())`——替换手写 Debug，杜绝 `{:?}` 泄漏。
//!
//! **fail-closed（Hard）**：每个字段必须显式带 `#[redact(...)]`（`mode = …` 与/或 `sensitivity = …`）；
//! 缺标注 / 未知 mode / `sensitivity = secret|pii|internal` 又 `mode = show` 均编译错误——「忘标脱敏的
//! secret 字段」「把敏感字段标成明文」从类型层不可表达（compile-fail golden 见 `tests/`）。
//!
//! 不依赖 `secure` crate：只生成 `::secure::…` 绝对路径 token（无编译环；`secure` 内自用经
//! `extern crate self as secure` 解析）。`sensitivity → mode` 默认映射不在此重复，运行期经
//! `::secure::Sensitivity::default_mode()` 单源解析。
//!
//! ref: iqlusioninc/crates secrecy/src/lib.rs@main（`SecretBox` Debug `[REDACTED]` 脱敏 + `ExposeSecret`
//! 受控借出范式；RSS 偏离：构造封闭 `Redacted::new` + 字段级 declared policy，而非 `Secret<T>` 包装）。

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Fields, Index};

/// 派生 `Redactable` + 安全 `Debug`，按每字段 `#[redact(...)]` 策略脱敏。
///
/// 字段属性 grammar（`mode` 与 `sensitivity` 至少其一；二者皆缺 = 编译错误）：
/// - `#[redact(mode = M)]`：`M ∈ { show | fixed | last4 | email_mask | hash | drop }`。
/// - `#[redact(sensitivity = S)]`：`S ∈ { public | internal | pii | secret }`；mode 缺省时经
///   `secure::Sensitivity::default_mode` 解析（`public → show`、`internal|secret → fixed`、
///   `pii → fixed`）。**注意 `sensitivity = pii` 在宏层取 `PiiKind::Generic`（→ `fixed`）**——
///   邮箱掩码 / 末 4 位等细分 PII 行为须显式写 `#[redact(mode = email_mask)]` / `#[redact(mode = last4)]`。
/// - `#[redact(sensitivity = S, mode = M)]`：显式 mode 优先；但 `S ∈ {internal,pii,secret}` 与
///   `mode = show` 同用 = 编译错误（敏感字段不可声明明文）。
#[proc_macro_derive(Redactable, attributes(redact))]
pub fn derive_redactable(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// 脱敏模式（与 `secure::RedactionMode` 同名变体，宏内只做 token 选择，不复制语义）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Show,
    Fixed,
    Last4,
    EmailMask,
    Hash,
    Drop,
}

/// 敏感度（与 `secure::Sensitivity` 对应；`Pii` 在宏层取 `Generic`，细分 PII 用显式 `mode`）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sens {
    Public,
    Internal,
    Pii,
    Secret,
}

/// 单字段解析所得策略 + 取值 token。
struct FieldPolicy {
    /// `Some("name")`（named 字段）/ `None`（tuple 字段，渲染为位置式）。
    name_token: TokenStream2,
    /// 解析到的 `::secure::RedactionMode` 值表达式。
    mode_expr: TokenStream2,
    /// 字段 `RedactValue` 取值表达式：读值 mode（show/last4/email_mask/hash 或 sensitivity 派生）
    /// 经 `RedactField::as_redact_value(&self.f)`；显式 `fixed`/`drop`（不读值）= `RedactValue::Absent`
    /// ——后者不施加 `RedactField` 约束，自定义字段类型即可固定脱敏（#1360 F2）。
    value_expr: TokenStream2,
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(
            input.span(),
            "Redactable 仅支持 struct（enum / union 不支持）",
        ));
    };
    let (is_tuple, fields) = match &data.fields {
        Fields::Named(f) => (false, &f.named),
        Fields::Unnamed(f) => (true, &f.unnamed),
        Fields::Unit => {
            return Err(syn::Error::new(
                input.span(),
                "Redactable 要求 struct 至少有一个字段（unit struct 无可脱敏字段）",
            ));
        }
    };

    let policies = fields
        .iter()
        .enumerate()
        .map(|(idx, field)| field_policy(field, idx))
        .collect::<syn::Result<Vec<_>>>()?;

    let field_inits = policies.iter().map(|p| {
        let FieldPolicy {
            name_token,
            mode_expr,
            value_expr,
        } = p;
        quote! {
            ::secure::FieldRedaction {
                name: #name_token,
                mode: #mode_expr,
                value: #value_expr,
            }
        }
    });

    let ident = &input.ident;
    let type_name = ident.to_string();
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics ::secure::Redactable for #ident #ty_generics #where_clause {
            fn redact(&self) -> ::std::string::String {
                ::secure::redact_struct(#type_name, #is_tuple, &[ #(#field_inits),* ])
            }
        }

        impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "{}", ::secure::Redactable::redact(self))
            }
        }
    })
}

fn field_policy(field: &syn::Field, idx: usize) -> syn::Result<FieldPolicy> {
    let (mode, sens) = parse_redact_attr(field)?;
    // 防误标：非 public 敏感字段（internal / pii / secret）不得标成明文 show。
    // 仅 public（或不声明 sensitivity）可用 show——fail-closed。
    if matches!(sens, Some(Sens::Secret | Sens::Pii | Sens::Internal)) && mode == Some(Mode::Show) {
        return Err(syn::Error::new(
            field.span(),
            "sensitivity = secret|pii|internal 不得与 mode = show 同用（敏感字段不可声明明文输出）",
        ));
    }

    // 解析最终 mode 表达式；fail-closed：mode/sensitivity 皆缺 ⇒ 编译错误（不得隐式明文）。
    let mode_expr = match (mode, sens) {
        (Some(m), _) => mode_path(m),
        // 只给 sensitivity：经 secure 单源映射解析默认 mode（不在宏内复制映射）。
        (None, Some(s)) => {
            let s_expr = sens_expr(s);
            quote!((#s_expr).default_mode())
        }
        (None, None) => {
            return Err(syn::Error::new(
                field.span(),
                "字段缺 #[redact(...)]：须显式声明 `mode = …` 和/或 `sensitivity = …`（fail-closed，不得隐式明文）",
            ));
        }
    };

    let (name_token, accessor) = match &field.ident {
        Some(name) => (
            quote!(::core::option::Option::Some(stringify!(#name))),
            quote!(&self.#name),
        ),
        None => {
            let index = Index::from(idx);
            (quote!(::core::option::Option::None), quote!(&self.#index))
        }
    };

    // 显式 `fixed`/`drop` 不读字段值 ⇒ `RedactValue::Absent`，**不**施加 `RedactField` 约束（#1360 F2，
    // 对标 serde `skip` 字段不走默认 Serialize bound）——自定义字段类型即可固定脱敏 / 剔除。其余 mode
    //（show/last4/email_mask/hash）及 sensitivity 派生 mode（运行期解析，宏静态不知是否读值，保守取值）
    // 经 `RedactField::as_redact_value`。
    let value_expr = if matches!(mode, Some(Mode::Fixed | Mode::Drop)) {
        quote!(::secure::RedactValue::Absent)
    } else {
        quote!(::secure::RedactField::as_redact_value(#accessor))
    };

    Ok(FieldPolicy {
        name_token,
        mode_expr,
        value_expr,
    })
}

/// 解析单字段的 `#[redact(...)]`。返回 `(mode, sensitivity)`（均可缺省，由调用方 fail-closed 校验）。
fn parse_redact_attr(field: &syn::Field) -> syn::Result<(Option<Mode>, Option<Sens>)> {
    let mut mode: Option<Mode> = None;
    let mut sens: Option<Sens> = None;
    for attr in &field.attrs {
        if !attr.path().is_ident("redact") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("mode") {
                let id: syn::Ident = meta.value()?.parse()?;
                mode = Some(parse_mode(&id)?);
                return Ok(());
            }
            if meta.path.is_ident("sensitivity") {
                let id: syn::Ident = meta.value()?.parse()?;
                sens = Some(parse_sens(&id)?);
                return Ok(());
            }
            Err(meta.error("未知 #[redact(...)] 键：仅支持 `mode` / `sensitivity`"))
        })?;
    }
    Ok((mode, sens))
}

fn parse_mode(id: &syn::Ident) -> syn::Result<Mode> {
    match id.to_string().as_str() {
        "show" => Ok(Mode::Show),
        "fixed" => Ok(Mode::Fixed),
        "last4" => Ok(Mode::Last4),
        "email_mask" => Ok(Mode::EmailMask),
        "hash" => Ok(Mode::Hash),
        "drop" => Ok(Mode::Drop),
        other => Err(syn::Error::new(
            id.span(),
            format!("未知 mode `{other}`：支持 show / fixed / last4 / email_mask / hash / drop"),
        )),
    }
}

fn parse_sens(id: &syn::Ident) -> syn::Result<Sens> {
    match id.to_string().as_str() {
        "public" => Ok(Sens::Public),
        "internal" => Ok(Sens::Internal),
        "pii" => Ok(Sens::Pii),
        "secret" => Ok(Sens::Secret),
        other => Err(syn::Error::new(
            id.span(),
            format!("未知 sensitivity `{other}`：支持 public / internal / pii / secret"),
        )),
    }
}

fn mode_path(m: Mode) -> TokenStream2 {
    match m {
        Mode::Show => quote!(::secure::RedactionMode::Show),
        Mode::Fixed => quote!(::secure::RedactionMode::Fixed),
        Mode::Last4 => quote!(::secure::RedactionMode::Last4),
        Mode::EmailMask => quote!(::secure::RedactionMode::EmailMask),
        Mode::Hash => quote!(::secure::RedactionMode::Hash),
        Mode::Drop => quote!(::secure::RedactionMode::Drop),
    }
}

fn sens_expr(s: Sens) -> TokenStream2 {
    match s {
        Sens::Public => quote!(::secure::Sensitivity::Public),
        Sens::Internal => quote!(::secure::Sensitivity::Internal),
        Sens::Pii => quote!(::secure::Sensitivity::Pii(::secure::PiiKind::Generic)),
        Sens::Secret => quote!(::secure::Sensitivity::Secret),
    }
}

#[cfg(test)]
// item-level carve-out（测试模块）：expect/expect_err 在此是意图清晰的 programmer-error 断言信号
// （对齐 secure::password #[cfg(test)] 模块约定）。
#[allow(clippy::expect_used)]
mod tests {
    use super::expand;

    fn expand_str(src: &str) -> syn::Result<String> {
        let input = syn::parse_str::<syn::DeriveInput>(src).expect("parse DeriveInput");
        expand(&input).map(|ts| ts.to_string())
    }

    #[test]
    fn named_struct_emits_both_impls() {
        let out = expand_str(
            "struct Coord { #[redact(sensitivity = secret)] store_id: String, #[redact(mode = fixed)] key: String }",
        )
        .expect("expand ok");
        assert!(out.contains("impl :: secure :: Redactable for Coord"));
        assert!(
            out.contains("impl :: secure :: Redactable for Coord")
                && out.contains("Debug for Coord")
        );
        assert!(out.contains("redact_struct"));
        assert!(out.contains("false")); // is_tuple = false
        // 显式 mode = fixed 直接选 RedactionMode::Fixed；sensitivity = secret 经 default_mode() 解析。
        assert!(out.contains("RedactionMode :: Fixed"));
        assert!(out.contains("default_mode"));
    }

    #[test]
    fn tuple_newtype_marks_is_tuple_true_and_no_name() {
        let out =
            expand_str("struct Ct(#[redact(sensitivity = secret)] Vec<u8>);").expect("expand ok");
        assert!(out.contains("redact_struct"));
        assert!(out.contains("true")); // is_tuple = true
        assert!(out.contains("Option :: None")); // tuple 字段 name = None
        assert!(out.contains("& self . 0")); // 位置式访问
    }

    #[test]
    fn missing_redact_attr_is_compile_error() {
        let err = expand_str("struct Bad { plain: String }").expect_err("must fail-closed");
        assert!(err.to_string().contains("缺 #[redact"));
    }

    #[test]
    fn secret_with_show_is_rejected() {
        let err =
            expand_str("struct Bad { #[redact(sensitivity = secret, mode = show)] x: String }")
                .expect_err("must reject mislabel");
        assert!(err.to_string().contains("不得与 mode = show"));
    }

    #[test]
    fn pii_with_show_is_rejected() {
        let err = expand_str("struct Bad { #[redact(sensitivity = pii, mode = show)] x: String }")
            .expect_err("must reject mislabel");
        assert!(err.to_string().contains("不得与 mode = show"));
    }

    #[test]
    fn internal_with_show_is_rejected() {
        // Internal 语义 = 不进 Debug；show 强制明文输出与之矛盾 ⇒ fail-closed 拒绝。
        let err =
            expand_str("struct Bad { #[redact(sensitivity = internal, mode = show)] x: String }")
                .expect_err("must reject mislabel");
        assert!(err.to_string().contains("不得与 mode = show"));
    }

    #[test]
    fn public_with_show_is_allowed() {
        // 仅 public 可显式 show（明文非敏感）。
        let out =
            expand_str("struct Ok { #[redact(sensitivity = public, mode = show)] x: String }")
                .expect("public + show 应放行");
        assert!(out.contains("Redactable"));
    }

    #[test]
    fn unknown_mode_is_error() {
        let err = expand_str("struct Bad { #[redact(mode = bogus)] x: String }")
            .expect_err("unknown mode");
        assert!(err.to_string().contains("未知 mode"));
    }

    #[test]
    fn unknown_sensitivity_is_error() {
        let err = expand_str("struct Bad { #[redact(sensitivity = vip)] x: String }")
            .expect_err("unknown sensitivity");
        assert!(err.to_string().contains("未知 sensitivity"));
    }

    #[test]
    fn unknown_redact_key_is_error() {
        let err = expand_str("struct Bad { #[redact(masking = fixed)] x: String }")
            .expect_err("unknown key");
        assert!(err.to_string().contains("未知 #[redact"));
    }

    #[test]
    fn enum_is_rejected() {
        let err = expand_str("enum E { A, B }").expect_err("enum unsupported");
        assert!(err.to_string().contains("仅支持 struct"));
    }

    #[test]
    fn unit_struct_is_rejected() {
        let err = expand_str("struct U;").expect_err("unit unsupported");
        assert!(err.to_string().contains("至少有一个字段"));
    }

    #[test]
    fn each_mode_ident_parses() {
        for m in ["show", "fixed", "last4", "email_mask", "hash", "drop"] {
            let src = format!("struct S {{ #[redact(mode = {m})] x: String }}");
            assert!(expand_str(&src).is_ok(), "mode {m} 应解析");
        }
    }
}
