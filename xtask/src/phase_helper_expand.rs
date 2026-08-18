//! Shared production inherent-helper utilities for semantic AST gates.

use crate::localtx_coverage::attrs_may_be_production;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PhaseExpandError {
    MissingEntry,
    AmbiguousImpl,
    Cycle(String),
}

impl fmt::Display for PhaseExpandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEntry => write!(f, "missing phase entry method or inherent impl"),
            Self::AmbiguousImpl => write!(f, "ambiguous inherent impl or private helper method"),
            Self::Cycle(name) => write!(f, "helper expansion cycle involving `{name}`"),
        }
    }
}

pub(crate) fn transparent_expr(mut expr: &syn::Expr) -> &syn::Expr {
    loop {
        match expr {
            syn::Expr::Block(block) if block.block.stmts.len() == 1 => {
                let syn::Stmt::Expr(inner, None) = &block.block.stmts[0] else {
                    return expr;
                };
                expr = inner;
            }
            syn::Expr::Group(group) => expr = &group.expr,
            syn::Expr::Paren(paren) => expr = &paren.expr,
            _ => return expr,
        }
    }
}

fn type_last_ident(ty: &syn::Type) -> Option<&syn::Ident> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path.segments.last().map(|segment| &segment.ident)
}

pub(crate) fn production_inherent_impl<'a>(
    file: &'a syn::File,
    owner: &str,
) -> Result<&'a syn::ItemImpl, PhaseExpandError> {
    let impls = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if item.trait_.is_none()
                    && attrs_may_be_production(&item.attrs)
                    && type_last_ident(&item.self_ty).is_some_and(|ident| ident == owner) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    match impls.as_slice() {
        [item] => Ok(item),
        [] => Err(PhaseExpandError::MissingEntry),
        _ => Err(PhaseExpandError::AmbiguousImpl),
    }
}

pub(crate) fn private_production_methods(
    implementation: &syn::ItemImpl,
) -> Result<BTreeMap<String, &syn::ImplItemFn>, PhaseExpandError> {
    let mut methods = BTreeMap::new();
    for item in &implementation.items {
        let syn::ImplItem::Fn(method) = item else {
            continue;
        };
        if !matches!(method.vis, syn::Visibility::Inherited) {
            continue;
        }
        if method
            .attrs
            .iter()
            .any(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        {
            continue;
        }
        if !attrs_may_be_production(&method.attrs) {
            continue;
        }
        let name = method.sig.ident.to_string();
        if methods.insert(name, method).is_some() {
            return Err(PhaseExpandError::AmbiguousImpl);
        }
    }
    Ok(methods)
}

pub(crate) fn inherent_entry_method<'a>(
    implementation: &'a syn::ItemImpl,
    name: &str,
) -> Result<&'a syn::ImplItemFn, PhaseExpandError> {
    let methods = implementation
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method)
                if method.sig.ident == name && attrs_may_be_production(&method.attrs) =>
            {
                Some(method)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    match methods.as_slice() {
        [method] => Ok(method),
        [] => Err(PhaseExpandError::MissingEntry),
        _ => Err(PhaseExpandError::AmbiguousImpl),
    }
}

pub(crate) fn self_or_owner_call<'a>(
    call: &'a syn::ExprCall,
    owner: &str,
    methods: &BTreeMap<String, &'a syn::ImplItemFn>,
) -> Option<(
    &'a syn::ImplItemFn,
    &'a syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
)> {
    let syn::Expr::Path(path) = transparent_expr(&call.func) else {
        return None;
    };
    if path.qself.is_some() || path.path.segments.len() != 2 {
        return None;
    }
    let mut segments = path.path.segments.iter();
    let first = segments.next()?;
    let second = segments.next()?;
    if !(first.ident == "Self" || first.ident == owner) {
        return None;
    }
    let method = methods.get(&second.ident.to_string())?;
    Some((method, &call.args))
}

pub(crate) fn self_receiver_helper_call<'a>(
    call: &'a syn::ExprMethodCall,
    methods: &BTreeMap<String, &'a syn::ImplItemFn>,
) -> Option<(
    &'a syn::ImplItemFn,
    &'a syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
)> {
    let syn::Expr::Path(path) = transparent_expr(&call.receiver) else {
        return None;
    };
    if path.qself.is_some() || path.path.segments.len() != 1 {
        return None;
    }
    if path.path.segments.first()?.ident != "self" {
        return None;
    }
    let method = methods.get(&call.method.to_string())?;
    let has_receiver = method
        .sig
        .inputs
        .iter()
        .any(|input| matches!(input, syn::FnArg::Receiver(_)));
    if !has_receiver {
        return None;
    }
    Some((method, &call.args))
}
