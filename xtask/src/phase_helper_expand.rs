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

pub(crate) fn mask_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if let Some(end) = raw_string_end(bytes, index) {
            mask_range(bytes, index, end, &mut out);
            index = end;
            continue;
        }

        if is_prefixed_string_start(bytes, index) {
            let end = quoted_string_end(bytes, index + 2);
            mask_range(bytes, index, end, &mut out);
            index = end;
            continue;
        }

        if bytes[index] == b'"' {
            let end = quoted_string_end(bytes, index + 1);
            mask_range(bytes, index, end, &mut out);
            index = end;
            continue;
        }

        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|offset| index + offset)
                .unwrap_or(bytes.len());
            mask_range(bytes, index, end, &mut out);
            index = end;
            continue;
        }

        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let end = block_comment_end(bytes, index);
            mask_range(bytes, index, end, &mut out);
            index = end;
            continue;
        }

        out.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn raw_string_end(bytes: &[u8], index: usize) -> Option<usize> {
    let mut cursor = match bytes.get(index) {
        Some(b'r') => index + 1,
        Some(b'b' | b'c') if bytes.get(index + 1) == Some(&b'r') => index + 2,
        _ => return None,
    };
    let hashes_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    let hashes = cursor - hashes_start;
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' && has_raw_string_hashes(bytes, cursor + 1, hashes) {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn has_raw_string_hashes(bytes: &[u8], start: usize, hashes: usize) -> bool {
    start + hashes <= bytes.len()
        && bytes[start..start + hashes]
            .iter()
            .all(|byte| *byte == b'#')
}

fn is_prefixed_string_start(bytes: &[u8], index: usize) -> bool {
    matches!(bytes.get(index), Some(b'b' | b'c')) && bytes.get(index + 1) == Some(&b'"')
}

fn quoted_string_end(bytes: &[u8], mut index: usize) -> usize {
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn block_comment_end(bytes: &[u8], mut index: usize) -> usize {
    let mut depth = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            depth += 1;
            index += 2;
            continue;
        }
        if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
            depth = depth.saturating_sub(1);
            index += 2;
            if depth == 0 {
                return index;
            }
            continue;
        }
        index += 1;
    }
    bytes.len()
}

fn mask_range(bytes: &[u8], start: usize, end: usize, out: &mut Vec<u8>) {
    for byte in &bytes[start..end] {
        match byte {
            b'\n' | b'\r' => out.push(*byte),
            _ => out.push(b' '),
        }
    }
}
