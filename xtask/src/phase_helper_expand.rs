//! Shared inherent phase-helper expansion for LIVE-01 anchors and DLX lifecycle funnel.
//!
//! Recursively inlines same-impl private `Self::helper` / `self.helper` calls in call order
//! into a virtual buffer (monotonic virtual offsets). Cycles and missing call spans fail closed.

use crate::localtx_coverage::attrs_may_be_production;
use std::collections::BTreeMap;
use std::fmt;
use syn::visit::Visit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PhaseExpandError {
    MissingEntry,
    AmbiguousImpl,
    Cycle(String),
    MissingBody(String),
    MissingCallSpan(String),
    Parse(String),
}

pub(crate) struct ExpandedInherentPhaseMethod {
    pub(crate) virtual_source: String,
}

impl fmt::Display for PhaseExpandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEntry => write!(f, "missing phase entry method or inherent impl"),
            Self::AmbiguousImpl => write!(f, "ambiguous inherent impl or private helper method"),
            Self::Cycle(name) => write!(f, "helper expansion cycle involving `{name}`"),
            Self::MissingBody(name) => write!(f, "missing body text for helper `{name}`"),
            Self::MissingCallSpan(name) => {
                write!(f, "missing call span while expanding helper `{name}`")
            }
            Self::Parse(detail) => write!(f, "failed to parse phase owner source: {detail}"),
        }
    }
}

fn transparent_expr(mut expr: &syn::Expr) -> &syn::Expr {
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

fn immutable_pat_ident(pat: &syn::Pat) -> Option<&syn::Ident> {
    match pat {
        syn::Pat::Ident(pat)
            if pat.by_ref.is_none() && pat.mutability.is_none() && pat.subpat.is_none() =>
        {
            Some(&pat.ident)
        }
        syn::Pat::Type(pat) => immutable_pat_ident(&pat.pat),
        _ => None,
    }
}

fn type_last_ident(ty: &syn::Type) -> Option<&syn::Ident> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path.segments.last().map(|segment| &segment.ident)
}

#[derive(Debug, Clone, Copy)]
struct BracedBody<'a> {
    body: &'a str,
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
        if !matches!(method.vis, syn::Visibility::Inherited)
            || !attrs_may_be_production(&method.attrs)
        {
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

fn line_start_offset(source: &str, line: usize) -> usize {
    if line <= 1 {
        return 0;
    }
    source
        .match_indices('\n')
        .nth(line - 2)
        .map_or(0, |(offset, _)| offset + 1)
}

fn inherent_method_body_text<'a>(source: &'a str, method: &syn::ImplItemFn) -> Option<&'a str> {
    let search_from = line_start_offset(source, method.sig.ident.span().start().line);
    let name = method.sig.ident.to_string();
    let async_needle = format!("async fn {name}(");
    let sync_needle = format!("fn {name}(");
    if method.sig.asyncness.is_some() {
        extract_braced_body_at(source, search_from, &async_needle)
            .or_else(|| extract_braced_body_at(source, search_from, &sync_needle))
    } else {
        extract_braced_body_at(source, search_from, &sync_needle)
            .or_else(|| extract_braced_body_at(source, search_from, &async_needle))
    }
    .map(|scope| scope.body)
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

struct ExpandableCallCollector<'ast> {
    owner: String,
    methods: BTreeMap<String, &'ast syn::ImplItemFn>,
    calls: Vec<(
        &'ast syn::ImplItemFn,
        &'ast syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
    )>,
}

impl<'ast> Visit<'ast> for ExpandableCallCollector<'ast> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Some((method, args)) = self_or_owner_call(call, &self.owner, &self.methods) {
            self.calls.push((method, args));
            return;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if let Some((method, args)) = self_receiver_helper_call(call, &self.methods) {
            self.calls.push((method, args));
            return;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// Returns `(param, arg)` pairs for simple path call arguments that bind to immutable params.
///
/// Callers that remap tracked bindings must apply **arg → param** (see
/// `RunRuntimeConfigWiring::push_binding_remaps`), not the reverse.
pub(crate) fn binding_remaps_for_call(
    method: &syn::ImplItemFn,
    args: &syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
) -> Vec<(syn::Ident, syn::Ident)> {
    let params = method
        .sig
        .inputs
        .iter()
        .filter_map(|input| match input {
            syn::FnArg::Typed(typed) => immutable_pat_ident(&typed.pat).cloned(),
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    params
        .into_iter()
        .zip(args.iter())
        .filter_map(|(param, arg)| {
            let syn::Expr::Path(path) = transparent_expr(arg) else {
                return None;
            };
            if path.qself.is_some() || path.path.segments.len() != 1 {
                return None;
            }
            let arg_ident = path.path.segments.first()?.ident.clone();
            Some((param, arg_ident))
        })
        .collect()
}

fn is_rust_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_rust_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn rewrite_binding_remaps_in_text(body: &str, remaps: &[(syn::Ident, syn::Ident)]) -> String {
    if remaps.is_empty() {
        return body.to_owned();
    }
    let remap = remaps
        .iter()
        .map(|(param, arg)| (param.to_string(), arg.to_string()))
        .collect::<BTreeMap<_, _>>();
    let masked = mask_comments_and_strings(body);
    let mask_bytes = masked.as_bytes();
    let mut out = String::with_capacity(body.len());
    let mut index = 0usize;
    while index < body.len() {
        if mask_bytes
            .get(index)
            .copied()
            .is_some_and(is_rust_ident_start)
        {
            let start = index;
            index += 1;
            while mask_bytes
                .get(index)
                .copied()
                .is_some_and(is_rust_ident_continue)
            {
                index += 1;
            }
            let ident = &masked[start..index];
            if let Some(replacement) = remap.get(ident) {
                out.push_str(replacement);
            } else {
                out.push_str(&body[start..index]);
            }
            continue;
        }
        let Some(ch) = body[index..].chars().next() else {
            break;
        };
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

fn find_helper_call_span(
    body: &str,
    from: usize,
    owner: &str,
    method: &str,
) -> Option<(usize, usize)> {
    let masked = mask_comments_and_strings(body);
    let needles = [
        format!("Self::{method}"),
        format!("{owner}::{method}"),
        format!("self.{method}"),
    ];
    let relative = masked.get(from..)?;
    let mut best: Option<usize> = None;
    for needle in &needles {
        let mut search_from = 0usize;
        while let Some(pos) = relative[search_from..].find(needle.as_str()) {
            let abs = from + search_from + pos;
            let after = abs + needle.len();
            if masked
                .as_bytes()
                .get(after)
                .copied()
                .is_some_and(is_rust_ident_continue)
            {
                search_from += pos + 1;
                continue;
            }
            let rest = masked.get(after..)?;
            let trimmed = rest.trim_start();
            if trimmed.starts_with('(') {
                best = Some(best.map_or(abs, |current| current.min(abs)));
                break;
            }
            search_from += pos + 1;
        }
    }
    let start = best?;
    let open = masked[start..].find('(')? + start;
    let mut depth = 0usize;
    for (offset, byte) in masked.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some((start, open + offset + 1));
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn expand_inherent_phase_method(
    source: &str,
    file: &syn::File,
    owner: &str,
    entry: &str,
) -> Result<ExpandedInherentPhaseMethod, PhaseExpandError> {
    let implementation = production_inherent_impl(file, owner)?;
    let methods = private_production_methods(implementation)?;
    let entry_method = inherent_entry_method(implementation, entry)?;
    let mut stack = Vec::new();
    let virtual_source = expand_method_recursive(
        source,
        owner,
        entry_method,
        &methods,
        &mut stack,
        Vec::new(),
    )?;
    Ok(ExpandedInherentPhaseMethod { virtual_source })
}

fn expand_method_recursive<'a>(
    source: &str,
    owner: &str,
    method: &'a syn::ImplItemFn,
    methods: &BTreeMap<String, &'a syn::ImplItemFn>,
    stack: &mut Vec<String>,
    remaps: Vec<(syn::Ident, syn::Ident)>,
) -> Result<String, PhaseExpandError> {
    let name = method.sig.ident.to_string();
    if stack.iter().any(|frame| frame == &name) {
        return Err(PhaseExpandError::Cycle(name));
    }
    stack.push(name.clone());
    let body_text = inherent_method_body_text(source, method)
        .ok_or_else(|| PhaseExpandError::MissingBody(name.clone()))?;
    let body = rewrite_binding_remaps_in_text(body_text, &remaps);
    let mut collector = ExpandableCallCollector {
        owner: owner.to_owned(),
        methods: methods.clone(),
        calls: Vec::new(),
    };
    collector.visit_block(&method.block);
    let mut virtual_source = String::new();
    let mut cursor = 0usize;
    for (helper, args) in collector.calls {
        let helper_name = helper.sig.ident.to_string();
        let Some((call_start, call_end)) =
            find_helper_call_span(&body, cursor, owner, &helper_name)
        else {
            stack.pop();
            return Err(PhaseExpandError::MissingCallSpan(helper_name));
        };
        virtual_source.push_str(&body[cursor..call_start]);
        let helper_remaps = binding_remaps_for_call(helper, args);
        let expanded =
            expand_method_recursive(source, owner, helper, methods, stack, helper_remaps)?;
        virtual_source.push_str(&expanded);
        cursor = call_end;
    }
    virtual_source.push_str(&body[cursor..]);
    stack.pop();
    Ok(virtual_source)
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

fn extract_braced_body_at<'a>(
    src: &'a str,
    search_from: usize,
    needle: &str,
) -> Option<BracedBody<'a>> {
    let start = src.get(search_from..)?.find(needle)? + search_from;
    let open = src[start..].find('{')? + start;
    let scan = mask_comments_and_strings(&src[open..]);
    let mut depth = 0usize;
    for (offset, byte) in scan.as_bytes().iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(BracedBody {
                        body: &src[open + 1..open + offset],
                    });
                }
            }
            _ => {}
        }
    }
    None
}
