//! Shared inherent phase-helper expansion for production LIVE-01 AST gates.
//!
//! Recursively inlines same-impl private `Self::helper` / `self.helper` calls in call order
//! into a virtual buffer (monotonic virtual offsets). Cycles and missing call spans fail closed.

use crate::localtx_coverage::attrs_may_be_production;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use syn::visit::Visit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PhaseExpandError {
    MissingEntry,
    AmbiguousImpl,
    Cycle(String),
    MissingBody(String),
    MissingCallSpan(String),
    NonDirectCall(String),
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
            Self::NonDirectCall(detail) => {
                write!(
                    f,
                    "phase helper call is not in a unique direct context: {detail}"
                )
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
    conditional_methods: BTreeSet<String>,
    calls: Vec<(
        &'ast syn::ImplItemFn,
        &'ast syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
    )>,
    opaque_contexts: Vec<&'static str>,
    error: Option<PhaseExpandError>,
}

impl<'ast> ExpandableCallCollector<'ast> {
    fn record_helper_call(
        &mut self,
        method: &'ast syn::ImplItemFn,
        args: &'ast syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
        attrs: &[syn::Attribute],
    ) {
        if self.error.is_some() {
            return;
        }
        let name = method.sig.ident.to_string();
        if attrs
            .iter()
            .any(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        {
            self.error = Some(PhaseExpandError::NonDirectCall(format!(
                "`{name}` has conditional call attributes"
            )));
        } else if let Some(context) = self.opaque_contexts.last() {
            self.error = Some(PhaseExpandError::NonDirectCall(format!(
                "`{name}` is nested under {context}"
            )));
        } else {
            self.calls.push((method, args));
        }
    }

    fn enter_opaque(&mut self, context: &'static str, visit: impl FnOnce(&mut Self)) {
        self.opaque_contexts.push(context);
        visit(self);
        self.opaque_contexts.pop();
    }

    fn canonical_once_closure(
        &self,
        call: &'ast syn::ExprCall,
    ) -> Option<(&'ast syn::Expr, &'ast syn::ExprClosure)> {
        let syn::Expr::Path(function) = transparent_expr(&call.func) else {
            return None;
        };
        let mut args = call.args.iter();
        let input = args.next()?;
        let syn::Expr::Closure(closure) = args.next().map(transparent_expr)? else {
            return None;
        };
        (call.attrs.is_empty()
            && function.qself.is_none()
            && function.path.segments.len() == 1
            && function.path.is_ident("after_required_preflight")
            && call.args.len() == 2
            && closure.attrs.is_empty()
            && closure.asyncness.is_none()
            && closure.movability.is_none()
            && closure.capture.is_none()
            && closure.inputs.len() == 1)
            .then_some((input, closure))
    }

    fn macro_mentions_helper(&self, mac: &syn::Macro) -> Option<String> {
        let tokens = mac.tokens.to_string();
        self.methods
            .keys()
            .chain(self.conditional_methods.iter())
            .find(|name| {
                tokens
                    .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                    .any(|token| token == name.as_str())
            })
            .cloned()
    }

    fn conditional_static_helper_call(&self, call: &syn::ExprCall) -> Option<String> {
        let syn::Expr::Path(path) = transparent_expr(&call.func) else {
            return None;
        };
        if path.qself.is_some() || path.path.segments.len() != 2 {
            return None;
        }
        let mut segments = path.path.segments.iter();
        let owner = segments.next()?;
        let method = segments.next()?.ident.to_string();
        ((owner.ident == "Self" || owner.ident == self.owner)
            && self.conditional_methods.contains(&method))
        .then_some(method)
    }

    fn conditional_receiver_helper_call(&self, call: &syn::ExprMethodCall) -> Option<String> {
        let syn::Expr::Path(receiver) = transparent_expr(&call.receiver) else {
            return None;
        };
        let method = call.method.to_string();
        (receiver.qself.is_none()
            && receiver.path.is_ident("self")
            && self.conditional_methods.contains(&method))
        .then_some(method)
    }
}

impl<'ast> Visit<'ast> for ExpandableCallCollector<'ast> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Some(method) = self.conditional_static_helper_call(call) {
            self.error = Some(PhaseExpandError::NonDirectCall(format!(
                "`{method}` resolves only to a conditional helper definition"
            )));
            return;
        }
        if let Some((method, args)) = self_or_owner_call(call, &self.owner, &self.methods) {
            self.record_helper_call(method, args, &call.attrs);
            return;
        }
        if self.canonical_once_closure(call).is_some() {
            self.enter_opaque("an unawaited once-funnel call", |visitor| {
                syn::visit::visit_expr_call(visitor, call);
            });
            return;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if let Some(method) = self.conditional_receiver_helper_call(call) {
            self.error = Some(PhaseExpandError::NonDirectCall(format!(
                "`{method}` resolves only to a conditional helper definition"
            )));
            return;
        }
        if let Some((method, args)) = self_receiver_helper_call(call, &self.methods) {
            self.record_helper_call(method, args, &call.attrs);
            return;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_await(&mut self, await_: &'ast syn::ExprAwait) {
        if await_.attrs.is_empty() {
            match transparent_expr(&await_.base) {
                syn::Expr::Async(async_) if async_.attrs.is_empty() && async_.capture.is_none() => {
                    self.visit_block(&async_.block);
                    return;
                }
                syn::Expr::Call(call) => {
                    if let Some((input, closure)) = self.canonical_once_closure(call) {
                        self.visit_expr(input);
                        self.visit_expr(&closure.body);
                        return;
                    }
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_await(self, await_);
    }

    fn visit_expr_async(&mut self, async_: &'ast syn::ExprAsync) {
        self.enter_opaque("an unproved async block", |visitor| {
            syn::visit::visit_expr_async(visitor, async_);
        });
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.enter_opaque("an arbitrary closure", |visitor| {
            syn::visit::visit_expr_closure(visitor, closure);
        });
    }

    fn visit_expr_if(&mut self, if_: &'ast syn::ExprIf) {
        self.enter_opaque("a conditional branch", |visitor| {
            syn::visit::visit_expr_if(visitor, if_);
        });
    }

    fn visit_expr_match(&mut self, match_: &'ast syn::ExprMatch) {
        self.enter_opaque("a match branch", |visitor| {
            syn::visit::visit_expr_match(visitor, match_);
        });
    }

    fn visit_expr_loop(&mut self, loop_: &'ast syn::ExprLoop) {
        self.enter_opaque("a loop", |visitor| {
            syn::visit::visit_expr_loop(visitor, loop_);
        });
    }

    fn visit_expr_for_loop(&mut self, loop_: &'ast syn::ExprForLoop) {
        self.enter_opaque("a for loop", |visitor| {
            syn::visit::visit_expr_for_loop(visitor, loop_);
        });
    }

    fn visit_expr_while(&mut self, while_: &'ast syn::ExprWhile) {
        self.enter_opaque("a while loop", |visitor| {
            syn::visit::visit_expr_while(visitor, while_);
        });
    }

    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        if matches!(binary.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) {
            self.enter_opaque("a short-circuit branch", |visitor| {
                syn::visit::visit_expr_binary(visitor, binary);
            });
        } else {
            syn::visit::visit_expr_binary(self, binary);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if self.error.is_none()
            && let Some(name) = self.macro_mentions_helper(mac)
        {
            self.error = Some(PhaseExpandError::NonDirectCall(format!(
                "`{name}` is hidden in macro tokens"
            )));
        }
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
    let conditional_methods = implementation
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method)
                if matches!(method.vis, syn::Visibility::Inherited)
                    && method.attrs.iter().any(|attr| {
                        attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr")
                    }) =>
            {
                Some(method.sig.ident.to_string())
            }
            _ => None,
        })
        .filter(|name| !methods.contains_key(name))
        .collect::<BTreeSet<_>>();
    let entry_method = inherent_entry_method(implementation, entry)?;
    let mut stack = Vec::new();
    let virtual_source = expand_method_recursive(
        source,
        owner,
        entry_method,
        &methods,
        &conditional_methods,
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
    conditional_methods: &BTreeSet<String>,
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
        conditional_methods: conditional_methods.clone(),
        calls: Vec::new(),
        opaque_contexts: Vec::new(),
        error: None,
    };
    collector.visit_block(&method.block);
    if let Some(error) = collector.error {
        stack.pop();
        return Err(error);
    }
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
        let expanded = expand_method_recursive(
            source,
            owner,
            helper,
            methods,
            conditional_methods,
            stack,
            helper_remaps,
        )?;
        virtual_source.push('{');
        virtual_source.push_str(&expanded);
        virtual_source.push('}');
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

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(source: &str) -> Result<ExpandedInherentPhaseMethod, PhaseExpandError> {
        let file =
            syn::parse_file(source).map_err(|error| PhaseExpandError::Parse(error.to_string()))?;
        expand_inherent_phase_method(source, &file, "Phase", "execute")
    }

    #[test]
    fn nested_self_and_self_receiver_helpers_expand_in_call_order() {
        let source = r#"
impl Phase {
    fn execute(&self) {
        first();
        Self::static_helper();
        self.receiver_helper();
        last();
    }
    fn static_helper() {
        static_start();
        Self::nested_helper();
        static_end();
    }
    fn nested_helper() { nested(); }
    fn receiver_helper(&self) { receiver(); }
}
"#;
        let expanded = expand(source)
            .expect("nested helper expansion")
            .virtual_source;
        let offsets = [
            "first()",
            "static_start()",
            "nested()",
            "static_end()",
            "receiver()",
            "last()",
        ]
        .map(|needle| expanded.find(needle).expect("expanded call"));
        assert!(
            offsets.windows(2).all(|pair| pair[0] < pair[1]),
            "{expanded}"
        );
        assert!(!expanded.contains("Self::static_helper"));
        assert!(!expanded.contains("self.receiver_helper"));
    }

    #[test]
    fn cycle_and_duplicate_helpers_fail_closed() {
        let cycle = r#"
impl Phase {
    fn execute() { Self::phase_a(); }
    fn phase_a() { Self::phase_b(); }
    fn phase_b() { Self::phase_a(); }
}
"#;
        assert!(matches!(expand(cycle), Err(PhaseExpandError::Cycle(name)) if name == "phase_a"));

        let duplicate = r#"
impl Phase {
    fn execute() { Self::helper(); }
    fn helper() { first(); }
    fn helper() { second(); }
}
"#;
        assert!(matches!(
            expand(duplicate),
            Err(PhaseExpandError::AmbiguousImpl)
        ));
    }

    #[test]
    fn comment_and_string_span_bait_is_masked_or_fails_closed() {
        let canonical = r#"
impl Phase {
    fn execute() {
        let _ = "Self::helper()";
        // Self::helper()
        Self::helper();
    }
    fn helper() { live_helper_body(); }
}
"#;
        let expanded = expand(canonical).expect("real call after bait must expand");
        assert!(expanded.virtual_source.contains("live_helper_body()"));

        let unmatchable_span = canonical.replace("Self::helper();", "Self :: helper();");
        assert!(matches!(
            expand(&unmatchable_span),
            Err(PhaseExpandError::MissingCallSpan(name)) if name == "helper"
        ));
    }

    #[test]
    fn helper_params_remap_to_call_arguments_without_rewriting_bait() {
        let source = r#"
impl Phase {
    fn execute() {
        Self::helper(live_config, live_provider);
    }
    fn helper(config: Config, provider: Provider) {
        let _ = "config provider";
        // config provider
        consume(config, provider);
    }
}
"#;
        let expanded = expand(source).expect("parameter remap").virtual_source;
        assert!(
            expanded.contains("consume(live_config, live_provider)"),
            "{expanded}"
        );
        assert!(expanded.contains("\"config provider\""), "{expanded}");
        assert!(expanded.contains("// config provider"), "{expanded}");
    }

    #[test]
    fn non_direct_helper_contexts_fail_closed() {
        let cases = [
            ("cfg expression", "#[cfg(test)] Self::helper();"),
            ("conditional branch", "if enabled() { Self::helper(); }"),
            ("loop body", "while enabled() { Self::helper(); }"),
            ("arbitrary closure", "let _deferred = || Self::helper();"),
            (
                "unawaited async block",
                "let _deferred = async { Self::helper(); };",
            ),
            (
                "unawaited once funnel",
                "let _deferred = after_required_preflight(input, |_| Self::helper());",
            ),
            ("macro tokens", "defer! { Self::helper() }"),
        ];
        for (label, call) in cases {
            let source = format!(
                "impl Phase {{ fn execute() {{ {call} }} fn helper() {{ live_helper_body(); }} }}"
            );
            assert!(
                expand(&source).is_err(),
                "{label} must not contribute production helper evidence"
            );
        }

        let conditional_definition = r#"
impl Phase {
    fn execute() { Self::helper(); }
    #[cfg(test)]
    fn helper() { test_only_evidence(); }
}
"#;
        assert!(matches!(
            expand(conditional_definition),
            Err(PhaseExpandError::NonDirectCall(detail))
                if detail.contains("conditional helper definition")
        ));
    }

    #[test]
    fn only_structurally_direct_async_and_once_funnel_contexts_expand() {
        let source = r#"
impl Phase {
    fn execute() {
        let result = async {
            Self::first();
            after_required_preflight(input, |verified| Self::second(verified)).await?;
            Ok(())
        }.await;
    }
    fn first() { first_evidence(); }
    fn second(verified: Verified) { second_evidence(verified); }
}
"#;
        let expanded = expand(source)
            .expect("direct awaited async and canonical once funnel must expand")
            .virtual_source;
        assert!(expanded.contains("first_evidence()"), "{expanded}");
        assert!(expanded.contains("second_evidence(verified)"), "{expanded}");
    }

    #[test]
    fn dead_helper_body_never_becomes_entry_evidence() {
        let source = r#"
impl Phase {
    fn execute() { entry_only(); }
    fn dead_helper() { live_helper_body(); }
}
"#;
        let expanded = expand(source).expect("entry expansion").virtual_source;
        assert!(!expanded.contains("live_helper_body()"), "{expanded}");
    }
}
