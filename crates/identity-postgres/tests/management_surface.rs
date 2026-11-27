//! Syntax-aware source guard: password candidates may issue sessions, never manage accounts.
//! ref: syn visit::Visit (full Rust syntax tree, including impl methods and aliases).
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use syn::visit::{self, Visit};
#[derive(Default)]
struct References(BTreeSet<String>);
impl<'a> Visit<'a> for References {
    fn visit_path(&mut self, path: &'a syn::Path) {
        if let Some(segment) = path.segments.last() {
            self.0.insert(segment.ident.to_string());
        }
        visit::visit_path(self, path);
    }
}
struct Surface<'a> {
    aliases: &'a BTreeSet<String>,
    checked: usize,
    rejected: Vec<String>,
}
impl Surface<'_> {
    fn signature(&mut self, visibility: &syn::Visibility, sig: &syn::Signature) {
        if !matches!(visibility, syn::Visibility::Public(_)) {
            return;
        }
        self.checked += 1;
        let mut refs = References::default();
        refs.visit_generics(&sig.generics);
        for arg in &sig.inputs {
            refs.visit_fn_arg(arg);
        }
        refs.visit_return_type(&sig.output);
        if !refs.0.is_disjoint(self.aliases) {
            self.rejected.push(sig.ident.to_string());
        }
    }
}
impl<'a> Visit<'a> for Surface<'_> {
    fn visit_item_trait(&mut self, item: &'a syn::ItemTrait) {
        if matches!(item.vis, syn::Visibility::Public(_)) {
            for member in &item.items {
                if let syn::TraitItem::Fn(function) = member {
                    self.signature(&item.vis, &function.sig);
                }
            }
        }
        visit::visit_item_trait(self, item);
    }

    fn visit_item_fn(&mut self, f: &'a syn::ItemFn) {
        self.signature(&f.vis, &f.sig);
        visit::visit_item_fn(self, f);
    }
    fn visit_impl_item_fn(&mut self, f: &'a syn::ImplItemFn) {
        self.signature(&f.vis, &f.sig);
        visit::visit_impl_item_fn(self, f);
    }
}
struct Aliases<'a>(&'a mut BTreeSet<String>);
impl<'a> Visit<'a> for Aliases<'_> {
    fn visit_item_type(&mut self, item: &'a syn::ItemType) {
        let mut refs = References::default();
        refs.visit_type(&item.ty);
        if !refs.0.is_disjoint(self.0) {
            self.0.insert(item.ident.to_string());
        }
        visit::visit_item_type(self, item);
    }
    fn visit_use_rename(&mut self, item: &'a syn::UseRename) {
        if self.0.contains(&item.ident.to_string()) {
            self.0.insert(item.rename.to_string());
        }
    }
}
fn check(files: &[(PathBuf, String)]) -> (usize, Vec<String>) {
    let trees: Vec<_> = files
        .iter()
        .map(|(_, text)| syn::parse_file(text).expect("parse canonical Rust source"))
        .collect();
    let mut aliases = BTreeSet::from(["AuthenticationCandidate".to_owned()]);
    loop {
        let before = aliases.len();
        for tree in &trees {
            Aliases(&mut aliases).visit_file(tree);
        }
        if before == aliases.len() {
            break;
        }
    }
    let mut checked = 0;
    let mut rejected = Vec::new();
    for ((path, _), tree) in files.iter().zip(trees.iter()) {
        let mut surface = Surface {
            aliases: &aliases,
            checked: 0,
            rejected: vec![],
        };
        surface.visit_file(tree);
        checked += surface.checked;
        rejected.extend(
            surface
                .rejected
                .into_iter()
                .map(|name| format!("{}:{name}", path.display())),
        );
    }
    (checked, rejected)
}
fn sources(root: &Path, path: &Path, out: &mut Vec<(PathBuf, String)>) {
    for entry in std::fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push((
                path.strip_prefix(root).unwrap().into(),
                std::fs::read_to_string(path).unwrap(),
            ));
        }
    }
}
#[test]
fn public_management_surface_never_accepts_password_candidates() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![];
    sources(&root, &root, &mut files);
    let (count, rejected) = check(&files);
    assert!(count > 30, "empty or incomplete canonical surface");
    assert!(rejected.is_empty(), "{rejected:?}");
}
#[test]
fn guard_detects_new_modules_parameter_renames_aliases_and_sync_functions() {
    let source = "use crate::AuthenticationCandidate as PasswordProof; type Alias = PasswordProof; impl Authority { pub fn manage(&self, renamed: &Alias) {} pub async fn other(&self, p: Option<crate::AuthenticationCandidate>) {} }";
    let (count, rejected) = check(&[("new/module.rs".into(), source.into())]);
    assert_eq!(count, 2);
    assert_eq!(rejected.len(), 2);
    let (_, rejected) = check(&[(
        "sessions.rs".into(),
        "impl Authority { pub fn create_session(&self, proof: AuthenticationCandidate) {} }".into(),
    )]);
    assert_eq!(rejected.len(), 1);
}

#[test]
fn guard_covers_public_traits_and_generic_candidate_bounds() {
    let source = "pub trait Management { fn change(&self, proof: AuthenticationCandidate); } pub fn update<T: Into<AuthenticationCandidate>>(proof: T) {}";
    let (_, rejected) = check(&[("new.rs".into(), source.into())]);
    assert_eq!(rejected.len(), 2);
}
