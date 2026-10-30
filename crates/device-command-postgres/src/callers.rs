//! Explicit deployment intent, never a database admission proof.
use std::sync::Arc;

/// Immutable, nonempty set of independent database login names allowed to call this component.
///
/// Names are exact catalog names, not SQL identifiers: no quoting, trimming or case folding is
/// performed. Every store validates the entire declaration against its own transaction. Cloning
/// this value shares only deployment intent; it grants no transaction or runtime authority.
#[derive(Clone)]
pub struct CallerRoles(Arc<[String]>);

/// A caller declaration is empty or contains an empty, NUL-containing or duplicate name.
#[derive(Debug, thiserror::Error)]
#[error("invalid device command caller roles")]
pub struct CallerRolesError;

impl CallerRoles {
    /// Declare all component callers. Existence and effective privileges are checked by the store.
    pub fn new(names: &[&str]) -> Result<Self, CallerRolesError> {
        if names.is_empty()
            || names.iter().enumerate().any(|(index, name)| {
                name.is_empty() || name.contains('\0') || names[..index].contains(name)
            })
        {
            return Err(CallerRolesError);
        }
        Ok(Self(names.iter().map(|name| (*name).to_owned()).collect()))
    }

    pub(crate) fn names(&self) -> &[String] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_declarations_are_unrepresentable() {
        for names in [&[][..], &[""], &["runtime\0suffix"], &["a", "a"]] {
            assert!(CallerRoles::new(names).is_err());
        }
    }

    #[test]
    fn declaration_owns_exact_names_without_normalization() -> Result<(), CallerRolesError> {
        let roles = {
            let name = String::from("角色 With Spaces");
            CallerRoles::new(&[&name, "runtime", "Runtime", " runtime "])?
        };
        assert_eq!(
            roles.clone().names(),
            ["角色 With Spaces", "runtime", "Runtime", " runtime "]
        );
        Ok(())
    }
}
