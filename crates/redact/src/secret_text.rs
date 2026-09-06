/// Owned UTF-8 secret material with opaque formatting and drop-time zeroization.
///
/// `SecretText` deliberately exposes neither `Clone`, `Display`, nor serialization. Callers must
/// make secret access explicit through [`SecretText::expose`] or transfer the allocation with
/// [`SecretText::into_string`].
///
/// INVARIANT: SECRET-TEXT-OPAQUE-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" } -- the private field, restricted API, `Redact`, and absence of `Clone`/`Display`/serialization prevent implicit disclosure; `ZeroizeOnDrop` clears the allocation while this owner retains it.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct SecretText(String);

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretText(<redacted>)")
    }
}

impl crate::Redact for SecretText {
    fn redact_scoped(&self, _scope: crate::RedactScope) -> String {
        format!("{self:?}")
    }
}

impl SecretText {
    /// Take ownership of an existing UTF-8 secret allocation without normalization.
    pub fn from_string(value: String) -> Self {
        Self(value)
    }

    /// Explicitly borrow the secret text.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Explicitly transfer the allocation to the next secret owner.
    ///
    /// Drop-time zeroization no longer covers the returned owner; callers must move it directly
    /// into another zeroizing secret carrier.
    #[must_use = "the transferred secret allocation must enter another secret owner"]
    pub fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}
