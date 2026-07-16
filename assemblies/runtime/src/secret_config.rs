/// Composition-root validation wrapper around the shared zeroizing secret carrier.
///
/// The field stays private to this sibling module. Runtime consumers can validate equality only
/// through [`EnvSecret::differs_from`] and can hand ownership to an approved zeroizing sink only
/// through the two explicitly named allocation funnels.
#[derive(secure::Redact)]
pub(crate) struct EnvSecret(#[redact(sensitivity = secret)] secure::SecretText);

impl EnvSecret {
    pub(crate) fn required_value(value: Option<&str>, name: &'static str) -> anyhow::Result<Self> {
        let value = value.ok_or_else(|| anyhow::anyhow!("missing required env var: {name}"))?;
        anyhow::ensure!(!value.is_empty(), "{name} must not be empty");
        anyhow::ensure!(
            value.trim() == value,
            "{name} must not have leading or trailing whitespace"
        );
        Ok(Self(secure::SecretText::from_string(value.to_owned())))
    }

    pub(crate) fn optional_value(
        value: Option<&str>,
        name: &'static str,
    ) -> anyhow::Result<Option<Self>> {
        value
            .map(|value| Self::required_value(Some(value), name))
            .transpose()
    }

    pub(crate) fn required(
        get: &impl Fn(&str) -> Option<String>,
        name: &'static str,
    ) -> anyhow::Result<Self> {
        let value = get(name);
        Self::required_value(value.as_deref(), name)
    }

    pub(crate) fn optional(
        get: &impl Fn(&str) -> Option<String>,
        name: &'static str,
    ) -> anyhow::Result<Option<Self>> {
        let value = get(name);
        Self::optional_value(value.as_deref(), name)
    }

    pub(crate) fn differs_from(&self, other: &Self) -> bool {
        self.0.expose() != other.0.expose()
    }

    #[must_use = "the copied secret allocation must enter another secret owner"]
    pub(crate) fn copy_secret_allocation(&self) -> String {
        self.0.expose().to_owned()
    }

    pub(crate) fn transfer_secret_allocation(self) -> String {
        self.0.into_string()
    }
}
