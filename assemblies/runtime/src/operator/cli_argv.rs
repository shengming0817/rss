//! Shared hand-rolled argv helpers for operator commands not yet on clap.

#![forbid(unused_imports)]
#![forbid(clippy::wildcard_imports)]

pub(super) fn set_cli_arg_once<T>(
    slot: &mut Option<T>,
    flag: &str,
    value: T,
) -> anyhow::Result<()> {
    anyhow::ensure!(slot.is_none(), "{flag} must not be repeated");
    *slot = Some(value);
    Ok(())
}

pub(super) fn next_cli_value<'a>(
    it: &mut std::slice::Iter<'a, String>,
    flag: &str,
) -> anyhow::Result<&'a str> {
    it.next()
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}
