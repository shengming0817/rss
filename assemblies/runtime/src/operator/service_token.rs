use std::fmt;
use std::io::{BufRead, Read as _};

use anyhow::Context as _;

pub(super) const OPERATOR_SERVICE_TOKEN_STDIN_FLAG: &str = "--operator-service-token-stdin";
const MAX_OPERATOR_SERVICE_TOKEN_BYTES: usize = 16 * 1024;
const MAX_OPERATOR_SERVICE_TOKEN_INPUT_BYTES: u64 = (MAX_OPERATOR_SERVICE_TOKEN_BYTES + 3) as u64;

/// A single owned operator service token captured from stdin.
///
/// The inner `SecretText` zeroizes on drop. This carrier intentionally has no `Clone`, `Display`,
/// or serialization surface, and its only formatting implementation is redacted.
pub(super) struct OperatorServiceToken(secure::SecretText);

impl OperatorServiceToken {
    pub(super) fn as_str(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for OperatorServiceToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorServiceToken(<redacted>)")
    }
}

/// Validate and remove the unique stdin carrier flag before family-specific parsing.
pub(super) fn parse_operator_service_token_stdin_args(
    args: &[String],
) -> anyhow::Result<Vec<String>> {
    let mut seen = false;
    let mut command_args = Vec::with_capacity(args.len().saturating_sub(1));
    for arg in args {
        if arg == OPERATOR_SERVICE_TOKEN_STDIN_FLAG {
            anyhow::ensure!(
                !seen,
                "{OPERATOR_SERVICE_TOKEN_STDIN_FLAG} must not be repeated"
            );
            seen = true;
        } else {
            command_args.push(arg.clone());
        }
    }
    anyhow::ensure!(seen, "{OPERATOR_SERVICE_TOKEN_STDIN_FLAG} is required");
    Ok(command_args)
}

/// Read exactly one bounded UTF-8 token, optionally followed by one LF or CRLF.
pub(super) fn read_operator_service_token_stdin(
    stdin: &mut impl BufRead,
) -> anyhow::Result<OperatorServiceToken> {
    let mut raw = zeroize::Zeroizing::new(Vec::new());
    stdin
        .take(MAX_OPERATOR_SERVICE_TOKEN_INPUT_BYTES)
        .read_to_end(&mut raw)
        .context("read operator service token from stdin")?;
    operator_service_token_from_bytes(raw)
}

fn operator_service_token_from_bytes(
    mut raw: zeroize::Zeroizing<Vec<u8>>,
) -> anyhow::Result<OperatorServiceToken> {
    anyhow::ensure!(
        raw.len() <= MAX_OPERATOR_SERVICE_TOKEN_BYTES + 2,
        "operator service token stdin exceeds {MAX_OPERATOR_SERVICE_TOKEN_BYTES} bytes"
    );
    let mut raw = match String::from_utf8(std::mem::take(&mut *raw)) {
        Ok(raw) => zeroize::Zeroizing::new(raw),
        Err(error) => {
            let _invalid = zeroize::Zeroizing::new(error.into_bytes());
            anyhow::bail!("operator service token stdin must be UTF-8");
        }
    };
    if raw.ends_with("\r\n") {
        let token_len = raw.len() - 2;
        raw.truncate(token_len);
    } else if raw.ends_with('\n') {
        let token_len = raw.len() - 1;
        raw.truncate(token_len);
    }
    anyhow::ensure!(
        !raw.is_empty(),
        "operator service token stdin must be non-empty"
    );
    anyhow::ensure!(
        raw.len() <= MAX_OPERATOR_SERVICE_TOKEN_BYTES,
        "operator service token stdin exceeds {MAX_OPERATOR_SERVICE_TOKEN_BYTES} bytes"
    );
    anyhow::ensure!(
        !raw.chars().any(char::is_whitespace),
        "operator service token stdin must contain exactly one token with at most one LF or CRLF terminator"
    );
    Ok(OperatorServiceToken(secure::SecretText::from_string(
        std::mem::take(&mut *raw),
    )))
}

#[cfg(test)]
mod tests {
    use super::operator_service_token_from_bytes;

    #[test]
    fn validated_token_moves_the_original_zeroizing_allocation() -> anyhow::Result<()> {
        let raw = zeroize::Zeroizing::new(b"opaque-token\n".to_vec());
        let allocation = raw.as_ptr();
        let token = operator_service_token_from_bytes(raw)?;
        assert_eq!(token.as_str(), "opaque-token");
        assert_eq!(token.as_str().as_ptr(), allocation);
        Ok(())
    }
}
