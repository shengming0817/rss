pub mod oidc;
pub mod pg;
pub mod redis;
pub mod s3;
pub mod signing_rotation;
pub mod vault;

use anyhow::Context as _;
use secure::PlaintextEndpointPolicy;

/// Parse ingress plaintext opt-in (`RSS_LISTENER_ALLOW_PLAINTEXT` only after #1710).
///
/// Egress paths (AMQP / Redis / S3) hardcode [`PlaintextEndpointPolicy::Deny`] and must not call
/// this helper.
pub(crate) fn plaintext_endpoint_policy_from_value(
    raw: Option<&str>,
    env: &str,
) -> anyhow::Result<PlaintextEndpointPolicy> {
    let Some(raw) = raw else {
        return Ok(PlaintextEndpointPolicy::Deny);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(PlaintextEndpointPolicy::AllowLoopback),
        "dev-container" => Ok(PlaintextEndpointPolicy::AllowDevContainer),
        "0" | "false" | "no" => Ok(PlaintextEndpointPolicy::Deny),
        _ => anyhow::bail!("{env} must be false, true, or dev-container"),
    }
}

/// Read a required private-CA PEM bundle path for production egress wiring (#1710).
///
/// Fail-fast when missing, empty, or unreadable. Does not log PEM contents.
/// Stable self-signed CA PEM shared by runtime unit/integration fixtures (#1710 / PR #642 F11).
///
/// Single source for Redis/AMQP/S3/PG/config hermetic trust-anchor bait; do not duplicate.
#[cfg(any(test, feature = "integration"))]
pub(crate) const TEST_PRIVATE_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDDTCCAfWgAwIBAgIUEW6UI4WQFqp8ELHVrDu8jZ9rP3kwDQYJKoZIhvcNAQEL\n\
BQAwFjEUMBIGA1UEAwwLcnNzLXRlc3QtY2EwHhcNMjYwNzMwMTk0NDM4WhcNMzYw\n\
NzI3MTk0NDM4WjAWMRQwEgYDVQQDDAtyc3MtdGVzdC1jYTCCASIwDQYJKoZIhvcN\n\
AQEBBQADggEPADCCAQoCggEBAJr3yUyUHXnTgF4ekrZdrw7KEttnk/GXt4t/ozWN\n\
lApGpaDF/eB3BmJkcKydyR4Nc/1Dd32uh31+G/dseRwnNJHcce1Vkzpn1Ke+irCM\n\
GBpS+KTdTfyDYb4j1quTh0m00IJN4fotTcBenuXlIFqIo7Q5JIavxDYNljfVLY6D\n\
u5kb8aApjeMaTVoF0TKc+NwRXorjMNKvZtCnUd5uCT0xU74Dvpjn8tjCTWGf78DN\n\
o8ELzkc9ioADyqYYRTX5GzrnEwa3GpQ9F5bPPyntcEMNp07lJk+qoEr4n6YuAodR\n\
5m3ed6PGKfudDur3goMPeLwzHSWEZ3SZrmR0EbLQg0y73J0CAwEAAaNTMFEwHQYD\n\
VR0OBBYEFGsKTekKRnrTlNwL1eofBNEq6pdcMB8GA1UdIwQYMBaAFGsKTekKRnrT\n\
lNwL1eofBNEq6pdcMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n\
AJPZrazNlWIWA5LwTmMGHPqBr/2X6VmGUh/5mCnU/O+y5ublcJkHCgD5FJMe4qxP\n\
QmebdwQo3WIFJD1VRnNk0ueYBMO3lac0yiJAvq2+2ATjBlbS96xHNMJ5FG33NTB1\n\
2joqQTQtsZKoTkOshZv9frromYnl7M8Gga/+GahNSN+bf9LAP7lxtZiP/gztdJqF\n\
R61mmgXBg2nKHurNaNrvJe7pQQobAyv5Hwz4kftJyAuBbNYvx0Gdri9UAzb/v4PK\n\
qf2zLCk/JuqtLitsYdWX2pSy5nAcZx5wlQiBMyEnN8p4qFuNCPHQLdgi+rmPjOvT\n\
1s3J9lHqm/Y6JXdErSSSoiw=\n\
-----END CERTIFICATE-----\n";

pub(crate) fn read_required_ca_pem(
    raw: Option<&str>,
    env: &'static str,
) -> anyhow::Result<Vec<u8>> {
    let path = raw.ok_or_else(|| anyhow::anyhow!("missing required env var: {env}"))?;
    let trimmed = path.trim();
    anyhow::ensure!(!trimmed.is_empty(), "{env} must not be empty");
    let pem = std::fs::read(trimmed).with_context(|| format!("read {env} PEM CA bundle"))?;
    anyhow::ensure!(
        !pem.is_empty(),
        "{env} must contain at least one PEM CA certificate"
    );
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure::PlaintextEndpointPolicy;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn plaintext_endpoint_policy_accepts_dev_container_explicitly() {
        const ENV: &str = "RSS_LISTENER_ALLOW_PLAINTEXT";
        let policy = plaintext_endpoint_policy_from_value(Some("dev-container"), ENV);
        assert!(
            matches!(policy, Ok(PlaintextEndpointPolicy::AllowDevContainer)),
            "dev-container 是 ingress demo compose 明文策略的唯一非 loopback opt-in"
        );
    }

    #[test]
    #[allow(clippy::expect_used, clippy::cognitive_complexity)]
    fn read_required_ca_pem_fails_fast_for_missing_empty_and_unreadable() {
        const ENV: &str = "RSS_TEST_CA_CERT_PEM_PATH";

        let missing = read_required_ca_pem(None, ENV);
        assert!(
            matches!(&missing, Err(e) if format!("{e:#}").contains(ENV)),
            "missing path must fail-fast: {missing:?}"
        );

        let empty = read_required_ca_pem(Some("   "), ENV);
        assert!(
            matches!(&empty, Err(e) if format!("{e:#}").contains("must not be empty")),
            "empty path must fail-fast: {empty:?}"
        );

        let empty_file =
            std::env::temp_dir().join(format!("rss-empty-ca-{}.pem", std::process::id()));
        std::fs::write(&empty_file, b"").expect("write empty CA");
        let empty_pem = read_required_ca_pem(empty_file.to_str(), ENV);
        let _ = std::fs::remove_file(&empty_file);
        assert!(
            matches!(&empty_pem, Err(e) if format!("{e:#}").contains("at least one PEM")),
            "empty PEM file must fail-fast: {empty_pem:?}"
        );

        let missing_file =
            std::env::temp_dir().join(format!("rss-missing-ca-{}.pem", std::process::id()));
        let _ = std::fs::remove_file(&missing_file);
        let unreadable_path = read_required_ca_pem(missing_file.to_str(), ENV);
        assert!(
            matches!(&unreadable_path, Err(e) if format!("{e:#}").contains("read")),
            "missing file must fail-fast: {unreadable_path:?}"
        );

        let unreadable =
            std::env::temp_dir().join(format!("rss-unreadable-ca-{}.pem", std::process::id()));
        {
            let mut file = std::fs::File::create(&unreadable).expect("create unreadable CA");
            file.write_all(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
                .expect("write CA bytes");
        }
        let mut perms = std::fs::metadata(&unreadable)
            .expect("stat unreadable CA")
            .permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&unreadable, perms).expect("chmod unreadable CA");
        let denied = read_required_ca_pem(unreadable.to_str(), ENV);
        let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::remove_file(&unreadable);
        assert!(
            matches!(&denied, Err(e) if format!("{e:#}").contains("read")),
            "unreadable PEM must fail-fast: {denied:?}"
        );
    }
}
