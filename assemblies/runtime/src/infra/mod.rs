pub mod oidc;
pub mod pg;
pub mod redis;
pub mod s3;
pub mod vault;

use secure::PlaintextEndpointPolicy;

pub(crate) fn plaintext_endpoint_policy_from(
    get: impl Fn(&str) -> Option<String>,
    env: &str,
) -> anyhow::Result<PlaintextEndpointPolicy> {
    let Some(raw) = get(env) else {
        return Ok(PlaintextEndpointPolicy::Deny);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(PlaintextEndpointPolicy::AllowLoopback),
        "dev-container" => Ok(PlaintextEndpointPolicy::AllowDevContainer),
        "0" | "false" | "no" => Ok(PlaintextEndpointPolicy::Deny),
        _ => anyhow::bail!("{env} must be false, true, or dev-container"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure::PlaintextEndpointPolicy;

    #[test]
    fn plaintext_endpoint_policy_accepts_dev_container_explicitly() {
        const ENV: &str = "RSS_REDIS_ALLOW_PLAINTEXT";
        let policy = plaintext_endpoint_policy_from(
            |name| (name == ENV).then(|| "dev-container".to_string()),
            ENV,
        );
        assert!(
            matches!(policy, Ok(PlaintextEndpointPolicy::AllowDevContainer)),
            "dev-container 是 demo compose 明文策略的唯一非 loopback opt-in"
        );
    }
}
