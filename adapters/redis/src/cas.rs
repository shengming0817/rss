//! Redis state-CAS provider (`diport::CasStore`).

use diport::{CasStore, CasStoreError, CasStoreOutcome, CasStoreRequest, RedactedBytes};

use crate::bundle::RedisCasStore;

const RESOURCE: &str = "redis";
const REDIS_CMD_EVAL: &str = "EVAL";
const CAS_NAMESPACE: &str = "_runtime:cas";

const STATUS_APPLIED: i64 = 1;
const STATUS_CONFLICT: i64 = 2;
const STATUS_FENCED: i64 = 3;
const STATUS_TOKEN_OVERFLOW: i64 = 4;
const EXPECTED_NONE: &str = "none";
const EXPECTED_SOME: &str = "some";
const MAX_LUA_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

// KEYS[1] = CAS hash key.
// ARGV[1] = expected mode ("none"|"some"), ARGV[2] = expected value bytes,
// ARGV[3] = new value bytes, ARGV[4] = expected fencing token or "",
// ARGV[5] = max Lua-safe integer token.
// Returns {1,next_token}=Applied, {2,current_token}=Conflict,
// {3,current_token}=Fenced, {4,current_token}=token overflow.
const LUA_CAS: &str = r#"
local current = redis.call('HGET', KEYS[1], 'value')
local current_token = redis.call('HGET', KEYS[1], 'token')
if current_token and ARGV[4] ~= '' and tonumber(ARGV[4]) < tonumber(current_token) then
  return {3, tonumber(current_token)}
end
if ARGV[1] == 'none' then
  if current then
    return {2, tonumber(current_token)}
  end
else
  if not current or current ~= ARGV[2] then
    if current_token then
      return {2, tonumber(current_token)}
    end
    return {2, 0}
  end
end
local next_token = 1
if current_token then
  next_token = tonumber(current_token) + 1
  if next_token > tonumber(ARGV[5]) then
    return {4, tonumber(current_token)}
  end
end
redis.call('HSET', KEYS[1], 'value', ARGV[3], 'token', next_token)
return {1, next_token}
"#;

fn cas_key(raw: &str) -> String {
    format!("{CAS_NAMESPACE}:{}:{raw}", raw.len())
}

fn cas_error<E>(operation: &'static str, error: E) -> CasStoreError
where
    E: std::error::Error + Send + Sync + 'static,
{
    tracing::warn!(
        resource = RESOURCE,
        operation,
        error = %secure::redact_error(&error),
        "redis cas operation failed"
    );
    CasStoreError::new(error)
}

async fn read_current(
    pool: &deadpool_redis::Pool,
    key: &str,
) -> Result<Option<RedactedBytes>, CasStoreError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| cas_error("cas-read-current-pool", e))?;
    let current: Option<Vec<u8>> = deadpool_redis::redis::cmd("HGET")
        .arg(key)
        .arg("value")
        .query_async(&mut *conn)
        .await
        .map_err(|e| cas_error("cas-read-current", e))?;
    Ok(current.map(RedactedBytes::new))
}

impl CasStore for RedisCasStore {
    async fn compare_and_swap(
        &self,
        request: CasStoreRequest,
    ) -> Result<CasStoreOutcome, CasStoreError> {
        let redis_key = cas_key(request.key.as_str());
        let expected_mode = if request.expected.is_some() {
            EXPECTED_SOME
        } else {
            EXPECTED_NONE
        };
        let expected = request.expected.as_ref().map(RedactedBytes::as_bytes);
        let expected_token = request
            .expected_token
            .map(|t| t.get().to_string())
            .unwrap_or_default();
        let mut conn = self
            .store()
            .pool()
            .get()
            .await
            .map_err(|e| cas_error("cas-pool", e))?;
        let (status, token): (i64, u64) = deadpool_redis::redis::cmd(REDIS_CMD_EVAL)
            .arg(LUA_CAS)
            .arg(1)
            .arg(&redis_key)
            .arg(expected_mode)
            .arg(expected.unwrap_or(&[]))
            .arg(request.new_value.as_bytes())
            .arg(expected_token)
            .arg(MAX_LUA_SAFE_INTEGER)
            .query_async(&mut *conn)
            .await
            .map_err(|e| cas_error("cas-eval", e))?;
        match status {
            STATUS_APPLIED => Ok(CasStoreOutcome::Applied {
                token: vocab::Epoch::new(token),
            }),
            STATUS_CONFLICT => Ok(CasStoreOutcome::Conflict {
                current: read_current(self.store().pool(), &redis_key).await?,
            }),
            STATUS_FENCED => Ok(CasStoreOutcome::Fenced {
                current_token: vocab::Epoch::new(token),
            }),
            STATUS_TOKEN_OVERFLOW => Err(CasStoreError::new(std::io::Error::other(
                "redis cas token exceeds Lua safe integer range",
            ))),
            _ => Err(CasStoreError::new(std::io::Error::other(
                "redis cas returned unknown status",
            ))),
        }
    }

    async fn shutdown(&self) -> Result<(), CasStoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cas_key_uses_length_prefix() {
        assert_ne!(cas_key("a:b:c"), cas_key("a:b"));
        assert_eq!(cas_key("abc"), "_runtime:cas:3:abc");
    }
}
