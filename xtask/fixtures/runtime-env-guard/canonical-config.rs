struct RuntimeConfigKey;
impl RuntimeConfigKey { fn as_str(&self) -> &str { "RSS_RUNTIME_CONFIG" } }
struct EnvConfigSource;
impl EnvConfigSource { fn read(&mut self, key: &RuntimeConfigKey) { let _ = std::env::var_os(key.as_str()); } }
