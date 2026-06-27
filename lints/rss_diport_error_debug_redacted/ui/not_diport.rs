// rss_diport_error_debug_redacted UI fixture（LOCAL_CRATE == "not_diport"，不在守护名单，全绿）。
// golden ui/not_diport.stderr 为空（anti-vacuity：验 LOCAL_CRATE 分支非恒报——
// 同形 `Box<dyn Error>` 字段在非守护 crate 不触发）。
#![allow(dead_code, unused)]

// G（全绿）：与红例完全相同的字段形状，但 LOCAL_CRATE=="not_diport" 不在守护名单 → 不触发。
// 证明 lint 非工作区全局。
struct SomeError {
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

fn main() {}
