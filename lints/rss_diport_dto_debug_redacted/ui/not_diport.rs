// rss_diport_dto_debug_redacted UI fixture（LOCAL_CRATE == "not_diport"，不在守护范围，全绿）。
// golden ui/not_diport.stderr 为空（anti-vacuity：验 LOCAL_CRATE 分支非恒报——
// 同形字节缓冲字段在非 diport crate 不触发）。
#![allow(dead_code, unused)]

// G（全绿）：与红例完全相同的字段形状，但 LOCAL_CRATE=="not_diport" 不在守护范围 → 不触发。
// 证明 lint 非工作区全局，只守 diport crate。
struct A {
    f: Vec<u8>,
}

struct B {
    f: [u8; 32],
}

struct C {
    f: Box<[u8]>,
}

struct D {
    f: Option<Vec<u8>>,
}

fn main() {}
