// rss_diport_envelope_reserved_writer UI fixture（callsite **不在** allowlist：
// example crate manifest 父目录为 `lints/rss_diport_envelope_reserved_writer`，父 `lints` ∉
// adapters/bins/assemblies ⇒ insert_wire_pair 触发；try_insert / item-level #[allow] 不触发）。
// golden 见 main.stderr；须用真 diport（dev-dep）：lint 按方法 DefId krate 名（diport）匹配，
// 本地同名 struct 方法 DefId krate 非 diport，无法触发。
// allow(unknown_lints)：普通 cargo build 本 example 时不认 rss_diport_envelope_reserved_writer，
// 抑制 G2 逃生门演示处 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
#![allow(unused, unknown_lints)]

use diport::EnvelopeMetadata;

// R1：非 allowlist crate 调 insert_wire_pair（reserved-capable 透传写面）→ 触发。
fn disallowed_wire_write() {
    let mut md = EnvelopeMetadata::empty();
    md.insert_wire_pair("trace", "abc");
}

// G1（specificity anti-vacuity）：try_insert 不触发——证明 lint 非「任意 EnvelopeMetadata 方法调用」。
fn allowed_business_write() {
    let mut md = EnvelopeMetadata::empty();
    let _ = md.try_insert("requestPath", "/login");
}

// G2（逃生门）：item-level #[allow] 抑制。
#[allow(rss_diport_envelope_reserved_writer)] // reason: UI fixture 验证逃生门
fn escape_hatch_example() {
    let mut md = EnvelopeMetadata::empty();
    md.insert_wire_pair("trace", "xyz");
}

// Dead-code / string bait must not satisfy the lint vacuously.
#[allow(dead_code)]
fn string_bait() {
    let _ = "insert_wire_pair";
}

fn main() {}
