//! rss_instrument_err_level UI fixture。
//! golden 见 main.stderr：
//!   RED：裸 `err` / `err,` / 无 `level` 的 `err(...)`（`err(Debug)` / `err(Display)` / `err()`）
//!   GREEN：`err(level = "warn")` / `err(level = "error")` / item-level allow / 无 err meta
//! allow(unknown_lints)：普通 cargo build 本 example 时不认本 lint（仅 dylint driver 认）。
#![allow(unused, unknown_lints)]

// R1：裸 `err` → 触发。
#[tracing::instrument(err)]
fn bare_err() -> Result<(), &'static str> {
    Err("client")
}

// R2：`err` 与其它 meta 并列（`,` 后裸 err）→ 触发。
#[tracing::instrument(skip_all, err)]
fn bare_err_after_comma() -> Result<(), &'static str> {
    Err("client")
}

// R3：`use tracing::instrument` 短路径裸 err → 触发。
use tracing::instrument;

#[instrument(err, ret)]
fn bare_err_short_path() -> Result<(), &'static str> {
    Err("client")
}

// R4：`err(Debug)` 仍默认 ERROR、无 `level` → 触发。
#[tracing::instrument(err(Debug))]
fn err_debug_format() -> Result<(), &'static str> {
    Err("client")
}

// R5：`err(Display)` 仍默认 ERROR、无 `level` → 触发。
#[tracing::instrument(err(Display))]
fn err_display_format() -> Result<(), &'static str> {
    Err("client")
}

// R6：空 `err()` 仍默认 ERROR、无 `level` → 触发。
#[tracing::instrument(err())]
fn err_empty_parens() -> Result<(), &'static str> {
    Err("client")
}

// G1：显式 warn level → 不触发。
#[tracing::instrument(err(level = "warn"))]
fn err_level_warn() -> Result<(), &'static str> {
    Err("client")
}

// G2：显式 error level → 不触发。
#[tracing::instrument(skip_all, err(level = "error"))]
fn err_level_error() -> Result<(), &'static str> {
    Err("server")
}

// G3：无 err meta → 不触发。
#[tracing::instrument(ret)]
fn ret_only() -> Result<(), &'static str> {
    Ok(())
}

// G4：item-level allow 逃生 → 不触发。
#[allow(rss_instrument_err_level)] // reason: UI fixture 验证逃生门
#[tracing::instrument(err)]
fn allowed_bare_err() -> Result<(), &'static str> {
    Err("exempt")
}

fn main() {}
