// rss_redact_debug_required UI fixture（红例 + 绿子例）。
// 须用 #![allow(unknown_lints)]：普通 `cargo build` 本 example 时不认 rss_redact_debug_required
// （仅 dylint driver 认），抑制 escape hatch 处的 unknown_lints 噪声。
#![allow(dead_code, unknown_lints)]

// R（红例）：高风险敏感 DTO 裸 derive(Debug)。
#[derive(Debug)]
struct AuditEvent {
    principal_id: String,
}

#[derive(Debug)]
struct RoleBinding {
    subject: String,
}

#[derive(Debug)]
struct Session {
    id: String,
}

#[derive(Debug)]
struct SessionId(String);

#[derive(Debug)]
struct RequestCtx {
    tenant: String,
}

#[derive(Debug)]
struct PrincipalSlot(String);

#[derive(Debug)]
struct SecretMaterial(Vec<u8>);

#[derive(Debug)]
struct SecretCoordinate {
    version: String,
}

// G1：普通类型 derive(Debug) 放行，避免 lint 退化成全仓禁 Debug。
#[derive(Debug)]
struct HarmlessDiagnostic {
    value: String,
}

// G2：高风险类型改用 secure::Redact 放行。
mod redact_ok {
    #[derive(secure::Redact)]
    struct RoleBinding {
        #[redact(sensitivity = pii)]
        subject: String,
        #[redact(sensitivity = public)]
        role_id: String,
    }
}

// G3：item-level escape hatch 可用，必须带 reason。
mod allow_ok {
    #[allow(rss_redact_debug_required)] // reason: UI fixture 验证逃生门
    #[derive(Debug)]
    struct Session {
        id: String,
    }
}

fn main() {}
