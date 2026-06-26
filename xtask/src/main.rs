//! xtask — RSS 治理 / codegen 入口。见 docs/rules/architecture.md §xtask、§Rust 原生强制（三档载体）。
//!
//! 子命令：
//!   `cargo xtask codegen [--check]`     契约 schema → committed `generated/`（--check 为 CI 漂移门）
//!   `cargo xtask contract validate`     契约元数据校验（多规则，编号见 `contract::validate` 的 `Rule`，CI 门）
//!   `cargo xtask layer-deps`            source-centric 分层依赖 lint（成员 Cargo.toml [dependencies] → §分层 矩阵，CI 门）
//!   `cargo xtask wsdeps-drift`          workspace.dependencies pin↔lock 漂移门（#1185，CI 门）
//!   `cargo xtask verify [--fast] [--allow-missing-tools]`
//!                                      本地全量治理门聚合入口（azure 无 CI ⇒ 唯一实际 gate）：fmt + meta（contract
//!                                      validate / layer-deps / codegen --check）+ build + clippy + nextest + deny + dylint；
//!                                      `--fast` 只跑无需编译的步（fmt+meta+deny）；`--allow-missing-tools` 缺外部
//!                                      工具时显式宽限（默认 fail-closed）。详见 `verify.rs`。
//!   `cargo xtask public-api [--layer basis|engine] [--check] [--allow-missing]`
//!                                      封装面 baseline（包装 cargo-public-api，需 nightly rustdoc-json）；
//!                                      --check 缺 baseline 默认 fail-fast，--allow-missing 显式宽限（PR-0 自检）
//!   `cargo xtask ci [--allow-missing-tools]`
//!                                      CI lane **超集**聚合（issue #1132，azure-pipelines.yml 薄壳唯一调用入口）：
//!                                      verify 全门（build/clippy 升 `--all-features --all-targets`）+ 覆盖率门
//!                                      （`cargo llvm-cov nextest` 替 nextest，单跑两子门：basis/engine ≥90% 绝对
//!                                      地板 + 本 PR diff 增量 ≥80%，见 `coverage.rs`/`diffcov.rs`）+ public-api
//!                                      --check（轴 A）+ cargo-audit（供应链漏洞，#1133）。verify 仍是本地 stable-only 快门，ci 是 CI 全工具超集。详见 `verify.rs`。
//!   `cargo xtask audit [--allow-missing-tools]`
//!                                      供应链漏洞**定时刷新** lane（issue #1133，azure-pipelines.yml 每日 `schedules:`
//!                                      cron 调用入口）：advisory-scoped `cargo deny check advisories` + `cargo audit`
//!                                      两门（皆 no-compile、快），捕获「未变依赖」新披露 CVE。详见 `verify.rs`。
//!   `cargo xtask integration [--allow-missing-tools]`
//!                                      真集成 lane（issue #1137，**opt-in**，不入 verify/ci）：testcontainers
//!                                      self-provision postgres/redis/rabbitmq 跑 `--features integration` 测试。
//!                                      **docker-gated**（fail-closed；env URL 全在则对接长存服务免 docker）。
//!                                      azure-pipelines 接线待 #1145（需 docker agent）。详见 `verify.rs`。
mod cmd;
mod codegen;
mod command_symmetry;
mod contract;
mod coverage;
mod diagnostic;
mod diffcov;
mod layerdeps;
mod layers;
mod pathsafe;
mod pdpallow;
mod publicapi;
mod schema_rls;
mod src_scan;
#[cfg(test)]
mod testutil;
mod verify;
mod wsdeps;

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    dispatch(&args)
}

/// 可测纯枚举：命令解析结果，与 IO 执行分离。
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Codegen {
        check: bool,
    },
    ContractValidate,
    LayerDeps,
    WsDepsDrift,
    Verify {
        fast: bool,
        allow_missing_tools: bool,
    },
    PublicApi {
        check: bool,
        allow_missing: bool,
        layer: Option<publicapi::Layer>,
    },
    Ci {
        allow_missing_tools: bool,
    },
    Audit {
        allow_missing_tools: bool,
    },
    Integration {
        allow_missing_tools: bool,
    },
    SchemaRls,
}

/// 从参数列表解析命令，不执行任何 IO。
///
/// 精确 argv 匹配（fail-closed）：合法子命令后出现任何未声明尾参即 `Err`——杜绝
/// `verify --bogus` / `contract validate --typo` 被静默吞掉而仍返回成功。
fn parse_command(args: &[String]) -> Result<Command> {
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    match argv.as_slice() {
        ["codegen"] => Ok(Command::Codegen { check: false }),
        ["codegen", "--check"] => Ok(Command::Codegen { check: true }),
        ["contract", "validate"] => Ok(Command::ContractValidate),
        ["layer-deps"] => Ok(Command::LayerDeps),
        ["wsdeps-drift"] => Ok(Command::WsDepsDrift),
        ["verify", rest @ ..] => parse_verify(rest),
        ["public-api", rest @ ..] => parse_public_api(rest),
        ["ci", rest @ ..] => parse_ci(rest),
        ["audit", rest @ ..] => parse_audit(rest),
        ["integration", rest @ ..] => parse_integration(rest),
        ["schema-rls"] => Ok(Command::SchemaRls),
        other => {
            bail!(
                "未知命令: {other:?}；用法: cargo xtask <codegen [--check] | contract validate | layer-deps | wsdeps-drift | schema-rls | verify [--fast] [--allow-missing-tools] | public-api [--layer basis|engine] [--check] [--allow-missing] | ci [--allow-missing-tools] | audit [--allow-missing-tools] | integration [--allow-missing-tools]>"
            )
        }
    }
}

/// 解析 `verify` 的可选 flag（fail-closed：未知 flag 即 `Err`）。
fn parse_verify(args: &[&str]) -> Result<Command> {
    let mut fast = false;
    let mut allow_missing_tools = false;
    for &tok in args {
        match tok {
            "--fast" => fast = true,
            "--allow-missing-tools" => allow_missing_tools = true,
            other => bail!(
                "verify 未知参数: {other}；用法: cargo xtask verify [--fast] [--allow-missing-tools]"
            ),
        }
    }
    Ok(Command::Verify {
        fast,
        allow_missing_tools,
    })
}

/// 解析 `ci` 的可选 flag（fail-closed：未知 flag 即 `Err`）。`ci` 无 `--fast`——CI 超集恒全量跑。
fn parse_ci(args: &[&str]) -> Result<Command> {
    let mut allow_missing_tools = false;
    for &tok in args {
        match tok {
            "--allow-missing-tools" => allow_missing_tools = true,
            other => {
                bail!("ci 未知参数: {other}；用法: cargo xtask ci [--allow-missing-tools]")
            }
        }
    }
    Ok(Command::Ci {
        allow_missing_tools,
    })
}

/// 解析 `audit` 的可选 flag（fail-closed：未知 flag 即 `Err`）。`audit` 无 `--fast`——供应链 lane 恒全量跑。
fn parse_audit(args: &[&str]) -> Result<Command> {
    let mut allow_missing_tools = false;
    for &tok in args {
        match tok {
            "--allow-missing-tools" => allow_missing_tools = true,
            other => {
                bail!("audit 未知参数: {other}；用法: cargo xtask audit [--allow-missing-tools]")
            }
        }
    }
    Ok(Command::Audit {
        allow_missing_tools,
    })
}

/// 解析 `integration` 的可选 flag（fail-closed：未知 flag 即 `Err`）。`integration` 无 `--fast`——真集成 lane 恒全量跑。
fn parse_integration(args: &[&str]) -> Result<Command> {
    let mut allow_missing_tools = false;
    for &tok in args {
        match tok {
            "--allow-missing-tools" => allow_missing_tools = true,
            other => {
                bail!(
                    "integration 未知参数: {other}；用法: cargo xtask integration [--allow-missing-tools]"
                )
            }
        }
    }
    Ok(Command::Integration {
        allow_missing_tools,
    })
}

/// 解析 `public-api` 的可选 flag（fail-closed：未知 flag / 缺 layer 值 / 非法 layer 即 `Err`）。
fn parse_public_api(args: &[&str]) -> Result<Command> {
    let mut check = false;
    let mut allow_missing = false;
    let mut layer = None;
    let mut it = args.iter();
    while let Some(&tok) = it.next() {
        match tok {
            "--check" => check = true,
            "--allow-missing" => allow_missing = true,
            "--layer" => {
                let val = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--layer 缺少值；用法: --layer basis|engine"))?;
                layer = Some(match *val {
                    "basis" => publicapi::Layer::Basis,
                    "engine" => publicapi::Layer::Engine,
                    other => bail!("未知 layer: {other}；用法: --layer basis|engine"),
                });
            }
            other => bail!(
                "public-api 未知参数: {other}；用法: --layer basis|engine | --check | --allow-missing"
            ),
        }
    }
    Ok(Command::PublicApi {
        check,
        allow_missing,
        layer,
    })
}

fn dispatch(args: &[String]) -> Result<()> {
    match parse_command(args)? {
        Command::Codegen { check } => codegen::run(check),
        Command::ContractValidate => diagnostic::run_check(&contract::validate::ContractValidate),
        Command::LayerDeps => diagnostic::run_check(&layerdeps::LayerDeps),
        Command::WsDepsDrift => diagnostic::run_check(&wsdeps::WsDepsDrift),
        Command::Verify {
            fast,
            allow_missing_tools,
        } => verify::run(fast, allow_missing_tools),
        Command::PublicApi {
            check,
            allow_missing,
            layer,
        } => publicapi::run(check, allow_missing, layer),
        Command::Ci {
            allow_missing_tools,
        } => verify::run_ci(allow_missing_tools),
        Command::Audit {
            allow_missing_tools,
        } => verify::run_audit(allow_missing_tools),
        Command::Integration {
            allow_missing_tools,
        } => verify::run_integration(allow_missing_tools),
        Command::SchemaRls => diagnostic::run_check(&schema_rls::SchemaRlsGuard),
    }
}

/// workspace 根 = xtask manifest 目录的父目录。取编译期 `CARGO_MANIFEST_DIR`，
/// **不**用运行期 `current_dir`——防 nextest 进程隔离 / 不同 cwd 下漂移。
pub(crate) fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("xtask manifest 目录无父目录"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_command_codegen_no_check() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["codegen"]))?,
            Command::Codegen { check: false }
        );
        Ok(())
    }

    #[test]
    fn parse_command_codegen_with_check() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["codegen", "--check"]))?,
            Command::Codegen { check: true }
        );
        Ok(())
    }

    #[test]
    fn parse_command_contract_validate() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["contract", "validate"]))?,
            Command::ContractValidate
        );
        Ok(())
    }

    #[test]
    fn parse_command_layer_deps() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["layer-deps"]))?, Command::LayerDeps);
        Ok(())
    }

    #[test]
    fn parse_command_wsdeps_drift() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["wsdeps-drift"]))?, Command::WsDepsDrift);
        Ok(())
    }

    /// wsdeps-drift fail-closed：未知尾参即 `Err`。
    #[test]
    fn parse_command_wsdeps_drift_rejects_trailing_args() {
        assert!(parse_command(&s(&["wsdeps-drift", "--bogus"])).is_err());
        assert!(parse_command(&s(&["wsdeps-drift", "extra"])).is_err());
    }

    #[test]
    fn parse_command_verify_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["verify"]))?,
            Command::Verify {
                fast: false,
                allow_missing_tools: false
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_verify_flags() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["verify", "--fast"]))?,
            Command::Verify {
                fast: true,
                allow_missing_tools: false
            }
        );
        assert_eq!(
            parse_command(&s(&["verify", "--allow-missing-tools"]))?,
            Command::Verify {
                fast: false,
                allow_missing_tools: true
            }
        );
        assert_eq!(
            parse_command(&s(&["verify", "--fast", "--allow-missing-tools"]))?,
            Command::Verify {
                fast: true,
                allow_missing_tools: true
            }
        );
        Ok(())
    }

    /// verify flag fail-closed：未知 flag 即 `Err`（不被静默吞掉）。
    #[test]
    fn parse_command_verify_rejects_unknown_flag() {
        assert!(parse_command(&s(&["verify", "--bogus"])).is_err());
        assert!(parse_command(&s(&["verify", "--fast", "extra"])).is_err());
    }

    #[test]
    fn parse_command_public_api_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["public-api"]))?,
            Command::PublicApi {
                check: false,
                allow_missing: false,
                layer: None
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_public_api_check_allow_missing() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["public-api", "--check", "--allow-missing"]))?,
            Command::PublicApi {
                check: true,
                allow_missing: true,
                layer: None
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_public_api_layer_basis() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["public-api", "--layer", "basis"]))?,
            Command::PublicApi {
                check: false,
                allow_missing: false,
                layer: Some(publicapi::Layer::Basis)
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_public_api_layer_engine_check() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["public-api", "--layer", "engine", "--check"]))?,
            Command::PublicApi {
                check: true,
                allow_missing: false,
                layer: Some(publicapi::Layer::Engine)
            }
        );
        Ok(())
    }

    /// public-api flag fail-closed：非法 layer 值 / 缺 layer 值 / 未知 flag 均 `Err`。
    #[test]
    fn parse_command_public_api_rejects_bad_flags() {
        assert!(parse_command(&s(&["public-api", "--layer", "bogus"])).is_err());
        assert!(parse_command(&s(&["public-api", "--layer"])).is_err()); // 缺值
        assert!(parse_command(&s(&["public-api", "--bogus"])).is_err());
    }

    #[test]
    fn parse_command_ci_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["ci"]))?,
            Command::Ci {
                allow_missing_tools: false
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_ci_allow_missing_tools() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["ci", "--allow-missing-tools"]))?,
            Command::Ci {
                allow_missing_tools: true
            }
        );
        Ok(())
    }

    /// ci flag fail-closed：未知 flag / 尾参 / 误用 `--fast`（ci 无此 flag）均 `Err`。
    #[test]
    fn parse_command_ci_rejects_unknown_flag() {
        assert!(parse_command(&s(&["ci", "--bogus"])).is_err());
        assert!(parse_command(&s(&["ci", "--fast"])).is_err()); // ci 无 --fast
        assert!(parse_command(&s(&["ci", "extra"])).is_err());
    }

    #[test]
    fn parse_command_audit_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["audit"]))?,
            Command::Audit {
                allow_missing_tools: false
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_audit_allow_missing_tools() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["audit", "--allow-missing-tools"]))?,
            Command::Audit {
                allow_missing_tools: true
            }
        );
        Ok(())
    }

    /// audit flag fail-closed：未知 flag / 尾参 / 误用 `--fast`（audit 无此 flag）均 `Err`。
    #[test]
    fn parse_command_audit_rejects_unknown_flag() {
        assert!(parse_command(&s(&["audit", "--bogus"])).is_err());
        assert!(parse_command(&s(&["audit", "--fast"])).is_err());
        assert!(parse_command(&s(&["audit", "extra"])).is_err());
    }

    #[test]
    fn parse_command_integration_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["integration"]))?,
            Command::Integration {
                allow_missing_tools: false
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_integration_allow_missing_tools() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["integration", "--allow-missing-tools"]))?,
            Command::Integration {
                allow_missing_tools: true
            }
        );
        Ok(())
    }

    /// integration flag fail-closed：未知 flag / 尾参 / 误用 `--fast`（无此 flag）均 `Err`。
    #[test]
    fn parse_command_integration_rejects_unknown_flag() {
        assert!(parse_command(&s(&["integration", "--bogus"])).is_err());
        assert!(parse_command(&s(&["integration", "--fast"])).is_err());
        assert!(parse_command(&s(&["integration", "extra"])).is_err());
    }

    #[test]
    fn parse_command_unknown_returns_err() {
        assert!(parse_command(&[]).is_err());
        assert!(parse_command(&s(&["bogus"])).is_err());
        assert!(parse_command(&s(&["contract"])).is_err()); // 缺 validate
        assert!(parse_command(&s(&["contract", "bogus"])).is_err());
    }

    /// 合法子命令后的未知尾参必须 fail-closed（不被静默吞掉）。
    #[test]
    fn parse_command_rejects_trailing_unknown_args() {
        assert!(parse_command(&s(&["verify", "--bogus"])).is_err());
        assert!(parse_command(&s(&["layer-deps", "--bogus"])).is_err());
        assert!(parse_command(&s(&["contract", "validate", "--bogus"])).is_err());
        assert!(parse_command(&s(&["codegen", "--bogus"])).is_err());
        assert!(parse_command(&s(&["codegen", "--check", "--bogus"])).is_err());
        assert!(parse_command(&s(&["codegen", "--check", "extra"])).is_err());
        assert!(parse_command(&s(&["public-api", "--bogus"])).is_err());
        assert!(parse_command(&s(&["public-api", "--check", "extra"])).is_err());
    }

    #[test]
    fn dispatch_rejects_unknown_and_incomplete() {
        assert!(dispatch(&[]).is_err());
        assert!(dispatch(&["bogus".to_string()]).is_err());
        assert!(dispatch(&["contract".to_string()]).is_err()); // 缺 validate 子命令
        assert!(dispatch(&["contract".to_string(), "bogus".to_string()]).is_err());
        // 尾参 fail-closed（dispatch 经 parse_command）。
        assert!(dispatch(&["verify".to_string(), "--bogus".to_string()]).is_err());
    }

    #[test]
    fn workspace_root_is_repo_root_with_contracts() -> anyhow::Result<()> {
        let root = workspace_root()?;
        assert!(root.join("contracts").is_dir());
        assert!(root.join("generated").is_dir());
        Ok(())
    }

    #[test]
    fn parse_command_schema_rls() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["schema-rls"]))?, Command::SchemaRls);
        Ok(())
    }

    /// schema-rls fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_schema_rls_rejects_trailing_args() {
        assert!(parse_command(&s(&["schema-rls", "--bogus"])).is_err());
        assert!(parse_command(&s(&["schema-rls", "extra"])).is_err());
    }
}
