//! xtask — RSS 治理 / codegen 入口。见 docs/rules/architecture.md §xtask、§Rust 原生强制（三档载体）。
//!
//! 子命令：
//!   `cargo xtask codegen [--check]`     契约 schema → committed `generated/`（--check 为 CI 漂移门）
//!   `cargo xtask contract validate`     契约元数据校验（R1–R6，CI 门）
//!   `cargo xtask layer-deps`            source-centric 分层依赖 lint（成员 Cargo.toml [dependencies] → §分层 矩阵，CI 门）
//!   `cargo xtask verify`                聚合门：contract validate + layer-deps + codegen --check（本地自验入口）
//!   `cargo xtask public-api [--layer basis|engine] [--check] [--allow-missing]`
//!                                      封装面 baseline（包装 cargo-public-api，需 nightly rustdoc-json）；
//!                                      --check 缺 baseline 默认 fail-fast，--allow-missing 显式宽限（PR-0 自检）
mod codegen;
mod contract;
mod layerdeps;
mod layers;
mod pathsafe;
mod publicapi;
#[cfg(test)]
mod testutil;

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
    Verify,
    PublicApi {
        check: bool,
        allow_missing: bool,
        layer: Option<publicapi::Layer>,
    },
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
        ["verify"] => Ok(Command::Verify),
        ["public-api", rest @ ..] => parse_public_api(rest),
        other => {
            bail!(
                "未知命令: {other:?}；用法: cargo xtask <codegen [--check] | contract validate | layer-deps | verify | public-api [--layer basis|engine] [--check] [--allow-missing]>"
            )
        }
    }
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
        Command::ContractValidate => contract::validate::run(),
        Command::LayerDeps => layerdeps::run(),
        Command::Verify => {
            contract::validate::run()?;
            layerdeps::run()?;
            codegen::run(true)?;
            eprintln!("verify: 全部通过（contract validate + layer-deps + codegen --check）");
            Ok(())
        }
        Command::PublicApi {
            check,
            allow_missing,
            layer,
        } => publicapi::run(check, allow_missing, layer),
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
    fn parse_command_verify() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["verify"]))?, Command::Verify);
        Ok(())
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
}
