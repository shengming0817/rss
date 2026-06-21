//! xtask — RSS 治理 / codegen 入口。见 docs/rules/architecture.md §xtask、§Rust 原生强制（三档载体）。
//!
//! 子命令：
//!   `cargo xtask codegen [--check]`     契约 schema → committed `generated/`（--check 为 CI 漂移门）
//!   `cargo xtask contract validate`     契约元数据校验（R1–R6，CI 门）
//!   `cargo xtask verify`                聚合门：contract validate + codegen --check（本地自验入口）
mod codegen;
mod contract;
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
    Codegen { check: bool },
    ContractValidate,
    Verify,
}

/// 从参数列表解析命令，不执行任何 IO。
fn parse_command(args: &[String]) -> Result<Command> {
    match args.first().map(String::as_str) {
        Some("codegen") => Ok(Command::Codegen {
            check: args.iter().any(|a| a == "--check"),
        }),
        Some("contract") if args.get(1).map(String::as_str) == Some("validate") => {
            Ok(Command::ContractValidate)
        }
        Some("verify") => Ok(Command::Verify),
        other => {
            bail!(
                "未知命令: {other:?}；用法: cargo xtask <codegen [--check] | contract validate | verify>"
            )
        }
    }
}

fn dispatch(args: &[String]) -> Result<()> {
    match parse_command(args)? {
        Command::Codegen { check } => codegen::run(check),
        Command::ContractValidate => contract::validate::run(),
        Command::Verify => {
            contract::validate::run()?;
            codegen::run(true)?;
            eprintln!("verify: 全部通过（contract validate + codegen --check）");
            Ok(())
        }
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
    fn parse_command_verify() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["verify"]))?, Command::Verify);
        Ok(())
    }

    #[test]
    fn parse_command_unknown_returns_err() {
        assert!(parse_command(&[]).is_err());
        assert!(parse_command(&s(&["bogus"])).is_err());
        assert!(parse_command(&s(&["contract"])).is_err()); // 缺 validate
        assert!(parse_command(&s(&["contract", "bogus"])).is_err());
    }

    #[test]
    fn dispatch_rejects_unknown_and_incomplete() {
        assert!(dispatch(&[]).is_err());
        assert!(dispatch(&["bogus".to_string()]).is_err());
        assert!(dispatch(&["contract".to_string()]).is_err()); // 缺 validate 子命令
        assert!(dispatch(&["contract".to_string(), "bogus".to_string()]).is_err());
    }

    #[test]
    fn workspace_root_is_repo_root_with_contracts() -> anyhow::Result<()> {
        let root = workspace_root()?;
        assert!(root.join("contracts").is_dir());
        assert!(root.join("generated").is_dir());
        Ok(())
    }
}
