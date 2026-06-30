//! xtask — RSS 治理 / codegen 入口。见 docs/rules/architecture.md §xtask、§Rust 原生强制（三档载体）。
//!
//! 子命令：
//!   `cargo xtask codegen [--check]`     契约 schema → committed `generated/`（--check 为 CI 漂移门）
//!   `cargo xtask contract validate`     契约元数据校验（多规则，编号见 `contract::validate` 的 `Rule`，CI 门）
//!   `cargo xtask assembly validate`     assembly-level DI provider 声明校验（RevocationStore 持久 provider 门）
//!   `cargo xtask archrules list|verify` ArchRules 派生索引（从真实 carrier 的 `INVARIANT:` 反向索引 rule
//!                                      → carrier → evidence → gate；verify 为 CI 门）
//!   `cargo xtask contract breaking [--against <git-ref>] [--deny]`
//!                                      wire JSON-Schema 跨版本破坏检测门（ADR-008，对标 Buf WIRE_JSON）：base ref
//!                                      （默认 origin/develop）↔ working-tree schema 递归 diff；窗口分级默认 warn
//!                                      （退出码 0），env `RSS_WIRE_BREAKING=deny` / `--deny` 升 deny（active 契约
//!                                      破坏退出码 1）。详见 `contract::breaking`。
//!   `cargo xtask layer-deps`            source-centric 分层依赖 lint（成员 Cargo.toml [dependencies] → §分层 矩阵，CI 门）
//!   `cargo xtask wsdeps-drift`          workspace.dependencies pin↔lock 漂移门（#1185，CI 门）
//!   `cargo xtask doc-contracts`         文档契约片段漂移门（command/outbox tenant-aware 签名，CI 门）
//!   `cargo xtask migrations`            migration 文件序号唯一性 + 连续性守卫（INVARIANT MIGRATION-SERIAL-UNIQUE-01，CI 门）
//!   `cargo xtask pg-tenant-tx-guard`    Postgres tenant 表 raw-pool / TxManager bypass 守卫（CI 门）
//!   `cargo xtask verify [--fast] [--allow-missing-tools]`
//!                                      本地全量治理门聚合入口（GitHub Actions 与本地共用同一门）：fmt + meta（contract
//!                                      validate / assembly validate / layer-deps / codegen --check）+ build + clippy + nextest + deny + dylint；
//!                                      `--fast` 只跑无需编译的步（fmt+meta+deny）；`--allow-missing-tools` 缺外部
//!                                      工具时显式宽限（默认 fail-closed）。详见 `verify.rs`。
//!   `cargo xtask public-api [--layer basis|engine|curated] [--check] [--allow-missing]`
//!                                      封装面 baseline（包装 cargo-public-api，需 nightly rustdoc-json；无
//!                                      --layer 时检查 basis + engine + curated extras）；
//!                                      --check 缺 baseline 默认 fail-fast，--allow-missing 显式宽限（PR-0 自检）
//!   `cargo xtask ci [--allow-missing-tools]`
//!                                      CI lane **超集**聚合（issue #1132，GitHub Actions 薄壳唯一调用入口）：
//!                                      verify 全门（build/clippy 升 `--all-features --all-targets`）+ 覆盖率门
//!                                      （`cargo llvm-cov nextest` 替 nextest，单跑两子门：basis/engine ≥90% 绝对
//!                                      地板 + 本 PR diff 增量 ≥80%，见 `coverage.rs`/`diffcov.rs`）+ public-api
//!                                      --check（轴 A）+ cargo-audit（供应链漏洞，#1133）。verify 仍是本地 stable-only 快门，ci 是 CI 全工具超集。详见 `verify.rs`。
//!   `cargo xtask audit [--allow-missing-tools]`
//!                                      供应链漏洞**定时刷新** lane（issue #1133，GitHub Actions `schedule:`
//!                                      cron 调用入口）：advisory-scoped `cargo deny check advisories` + `cargo audit`
//!                                      两门（皆 no-compile、快），捕获「未变依赖」新披露 CVE。详见 `verify.rs`。
//!   `cargo xtask integration [--allow-missing-tools]`
//!                                      真集成 lane（issue #1137，**opt-in**，不入 verify/ci）：testcontainers
//!                                      self-provision postgres/redis/rabbitmq 跑 `--features integration` 测试。
//!                                      **docker-gated**（fail-closed；env URL 全在则对接长存服务免 docker）。
//!                                      **已接入 GitHub Actions PR/push lane**（#1145，CI-INTEGRATION-LANE-01）。详见 `verify.rs`。
mod archrules;
mod assembly;
mod cmd;
mod codegen;
mod command_symmetry;
mod contract;
mod coverage;
mod defergate;
mod diagnostic;
mod diffcov;
mod doc_contracts;
mod event_transport_guard;
mod layerdeps;
mod layers;
mod migrations;
mod pathsafe;
mod pdpallow;
mod pg_tenant_tx_guard;
mod publicapi;
mod schema_rls;
mod setlocal_funnel;
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
    AssemblyValidate,
    ArchRulesList,
    ArchRulesVerify,
    ContractBreaking {
        /// base git-ref（缺省 = `contract::breaking::DEFAULT_AGAINST`）。
        against: Option<String>,
        /// `--deny`：显式升 deny 模式（覆盖 env），供本地测试 fail-closed 路径。
        deny: bool,
    },
    LayerDeps,
    WsDepsDrift,
    DocContracts,
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
    /// tenant-scope SET-LOCAL 单漏斗守卫（TENANCY-SETLOCAL-FUNNEL-01）。
    SetLocalFunnel,
    /// Postgres tenant-table raw-pool / TxManager bypass guard（TENANCY-PG-TX-FUNNEL-01）。
    PgTenantTxGuard,
    DeferGate,
    Migrations,
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
        ["archrules", rest @ ..] => parse_archrules(rest),
        ["contract", rest @ ..] => parse_contract(rest),
        ["assembly", rest @ ..] => parse_assembly(rest),
        ["layer-deps"] => Ok(Command::LayerDeps),
        ["wsdeps-drift"] => Ok(Command::WsDepsDrift),
        ["doc-contracts"] => Ok(Command::DocContracts),
        ["verify", rest @ ..] => parse_verify(rest),
        ["public-api", rest @ ..] => parse_public_api(rest),
        ["ci", rest @ ..] => parse_ci(rest),
        ["audit", rest @ ..] => parse_audit(rest),
        ["integration", rest @ ..] => parse_integration(rest),
        ["schema-rls"] => Ok(Command::SchemaRls),
        ["setlocal-funnel"] => Ok(Command::SetLocalFunnel),
        ["pg-tenant-tx-guard"] => Ok(Command::PgTenantTxGuard),
        ["defer-gate"] => Ok(Command::DeferGate),
        ["migrations"] => Ok(Command::Migrations),
        other => {
            bail!(
                "未知命令: {other:?}；用法: cargo xtask <codegen [--check] | archrules <list | verify> | contract <validate | breaking [--against <git-ref>] [--deny]> | assembly validate | layer-deps | wsdeps-drift | doc-contracts | migrations | schema-rls | setlocal-funnel | pg-tenant-tx-guard | defer-gate | verify [--fast] [--allow-missing-tools] | public-api [--layer basis|engine|curated] [--check] [--allow-missing] | ci [--allow-missing-tools] | audit [--allow-missing-tools] | integration [--allow-missing-tools]>"
            )
        }
    }
}

/// 解析 `archrules <sub>` 子命令（fail-closed：只接受 positional list/verify，不提供 --list 兼容形态）。
fn parse_archrules(args: &[&str]) -> Result<Command> {
    match args {
        ["list"] => Ok(Command::ArchRulesList),
        ["verify"] => Ok(Command::ArchRulesVerify),
        other => {
            bail!("未知 archrules 子命令: {other:?}；用法: cargo xtask archrules <list | verify>")
        }
    }
}

/// 解析 `contract <sub>` 子命令（fail-closed：未知子命令即 `Err`）。
fn parse_contract(args: &[&str]) -> Result<Command> {
    match args {
        ["validate"] => Ok(Command::ContractValidate),
        ["breaking", rest @ ..] => parse_contract_breaking(rest),
        other => bail!(
            "未知 contract 子命令: {other:?}；用法: cargo xtask contract <validate | breaking [--against <git-ref>] [--deny]>"
        ),
    }
}

/// 解析 `assembly <sub>` 子命令（fail-closed：未知子命令即 `Err`）。
fn parse_assembly(args: &[&str]) -> Result<Command> {
    match args {
        ["validate"] => Ok(Command::AssemblyValidate),
        other => bail!("未知 assembly 子命令: {other:?}；用法: cargo xtask assembly validate"),
    }
}

/// 解析 `contract breaking` 的可选 flag（fail-closed：未知 flag / `--against` 缺值即 `Err`）。
fn parse_contract_breaking(args: &[&str]) -> Result<Command> {
    let mut against = None;
    let mut deny = false;
    let mut it = args.iter();
    while let Some(&tok) = it.next() {
        match tok {
            "--deny" => deny = true,
            "--against" => {
                let val = it.next().ok_or_else(|| {
                    anyhow::anyhow!("--against 缺少值；用法: --against <git-ref>")
                })?;
                against = Some((*val).to_string());
            }
            other => {
                bail!(
                    "contract breaking 未知参数: {other}；用法: --against <git-ref> | --deny（亦可 env RSS_WIRE_BREAKING=deny 升 deny 模式）"
                )
            }
        }
    }
    Ok(Command::ContractBreaking { against, deny })
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
                let val = it.next().ok_or_else(|| {
                    anyhow::anyhow!("--layer 缺少值；用法: --layer basis|engine|curated")
                })?;
                layer = Some(match *val {
                    "basis" => publicapi::Layer::Basis,
                    "engine" => publicapi::Layer::Engine,
                    "curated" => publicapi::Layer::Curated,
                    other => bail!("未知 layer: {other}；用法: --layer basis|engine|curated"),
                });
            }
            other => bail!(
                "public-api 未知参数: {other}；用法: --layer basis|engine|curated | --check | --allow-missing"
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
        Command::AssemblyValidate => diagnostic::run_check(&assembly::AssemblyValidate),
        Command::ArchRulesList => archrules::list(),
        Command::ArchRulesVerify => diagnostic::run_check(&archrules::ArchRules),
        Command::ContractBreaking { against, deny } => {
            let mode = if deny {
                contract::breaking::EnforcementMode::Deny
            } else {
                contract::breaking::EnforcementMode::from_env()
            };
            let against =
                against.unwrap_or_else(|| contract::breaking::DEFAULT_AGAINST.to_string());
            contract::breaking::run(&against, mode)
        }
        Command::LayerDeps => diagnostic::run_check(&layerdeps::LayerDeps),
        Command::WsDepsDrift => diagnostic::run_check(&wsdeps::WsDepsDrift),
        Command::DocContracts => diagnostic::run_check(&doc_contracts::DocContracts),
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
        Command::SetLocalFunnel => diagnostic::run_check(&setlocal_funnel::SetLocalFunnelGuard),
        Command::PgTenantTxGuard => diagnostic::run_check(&pg_tenant_tx_guard::PgTenantTxGuard),
        Command::DeferGate => diagnostic::run_check(&defergate::DeferGate),
        Command::Migrations => diagnostic::run_check(&migrations::MigrationSerialGuard),
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
    fn parse_command_assembly_validate() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["assembly", "validate"]))?,
            Command::AssemblyValidate
        );
        Ok(())
    }

    #[test]
    fn parse_command_archrules_list_verify() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["archrules", "list"]))?,
            Command::ArchRulesList
        );
        assert_eq!(
            parse_command(&s(&["archrules", "verify"]))?,
            Command::ArchRulesVerify
        );
        Ok(())
    }

    #[test]
    fn parse_command_archrules_rejects_bad() {
        assert!(parse_command(&s(&["archrules"])).is_err());
        assert!(parse_command(&s(&["archrules", "--list"])).is_err());
        assert!(parse_command(&s(&["archrules", "list", "extra"])).is_err());
        assert!(parse_command(&s(&["archrules", "bogus"])).is_err());
    }

    #[test]
    fn parse_command_contract_breaking_bare() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["contract", "breaking"]))?,
            Command::ContractBreaking {
                against: None,
                deny: false
            }
        );
        Ok(())
    }

    #[test]
    fn parse_command_contract_breaking_flags() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["contract", "breaking", "--against", "HEAD~1"]))?,
            Command::ContractBreaking {
                against: Some("HEAD~1".to_string()),
                deny: false
            }
        );
        assert_eq!(
            parse_command(&s(&["contract", "breaking", "--deny"]))?,
            Command::ContractBreaking {
                against: None,
                deny: true
            }
        );
        assert_eq!(
            parse_command(&s(&[
                "contract",
                "breaking",
                "--against",
                "origin/develop",
                "--deny"
            ]))?,
            Command::ContractBreaking {
                against: Some("origin/develop".to_string()),
                deny: true
            }
        );
        Ok(())
    }

    /// contract 子命令 fail-closed：未知子命令 / 未知 flag / `--against` 缺值均 `Err`。
    #[test]
    fn parse_command_contract_rejects_bad() {
        assert!(parse_command(&s(&["contract", "bogus"])).is_err());
        assert!(parse_command(&s(&["contract", "validate", "--bogus"])).is_err());
        assert!(parse_command(&s(&["contract", "breaking", "--bogus"])).is_err());
        assert!(parse_command(&s(&["contract", "breaking", "--against"])).is_err()); // 缺值
        assert!(parse_command(&s(&["assembly", "bogus"])).is_err());
        assert!(parse_command(&s(&["assembly", "validate", "--bogus"])).is_err());
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

    #[test]
    fn parse_command_doc_contracts() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["doc-contracts"]))?,
            Command::DocContracts
        );
        Ok(())
    }

    /// wsdeps-drift fail-closed：未知尾参即 `Err`。
    #[test]
    fn parse_command_wsdeps_drift_rejects_trailing_args() {
        assert!(parse_command(&s(&["wsdeps-drift", "--bogus"])).is_err());
        assert!(parse_command(&s(&["wsdeps-drift", "extra"])).is_err());
    }

    #[test]
    fn parse_command_doc_contracts_rejects_trailing_args() {
        assert!(parse_command(&s(&["doc-contracts", "--bogus"])).is_err());
        assert!(parse_command(&s(&["doc-contracts", "extra"])).is_err());
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

    #[test]
    fn parse_command_public_api_layer_curated_check() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["public-api", "--layer", "curated", "--check"]))?,
            Command::PublicApi {
                check: true,
                allow_missing: false,
                layer: Some(publicapi::Layer::Curated)
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
        assert!(parse_command(&s(&["assembly"])).is_err()); // 缺 validate
        assert!(parse_command(&s(&["assembly", "bogus"])).is_err());
    }

    /// 合法子命令后的未知尾参必须 fail-closed（不被静默吞掉）。
    #[test]
    fn parse_command_rejects_trailing_unknown_args() {
        assert!(parse_command(&s(&["verify", "--bogus"])).is_err());
        assert!(parse_command(&s(&["layer-deps", "--bogus"])).is_err());
        assert!(parse_command(&s(&["contract", "validate", "--bogus"])).is_err());
        assert!(parse_command(&s(&["assembly", "validate", "--bogus"])).is_err());
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

    #[test]
    fn parse_command_setlocal_funnel() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["setlocal-funnel"]))?,
            Command::SetLocalFunnel
        );
        Ok(())
    }

    /// setlocal-funnel fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_setlocal_funnel_rejects_trailing_args() {
        assert!(parse_command(&s(&["setlocal-funnel", "--bogus"])).is_err());
        assert!(parse_command(&s(&["setlocal-funnel", "extra"])).is_err());
    }

    #[test]
    fn parse_command_pg_tenant_tx_guard() -> anyhow::Result<()> {
        assert_eq!(
            parse_command(&s(&["pg-tenant-tx-guard"]))?,
            Command::PgTenantTxGuard
        );
        Ok(())
    }

    /// pg-tenant-tx-guard fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_pg_tenant_tx_guard_rejects_trailing_args() {
        assert!(parse_command(&s(&["pg-tenant-tx-guard", "--bogus"])).is_err());
        assert!(parse_command(&s(&["pg-tenant-tx-guard", "extra"])).is_err());
    }

    #[test]
    fn parse_command_defer_gate() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["defer-gate"]))?, Command::DeferGate);
        Ok(())
    }

    /// defer-gate fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_defer_gate_rejects_trailing_args() {
        assert!(parse_command(&s(&["defer-gate", "--bogus"])).is_err());
        assert!(parse_command(&s(&["defer-gate", "extra"])).is_err());
    }

    #[test]
    fn parse_command_migrations() -> anyhow::Result<()> {
        assert_eq!(parse_command(&s(&["migrations"]))?, Command::Migrations);
        Ok(())
    }

    /// migrations fail-closed：尾参即 `Err`。
    #[test]
    fn parse_command_migrations_rejects_trailing_args() {
        assert!(parse_command(&s(&["migrations", "--bogus"])).is_err());
        assert!(parse_command(&s(&["migrations", "extra"])).is_err());
    }
}
