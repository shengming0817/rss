#![recursion_limit = "256"]

//! server — RSS 组合根 binary（薄 entry）。运行时编排在 `runtime::run`（#1309 抽 assemblies/runtime 去 bins 双写）。
//!
//! `server` 默认是 serving-only entry，委托 `runtime::run()`；operator CLI 由 `rss` binary 在进入 serving 前
//! 显式 dispatch。`version` 在 `prepare_runtime` 之前离线输出 compile-time bake-in 身份（#1496），
//! 供 release smoke 校验发布产物，不进入 serving env 依赖。

enum CommandFamily {
    Version,
    Serving,
}

fn classify_command(args: &[String]) -> anyhow::Result<CommandFamily> {
    match args {
        [] => Ok(CommandFamily::Serving),
        [command] if command == "version" => Ok(CommandFamily::Version),
        _ => anyhow::bail!("unknown server command: {args:?}"),
    }
}

fn format_version_lines() -> String {
    format!(
        "GIT_SHA={}\nBUILD_DATE={}\n",
        env!("GIT_SHA"),
        env!("BUILD_DATE")
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match classify_command(&args)? {
        CommandFamily::Version => {
            print!("{}", format_version_lines());
            Ok(())
        }
        CommandFamily::Serving => {
            let runtime_inputs = runtime::prepare_runtime()?;
            runtime::run(runtime_inputs).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn version_subcommand_classifies_before_serving() {
        assert!(matches!(
            classify_command(&args(&["version"])),
            Ok(CommandFamily::Version)
        ));
        assert!(matches!(
            classify_command(&args(&[])),
            Ok(CommandFamily::Serving)
        ));
        assert!(classify_command(&args(&["bogus"])).is_err());
        assert!(classify_command(&args(&["version", "extra"])).is_err());
    }

    #[test]
    fn format_version_lines_emits_git_sha_and_build_date_keys() {
        let lines = format_version_lines();
        assert!(
            lines.lines().any(|line| line.starts_with("GIT_SHA=")),
            "missing GIT_SHA= line in:\n{lines}"
        );
        assert!(
            lines.lines().any(|line| line.starts_with("BUILD_DATE=")),
            "missing BUILD_DATE= line in:\n{lines}"
        );
        assert_eq!(
            lines.lines().count(),
            2,
            "expected exactly two lines:\n{lines}"
        );
    }
}
