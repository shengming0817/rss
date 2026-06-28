//! xtask 治理校验器共用诊断件（issue #1058）。
//!
//! 两个（及后续）governance 校验器（contract validate / layer-deps / …）此前各自复制结构相同的
//! 诊断三件套（`Finding` 壳 + `finding()` 构造器 + `  [{:?}] {}: {}` 打印循环）+ `run()` 编排
//! （collect → 空则成功摘要 / 非空则打印 + bail）。此处抽取为单源：
//!   - 泛型 [`Finding`]（各校验器只定义自己的 `Rule` enum 作 `R`）
//!   - [`finding`] 构造器 + [`print_findings`] 打印
//!   - [`GovernanceCheck`] trait（`name()` + `check()`，只供数据）+ free fn [`run_check`]（统一编排，实现者不可覆写）
//!
//! INVARIANT: DIAG-FINDING-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— 诊断壳 + 打印 + run 编排单源（不再逐校验器复制）。

use anyhow::{Result, bail};
use std::fmt::Debug;

/// 单条治理校验失败：被违反的规则 `R`（各校验器自有 enum）+ 出错主体 + 详情。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding<R> {
    pub(crate) rule: R,
    /// 出错主体（契约目录 / 成员名 / manifest 路径 …）。
    pub(crate) subject: String,
    pub(crate) detail: String,
}

/// 构造一条 finding（`subject` / `detail` 接受任意 `Into<String>`）。
pub(crate) fn finding<R>(
    rule: R,
    subject: impl Into<String>,
    detail: impl Into<String>,
) -> Finding<R> {
    Finding {
        rule,
        subject: subject.into(),
        detail: detail.into(),
    }
}

/// 单条 finding 的展示行（`  [{Rule:?}] {subject}: {detail}`）——纯函数，便于精确断言格式。
pub(crate) fn format_finding<R: Debug>(f: &Finding<R>) -> String {
    format!("  [{:?}] {}: {}", f.rule, f.subject, f.detail)
}

/// 逐行打印 findings 到 stderr（格式单源 = [`format_finding`]）。
pub(crate) fn print_findings<R: Debug>(findings: &[Finding<R>]) {
    for f in findings {
        eprintln!("{}", format_finding(f));
    }
}

/// xtask 治理校验器统一形态：跑出 findings 列表，空 = 通过、非空 = fail-fast。
/// 各校验器只实现 domain-specific 的 [`name`](Self::name) + [`check`](Self::check)（只供数据）；
/// 执行权收敛于 free fn [`run_check`]（统一编排，实现者不可覆写，DIAG-FINDING-01）。
pub(crate) trait GovernanceCheck {
    /// 该校验器的规则枚举（作 `Finding<R>` 的 `R`）。
    type Rule: Debug;

    /// 校验器名，作成功 / 失败消息前缀（如 `contract validate` / `layer-deps`）。
    fn name(&self) -> &'static str;

    /// 执行校验：`Ok((成功摘要, findings))`。硬错误（IO / 配置灾难 canary）→ `Err` 冒泡。
    /// 成功摘要在 findings 为空时打印（携带各校验器自有统计，如契约数 / 成员数）。
    /// findings 非空时成功摘要被忽略（不打印）——实现者可传 `String::new()`。
    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)>;
}

/// 治理校验统一编排 driver（free fn，**非 trait method**——实现者无法覆写，把「统一 fail-fast 编排
/// 不可绕过」从注释约定（Soft）上移为结构强制：校验器只经 [`GovernanceCheck`] 提供 `name()`/`check()`
/// 数据，打印 + bail 的执行权收敛此单点）。空 findings → 打印成功摘要并 `Ok`；非空 → 打印各 finding
/// 并 `bail`（fail-fast）。INVARIANT: DIAG-FINDING-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
pub(crate) fn run_check<C: GovernanceCheck>(check: &C) -> Result<()> {
    let (summary, findings) = check.check()?;
    if findings.is_empty() {
        eprintln!("{}: {summary}", check.name());
        return Ok(());
    }
    print_findings(&findings);
    bail!("{}: {} 项校验失败", check.name(), findings.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, bail};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestRule {
        A,
        B,
    }

    #[test]
    fn finding_sets_fields() {
        let f = finding(TestRule::A, "subj", "det");
        assert_eq!(f.rule, TestRule::A);
        assert_eq!(f.subject, "subj");
        assert_eq!(f.detail, "det");
    }

    /// 打印行格式单源（精确 layout，含 2 空格缩进 + `[Rule:?]` + `subject: detail`）。
    #[test]
    fn format_finding_exact_layout() {
        let f = finding(TestRule::B, "crates/x", "boom");
        assert_eq!(format_finding(&f), "  [B] crates/x: boom");
    }

    /// 可注入结果的假校验器，验证 provided `run()` 三路径（空 / 非空 / 硬错）。
    struct Fake {
        outcome: Outcome,
    }
    enum Outcome {
        Empty,
        NonEmpty,
        HardErr,
    }
    impl GovernanceCheck for Fake {
        type Rule = TestRule;
        fn name(&self) -> &'static str {
            "fake"
        }
        fn check(&self) -> Result<(String, Vec<Finding<TestRule>>)> {
            match self.outcome {
                Outcome::Empty => Ok(("0 项全过".to_string(), vec![])),
                Outcome::NonEmpty => Ok((String::new(), vec![finding(TestRule::A, "s", "d")])),
                Outcome::HardErr => bail!("io 炸了"),
            }
        }
    }

    #[test]
    fn run_empty_findings_is_ok() {
        let fake = Fake {
            outcome: Outcome::Empty,
        };
        assert!(run_check(&fake).is_ok());
    }

    #[test]
    fn run_nonempty_findings_is_err_with_count_prefix() -> Result<()> {
        // 非空路径会经 print_findings 打 stderr（副作用无法在单测捕获，由功能等价手跑核验）；此处断言 bail 文案。
        let fake = Fake {
            outcome: Outcome::NonEmpty,
        };
        match run_check(&fake) {
            Ok(()) => bail!("非空 findings 应 fail，实返回 Ok"),
            Err(e) => assert!(
                e.to_string().contains("fake: 1 项校验失败"),
                "失败消息须含 name 前缀 + 计数: {e}"
            ),
        }
        Ok(())
    }

    #[test]
    fn run_hard_error_propagates() -> Result<()> {
        let fake = Fake {
            outcome: Outcome::HardErr,
        };
        match run_check(&fake) {
            Ok(()) => bail!("硬错误应冒泡为 Err"),
            Err(e) => assert!(e.to_string().contains("io 炸了"), "{e}"),
        }
        Ok(())
    }
}
