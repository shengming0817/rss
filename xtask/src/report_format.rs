//! Consistency / LocalTx report wire format（闭枚举：`json` | `markdown`）。

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ReportFormat {
    Json,
    Markdown,
}
