//! 契约归属 `ContractOwner`（sealed enum：Domain(name) | Framework）。
//! owner→域解析只经 [`ContractOwner::domain`]；Framework 归属返回 None（类型层收口，无运行期 guard）。

/// 契约归属。`Framework` 是 provider-agnostic 中立契约的保留 sentinel，不绑定单一域。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContractOwner {
    Domain(DomainName),
    Framework,
}

impl ContractOwner {
    /// 解析归属域 crate；`Framework` 归属返回 `None`。
    pub fn domain(&self) -> Option<&DomainName> {
        todo!()
    }
}

/// `DomainName` 解析错误。空值 / 非法字符（非 crate-name 形）非法（校验在行为 PR 兑现）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DomainNameError {
    #[error("domain name is empty")]
    Empty,
    #[error("domain name has invalid format")]
    Format,
}

/// 域名 newtype（私有字段，构造经 fallible funnel）。
///
/// 域名是契约归属路径段（crate-name 形）——冻结为可失败构造，拒绝空值 / 非法字符。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainName(String);

impl DomainName {
    /// 解析域名；拒绝空值 / 非法格式（校验在行为 PR 兑现）。
    pub fn parse(_raw: &str) -> Result<Self, DomainNameError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }
}
