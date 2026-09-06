# ADR：2296 首次安装定义在合并前收敛

状态：采纳；范围仅 PR 928 的首次 Observation schema，关联 #2296。

## 背景与决定

基线 develop 没有 Observation package 或 schema。本 PR 首次提交的安装定义尚未发布或合并，
真实数据库证据来自每次新建的组件 fixture，不存在需要升级的历史 Observation 消费者。
用户明确授权此次全新契约不保留历史兼容路径。

内置审查发现 SQL 重复枚举可应用状态。采用核心唯一计算 applicability，adapter 在同一事务
显式持久化布尔值；同步补齐核心持久表示 V1 恢复校验。本次按 Rust 规则的 ADR 例外修订
本 PR 的 0001 首次安装定义并更新精确 catalog fingerprint，不增加无消费者的升级路径。

## 约束与证据

例外仅适用于这次合并前的安装定义收敛；发布/合并后的 schema 改动必须新增升级定义。
每轮 T2 新建 PostgreSQL 16 schema，验证完整性、原子性、权限与 catalog 漂移；核心验证未知
持久版本与不可达状态拒绝。该决定不授权改写任何现存组件的迁移，也不扩展 MDM 产品职责。
