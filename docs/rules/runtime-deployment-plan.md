# Runtime DeploymentPlan 规则

## 上游身份

- DeploymentPlan MUST 由已验证的 RuntimePlan 编译，并逐字携带其 assembly 与 runtime-plan fingerprints。
- 公开 reader MUST 接收当前 RuntimePlan 并执行 exact-match；MUST NOT 从 DeploymentPlan 的部分字段重构上游身份。
- 失败语义：上游身份、stage tag、schema version 或 fingerprint 不匹配时 fail closed。
- 载体：`INVARIANT: DEPLOYMENT-PLAN-UPSTREAM-IDENTITY-01` -> `assembly-schema::DeploymentPlan`。

## 构造与生成物

- 唯一实例声明 MUST 位于 `assemblies/artifacts.toml`；supported assembly MUST 各有一个 deployment block，compile-only assembly MUST NOT 有该 block。
- workload、service、port、resource、probe、identity 与 secret reference MUST 经封闭类型和必填构造器进入 v1；MUST NOT 提供旧 reader、alias、fallback、shim 或双写。
- `cargo xtask deployment plan render` MUST 在全量预检与内存编译成功后逐目标原子替换 exact generated set，并在发布后重验集合与 bytes；`check` MUST 零写入并拒绝 missing、orphan、symlink、CRLF 与 raw-byte drift。该仓库生成命令不定义并发 writer 或多文件线性化事务。
- 失败语义：输入集合或引用闭包不完整、输出集合不精确或 bytes 漂移时 fail closed。
- 载体：`INVARIANT: DEPLOYMENT-PLAN-CONSTRUCTION-01` -> `assembly-schema::DeploymentPlan`；`INVARIANT: DEPLOYMENT-PLAN-ARTIFACT-CLOSURE-01` -> `cargo xtask deployment plan check`。

## Secret 与镜像边界

- DeploymentPlan MUST 只表示 Kubernetes/Vault typed secret references；MUST NOT 表示、记录或诊断 secret value。
- image MUST 是 `repository@sha256:digest` 的期望内容寻址 identity；该字段 MUST NOT 被解释为构建、签名或 same-head receipt 证据。
- 失败语义：可变/非法 image、inline secret 或自由形态 secret map 均拒绝，诊断不得回显输入值。
- 载体：`INVARIANT: DEPLOYMENT-PLAN-SECRET-BOUNDARY-01` -> `assembly-schema::SecretRef`。
