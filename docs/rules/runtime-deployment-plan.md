# Runtime DeploymentPlan 规则

## 上游身份

- DeploymentPlan MUST 由已验证的 RuntimePlan 编译，并逐字携带其 assembly 与 runtime-plan fingerprints。
- 公开 reader MUST 接收当前 RuntimePlan 并执行 exact-match；MUST NOT 从 DeploymentPlan 的部分字段重构上游身份。
- 失败语义：上游身份、stage tag、schema version 或 fingerprint 不匹配时 fail closed。
- 载体：`INVARIANT: DEPLOYMENT-PLAN-UPSTREAM-IDENTITY-01` -> `assembly-schema::DeploymentPlan`。

## 构造与生成物

- 唯一实例声明 MUST 位于 `assemblies/artifacts.toml`；supported assembly MUST 各有一个 deployment block，compile-only assembly MUST NOT 有该 block。
- workload、service、port、resource、probe、identity、migration mode、availability class、drain、dependency peer role 与 secret binding MUST 经封闭类型和必填构造器进入 v1；MUST NOT 提供旧 reader、alias、fallback、shim 或双写。
- `cargo xtask deployment plan render` MUST 在全量预检与内存编译成功后逐目标原子替换 exact generated set，并在发布后重验集合与 bytes；`check` MUST 零写入并拒绝 missing、orphan、symlink、CRLF 与 raw-byte drift。该仓库生成命令不定义并发 writer 或多文件线性化事务。
- 失败语义：输入集合或引用闭包不完整、输出集合不精确或 bytes 漂移时 fail closed。
- 载体：`INVARIANT: DEPLOYMENT-PLAN-CONSTRUCTION-01` -> `assembly-schema::DeploymentPlan`；`INVARIANT: DEPLOYMENT-PLAN-ARTIFACT-CLOSURE-01` -> `cargo xtask deployment plan check`。

## Secret 与镜像边界

- DeploymentPlan MUST 只表示 purpose/consumer-bound `VaultObjectRef`；target file name 与绝对 mount path MUST 由封闭 `SecretPurpose` 派生。Kubernetes Secret、target env/path 自由字符串、inline value 与双来源均无协议表示。
- image MUST 是 `repository@sha256:digest` 的期望内容寻址 identity；该字段 MUST NOT 被解释为构建、签名或 same-head receipt 证据。
- 失败语义：可变/非法 image、inline secret 或自由形态 secret map 均拒绝，诊断不得回显输入值。
- 载体：`INVARIANT: DEPLOYMENT-PLAN-SECRET-BOUNDARY-01` -> `assembly-schema::SecretBinding`；`INVARIANT: SECRET-FILE-BOUNDARY-01` -> serving/operator config file-only readers。

## Helm 静态投影

- 同一 chart MUST 只接受 `runtime|settingsonly|identityaudit` profile 与 `migration|serving` phase，并从 chart 内对应的 committed DeploymentPlan 读取所有事实；values MUST NOT 覆盖或重建这些事实。默认 phase 是 fail-safe `migration`。
- `cargo xtask deployment plan render|check` MUST 关闭 chart 内 plan、default/profile values、values schema
  与三 profile × 两 phase Helm render golden、core manifests、extension manifests 的 exact set。`check` 使用精确 Helm 4.2.0 完成六组合 lint/render 与共享 policy semantic preflight，且零写入；
  `render` MUST 在全量 Helm 预检后才原子发布所有生成载体。
- 基础模板 MUST 保持 non-root、read-only root filesystem、drop ALL、禁 privilege escalation、无 shell
  假设；`workloadOnly` port MUST NOT 进入 Service。
- migration phase MUST 只生成 fingerprinted migrate-all Job、独立 SA/Vault SPC 与最小网络边界；serving phase MUST 无 migration capability，并生成 Vault file CSI、按 workload-only listener 派生的 SPIFFE CSI、default-deny NetworkPolicy、HPA/PDB/topology/drain 与 ServiceMonitor。
- `cargo xtask deployment policy check` MUST 复用相同 semantic validator，验证 6+6 committed manifest exact tree、固定 CRD schema digest，并用精确 kubeconform v0.7.0 对 Kubernetes 1.30 core schema与本地 CRD schema执行 strict validation；禁止 ignore-missing-schemas。
- 本静态闭包不声称 cluster controller/CRD 已安装或产生 kind/release runtime evidence；该运行证据仍由 #1805 所有。
- migration 是 forward-only fence：旧 workload 归零后执行 migration phase，成功后才进入 serving phase。数据库已推进后禁止用旧 image 或 `helm rollback` 冒充可行回滚；仓库载体可 whole-change revert，但 live rollout 只能 roll forward 到兼容新 schema 的 image。
