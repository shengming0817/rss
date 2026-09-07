# rss-ledger

面向 Rust 消费者的可校验追加账本协议。核心不依赖 PG、消息执行器或身份产品模型。

```rust
use rss_ledger::{Authenticator, AppendRequest, ChainId, KeyId, LedgerId, RecordId};
use rss_request_context::TenantId;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
// 示例密钥仅用于演示；产品必须注入秘密随机材料。
let auth = Authenticator::new(KeyId::parse("example-key")?, vec![7; 32])?;
let ledger = LedgerId::new(TenantId::parse("10000000-0000-4000-8000-000000000001")?, ChainId::parse("events")?);
let request = AppendRequest::new(ledger.clone(), RecordId::parse("stable-record")?, b"exact bytes".to_vec())?;
let entry = auth.append(&request, None)?;
assert_eq!(auth.verify_chain(&ledger, &[entry])?.count(), 1);
# Ok(()) }
```

## V1 持久协议

认证输入严格按以下顺序连接：

1. ASCII 域标记 `rss.ledger.entry` 和一个 NUL。
2. 编码版本 `u16 BE = 1`，租户 UUID 的 16 个原始字节。
3. chain_id 的 `u32 BE` 字节长度和 UTF-8 字节，seq 的 `u64 BE`。
4. record_id、key_id，分别使用相同的 `u32 BE` 长度前缀。
5. 前驱的完整 32 字节认证值。
6. payload 的 `u64 BE` 字节长度和精确 payload 字节。

认证值为完整 HMAC-SHA256 输出。首条 seq=0、前驱全零；后继 checked 加一。
身份非空、最多 255 UTF-8 字节、不含 NUL；payload 允许为空、最大 1 MiB，不做 JSON 规范化。
上限、字段顺序、字节序和版本均属于 V1 存储协议，未来变更须独立版本化。

每个 Authenticator 固定一个 key_id 及至少 32 字节的密钥。密钥输入用完清零，Debug 脱敏；
不宣称编译器/密码原语的全部内部临时状态均可清零。产品拥有随机密钥生成、注入、托管及轮转策略。
未知编码/密钥身份拒绝；key_id 不是轮转功能。同一链不支持跨密钥或编码代际追加。

## 验证与信任来源

`Entry::from_parts` 只重建有界值，不提供认证证据；必须通过 Authenticator 验证。
`verify_chain` 从 genesis 开始，`verify_window` 可接收立即前驱，先验证前驱认证再验证连续窗口。
报告只描述输入中的已校验记录，不承诺存储持久性或输入完整性。空窗口验证零条记录，不能证明账本为空。

调用方拥有锚点信任决策。与记录同库读取的前驱不是外部可信 checkpoint；持钥方能重新计算认证。
HMAC 不提供对持钥方的不可抵赖性；局部链不能证明未截尾/漏记，也不提供 WORM 合规保证。

## 来源及状态

ref: RustCrypto/MACs hmac/src/lib.rs@hmac-v0.12.1
ref: RustCrypto/hashes sha2/src/lib.rs@sha2-v0.10.9
历史来源固定 `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`，仅提取链链接/窗口概念；
没有历史模型别名、旧编码兼容层或 FAIL_HASH。#2312 接纳，0.1 实验版本线，Rust API 尚无发布兼容承诺。
示例及 artifact 消费证明不代表已有生产消费者或实际发布。
