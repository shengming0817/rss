//! eventtransport journey：`bootstrap::eventtransport` resolver 决策 → 组合根 match 构造传输 → 端到端。
//!
//! 兑现 issue #1119 的两个治理点（resolver 单测在 bootstrap，本 journey 验**决策→构造**接缝在 dev root）：
//! - **TOPO-INMEM-SEAL-01（dev root 落地）**：`MemBus` 只在 `ResolvedTransport::Demo` 臂构造——经
//!   [`resolve_demo_bus`] 的 match 绑定到已校验决策；非 Demo 决策不可达此构造。生产 bin（`bins/server`）
//!   经 cargo-deny 连 `memory` 都依赖不到（更强 Hard），故 sealing 在两端都成立。
//! - **TOPO-FAILCLOSED-01（root 边界）**：durable 拓扑缺 broker URL ⇒ `resolve` 返 `Err`，组合根
//!   fail-fast 拒绝启动，绝不降级回 in-mem（见 [`durable_topology_fails_closed_without_broker`]）。
//!
//! demo 闭环：resolve(Demo) → MemBus → publish→subscribe（对标既有 identity journey 的 in-mem 传输）。
//! 本 journey 全程 in-process（不需 broker），故 **不** feature-gate——是默认 `cargo test` / `verify` 验收门。
//! 真实 amqp broker I/O 的传输验收见 `adapters/amqp/tests/integration.rs`（`integration` feature 门控）。

use bootstrap::{ResolvedTransport, Topology, TransportConfig, TransportResolveError, resolve};
use diport::{PublishRequest, Publisher, Subscriber, Topic};
use futures::StreamExt;
use memory::MemBus;
use tokio_util::sync::CancellationToken;

const TOPIC: &str = "identity.session-created";

/// 经 eventtransport resolver 的 **demo 决策** 取进程内 bus——TOPO-INMEM-SEAL-01 在 dev root 的物理落地：
/// `MemBus` 只在 `ResolvedTransport::Demo` 臂构造（绑定已校验决策；非 Demo 决策不可达此构造路径）。
#[allow(clippy::expect_used)] // journey 断言：item-level carve-out（workspace lints 约定）
fn resolve_demo_bus() -> MemBus {
    let resolved =
        resolve(Topology::Demo, TransportConfig::default(), &[]).expect("demo topology resolves");
    match resolved {
        ResolvedTransport::Demo => MemBus::new(),
        // 非 Demo（Durable / 未来变体）在 demo 组合根不可达——in-mem 仅经 Demo 臂构造（sealing）。
        _ => unreachable!("demo topology resolves to Demo only"),
    }
}

/// demo 决策解析出进程内 bus，且 publisher/subscriber 同实例闭环（publish→subscribe）。
#[tokio::test]
#[allow(clippy::expect_used)] // journey 断言：item-level carve-out（workspace lints 约定）
async fn demo_resolver_yields_inprocess_bus_roundtrip() {
    let bus = resolve_demo_bus();
    let token = CancellationToken::new();
    // 订阅须先于发布（in-mem 无重放）。
    let mut stream = bus
        .subscriber()
        .subscribe(Topic::new(TOPIC), token.clone())
        .await
        .expect("subscribe");
    bus.publisher()
        .publish(PublishRequest {
            topic: Topic::new(TOPIC),
            payload: b"session-evt".to_vec(),
        })
        .await
        .expect("publish");
    let msg = stream
        .next()
        .await
        .expect("message delivered via resolved demo bus");
    assert_eq!(msg.payload, b"session-evt".to_vec());
}

/// durable 拓扑缺 broker URL ⇒ fail-closed（精确 `MissingBrokerUrl{domain}`），绝不降级回 demo/in-mem
/// （TOPO-FAILCLOSED-01；类型层 `Durable` 路径无 `Ok(Demo)` 可表达变体，故无静默回退的可能）。
#[test]
fn durable_topology_fails_closed_without_broker() {
    let got = resolve(
        Topology::DurableShared,
        TransportConfig::default(),
        &["identity"],
    );
    assert!(matches!(
        got,
        Err(TransportResolveError::MissingBrokerUrl { domain }) if domain == "IDENTITY"
    ));
}
