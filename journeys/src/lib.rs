//! journeys — RSS 验收 journey 组合根（组合根层，可依赖所有库 crate）。
//!
//! RW-G1 追踪弹：identity 登录 → in-mem outbox → in-mem 分发 → audit append，组装在
//! httpserve + authn + bootstrap demo topology 上，端到端证明冻结接缝能拼成闭环。
//! demo 组装根 + journey 集成测试见 `tests/`（批次3 落地）。
