//! fail：`async fn` in trait 破坏 dyn-compatibility —— 这正是 dynosaur 为 DI port 解决的根问题
//! （ADR-003 §1）：裸 `Box<dyn RawAsyncPort>` 编不过（E0038）。锁错误形态——DI port 的 async 方法
//! 必须经 dynosaur `dyn(box)` wrapper（`DynX`）才能 dyn 派发，不能直接 `dyn Trait`。
trait RawAsyncPort {
    async fn run(&self) -> u32;
}

fn main() {
    let _: Box<dyn RawAsyncPort> = make();
}

fn make() -> Box<dyn RawAsyncPort> {
    unimplemented!()
}
