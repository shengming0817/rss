//! fail：泛型方法破坏 dyn-compatibility → `Box<dyn _>` 编不过（E0038）。锁错误形态——DI port 写法
//! 须遵 ADR-003 §4.6 dos/don'ts（无泛型方法 / 返回 Self / impl Trait）。
trait NonDynCompatiblePort {
    fn handle<T>(&self, value: T);
}

fn main() {
    let _: Box<dyn NonDynCompatiblePort> = make();
}

fn make() -> Box<dyn NonDynCompatiblePort> {
    unimplemented!()
}
