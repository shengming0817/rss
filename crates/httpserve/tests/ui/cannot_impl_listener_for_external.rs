//! ROUTE-LISTENER-TYPED-01（sealed listener marker）：外部 crate 无法为自定义类型实现 `Listener`——
//! `Listener: sealed::Sealed` 的 supertrait `Sealed` 在私有 `mod sealed` 内，外部既不可命名也不可满足，
//! 故无法新增 listener marker（typed function choice 的 Hard 闭环上游）。
struct MyListener;

impl httpserve::Listener for MyListener {
    const KIND: primitives::ListenerKind = primitives::ListenerKind::Primary;
}

fn main() {}
