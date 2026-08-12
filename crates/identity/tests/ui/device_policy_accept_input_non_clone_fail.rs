fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<identity::ports::device_certificate::AcceptDesiredPolicy>();
}
