use identity::ports::device_certificate::DevicePolicyAuthorizationReceipt;

fn assert_serialize<T: serde::Serialize>() {}

fn main() {
    assert_serialize::<DevicePolicyAuthorizationReceipt>();
}
