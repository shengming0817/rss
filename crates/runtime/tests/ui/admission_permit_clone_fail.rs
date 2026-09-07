use rss_runtime::AdmissionPermit;
fn duplicate(permit: AdmissionPermit) {
    let _other = permit.clone();
}
fn main() {}
