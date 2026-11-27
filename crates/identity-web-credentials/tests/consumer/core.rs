fn main() {
    let context = rss_identity_core::step_up::StepUpContext::new("authorize".into(), [7; 32]).unwrap();
    assert_eq!(context.purpose(), "authorize");
    assert!(rss_identity_core::step_up::StepUpContext::new("\n".into(), [7; 32]).is_err());
    println!("passed");
}
