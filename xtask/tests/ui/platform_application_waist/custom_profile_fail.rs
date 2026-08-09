use platform_application_waist_contract::{ApplicationBuilder, ApplicationName, profile};

struct CustomProfile;

fn main() {
    let _ = std::any::type_name::<profile::Core>();
    let _custom = ApplicationBuilder::<CustomProfile>::new(
        ApplicationName::parse("custom_app").unwrap(),
    );
}
