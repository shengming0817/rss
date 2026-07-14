use audit::ports::AuditListTenantAppend;

fn fake<T>() -> T {
    panic!("compile-fail fixture")
}

fn bypass() {
    let _command = AuditListTenantAppend {
        scope: fake(),
        event: fake(),
        observation: fake(),
    };
}

fn main() {}
